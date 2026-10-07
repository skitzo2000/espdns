package main

import (
	"context"
	"crypto/hmac"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/configs"
	"github.com/skitzo2000/espdns/controller/internal/fleet"
	"github.com/skitzo2000/espdns/controller/internal/jobs"
	"github.com/skitzo2000/espdns/controller/internal/keys"
	"github.com/skitzo2000/espdns/controller/internal/nodecfg"
	"github.com/skitzo2000/espdns/controller/internal/nodes"
	"github.com/skitzo2000/espdns/controller/internal/pins"
	"github.com/skitzo2000/espdns/controller/internal/release"
	"github.com/skitzo2000/espdns/controller/internal/rolling"
	"github.com/skitzo2000/espdns/controller/internal/settings"
)

// The rolling push (the Push page): firmware, a config per node, a blocklist, overrides or
// the hosted zones across the nodes in settings.json, as make fleet-rollout KIND=... does
// it, through the same code: the page's request becomes the request the CLI's flags make
// (internal/rolling, Web), built into the same plan and change, and the job runs
// fleet.Rollout on them under the fleet lock, in the action log with the logged-in user.
//
//	GET  /api/push/sources   what there is to push (internal/rolling, Sources), the nodes, the defaults
//	POST /api/push/preview   {Web}: what each node would get, from its /status (read-only, no job)
//	POST /api/jobs           {"kind": "rollout", "params": {Web, "dry_run": true}}: the dry run
//	POST /api/jobs           {"kind": "rollout", "params": {Web, "after": "<the dry run's job ID>"}}: the push
//
// A push must name a dry run of the same request, with the same files (the same bytes),
// that passed in the last 15 minutes: the page runs it first and shows its outcome per
// node. Nothing the CLI's rule has is loosened: no -force, -allow-single, -no-dns-checks,
// -reinstall or -empty; the soak only longer than the default; settings.json's nodes
// only, mDNS not counted (the Makefile's -mdns 0).

type pushKind struct {
	actions
	catalog string
	// job is the runner's job of an ID (the dry run a push names).
	job func(id string) (jobs.Job, bool)
	// secret keys the fingerprint of what a dry run checked; new at every start.
	secret []byte
	nodes  func() []nodes.Node
	// used are the dry runs already followed by a push (one push per dry run).
	used *usedRuns
	// adjust, in tests only, shortens the plan's waits after it is built.
	adjust func(*fleet.Plan)
}

// rolloutResult is a rollout job's result.
type rolloutResult struct {
	Kind        string   `json:"kind"`
	DryRun      bool     `json:"dry_run"`
	Fingerprint string   `json:"fingerprint"`
	Order       []string `json:"order"`
	Done        []string `json:"done,omitempty"`
	Skipped     []string `json:"skipped,omitempty"`
	Failed      string   `json:"failed,omitempty"`
	Left        []string `json:"left,omitempty"`
	// A list rollout that failed: the nodes sent back to the copy each had, and the ones
	// that couldn't be (why, the way on).
	Reverted    []string            `json:"reverted,omitempty"`
	NotReverted []fleet.NotReverted `json:"not_reverted,omitempty"`
}

// fingerprint keys the request (its files resolved) and the bytes of every file it reads,
// so a push matches its dry run only while nothing it pushes has changed. The bytes are
// read through the request's Files, which the rollout then builds from: what was compared
// with the dry run is what is pushed, even if a file is replaced meanwhile.
func (p pushKind) fingerprint(r rolling.Request) string { return r.Fingerprint(p.secret) }

// usedRuns are the dry runs a push has followed: each is good for one push.
type usedRuns struct {
	mu  sync.Mutex
	ids map[string]bool
}

// claim takes the dry run id for a push; false if one already took it.
func (u *usedRuns) claim(id string) bool {
	if u == nil {
		return true
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.ids == nil {
		u.ids = map[string]bool{}
	}
	if u.ids[id] {
		return false
	}
	u.ids[id] = true
	return true
}

func (p pushKind) kind(raw json.RawMessage) (jobs.Func, error) {
	w, err := rolling.ParseWeb(raw)
	if err != nil {
		return nil, err
	}
	req, err := w.Request(p.dataDir, p.catalog)
	if err != nil {
		return nil, err
	}
	// Every file read and checked now (the firmware's descriptors, the configs, the list's
	// header, the zones), so a bad one isn't queued; again when the job runs.
	if _, _, err := rolling.LoadChange(req, req.Hosts, func(string, ...any) {}); err != nil {
		return nil, err
	}
	if w.DryRun {
		if w.After != "" {
			return nil, errors.New(`params: "after" is for the push after a dry run`)
		}
	} else {
		if _, err := p.signer(); err != nil {
			return nil, err
		}
		if err := p.dryRunFor(w.After, req); err != nil {
			return nil, err
		}
		// One push per dry run: after a push that stopped or failed, what comes next is
		// a new dry run of what is left (docs/rollout.md, When a rollout stops).
		if !p.used.claim(w.After) {
			return nil, fmt.Errorf("the dry run %s was already followed by a push: run the dry run again", w.After)
		}
	}
	return func(ctx context.Context, run *jobs.Run) (any, error) { return p.run(ctx, run, w) }, nil
}

// dryRunFor checks that after is a rollout dry run that passed, not long ago, for this
// request with these files.
func (p pushKind) dryRunFor(after string, req rolling.Request) error {
	if after == "" {
		return errors.New(`a push needs a dry run first: run it with "dry_run": true, then push with "after": its job ID`)
	}
	j, ok := p.job(after)
	var res rolloutResult
	switch {
	case !ok || j.Kind != "rollout":
		return fmt.Errorf("no rollout dry run %s", after)
	case j.State != jobs.Done:
		return fmt.Errorf("the dry run %s didn't pass (%s): fix what it says and run it again", after, j.State)
	case json.Unmarshal(j.Result, &res) != nil || !res.DryRun:
		return fmt.Errorf("%s is not a dry run", after)
	case time.Since(j.Ended) > dryRunValid:
		return fmt.Errorf("the dry run %s is over %v old: run it again", after, dryRunValid)
	case !hmac.Equal([]byte(res.Fingerprint), []byte(p.fingerprint(req))):
		return fmt.Errorf("the push isn't the one the dry run %s checked: the nodes, the order, the checks or a file "+
			"changed since (or the controller restarted): run the dry run again", after)
	}
	return nil
}

// nodeState is one node's place in a rollout job, for the page.
type nodeState struct {
	// waiting, gate, would-push, pushing, rebooting, checking, checked, soaking, done, skipped,
	// failed, left, refused; a list sent back after a failure: reverting, reverted, not-reverted
	State   string    `json:"state"`
	Detail  string    `json:"detail,omitempty"`
	Revert  string    `json:"revert,omitempty"`  // a list's revert: where it went back to, or why not and the way on
	Expect  string    `json:"expect,omitempty"`  // what it gets (the preview)
	Refused string    `json:"refused,omitempty"` // why it can't take it (the preview)
	Note    string    `json:"note,omitempty"`
	Checks  string    `json:"checks,omitempty"` // the DNS checks' last outcome
	Since   time.Time `json:"since"`
	Until   time.Time `json:"until,omitzero"` // the soak's end
}

// pushProgress is a rollout job's progress: the order, each node's state.
type pushProgress struct {
	Kind    string                `json:"kind"`
	DryRun  bool                  `json:"dry_run"`
	Order   []string              `json:"order"`
	Canary  string                `json:"canary,omitempty"`
	SoakS   float64               `json:"soak_s"`
	Checks  []string              `json:"checks"`
	Plan    []string              `json:"plan,omitempty"`   // how it goes (fleet.Plan.Describe): canary, soak, a failure
	Revert  bool                  `json:"revert,omitempty"` // a list: a failure sends every node that took it back
	Nodes   map[string]*nodeState `json:"nodes"`
	Outcome string                `json:"outcome,omitempty"`
	Left    []string              `json:"left,omitempty"`
	Hints   []string              `json:"hints,omitempty"`
}

type tracker struct {
	mu  sync.Mutex
	run *jobs.Run
	p   pushProgress
}

func (t *tracker) set(host, state, detail string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := t.p.Nodes[host]
	if n == nil {
		return
	}
	n.State, n.Detail, n.Since, n.Until = state, detail, time.Now(), time.Time{}
	switch state {
	case string(fleet.StepSoaking):
		if d, err := time.ParseDuration(detail); err == nil {
			n.Until = n.Since.Add(d)
		}
	case string(fleet.StepChecked):
		n.Checks = "passed: in service, " + strings.Join(t.p.Checks, ", ")
		if detail != "" {
			n.Checks += " (" + detail + ")"
		}
	case string(fleet.StepReverted):
		n.Revert, n.Detail = detail, ""
	case string(fleet.StepNotReverted):
		n.Revert, n.Detail = "not reverted: "+detail, ""
	}
	t.run.SetProgress(t.p)
}

func (t *tracker) update(f func(p *pushProgress)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	f(&t.p)
	t.run.SetProgress(t.p)
}

// checksText says what the DNS checks after each node ask.
func checksText(ch fleet.Checks) []string {
	out := []string{"its zones' SOA answered"}
	if ch.Off {
		return []string{"it answers DNS"}
	}
	if len(ch.Forwarded) > 0 {
		out = append(out, strings.Join(ch.Forwarded, ", ")+" resolves")
	}
	if len(ch.Blocked) > 0 {
		out = append(out, strings.Join(ch.Blocked, ", ")+" blocked (while its blocklist is on)")
	}
	if len(ch.MustResolve) > 0 {
		out = append(out, fmt.Sprintf("%d must-resolve names resolve", len(ch.MustResolve)))
	}
	return out
}

func (p pushKind) run(ctx context.Context, run *jobs.Run, w rolling.Web) (any, error) {
	// Everything again, as it is now: the settings, the files, the dry run, the key.
	req, err := w.Request(p.dataDir, p.catalog)
	if err != nil {
		return nil, err
	}
	res := rolloutResult{Kind: req.Kind.String(), DryRun: req.DryRun, Fingerprint: p.fingerprint(req)}
	if !req.DryRun {
		if err := p.dryRunFor(w.After, req); err != nil {
			return nil, err
		}
	}
	c := p.client()
	c.Logf = run.Logf
	if k, err := p.signer(); err == nil {
		c.Pusher = &release.Pusher{Key: k, KeyID: release.KeyRelease, Pins: pins.Open(p.dataDir), Client: c.HTTP}
		run.Logf("signing with the release key %s", keys.Fingerprint(k))
	} else if !req.DryRun {
		return nil, err
	} else {
		run.Logf("no release key (%v): a dry run goes on without one", err)
	}
	order := req.Order()
	res.Order = order
	t := &tracker{run: run, p: pushProgress{Kind: res.Kind, DryRun: req.DryRun, Order: order, Canary: order[0],
		SoakS: req.Soak.Seconds(), Nodes: map[string]*nodeState{}}}
	for _, h := range order {
		t.p.Nodes[h] = &nodeState{State: "waiting", Since: time.Now()}
	}
	run.SetProgress(t.p)

	b, err := rolling.Build(ctx, c, req, run.Logf)
	if err != nil {
		t.update(func(pp *pushProgress) { pp.Outcome = "not started: " + err.Error() })
		return res, err
	}
	b.Plan.Stop = run.Stop()
	if p.adjust != nil {
		p.adjust(&b.Plan)
	}
	order = b.Plan.Order()
	res.Order = order
	t.update(func(pp *pushProgress) {
		pp.Checks = checksText(b.Plan.Checks)
		pp.Order, pp.Canary, pp.Plan = order, order[0], b.Plan.Describe(req.Kind)
		pp.Revert = req.Kind == release.Blocklist || req.Kind == release.Overrides
	})
	// What each node would get, from its /status: shown before the rollout's own checks.
	for _, pv := range p.preview(ctx, c, req, b) {
		t.update(func(pp *pushProgress) {
			n := pp.Nodes[pv.Host]
			n.Expect, n.Refused, n.Note = pv.Expect, pv.Refused, pv.Note
		})
	}
	c.Progress = func(host string, s fleet.Step, detail string) { t.set(host, string(s), detail) }
	run.Logf("rolling out %s to %s", req.Kind, strings.Join(b.Plan.Order(), ", then "))
	r, err := c.Rollout(ctx, b.Plan, b.Change)
	if errors.Is(err, fleet.ErrSingle) {
		err = fmt.Errorf("%w (add the other nodes or a DNS peer to settings.json; the CLI's -allow-single is not offered here)", err)
	}
	rolling.Report(run.Logf, b.Plan, r)
	if req.Kind == release.Config && !req.DryRun {
		rolling.RecordPushed(ctx, c, p.dataDir, b.Specs, r.Done, "controller", run.Logf)
	}
	if req.Kind == release.Zones && !req.DryRun {
		rolling.RecordZones(ctx, c, req, r.Done, "controller", run.Logf)
	}
	res.Done, res.Skipped, res.Failed, res.Left = r.Done, r.Skipped, r.Failed, r.Left
	res.Reverted, res.NotReverted = r.Reverted, r.NotReverted
	p.finish(ctx, c, t, req, r, err)
	if err == nil && req.DryRun {
		run.Logf("dry run passed: nothing was pushed")
	}
	return res, err
}

// finish sets each node's last state, what the run left and how to go on.
func (p pushKind) finish(ctx context.Context, c *fleet.Client, t *tracker, req rolling.Request, r fleet.Result, err error) {
	t.update(func(pp *pushProgress) {
		for _, h := range r.Done {
			pp.Nodes[h].State, pp.Nodes[h].Detail, pp.Nodes[h].Until = "done", "", time.Time{}
		}
		for _, h := range r.Skipped {
			pp.Nodes[h].State, pp.Nodes[h].Detail = "skipped", "already had it"
		}
		if r.Failed != "" && err != nil {
			pp.Nodes[r.Failed].State, pp.Nodes[r.Failed].Detail = "failed", err.Error()
		}
		// A list sent back: each node that took it, the failed one too (its failure kept
		// in the detail); the revert's outcome in Revert.
		for _, h := range r.Reverted {
			pp.Nodes[h].State, pp.Nodes[h].Until = "reverted", time.Time{}
		}
		for _, nr := range r.NotReverted {
			if nr.Host != r.Failed {
				pp.Nodes[nr.Host].State, pp.Nodes[nr.Host].Until = "not-reverted", time.Time{}
			}
		}
		switch {
		case req.DryRun && err == nil:
			pp.Outcome = "dry run passed: every node would take it now; nothing was pushed"
		case req.DryRun:
			pp.Outcome = "dry run failed: " + err.Error()
		case errors.Is(err, fleet.ErrStopped):
			pp.Outcome = "stopped on request"
		case err != nil:
			pp.Outcome = "stopped: " + err.Error()
			if len(r.Reverted) > 0 {
				pp.Outcome += "; reverted on " + strings.Join(r.Reverted, ", ")
			}
			if len(r.NotReverted) > 0 {
				var hs []string
				for _, nr := range r.NotReverted {
					hs = append(hs, nr.Host)
				}
				pp.Outcome += "; NOT reverted on " + strings.Join(hs, ", ")
			}
		default:
			pp.Outcome = fmt.Sprintf("done: %d changed and checked, %d already had it", len(r.Done), len(r.Skipped))
		}
		// Refused before any node was touched: the nodes that can't take it say why.
		for _, h := range pp.Order {
			if n := pp.Nodes[h]; err != nil && r.Failed == "" && n.State == "waiting" && n.Refused != "" {
				n.State = "refused"
			}
		}
		if req.DryRun && err != nil {
			for _, h := range pp.Order {
				if n := pp.Nodes[h]; n.State == "waiting" {
					n.State = "left" // a dry run that stopped before it got there
				}
			}
		}
		if !req.DryRun {
			for _, h := range r.Left {
				if n := pp.Nodes[h]; n.State == "waiting" || n.State == "gate" {
					n.State = "left"
				}
			}
			pp.Left = r.Left
		}
	})
	if err == nil || req.DryRun {
		return
	}
	// How to go on (docs/rollout.md, When a rollout stops).
	var hints []string
	if len(r.Left) > 0 {
		hints = append(hints, "Not touched: "+strings.Join(r.Left, ", ")+". A run that skips a node is a new dry run "+
			"and push with that node left out: your decision, not a default.")
	}
	// Any node of the fleet left waiting for a reboot, changed in this run or before.
	s, _ := settings.Load(settings.Path(p.dataDir))
	for _, h := range s.Nodes {
		st, serr := c.Status(ctx, h)
		if serr == nil && st.Reboot != nil && st.Reboot.Pending {
			hints = append(hints, fmt.Sprintf("%s is left with a reboot pending (%s): reboot it from the Nodes page "+
				"(its Reboot, coordinated, as espdns reboot -host %s -if-pending), then check the fleet.",
				h, strings.Join(st.Reboot.Reasons, ", "), h))
		}
	}
	// A list sent back (fleet.Rollout's revert): what went back, what didn't and the way on.
	if len(r.Reverted) > 0 {
		hints = append(hints, fmt.Sprintf("Sent back to the %s each had before: %s. The nodes that took this one run their "+
			"old one again; fix the %s (what failed above) and start again from the dry run.", req.Kind,
			strings.Join(r.Reverted, ", "), req.Kind))
	}
	for _, nr := range r.NotReverted {
		hints = append(hints, fmt.Sprintf("%s keeps the new %s, not reverted: %s. The way on: %s.", nr.Host, req.Kind,
			nr.Why, nr.WayOn))
	}
	reverting := len(r.Reverted)+len(r.NotReverted) > 0
	switch {
	case errors.Is(err, fleet.ErrStopped):
	case reverting:
	case strings.Contains(err.Error(), "not started"):
		hints = append(hints, "Nothing was pushed to "+r.Failed+": fix the other node or the DNS peer, then a new dry run "+
			"and push (nodes already on it are skipped).")
	case strings.Contains(err.Error(), "rolled back"):
		hints = append(hints, r.Failed+" rolled back to its previous firmware: don't push the same build again; find "+
			"out why it failed (its /status, its serial log over USB), fix it, rebuild, and start from the dry run.")
	case r.Failed != "":
		hints = append(hints, "If "+r.Failed+" took the change but isn't back in service, wait and check the fleet "+
			"again: a node on trial rolls itself back within its trial window.")
	}
	t.update(func(pp *pushProgress) { pp.Hints = hints })
}

// nodePreview is what one node would get.
type nodePreview struct {
	Host    string `json:"host"`
	Online  bool   `json:"online"`
	Board   string `json:"board,omitempty"`
	Image   string `json:"image,omitempty"`
	Runs    string `json:"runs,omitempty"`
	Expect  string `json:"expect,omitempty"`
	Refused string `json:"refused,omitempty"`
	Note    string `json:"note,omitempty"`
}

// preview reads each node's /status and says what it would get, or why it can't take it:
// the rollout's own checks for a node (fleet.Change.Prepare), for every node, not only up
// to the first that fails.
func (p pushKind) preview(ctx context.Context, c *fleet.Client, req rolling.Request, b rolling.Built) []nodePreview {
	var out []nodePreview
	for _, h := range req.Order() {
		pv := nodePreview{Host: h}
		st, err := c.Status(ctx, h)
		if err != nil {
			pv.Refused = "can't be read: " + err.Error()
			out = append(out, pv)
			continue
		}
		pv.Online, pv.Board, pv.Image = true, st.Board, st.Image
		pv.Runs = fmt.Sprintf("%s %s (elf %s)", st.Project, st.Version, st.ElfSHA256)
		if st.Reboot != nil && st.Reboot.Pending {
			pv.Note = "reboot pending (" + strings.Join(st.Reboot.Reasons, ", ") + ")"
		}
		payload, place, err := b.Change.Prepare(ctx, h, st)
		if err != nil {
			pv.Refused = err.Error()
			out = append(out, pv)
			continue
		}
		switch req.Kind {
		case release.Firmware:
			fw, _ := b.Change.FirmwareFor(st)
			if fw.Desc.ElfSHA256 == st.ElfSHA256 {
				pv.Expect = fmt.Sprintf("already runs %s %s (elf %s): skipped", fw.Desc.Project, fw.Desc.Version, fw.Desc.ElfSHA256)
			} else {
				pv.Expect = fmt.Sprintf("firmware %s %s (elf %s, for %s), then a coordinated reboot", fw.Desc.Project,
					fw.Desc.Version, fw.Desc.ElfSHA256, fw.Image)
			}
			if st.Config != nil && st.Config.AddressFrom == "firmware" {
				pv.Note = strings.TrimPrefix(pv.Note+"; its address is built into the firmware it runs: "+
					"firmware without it (an exported chip image) would leave it without one", "; ")
			}
		case release.Config:
			pv.Expect = p.configExpect(req, b, h, st)
		case release.Blocklist, release.Overrides:
			pv.Expect = fmt.Sprintf("%s, %d KB", req.Kind, (len(payload)+1023)/1024)
			if place != "" {
				pv.Expect += ": " + place
			} else {
				pv.Expect += ": its firmware is from before the memory plan, so the node decides where it goes"
			}
		case release.Zones:
			limit := 0
			if st.Hosted != nil {
				limit = st.Hosted.LimitBytes / 1024
			}
			pv.Expect = fmt.Sprintf("hosted zones, a %d-byte bundle (its limit %d KB), replacing the ones it serves, live",
				len(payload), limit)
		}
		// What else it does there, as the CLI's dry run says it (fleet.Change.Note): for
		// zones, the hosted zones it stops serving.
		if n := b.Change.NoteFor(h, st); n != "" {
			pv.Note = strings.TrimPrefix(pv.Note+"; "+n, "; ")
		}
		out = append(out, pv)
	}
	return out
}

// configExpect says what a config does on the node: live, or with a reboot.
func (p pushKind) configExpect(req rolling.Request, b rolling.Built, host string, st release.NodeStatus) string {
	i := slices.IndexFunc(b.Specs, func(s configs.Spec) bool { return s.Host == host })
	if i < 0 {
		return ""
	}
	sp := b.Specs[i]
	name := sp.Path[strings.LastIndexByte(sp.Path, '/')+1:]
	f, err := configs.Read(p.dataDir, name)
	var fp *configs.File
	if err == nil {
		fp = &f
	}
	runs := configs.NodeRuns(p.dataDir, name, fp, st)
	ch := nodecfg.Compare(runs.Config, sp.Config, configs.RunningNetwork(st))
	out := name + ": "
	switch {
	case len(ch.Reboot) > 0:
		out += "needs a reboot (" + strings.Join(ch.Reboot, ", ") + "), coordinated"
	case len(ch.Maybe) > 0:
		out += "may need a reboot (" + strings.Join(ch.Maybe, ", ") + ")"
	case len(ch.Live) > 0:
		out += "applies live (" + strings.Join(ch.Live, ", ") + ")"
	default:
		out += "the same settings it runs"
	}
	if runs.Assumed {
		out += "; compared with the file as saved (what it runs isn't recorded here)"
	}
	return out
}

// ---- the page's reads ------------------------------------------------------------------

type pushNode struct {
	Host    string   `json:"host"`
	ID      string   `json:"id,omitempty"`
	Online  bool     `json:"online"`
	Board   string   `json:"board,omitempty"`
	Image   string   `json:"image,omitempty"`
	Version string   `json:"version,omitempty"`
	Elf     string   `json:"elf,omitempty"`
	State   string   `json:"state,omitempty"`
	Reboot  []string `json:"reboot,omitempty"`
	Config  string   `json:"config,omitempty"` // the config file it matches
	Off     []string `json:"off,omitempty"`    // services off in its config
}

func (p pushKind) routes(mux *routes) {
	mux.HandleFunc("GET /api/push/sources", needLogin("the rolling push needs", p.sources))
	mux.HandleFunc("POST /api/push/preview", needLogin("the rolling push needs", p.previewRoute))
}

func (p pushKind) sources(w http.ResponseWriter, r *http.Request) {
	s, err := settings.Load(settings.Path(p.dataDir))
	if err != nil {
		httpErr(w, http.StatusInternalServerError, err)
		return
	}
	src := rolling.ReadSources(p.dataDir, p.catalog)
	known := map[string]nodes.Node{}
	for _, n := range p.nodes() {
		known[n.Addr] = n
	}
	files, _ := configs.List(p.dataDir)
	var ns []pushNode
	for _, h := range s.Nodes {
		pn := pushNode{Host: h}
		if n, ok := known[h]; ok {
			pn.ID, pn.Online = n.ID, n.Online
			if st, ok := status(n); ok {
				pn.Board, pn.Image, pn.Version, pn.Elf = st.Board, st.Image, st.Version, st.ElfSHA256
				if st.Health != nil {
					pn.State = st.Health.State
				}
				if st.Reboot != nil && st.Reboot.Pending {
					pn.Reboot = st.Reboot.Reasons
				}
				for _, sv := range st.Services {
					if sv.State == "off" {
						pn.Off = append(pn.Off, sv.Name)
					}
				}
				for _, f := range files {
					if configs.Matches(f.Config, h, st) || pushedHere(p.dataDir, st, f.Name) {
						pn.Config = f.Name
						break
					}
				}
			}
		}
		ns = append(ns, pn)
	}
	if ns == nil {
		ns = []pushNode{}
	}
	_, kerr := p.signer()
	out := map[string]any{"sources": src, "nodes": ns, "canary": s.Canary, "dns_peers": s.DNSPeers,
		"soak_s": rolling.DefaultSoak.Seconds(), "max_soak_s": rolling.MaxSoak.Seconds(), "key": kerr == nil,
		"dry_run_valid_s": dryRunValid.Seconds()}
	if kerr != nil {
		out["key_error"] = kerr.Error()
	}
	writeJSON(w, out)
}

func (p pushKind) previewRoute(w http.ResponseWriter, r *http.Request) {
	var raw json.RawMessage
	if err := body(w, r, &raw); err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	web, err := rolling.ParseWeb(raw)
	if err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	web.DryRun = true
	req, err := web.Request(p.dataDir, p.catalog)
	if err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	c := p.client()
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	ch, specs, err := rolling.LoadChange(req, req.Hosts, func(string, ...any) {})
	if err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	b := rolling.Built{Change: ch, Specs: specs}
	writeJSON(w, map[string]any{"order": req.Order(),
		"nodes": p.preview(ctx, c, req, b)})
}
