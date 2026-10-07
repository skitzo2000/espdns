package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/adoption"
	"github.com/skitzo2000/espdns/controller/internal/configs"
	"github.com/skitzo2000/espdns/controller/internal/fleet"
	"github.com/skitzo2000/espdns/controller/internal/jobs"
	"github.com/skitzo2000/espdns/controller/internal/keys"
	"github.com/skitzo2000/espdns/controller/internal/nodecfg"
	"github.com/skitzo2000/espdns/controller/internal/nodes"
	"github.com/skitzo2000/espdns/controller/internal/pins"
	"github.com/skitzo2000/espdns/controller/internal/primary"
	"github.com/skitzo2000/espdns/controller/internal/release"
	"github.com/skitzo2000/espdns/controller/internal/settings"
)

// Adoption (the Adopt page): a node the controller found and that isn't adopted, given a
// config from <data>/configs and its address, as make fleet-adopt does it, through the same
// code: the page's request becomes the request the CLI's flags make (internal/adoption,
// Web), built and run by the same functions (fleet.AdoptNode: the address checked free, the
// config checked for the node, the zone primary's allow lists, the config pushed, the node
// confirmed on its address), then the config it runs recorded and, if asked, its address
// added to settings.json.
//
//	GET  /api/adopt              the nodes found (unadopted ones to adopt; adopted ones not in settings.json), the configs, the zone primary
//	POST /api/adopt/preview      {Web}: the address it would get, the config checked for the node, the zones (read-only, no job)
//	POST /api/jobs               {"kind": "adopt", "params": {Web, "dry_run": true}}: the dry run (the zone primary read, not changed)
//	POST /api/jobs               {"kind": "adopt", "params": {Web, "after": "<the dry run's job ID>", ...}}: the adoption
//	GET  /api/primary            each secondary zone's transfer and NOTIFY lists (or, changed by hand, what each node needs), and
//	                             whether every node in settings.json carrying it is in them
//	POST /api/jobs               {"kind": "primary", "params": {"zone", "address", "action": "allow"|"remove"}}: one list entry fixed
//	POST /api/jobs               {"kind": "settings-add", "params": {"node": "<address>"}}: an adopted node added to settings.json
//
// An adoption signs a config for a node found over mDNS, not one in settings.json (that is
// what adopting is): so only a node that says it isn't adopted, under an ID no other node
// the controller knows has, as the dry run found it (the same ID, the same files), within
// 15 minutes of it; one adoption per dry run. When the zone primary isn't changed from here
// (settings.json's "primary" is of the manual kind, or there is none, or no API address or
// token: internal/primary), the dry run says what to change on it by hand, and the adoption
// goes ahead only once the page says it was done ("primary_done"). The token never leaves
// the controller: not in a reply, a job's record, its log or the action log.

type adoptKind struct {
	actions
	catalog string
	job     func(id string) (jobs.Job, bool)
	secret  []byte
	nodes   func() []nodes.Node
	used    *usedRuns
	token   keys.TokenSource
	// adjust, in tests only, shortens the adoption's waits after it is built.
	adjust func(*fleet.Adopt)
}

// tokenFunc is the token for internal/adoption: "" when none is set up.
func tokenFunc(src keys.TokenSource) adoption.Token {
	return func() (string, error) {
		if src == nil {
			return "", nil
		}
		t, err := src.Token()
		if errors.Is(err, keys.ErrNoToken) {
			return "", nil
		}
		return t, err
	}
}

// adoptResult is an adopt job's result.
type adoptResult struct {
	Node            string   `json:"node"`
	NodeID          string   `json:"node_id"`
	Config          string   `json:"config"`
	DryRun          bool     `json:"dry_run"`
	Fingerprint     string   `json:"fingerprint"`
	Address         string   `json:"address,omitempty"` // where it is confirmed
	Seq             uint64   `json:"seq,omitempty"`
	Recorded        bool     `json:"recorded,omitempty"`
	AddedToSettings bool     `json:"added_to_settings,omitempty"`
	InSettings      bool     `json:"in_settings,omitempty"`
	Servers         []string `json:"servers,omitempty"`
}

// adoptStep is one step of the adoption, for the page.
type adoptStep struct {
	N      int    `json:"n"`
	Title  string `json:"title"`
	State  string `json:"state"` // waiting, running, done, failed, skipped
	Detail string `json:"detail,omitempty"`
}

// adoptProgress is an adopt job's progress.
type adoptProgress struct {
	DryRun  bool         `json:"dry_run"`
	Node    string       `json:"node"`
	NodeID  string       `json:"node_id"`
	Config  string       `json:"config"`
	Address string       `json:"address,omitempty"`
	Steps   []adoptStep  `json:"steps"`
	Primary primaryState `json:"primary"`
	Outcome string       `json:"outcome,omitempty"`
	Hints   []string     `json:"hints,omitempty"`
}

// primaryState is step 4 as the page shows it.
type primaryState struct {
	Kind    string         `json:"kind,omitempty"`
	API     string         `json:"api,omitempty"` // the API used; "" when changed by hand
	Why     string         `json:"why,omitempty"` // why the changes are made by hand
	Primary string         `json:"primary,omitempty"`
	Zones   []string       `json:"zones,omitempty"`
	Manual  []string       `json:"manual,omitempty"` // the changes to make by hand, per zone
	Done    bool           `json:"done,omitempty"`   // confirmed made by hand
	Edits   []primary.Edit `json:"edits,omitempty"`  // what the API changed, or would
}

var stepTitles = map[int]string{2: "Find the node", 3: "The address and the config", 4: "The zone primary's allow lists",
	5: "Push the config", 6: "Confirm it on its address", 7: "The clients' DNS servers"}

type adoptTracker struct {
	mu  sync.Mutex
	run *jobs.Run
	p   adoptProgress
}

func (t *adoptTracker) update(f func(p *adoptProgress)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	f(&t.p)
	t.run.SetProgress(t.p)
}

func (t *adoptTracker) step(n int, what string) {
	t.update(func(p *adoptProgress) {
		for i := range p.Steps {
			s := &p.Steps[i]
			switch {
			case s.N < n && (s.State == "running" || s.State == "waiting"):
				s.State = "done"
			case s.N == n:
				s.State, s.Detail = "running", what
			}
		}
	})
}

// fingerprint keys what the dry run checked: the request, the config's bytes, the settings.
func (p adoptKind) fingerprint(w adoption.Web, text, set []byte) string {
	m := hmac.New(sha256.New, p.secret)
	m.Write([]byte(w.Key() + "\x00"))
	m.Write(text)
	m.Write([]byte{0})
	m.Write(set)
	return hex.EncodeToString(m.Sum(nil))
}

// inputs are the config's and the settings' bytes, read once.
func (p adoptKind) inputs(w adoption.Web) (text, set []byte, err error) {
	f, err := configs.Read(p.dataDir, w.Config)
	if err != nil {
		return nil, nil, err
	}
	if f.Error != "" {
		return nil, nil, fmt.Errorf("%s: %s", w.Config, f.Error)
	}
	set, err = os.ReadFile(settings.Path(p.dataDir))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}
	return f.Text, set, nil
}

// candidate checks the node is one the page may adopt: found, saying it isn't adopted, as
// the ID the page showed, and an ID no other node the controller knows has.
func (p adoptKind) candidate(w adoption.Web) error {
	all := p.nodes()
	i := slices.IndexFunc(all, func(n nodes.Node) bool { return n.Addr == w.Node })
	if i < 0 {
		return fmt.Errorf("%s is not a node the controller has found (mDNS or settings.json)", w.Node)
	}
	st, ok := status(all[i])
	switch {
	case !ok:
		return fmt.Errorf("%s: no /status read yet", w.Node)
	case !strings.EqualFold(st.NodeID, w.NodeID):
		return fmt.Errorf("%s is node %s now, not %s: look again", w.Node, st.NodeID, w.NodeID)
	case st.Config == nil:
		return fmt.Errorf("%s: its firmware takes no node configs: update it first", w.Node)
	}
	if why := adoptedBefore(st); why != "" {
		return fmt.Errorf("%s: %s", w.Node, why)
	}
	// An ID a config was pushed to before is a node adopted before: one that answers as it,
	// saying it isn't adopted, could be it wiped, or something else claiming its ID (mDNS
	// and /status are unauthenticated) to get a config signed for it.
	if pr, _ := configs.LoadPushed(p.dataDir, strings.ToLower(st.NodeID)); pr != nil {
		return fmt.Errorf("%s says it is node %s, which was given %s at %s (%s): not adopted from here; if it is that node, "+
			"wiped, adopt it with espdns adopt (its dry run first; docs/reference/cli.md#adopt)", w.Node, st.NodeID, pr.File, pr.Host,
			pr.Time.Format("2006-01-02"))
	}
	for _, n := range all {
		if n.Addr != w.Node && strings.EqualFold(n.ID, w.NodeID) {
			return fmt.Errorf("%s says it is node %s, which the controller knows at %s: not adopted (a release signed for it "+
				"would be good on that node too)", w.Node, w.NodeID, n.Addr)
		}
	}
	return nil
}

// adoptedBefore says why a node whose /status is st is no node for the Adopt page: one
// that runs a pushed config, or one that took a config before and runs its board's settings
// now (a node in service whose config was refused or failed its trial looks unadopted, and
// adopting it here could give it another config and address). "" if it never took one.
func adoptedBefore(st release.NodeStatus) string {
	switch {
	case st.Config == nil:
		return ""
	case st.Config.Source == "node":
		return "adopted already (it runs a pushed config): change its address or config from the Configs page"
	case st.Seq["config"] > 0:
		why := ""
		if st.Config.Error != "" {
			why = " (" + st.Config.Error + ")"
		}
		return fmt.Sprintf("it took a node config before (config seq %d) and runs its board's settings now%s: it may be a "+
			"node in service that fell back, so it isn't adopted from here; adopt it again with espdns adopt (its dry run "+
			"first; docs/reference/cli.md#adopt), once you know which node it is", st.Seq["config"], why)
	}
	return ""
}

func (p adoptKind) kind(raw json.RawMessage) (jobs.Func, error) {
	w, err := adoption.ParseWeb(raw)
	if err != nil {
		return nil, err
	}
	req, err := w.Request(p.dataDir, p.catalog)
	if err != nil {
		return nil, err
	}
	if err := p.candidate(w); err != nil {
		return nil, err
	}
	text, set, err := p.inputs(w)
	if err != nil {
		return nil, err
	}
	cfg, _ := nodecfg.Parse(text)
	if w.DryRun {
		if w.After != "" || w.PrimaryDone || w.AddToSettings {
			return nil, errors.New(`params: "after", "primary_done" and "add_to_settings" are for the adoption after a dry run`)
		}
	} else {
		if _, err := p.signer(); err != nil {
			return nil, err
		}
		if err := p.dryRunFor(w, text, set); err != nil {
			return nil, err
		}
		if zs := zonesOf(cfg); len(zs) > 0 && !w.PrimaryDone {
			if why := p.manualWhy(req); why != "" {
				return nil, fmt.Errorf("%s, so the dry run named the changes to make by hand on the zone primary for %s: make them, "+
					"then say they are done", why, strings.Join(zs, ", "))
			}
		}
		if !p.used.claim(w.After) {
			return nil, fmt.Errorf("the dry run %s was already followed by an adoption: run the dry run again", w.After)
		}
	}
	return func(ctx context.Context, run *jobs.Run) (any, error) { return p.run(ctx, run, w) }, nil
}

// manualWhy is why the zone primary's changes are made by hand ("" if its API is used), as
// adoption.Build works it out.
func (p adoptKind) manualWhy(req adoption.Request) string {
	zp, _, err := p.zonePrimary(req)
	if err != nil {
		return err.Error()
	}
	return primary.Why(zp)
}

// zonePrimary is the zone primary req uses, as adoption.Build opens it (reading nothing
// from it), and settings.json as read for it.
func (p adoptKind) zonePrimary(req adoption.Request) (primary.Primary, settings.Settings, error) {
	s, err := settings.Load(req.SettingsPath())
	if err != nil {
		return nil, s, err
	}
	zp, _, err := req.ZonePrimary(s, tokenFunc(p.token), true, primary.Options{})
	return zp, s, err
}

func zonesOf(c *nodecfg.Config) []string {
	if c == nil || c.Secondary == nil || c.Secondary.Zones == nil {
		return nil
	}
	return *c.Secondary.Zones
}

// dryRunFor checks w.After is an adopt dry run that passed, not long ago, of this request
// with these files.
func (p adoptKind) dryRunFor(w adoption.Web, text, set []byte) error {
	if w.After == "" {
		return errors.New(`an adoption needs a dry run first: run it with "dry_run": true, then adopt with "after": its job ID`)
	}
	j, ok := p.job(w.After)
	var res adoptResult
	switch {
	case !ok || j.Kind != "adopt":
		return fmt.Errorf("no adopt dry run %s", w.After)
	case j.State != jobs.Done:
		return fmt.Errorf("the dry run %s didn't pass (%s): fix what it says and run it again", w.After, j.State)
	case json.Unmarshal(j.Result, &res) != nil || !res.DryRun:
		return fmt.Errorf("%s is not a dry run", w.After)
	case time.Since(j.Ended) > dryRunValid:
		return fmt.Errorf("the dry run %s is over %v old: run it again", w.After, dryRunValid)
	case !hmac.Equal([]byte(res.Fingerprint), []byte(p.fingerprint(w, text, set))):
		return fmt.Errorf("the adoption isn't the one the dry run %s checked: the node, the address, the config or "+
			"settings.json changed since (or the controller restarted): run the dry run again", w.After)
	}
	return nil
}

func (p adoptKind) run(ctx context.Context, run *jobs.Run, w adoption.Web) (any, error) {
	// Everything again, as it is now: the node, the files, the dry run, the key.
	req, err := w.Request(p.dataDir, p.catalog)
	if err != nil {
		return nil, err
	}
	if err := p.candidate(w); err != nil {
		return nil, err
	}
	text, set, err := p.inputs(w)
	if err != nil {
		return nil, err
	}
	res := adoptResult{Node: w.Node, NodeID: w.NodeID, Config: w.Config, DryRun: w.DryRun, Fingerprint: p.fingerprint(w, text, set)}
	if !w.DryRun {
		if err := p.dryRunFor(w, text, set); err != nil {
			return nil, err
		}
	}
	req.ConfigText = text
	var t *adoptTracker
	req.Report = func(e primary.Edit) {
		t.update(func(pp *adoptProgress) { pp.Primary.Edits = append(pp.Primary.Edits, e) })
	}
	c := p.client()
	c.Logf = run.Logf
	if k, err := p.signer(); err == nil {
		c.Pusher = &release.Pusher{Key: k, KeyID: release.KeyRelease, Pins: pins.Open(p.dataDir), Client: c.HTTP}
		run.Logf("signing with the release key %s", keys.Fingerprint(k))
	} else if !w.DryRun {
		return nil, err
	} else {
		run.Logf("no release key (%v): a dry run goes on without one", err)
	}
	t = &adoptTracker{run: run, p: adoptProgress{DryRun: w.DryRun, Node: w.Node, NodeID: w.NodeID, Config: w.Config}}
	for n := 2; n <= 7; n++ {
		t.p.Steps = append(t.p.Steps, adoptStep{N: n, Title: stepTitles[n], State: "waiting"})
	}
	run.SetProgress(t.p)

	b, err := adoption.Build(ctx, c, req, tokenFunc(p.token), run.Logf)
	if err != nil {
		t.update(func(pp *adoptProgress) { pp.Outcome = "not started: " + err.Error() })
		return res, err
	}
	t.update(func(pp *adoptProgress) {
		pp.Primary = primaryState{Kind: b.PrimaryKind, API: b.PrimaryAPI, Why: b.PrimaryWhy, Primary: b.Primary, Zones: b.Zones,
			Done: b.PrimaryAPI == "" && w.PrimaryDone}
	})
	// The node as step 2 reads it now, not as the registry last polled it: one adopted (or
	// one that took a config) since is not adopted from here, before anything changes.
	check := b.Adopt.Check
	b.Adopt.Check = func(cfg *nodecfg.Config, st release.NodeStatus) error {
		if why := adoptedBefore(st); why != "" {
			return errors.New(why)
		}
		return check(cfg, st)
	}
	// Build read settings.json again: still the bytes the dry run checked.
	if !w.DryRun {
		if text2, set2, err := p.inputs(w); err != nil || string(text2) != string(text) || string(set2) != string(set) {
			err = errors.New("the config or settings.json changed while the adoption started: run the dry run again")
			t.update(func(pp *adoptProgress) { pp.Outcome = "not started: " + err.Error() })
			return res, err
		}
	}
	b.Adopt.Step = t.step
	b.Adopt.Resolved = func(addr string) {
		t.update(func(pp *adoptProgress) {
			pp.Address = addr
			for i := range pp.Steps {
				if pp.Steps[i].N == 3 {
					pp.Steps[i].Detail = "the node is adopted on " + addr + "; the config checked for it with that address"
				}
			}
			if b.PrimaryAPI == "" {
				pp.Primary.Manual = b.ManualSteps(addr)
			}
		})
	}
	if p.adjust != nil {
		p.adjust(&b.Adopt)
	}
	r, err := adoption.Run(ctx, c, b, "controller", run.Logf)
	res.Address, res.Seq, res.Recorded, res.AddedToSettings, res.InSettings, res.Servers =
		r.Addr, r.Seq, r.Recorded, r.AddedToSettings, r.InSettings, r.Servers
	p.finish(t, w, b, r, err)
	if err == nil && w.DryRun {
		run.Logf("dry run passed: nothing was changed")
	}
	return res, err
}

// finish sets each step's last state, the outcome and what to do next.
func (p adoptKind) finish(t *adoptTracker, w adoption.Web, b adoption.Built, r adoption.Result, err error) {
	failed := 0
	if err != nil {
		if n, rest, ok := strings.Cut(err.Error(), ". "); ok && len(n) == 1 && rest != "" {
			failed, _ = strconv.Atoi(n)
		}
	}
	t.update(func(pp *adoptProgress) {
		for i := range pp.Steps {
			s := &pp.Steps[i]
			switch {
			case err == nil && w.DryRun && s.N >= 5:
				s.State = "skipped"
				if s.N == 5 {
					s.State, s.Detail = "done", "checked: the config would be pushed now (dry run: not pushed)"
				}
			case err == nil:
				if s.State != "skipped" {
					s.State = "done"
				}
			case s.N == failed || failed == 0 && s.State == "running":
				s.State, s.Detail = "failed", err.Error()
			case s.State == "running":
				s.State = "done"
			}
		}
		var hints []string
		switch {
		case err == nil && w.DryRun:
			pp.Outcome = "dry run passed: every step checked; nothing was changed"
			if b.PrimaryAPI == "" && len(b.Zones) > 0 {
				hints = append(hints, "Make the changes on the zone primary above by hand before you adopt, then tick that they "+
					"are done: "+b.PrimaryWhy+".")
			}
		case err == nil:
			pp.Outcome = fmt.Sprintf("adopted: node %s on %s, config seq %d", r.NodeID, r.Addr, r.Seq)
			if len(r.Servers) >= 2 {
				hints = append(hints, "Hand out "+strings.Join(r.Servers, ", ")+" as the clients' DNS servers (the router's "+
					"DHCP DNS setting, on the networks that use DHCP).")
			} else {
				hints = append(hints, "Adopt a second node, then hand out both as the clients' DNS servers.")
			}
			if !r.InSettings {
				hints = append(hints, r.Addr+" is not in settings.json: add it (below) so rollouts count it and change it.")
			}
		case errors.Is(err, fleet.ErrStopped):
			pp.Outcome = "stopped on request"
		default:
			pp.Outcome = "stopped: " + err.Error()
			if failed >= 6 {
				hints = append(hints, "The node took the config but wasn't confirmed on its address: on trial, it goes back to "+
					"its previous config within its trial window. Check it on the Nodes page before trying again.")
			} else if failed > 0 && failed <= 4 {
				hints = append(hints, "Nothing was pushed to the node.")
			}
		}
		pp.Hints = hints
	})
}

// ---- the page's reads ------------------------------------------------------------------

type adoptNode struct {
	Host     string   `json:"host"`
	ID       string   `json:"id,omitempty"`
	Hostname string   `json:"hostname,omitempty"`
	Source   string   `json:"source"` // nodes.SourceSettings, SourceMDNS or SourceLookup
	Online   bool     `json:"online"`
	Read     bool     `json:"read"`           // its /status is read: only then is it known whether it is adopted
	Name     string   `json:"name,omitempty"` // its config's name, as it runs it
	Board    string   `json:"board,omitempty"`
	Image    string   `json:"image,omitempty"`
	Version  string   `json:"version,omitempty"`
	Net      string   `json:"net,omitempty"`
	MAC      string   `json:"mac,omitempty"` // its interface's (release.MAC): for a DHCP reservation, or a static address
	State    string   `json:"state,omitempty"`
	Adopted  bool     `json:"adopted"`
	Listed   bool     `json:"listed"`            // in settings.json
	Address  string   `json:"address,omitempty"` // the static address it runs on, with its prefix
	Gateway  string   `json:"gateway,omitempty"`
	From     string   `json:"from,omitempty"` // where its address comes from
	Configs  bool     `json:"configs"`        // its firmware takes node configs
	Refusals []string `json:"refusals,omitempty"`
	Config   string   `json:"config,omitempty"` // a config file that names it (its name or address)
}

type adoptConfig struct {
	Name    string   `json:"name"`
	Config  string   `json:"config_name,omitempty"`
	Address string   `json:"address,omitempty"`
	Gateway string   `json:"gateway,omitempty"`
	Primary string   `json:"primary,omitempty"`
	Zones   []string `json:"zones,omitempty"`
	Error   string   `json:"error,omitempty"`
}

func (p adoptKind) routes(mux *routes) {
	mux.HandleFunc("GET /api/adopt", needLogin("adoption needs", p.list))
	mux.HandleFunc("POST /api/adopt/preview", needLogin("adoption needs", p.preview))
	mux.HandleFunc("GET /api/primary", needLogin("the zone primary's lists need", p.lists))
}

func (p adoptKind) list(w http.ResponseWriter, r *http.Request) {
	s, err := settings.Load(settings.Path(p.dataDir))
	if err != nil {
		httpErr(w, http.StatusInternalServerError, err)
		return
	}
	files, _ := configs.List(p.dataDir)
	all := p.nodes()
	out := []adoptNode{}
	for _, n := range all {
		out = append(out, p.describe(n, all, s, files))
	}
	cs := []adoptConfig{}
	for _, f := range files {
		c := adoptConfig{Name: f.Name, Error: f.Error}
		if f.Config != nil {
			c.Config = f.Config.Name
			if f.Config.Network != nil {
				c.Address, c.Gateway = f.Config.Network.Address, f.Config.Network.Gateway
			}
			if sec := f.Config.Secondary; sec != nil {
				c.Primary, c.Zones = sec.Primary, zonesOf(f.Config)
			}
		}
		cs = append(cs, c)
	}
	_, kerr := p.signer()
	out2 := map[string]any{"nodes": out, "configs": cs, "primary": p.primaryFacts(s), "key": kerr == nil, "no_dhcp": append([]string{}, s.NoDHCP...),
		"dry_run_valid_s": dryRunValid.Seconds(), "dns_peers": s.DNSPeers}
	if kerr != nil {
		out2["key_error"] = kerr.Error()
	}
	writeJSON(w, out2)
}

// describe is node n as the Adopt page (and Add node: addnode.go) shows it: what it is, from
// its last /status, whether it is adopted and listed, and why it can't be adopted from here
// (Refusals). all is every node the controller knows, s settings.json, files the configs.
func (p adoptKind) describe(n nodes.Node, all []nodes.Node, s settings.Settings, files []configs.File) adoptNode {
	an := adoptNode{Host: n.Addr, ID: n.ID, Hostname: n.Hostname, Source: n.Source, Online: n.Online,
		Listed: slices.Contains(s.Nodes, n.Addr)}
	st, ok := status(n)
	an.Read = ok
	if ok {
		an.Board, an.Image, an.Version, an.Net, an.MAC = st.Board, st.Image, st.Version, st.Net.Kind, release.MAC(st.Net.MAC)
		if st.Health != nil {
			an.State = st.Health.State
		}
		if st.Config != nil {
			an.Name, an.Configs = st.Config.Name, true
			an.Adopted = st.Config.Source == "node"
			an.From = st.Config.AddressFrom
			if st.Config.Address == "static" {
				an.Address, an.Gateway = st.Config.IP, st.Config.Gateway
			} else {
				an.Address = st.Config.Address
			}
		}
		for _, f := range files {
			if configs.Matches(f.Config, n.Addr, st) {
				an.Config = f.Name
				break
			}
		}
	}
	switch {
	case !ok:
		an.Refusals = append(an.Refusals, "no /status read yet")
	case !an.Configs:
		an.Refusals = append(an.Refusals, "its firmware takes no node configs: update it first")
	case !an.Adopted && adoptedBefore(st) != "":
		an.Refusals = append(an.Refusals, adoptedBefore(st))
	case !an.Adopted:
		if pr, _ := configs.LoadPushed(p.dataDir, strings.ToLower(st.NodeID)); pr != nil {
			an.Refusals = append(an.Refusals, fmt.Sprintf("node %s was given %s at %s before: adopt it again with make "+
				"fleet-adopt, if it is that node wiped", st.NodeID, pr.File, pr.Host))
		}
	}
	for _, o := range all {
		if o.Addr != n.Addr && o.ID != "" && strings.EqualFold(o.ID, n.ID) {
			an.Refusals = append(an.Refusals, "another node the controller knows ("+o.Addr+") has the same ID")
		}
	}
	return an
}

// primaryFacts is the zone primary as settings.json names it, for the page: its kind (set
// or not), its API, whether it has one and the token is there (never the token).
func (p adoptKind) primaryFacts(s settings.Settings) map[string]any {
	zp := s.ZonePrimary()
	kind := zp.Kind
	if zp.IsZero() {
		kind = primary.KindManual
	}
	d, _ := primary.Lookup(kind)
	out := map[string]any{"kind": kind, "set": !zp.IsZero(), "url": zp.URL, "api": d.API, "name": d.Name, "cert_sha256": zp.CertSHA256}
	if d.API || zp.IsZero() {
		tok, terr := tokenFunc(p.token)()
		out["token"] = tok != ""
		if terr != nil {
			out["token_error"] = terr.Error()
		}
		if src, ok := p.token.(keys.DataTokenSource); ok {
			out["token_file"] = strings.TrimPrefix(src.Path(), p.dataDir+"/")
		}
	}
	return out
}

// adoptPreview is what the page shows before the dry run.
type adoptPreview struct {
	Address string         `json:"address,omitempty"` // with its prefix, or "dhcp"
	Gateway string         `json:"gateway,omitempty"`
	How     string         `json:"how,omitempty"` // kept (from where) or new
	From    string         `json:"from,omitempty"`
	Check   configs.Result `json:"check"`
	Refusal string         `json:"refusal,omitempty"` // why it can't be adopted so
	Notes   []string       `json:"notes,omitempty"`
	Primary string         `json:"primary,omitempty"`
	Zones   []string       `json:"zones,omitempty"`
	Manual  []string       `json:"manual,omitempty"` // changed by hand: the changes, per zone
	// The zone primary: its kind, the API step 4 uses ("" when changed by hand), and why
	// it is changed by hand.
	PrimaryKind string `json:"primary_kind,omitempty"`
	PrimaryAPI  string `json:"primary_api,omitempty"`
	PrimaryWhy  string `json:"primary_why,omitempty"`
}

// preview reads the node's /status now and works out the address and the config check as
// the adoption would (fleet.Adopt.Resolve, adoption.CheckConfig), changing nothing.
func (p adoptKind) preview(w http.ResponseWriter, r *http.Request) {
	var raw json.RawMessage
	if err := body(w, r, &raw); err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	web, err := adoption.ParseWeb(raw)
	if err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	web.DryRun, web.After, web.PrimaryDone, web.AddToSettings = true, "", false, false
	req, err := web.Request(p.dataDir, p.catalog)
	if err == nil {
		err = p.candidate(web)
	}
	if err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	text, _, err := p.inputs(web)
	if err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	cfg, err := nodecfg.Parse(text)
	if err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	st, err := p.client().Status(ctx, web.Node)
	if err != nil {
		httpErr(w, http.StatusBadGateway, fmt.Errorf("%s: %v", web.Node, err))
		return
	}
	var out adoptPreview
	out.Primary, out.Zones = "", zonesOf(cfg)
	if cfg.Secondary != nil {
		out.Primary = cfg.Secondary.Primary
	}
	// The address as Build and step 3 work it out.
	addr, gw := req.Address, req.Gateway
	out.From = "the address it runs on"
	switch {
	case addr != "":
		out.From = "chosen here"
	case cfg.Network != nil:
		addr, out.From = cfg.Network.Address, "the config's network"
	}
	if gw == "" && cfg.Network != nil {
		gw = cfg.Network.Gateway
	}
	a := fleet.Adopt{DHCP: addr == "dhcp"}
	if addr != "" && !a.DHCP {
		a.Address, _ = netip.ParsePrefix(addr)
	}
	if gw != "" && !a.DHCP {
		a.Gateway, _ = netip.ParseAddr(gw)
	}
	at := adoption.HostOnly(web.Node)
	refuse := func(e string) {
		if out.Refusal == "" {
			out.Refusal = e
		}
	}
	if a.DHCP {
		out.Address, out.How = "dhcp", "dhcp"
		cfg.Network = &nodecfg.Network{Address: "dhcp"}
		s, serr := settings.Load(req.SettingsPath())
		h, herr := netip.ParseAddr(at)
		n, none := netip.Prefix{}, false
		if serr == nil && herr == nil {
			n, none = s.NoDHCPAt(h)
		}
		if serr != nil {
			refuse(serr.Error())
		} else if none {
			refuse(fmt.Sprintf("%s has no DHCP server (settings.json, no_dhcp): a node there gets a static address", n))
		} else if !web.Reserved {
			out.Notes = append(out.Notes, fmt.Sprintf("Reserve %s for MAC %s in that network's DHCP server first, then tick that it is reserved.", at, st.Net.MAC))
		}
	} else if err := a.Resolve(st); err != nil {
		refuse(err.Error())
	} else {
		out.Address, out.Gateway, out.How = a.Address.String(), a.Gateway.String(), a.AddressHow(st)
		cfg.Network = &nodecfg.Network{Address: a.Address.String(), Gateway: a.Gateway.String()}
		at = a.Address.Addr().String()
		if a.Address.Addr().String() != adoption.HostOnly(web.Node) {
			out.Notes = append(out.Notes, "A new address: the dry run checks nothing else answers there; the node moves there "+
				"with a reboot and keeps it only once it is reached there.")
		}
	}
	if f, err := configs.Read(p.dataDir, web.Config); err == nil && f.Config != nil && out.Address != "" {
		switch n := f.Config.Network; {
		case n == nil:
			out.Notes = append(out.Notes, fmt.Sprintf("%s has no network: the node gets %s in the config pushed, but a later push "+
				"of the file as it is would be refused (it would drop the node off its address): add the network to the file.",
				web.Config, out.Address))
		case n.Address != out.Address:
			out.Notes = append(out.Notes, fmt.Sprintf("%s says %s: the node gets %s in the config pushed; change the file to it, "+
				"or a later push of the file moves the node back.", web.Config, n.Address, out.Address))
		}
	}
	out.Check = configs.Check{Name: web.Config, Text: mustPayload(cfg), Catalog: p.catalog, Host: web.Node, Status: &st,
		DataDir: p.dataDir}.Run()
	if !out.Check.OK {
		refuse("the config doesn't pass its checks for this node: " +
			adoption.CheckConfig(web.Config, cfg, web.Node, st, p.catalog, p.dataDir).Error())
	}
	zp, _, err := p.zonePrimary(req)
	switch {
	case err != nil:
		refuse(err.Error())
	case zp.Ready() != nil:
		out.PrimaryKind, out.PrimaryWhy = zp.Kind(), primary.Why(zp)
		for _, z := range out.Zones {
			out.Manual = append(out.Manual, zp.Manual(out.Primary, z, at))
		}
	default:
		out.PrimaryKind, out.PrimaryAPI = zp.Kind(), zp.API()
	}
	writeJSON(w, out)
}

func mustPayload(c *nodecfg.Config) []byte {
	b, err := c.Payload()
	if err != nil {
		b, _ = json.Marshal(c)
	}
	return b
}

// ---- The zone primary: the lists, and one entry fixed -----------------------------------

type primaryNode struct {
	Host     string `json:"host"`
	ID       string `json:"id,omitempty"`
	Transfer bool   `json:"transfer"`
	Notify   bool   `json:"notify"`
	// Manual: the lists can't be read from here: the change this node needs on the primary
	// (made already or not: only the primary knows).
	Manual string `json:"manual,omitempty"`
}

type primaryEntry struct {
	Addr     string `json:"addr"`
	Transfer bool   `json:"transfer"` // in the zone transfer list
	Notify   bool   `json:"notify"`   // in the NOTIFY list
	Former   string `json:"former,omitempty"`
	InUse    string `json:"in_use,omitempty"` // what it still is (inUse): not removed from here
}

type primaryZone struct {
	Zone    string         `json:"zone"`
	Primary string         `json:"primary,omitempty"`
	Configs []string       `json:"configs"`
	Lists   *primary.Lists `json:"lists,omitempty"`
	Error   string         `json:"error,omitempty"`
	Nodes   []primaryNode  `json:"nodes"`            // the nodes in settings.json that carry it
	Extra   []primaryEntry `json:"extra"`            // entries that are no node in settings.json
	Unread  []string       `json:"unread,omitempty"` // nodes in settings.json whose zones aren't known
}

// secondaryZones are the secondary zones the configs carry, with their primary and the
// configs that carry each.
func secondaryZones(dataDir string) map[string]*primaryZone {
	out := map[string]*primaryZone{}
	files, _ := configs.List(dataDir)
	for _, f := range files {
		for _, z := range zonesOf(f.Config) {
			pz := out[z]
			if pz == nil {
				pz = &primaryZone{Zone: z, Primary: f.Config.Secondary.Primary, Nodes: []primaryNode{}, Extra: []primaryEntry{}}
				out[z] = pz
			}
			if pz.Primary == "" { // a config that names none (its board's, say) doesn't hide one that does
				pz.Primary = f.Config.Secondary.Primary
			}
			pz.Configs = append(pz.Configs, f.Name)
		}
	}
	return out
}

// zonePrimaryOf is the zone primary settings.json names, as the view and its jobs use it:
// one changed by hand (Ready says why) when it isn't reached from here. Unlike adoption, a
// token without a primary is no error here: there is just nothing to read.
func (p adoptKind) zonePrimaryOf(s settings.Settings, o primary.Options) (primary.Primary, error) {
	zp := s.ZonePrimary()
	if zp.IsZero() {
		d, _ := primary.Lookup(primary.KindManual)
		return primary.ByHand(d, `no zone primary in settings.json ("primary"): any primary, its lists changed by hand`), nil
	}
	tok := ""
	if d, _ := primary.Lookup(zp.Kind); d.API {
		var err error
		if tok, err = tokenFunc(p.token)(); err != nil {
			return nil, fmt.Errorf("the zone primary token can't be used: %v", err)
		}
	}
	return primary.Open(zp, tok, o)
}

// lists reads each secondary zone's lists from the zone primary (read-only) and says, for
// each node in settings.json carrying it (its /status zones), whether it is in them. A
// primary changed by hand: the change each such node needs, as adoption names it.
func (p adoptKind) lists(w http.ResponseWriter, r *http.Request) {
	s, err := settings.Load(settings.Path(p.dataDir))
	if err != nil {
		httpErr(w, http.StatusInternalServerError, err)
		return
	}
	zs := secondaryZones(p.dataDir)
	names := make([]string, 0, len(zs))
	for z := range zs {
		names = append(names, z)
	}
	sort.Strings(names)
	out := map[string]any{"primary": p.primaryFacts(s), "zones": []*primaryZone{}}
	zp, perr := p.zonePrimaryOf(s, primary.Options{})
	if perr == nil && zp.Ready() != nil {
		out["by_hand"] = primary.Why(zp)
	} else if perr != nil {
		out["error"] = perr.Error()
	} else {
		out["api"] = zp.API()
	}
	byAddr := map[string]nodes.Node{}
	for _, n := range p.nodes() {
		byAddr[n.Addr] = n
	}
	former := map[string]string{}
	for _, pr := range configs.AllPushed(p.dataDir) {
		former[adoption.HostOnly(pr.Host)] = pr.NodeID
	}
	listed := map[string]bool{}
	for _, h := range s.Nodes {
		listed[adoption.HostOnly(h)] = true
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	var res []*primaryZone
	for _, z := range names {
		pz := zs[z]
		for _, h := range s.Nodes {
			n, ok := byAddr[h]
			st, sok := status(n)
			if !ok || !sok {
				pz.Unread = append(pz.Unread, h)
				continue
			}
			if st.Config == nil || st.Config.Source != "node" {
				continue // not adopted: its lists are adoption's step 4
			}
			carries := false
			for _, x := range st.Zones {
				carries = carries || x.Name == z
			}
			if !carries {
				continue
			}
			pn := primaryNode{Host: h, ID: st.NodeID}
			if zp != nil && zp.Ready() != nil {
				pn.Manual = zp.Manual(pz.Primary, z, adoption.HostOnly(h))
			}
			pz.Nodes = append(pz.Nodes, pn)
		}
		if zp != nil && zp.Ready() == nil {
			l, err := zp.Lists(ctx, z)
			if err != nil {
				pz.Error = err.Error()
			} else {
				pz.Lists = &l
				for i := range pz.Nodes {
					pz.Nodes[i].Transfer, pz.Nodes[i].Notify = l.Has(adoption.HostOnly(pz.Nodes[i].Host))
				}
				seen := map[string]bool{}
				for _, e := range append(slices.Clone(l.TransferList), l.NotifyList...) {
					a, err := netip.ParseAddr(e)
					if err != nil || seen[e] || listed[e] {
						continue // a network, a name or a node in settings.json
					}
					seen[e] = true
					x := primaryEntry{Addr: a.String(), Transfer: slices.Contains(l.TransferList, e), Notify: slices.Contains(l.NotifyList, e)}
					if id, ok := former[e]; ok {
						x.Former = id
					}
					x.InUse = p.inUse(s, z, x.Addr)
					pz.Extra = append(pz.Extra, x)
				}
			}
		}
		res = append(res, pz)
	}
	if res != nil {
		out["zones"] = res
	}
	writeJSON(w, out)
}

// primaryParams is a zone primary job: one address allowed in, or taken off, one zone's lists.
type primaryParams struct {
	Zone    string `json:"zone"`
	Address string `json:"address"`
	Action  string `json:"action"` // allow or remove
}

// driven is the zone primary settings.json names, refused when it isn't reached from here.
func (p adoptKind) driven(s settings.Settings, o primary.Options) (primary.Primary, error) {
	zp, err := p.zonePrimaryOf(s, o)
	if err != nil {
		return nil, err
	}
	if err := zp.Ready(); err != nil {
		return nil, fmt.Errorf("%v: make the change on the primary by hand (the Zone primary view says what each node needs)", err)
	}
	return zp, nil
}

// primaryKind is the job kind "primary": a node in
// settings.json allowed to transfer a zone the configs carry and sent its NOTIFYs
// (Primary.Allow, as adoption's step 4), or an address that is no node in settings.json
// taken off them (Remove), only when asked; only for a zone primary reached from here.
func (p adoptKind) primaryKind(raw json.RawMessage) (jobs.Func, error) {
	var tp primaryParams
	if err := decodeStrict(raw, &tp); err != nil {
		return nil, err
	}
	s, err := settings.Load(settings.Path(p.dataDir))
	if err != nil {
		return nil, err
	}
	if _, ok := secondaryZones(p.dataDir)[tp.Zone]; !ok {
		return nil, fmt.Errorf("%q is no secondary zone of the configs in %s", tp.Zone, configs.Path(p.dataDir))
	}
	a, err := netip.ParseAddr(tp.Address)
	if err != nil || !a.Is4() || a.String() != tp.Address {
		return nil, fmt.Errorf("address: %q is not an IPv4 address", tp.Address)
	}
	inSettings := slices.ContainsFunc(s.Nodes, func(h string) bool { return adoption.HostOnly(h) == tp.Address })
	switch tp.Action {
	case "allow":
		if !inSettings {
			return nil, fmt.Errorf("%s is not a node in settings.json: only those are allowed in from here", tp.Address)
		}
	case "remove":
		if inSettings {
			return nil, fmt.Errorf("%s is a node in settings.json: take it out of settings.json first, then remove it here", tp.Address)
		}
		if why := p.inUse(s, tp.Zone, tp.Address); why != "" {
			return nil, fmt.Errorf("%s is %s: not removed from %s's lists", tp.Address, why, tp.Zone)
		}
	default:
		return nil, errors.New(`action: "allow" or "remove"`)
	}
	if _, err := p.driven(s, primary.Options{}); err != nil {
		return nil, err
	}
	return func(ctx context.Context, run *jobs.Run) (any, error) {
		s, err := settings.Load(settings.Path(p.dataDir))
		if err != nil {
			return nil, err
		}
		var edits []primary.Edit
		zp, err := p.driven(s, primary.Options{Logf: run.Logf, Report: func(e primary.Edit) { edits = append(edits, e) }})
		if err != nil {
			return nil, err
		}
		run.Logf("%s: %s %s (zone primary: %s %s)", tp.Zone, map[string]string{"allow": "allowing", "remove": "taking off"}[tp.Action],
			tp.Address, zp.Kind(), zp.API())
		if tp.Action == "allow" {
			err = zp.Allow(ctx, tp.Zone, tp.Address)
		} else if why := p.inUse(s, tp.Zone, tp.Address); why != "" {
			return nil, fmt.Errorf("%s is %s: not removed from %s's lists", tp.Address, why, tp.Zone)
		} else if slices.ContainsFunc(s.Nodes, func(h string) bool { return adoption.HostOnly(h) == tp.Address }) {
			return nil, fmt.Errorf("%s is a node in settings.json now: not removed", tp.Address)
		} else {
			err = zp.Remove(ctx, tp.Zone, tp.Address)
		}
		if err != nil {
			return nil, err
		}
		return map[string]any{"zone": tp.Zone, "address": tp.Address, "action": tp.Action, "edits": edits}, nil
	}, nil
}

// inUse says what an address in a zone's lists still is, that Remove must leave alone: a
// node the controller finds (over mDNS, or polled), a DNS peer in settings.json, or the
// zone's primary as the configs name it. "" if none of those.
func (p adoptKind) inUse(s settings.Settings, zone, addr string) string {
	for _, n := range p.nodes() {
		if adoption.HostOnly(n.Addr) == addr && (n.Source != nodes.SourceSettings || n.Online) {
			return "a node the controller finds now (" + n.Source + ")"
		}
	}
	for _, d := range s.DNSPeers {
		if adoption.HostOnly(d) == addr {
			return "a DNS peer in settings.json"
		}
	}
	files, _ := configs.List(p.dataDir)
	for _, f := range files {
		if slices.Contains(zonesOf(f.Config), zone) && adoption.HostOnly(f.Config.Secondary.Primary) == addr {
			return "the zone's primary (" + f.Name + ")"
		}
	}
	return ""
}

// settingsAdd is the job kind "settings-add": a node the controller found, adopted (it
// runs a pushed config), added to settings.json, written whole.
func (p adoptKind) settingsAdd(raw json.RawMessage) (jobs.Func, error) {
	var np struct {
		Node string `json:"node"`
	}
	if err := decodeStrict(raw, &np); err != nil {
		return nil, err
	}
	check := func() error {
		all := p.nodes()
		i := slices.IndexFunc(all, func(n nodes.Node) bool { return n.Addr == np.Node })
		if i < 0 {
			return fmt.Errorf("%s is not a node the controller has found", np.Node)
		}
		st, ok := status(all[i])
		if !ok || st.Config == nil || st.Config.Source != "node" {
			return fmt.Errorf("%s is not adopted (no pushed config): adopt it first", np.Node)
		}
		s, err := settings.Load(settings.Path(p.dataDir))
		if err != nil {
			return err
		}
		if slices.Contains(s.Nodes, np.Node) {
			return fmt.Errorf("%s is in settings.json already", np.Node)
		}
		for _, n := range all {
			if n.Addr != np.Node && strings.EqualFold(n.ID, st.NodeID) && slices.Contains(s.Nodes, n.Addr) {
				return fmt.Errorf("%s says it is node %s, which settings.json has at %s: change that entry by hand if it moved",
					np.Node, st.NodeID, n.Addr)
			}
		}
		return nil
	}
	if err := check(); err != nil {
		return nil, err
	}
	return func(ctx context.Context, run *jobs.Run) (any, error) {
		if err := check(); err != nil {
			return nil, err
		}
		added, err := settings.AddNode(settings.Path(p.dataDir), np.Node)
		if err != nil {
			return nil, err
		}
		run.Logf("added %s to settings.json: it counts as a peer in rollouts, and the controller's actions take it", np.Node)
		return map[string]any{"node": np.Node, "added": added}, nil
	}, nil
}

// decodeStrict reads a job's params, unknown fields refused.
func decodeStrict(raw json.RawMessage, v any) error {
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return fmt.Errorf("params: %v", err)
	}
	return nil
}
