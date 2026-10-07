package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/blocking"
	"github.com/skitzo2000/espdns/controller/internal/blocklist"
	"github.com/skitzo2000/espdns/controller/internal/changes"
	"github.com/skitzo2000/espdns/controller/internal/configs"
	"github.com/skitzo2000/espdns/controller/internal/fleet"
	"github.com/skitzo2000/espdns/controller/internal/jobs"
	"github.com/skitzo2000/espdns/controller/internal/keys"
	"github.com/skitzo2000/espdns/controller/internal/nodecfg"
	"github.com/skitzo2000/espdns/controller/internal/pins"
	"github.com/skitzo2000/espdns/controller/internal/release"
	"github.com/skitzo2000/espdns/controller/internal/rolling"
	"github.com/skitzo2000/espdns/controller/internal/settings"
	"github.com/skitzo2000/espdns/controller/internal/zonefiles"
	"github.com/skitzo2000/espdns/controller/internal/zones"
)

// The apply (the job kind "apply"): every pending change (internal/changes) sent as one
// safe rolling change, in five steps, its progress live as any job's:
//
//	check     the changes against the files (each on the version it edits) and against each
//	          other (the zones as one set, the lists' files there); every node in
//	          settings.json read, so the nodes each change goes to are known
//	write     the files written through their stores (each version replaced kept in its history)
//	compile   the blocklists the changes touch compiled again (as the job "blocklist"); one
//	          refused by the size-change check stops the apply to ask (below)
//	dry run   every rollout checked against every node it goes to, before any node is touched
//	push      the rollouts one after the other (configs, hosted zones, overrides, blocklists,
//	          firmware), each one node at a time: the canary first, its DNS checked, watched,
//	          then the next; a change that needs a reboot reboots one node at a time
//	          (fleet.Rollout, as the Push page's rollouts)
//
//	POST /api/jobs  {"kind": "apply", "params": {"canary": "<node>", "soak_s": 60, "accept_change": ["<list>"]}}
//
// Everything is optional: the canary (one of settings.json's nodes; else settings.json's
// "canary"), how long each node is watched (rolling.DefaultSoak to rolling.MaxSoak), and the
// lists whose size change is taken this once. A change goes to the nodes it is for: a node
// config to the node that runs it (by its name, or its address, as the config becomes, is,
// or was before an apply that stopped wrote it; or the node it was last pushed to), the
// hosted zones and the overrides to every node, a blocklist to the nodes that run it (its
// compiled file, or one an apply that didn't end well compiled it from; every node when it
// is the only one and no node runs it yet), a firmware update to the nodes it names.
//
// When it all went through, the changes are no longer pending. When it stops part way (a
// node failed its checks, a stop was asked for), the changes stay pending, marked written
// once their files are: applying again finishes them (the nodes that have them are
// skipped), discarding puts the files back (internal/changes).
//
// The size-change check asks rather than fails: the apply ends "stopped" with a question
// for each list in its result ("questions": the list, the change in words, and the params
// that take it); nothing is pushed. Applying again with those params takes the change once;
// discarding the change keeps the lists the nodes have.

type applyKind struct {
	actions
	catalog string
	store   *changes.Store
	// fetch: how a blocklist's URL sources are fetched besides blocklist's rules (nil in
	// use; a test's server).
	fetch *blocklist.Fetch
	// adjust, in tests only, shortens each plan's waits after it is built.
	adjust func(*fleet.Plan)
}

type applyParams struct {
	Canary       string   `json:"canary,omitempty"`
	SoakS        int      `json:"soak_s,omitempty"`
	AcceptChange []string `json:"accept_change,omitempty"`
}

// question is what an apply stopped to ask.
type question struct {
	Kind string `json:"kind"` // size-change
	List string `json:"list"`
	Text string `json:"text"`
	// Params are the apply's params that take it: apply again with them.
	Params applyParams `json:"params"`
}

// askError ends an apply "stopped" (jobs: fleet.ErrStopped) with its questions.
type askError struct{ text string }

func (e askError) Error() string        { return "waiting for an answer: " + e.text }
func (e askError) Is(target error) bool { return target == fleet.ErrStopped }

type applyStep struct {
	Name   string `json:"name"`  // check, write, compile, dry run, push
	State  string `json:"state"` // waiting, running, done, failed, stopped, skipped
	Detail string `json:"detail,omitempty"`
}

// applyRollout is one rollout of an apply, as its progress shows it.
type applyRollout struct {
	Kind    string                `json:"kind"`
	What    string                `json:"what"`
	Order   []string              `json:"order"`
	State   string                `json:"state"` // waiting, checking, checked, pushing, done, failed, stopped
	Nodes   map[string]*nodeState `json:"nodes"`
	Outcome string                `json:"outcome,omitempty"`
}

// applyProgress is an apply's progress.
type applyProgress struct {
	Changes   []string        `json:"changes"`
	Steps     []applyStep     `json:"steps"`
	Rollouts  []*applyRollout `json:"rollouts"`
	Notes     []string        `json:"notes,omitempty"`
	Questions []question      `json:"questions,omitempty"`
	Outcome   string          `json:"outcome,omitempty"`
	Hints     []string        `json:"hints,omitempty"`
}

// applyResult is an apply's result.
type applyResult struct {
	Changes   []string        `json:"changes"` // the changes it took
	Applied   bool            `json:"applied"` // every one on every node it is for: no longer pending
	Written   bool            `json:"written"` // the files were written
	Rollouts  []rolloutResult `json:"rollouts,omitempty"`
	Questions []question      `json:"questions,omitempty"`
	Notes     []string        `json:"notes,omitempty"`
	// compiled are the lists compiled again: once every node they go to has them, the
	// compiled files remembered for them are forgotten.
	compiled []string
}

type applyTracker struct {
	mu  sync.Mutex
	run *jobs.Run
	p   applyProgress
	cur *applyRollout
}

func (t *applyTracker) update(f func(p *applyProgress)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	f(&t.p)
	t.run.SetProgress(t.p)
}

func (t *applyTracker) step(name, state, detail string) {
	t.update(func(p *applyProgress) {
		for i := range p.Steps {
			if p.Steps[i].Name == name {
				p.Steps[i].State, p.Steps[i].Detail = state, detail
			}
		}
	})
}

func (t *applyTracker) note(format string, args ...any) {
	t.update(func(p *applyProgress) { p.Notes = append(p.Notes, fmt.Sprintf(format, args...)) })
}

// set is fleet.Client's Progress for the rollout running now.
func (t *applyTracker) set(host, state, detail string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.cur == nil {
		return
	}
	n := t.cur.Nodes[host]
	if n == nil {
		return
	}
	n.State, n.Detail, n.Since, n.Until = state, detail, time.Now(), time.Time{}
	if state == string(fleet.StepSoaking) {
		if d, err := time.ParseDuration(detail); err == nil {
			n.Until = n.Since.Add(d)
		}
	}
	t.run.SetProgress(t.p)
}

func (a applyKind) kind(raw json.RawMessage) (jobs.Func, error) {
	var p applyParams
	if len(bytes.TrimSpace(raw)) > 0 && string(bytes.TrimSpace(raw)) != "null" {
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		if err := d.Decode(&p); err != nil {
			return nil, fmt.Errorf("params: %v", err)
		}
	}
	if err := a.checkParams(p); err != nil {
		return nil, err
	}
	cs, err := a.store.List()
	if err != nil {
		return nil, err
	}
	if len(cs) == 0 {
		return nil, errors.New("nothing to apply: no pending changes")
	}
	if _, err := a.signer(); err != nil {
		return nil, err
	}
	return func(ctx context.Context, run *jobs.Run) (any, error) { return a.run(ctx, run, p) }, nil
}

func (a applyKind) checkParams(p applyParams) error {
	s, err := settings.Load(settings.Path(a.dataDir))
	if err != nil {
		return err
	}
	if len(s.Nodes) == 0 {
		return errors.New("no nodes in settings.json: an apply changes only the nodes listed there")
	}
	if p.Canary != "" && !slices.Contains(s.Nodes, p.Canary) {
		return fmt.Errorf("canary: %s is not in settings.json", p.Canary)
	}
	if p.SoakS != 0 && (p.SoakS < int(rolling.DefaultSoak/time.Second) || p.SoakS > int(rolling.MaxSoak/time.Second)) {
		return fmt.Errorf("soak_s: %v to %v, not %d s", rolling.DefaultSoak, rolling.MaxSoak, p.SoakS)
	}
	for _, l := range p.AcceptChange {
		if err := blocking.ListName(l); err != nil {
			return fmt.Errorf("accept_change: %v", err)
		}
	}
	return nil
}

// fileWrite is one file an apply writes: the last of its changes.
type fileWrite struct {
	kind   changes.Kind
	name   string
	ids    []string
	cur    changes.View // the file now
	text   []byte       // what it becomes
	exists bool
	hash   string
	// base: the first change wasn't written before, so the file now is what a discard
	// puts back.
	base bool
	head string
	// redo: an earlier apply wrote one of its changes, or one puts a file back: the file
	// may be what the nodes should have already, the nodes not yet.
	redo bool
}

func (w fileWrite) same() bool {
	return w.cur.Exists == w.exists && (!w.exists || w.cur.Hash == w.hash)
}

// applyPlan is what the check found to do.
type applyPlan struct {
	writes   []fileWrite
	compile  []blocking.List     // the lists to compile again, the overrides first
	listTo   map[string][]string // a list's nodes
	configTo map[string]string   // node: config file, for the configs changed
	zones    bool                // the hosted zones changed
	firmware []changes.Change    // the firmware updates
	statuses map[string]release.NodeStatus
}

func (a applyKind) run(ctx context.Context, run *jobs.Run, p applyParams) (any, error) {
	cs, err := a.store.List()
	if err != nil {
		return nil, err
	}
	if len(cs) == 0 {
		return nil, errors.New("nothing to apply: no pending changes")
	}
	var ids []string
	for _, c := range cs {
		ids = append(ids, c.ID)
	}
	if err := a.store.Hold(ids); err != nil {
		return nil, err
	}
	defer a.store.Release(ids)
	res := &applyResult{Changes: ids}
	t := &applyTracker{run: run, p: applyProgress{Changes: ids, Rollouts: []*applyRollout{}}}
	for _, s := range []string{"check", "write", "compile", "dry run", "push"} {
		t.p.Steps = append(t.p.Steps, applyStep{Name: s, State: "waiting"})
	}
	run.SetProgress(t.p)
	for _, c := range cs {
		run.Logf("change %s: %s", c.ID, c.Summary)
	}
	step := "check"
	err = a.apply(ctx, run, t, p, cs, res, &step)
	t.update(func(pp *applyProgress) {
		pp.Notes, pp.Questions = res.Notes, res.Questions
		switch {
		case err == nil:
			pp.Outcome = fmt.Sprintf("done: %d change(s) on every node they are for", len(ids))
		case errors.As(err, new(askError)):
			pp.Outcome = "stopped to ask: nothing was pushed"
			for i := range pp.Steps {
				if pp.Steps[i].Name == step {
					pp.Steps[i].State = "stopped"
				}
			}
		case errors.Is(err, fleet.ErrStopped):
			pp.Outcome = "stopped on request"
		default:
			pp.Outcome = "stopped: " + err.Error()
		}
		if err != nil && !errors.As(err, new(askError)) {
			for i := range pp.Steps {
				if pp.Steps[i].Name == step && pp.Steps[i].State == "running" {
					pp.Steps[i].State, pp.Steps[i].Detail = "failed", err.Error()
					if errors.Is(err, fleet.ErrStopped) {
						pp.Steps[i].State = "stopped"
					}
				}
			}
			if res.Written || len(res.Rollouts) > 0 {
				pp.Hints = append(pp.Hints, "The changes stay pending: apply again to finish them "+
					"(the nodes that have them are skipped), or discard them (a file written is put back).")
			} else {
				pp.Hints = append(pp.Hints, "Nothing was written or pushed: the changes stay pending.")
			}
		}
	})
	if err == nil {
		if ferr := a.store.ForgetListSums(res.compiled); ferr != nil {
			run.Logf("the compiled lists' earlier files are still remembered: %v", ferr)
		}
		if aerr := a.store.Applied(ids); aerr != nil {
			run.Logf("the changes went out, but are still listed as pending: %v", aerr)
		}
		res.Applied = true
		run.Logf("applied: %d change(s)", len(ids))
	}
	return res, err
}

func (a applyKind) apply(ctx context.Context, run *jobs.Run, t *applyTracker, p applyParams, cs []changes.Change,
	res *applyResult, step *string) error {
	stopped := func() bool {
		select {
		case <-run.Stop():
			return true
		default:
			return false
		}
	}
	begin := func(s string) error {
		if stopped() {
			return fleet.ErrStopped
		}
		*step = s
		t.step(s, "running", "")
		return nil
	}
	c := a.client()
	c.Logf = run.Logf
	k, err := a.signer()
	if err != nil {
		return err
	}
	c.Pusher = &release.Pusher{Key: k, KeyID: release.KeyRelease, Pins: pins.Open(a.dataDir), Client: c.HTTP}
	run.Logf("signing with the release key %s", keys.Fingerprint(k))

	// 1. Check.
	if err := begin("check"); err != nil {
		return err
	}
	pl, err := a.check(ctx, c, cs, res)
	if err != nil {
		return err
	}
	t.step("check", "done", "")

	// 2. Write.
	if err := begin("write"); err != nil {
		return err
	}
	n, err := a.write(pl.writes)
	if n > 0 {
		res.Written = true
	}
	if err != nil {
		return err
	}
	t.step("write", "done", fmt.Sprintf("%d file(s) written", n))

	// 3. Compile.
	if len(pl.compile) == 0 {
		t.step("compile", "skipped", "no blocklist changed")
	} else {
		if err := begin("compile"); err != nil {
			return err
		}
		// The compiled files the nodes run now, kept: an apply that stops after the compile
		// still finds the list's nodes the next time, by what they run.
		for _, l := range pl.compile {
			if l.IsOverrides() {
				continue
			}
			if err := a.store.RememberListSum(l.Name, fileSHA256(blocking.Out(a.dataDir, l.Name))); err != nil {
				return err
			}
			res.compiled = append(res.compiled, l.Name)
		}
		if err := a.compileLists(ctx, run, p, pl, res); err != nil {
			return err
		}
		t.step("compile", "done", "")
	}

	// 4. The dry runs, every one before any node is touched.
	reqs, err := a.requests(p, pl)
	if err != nil {
		return err
	}
	if len(reqs) == 0 {
		t.step("dry run", "skipped", "nothing to send to the nodes")
		t.step("push", "skipped", "nothing to send to the nodes")
		return nil
	}
	t.update(func(pp *applyProgress) {
		for _, r := range reqs {
			ar := &applyRollout{Kind: r.req.Kind.String(), What: r.what, Order: r.req.Order(), State: "waiting", Nodes: map[string]*nodeState{}}
			for _, h := range ar.Order {
				ar.Nodes[h] = &nodeState{State: "waiting", Since: time.Now()}
			}
			pp.Rollouts = append(pp.Rollouts, ar)
		}
	})
	if err := begin("dry run"); err != nil {
		return err
	}
	for i, r := range reqs {
		if stopped() {
			return fleet.ErrStopped
		}
		ar := t.p.Rollouts[i]
		t.update(func(*applyProgress) { ar.State = "checking" })
		b, err := rolling.Build(ctx, c, r.req, run.Logf)
		if err == nil {
			b.Plan.Stop = run.Stop()
			_, err = c.Rollout(ctx, b.Plan, b.Change)
		}
		if err != nil {
			if errors.Is(err, fleet.ErrSingle) {
				err = fmt.Errorf("%w (add another node, or a DNS peer, to settings.json)", err)
			}
			t.update(func(*applyProgress) { ar.State, ar.Outcome = "failed", "check failed: "+err.Error() })
			return fmt.Errorf("%s: the check before any push: %w", r.what, err)
		}
		t.update(func(*applyProgress) { ar.State = "checked" })
	}
	t.step("dry run", "done", "every node takes it")

	// 5. Push, one rollout after the other, each one node at a time.
	if err := begin("push"); err != nil {
		return err
	}
	c.Progress = func(host string, s fleet.Step, detail string) { t.set(host, string(s), detail) }
	for i, r := range reqs {
		if stopped() {
			return fleet.ErrStopped
		}
		ar := t.p.Rollouts[i]
		req := r.req
		req.DryRun = false // the same request: the same bytes the dry run checked
		b, err := rolling.Build(ctx, c, req, run.Logf)
		if err != nil {
			t.update(func(*applyProgress) { ar.State, ar.Outcome = "failed", err.Error() })
			return fmt.Errorf("%s: %w", r.what, err)
		}
		b.Plan.Stop = run.Stop()
		if a.adjust != nil {
			a.adjust(&b.Plan)
		}
		t.update(func(*applyProgress) {
			ar.State, ar.Order = "pushing", b.Plan.Order()
			t.cur = ar
		})
		run.Logf("%s: to %s", r.what, strings.Join(b.Plan.Order(), ", then "))
		out, err := c.Rollout(ctx, b.Plan, b.Change)
		rolling.Report(run.Logf, b.Plan, out)
		if req.Kind == release.Config {
			rolling.RecordPushed(ctx, c, a.dataDir, b.Specs, out.Done, "controller", run.Logf)
		}
		if req.Kind == release.Zones {
			rolling.RecordZones(ctx, c, req, out.Done, "controller", run.Logf)
		}
		rr := rolloutResult{Kind: req.Kind.String(), Order: b.Plan.Order(), Done: out.Done, Skipped: out.Skipped,
			Failed: out.Failed, Left: out.Left, Reverted: out.Reverted, NotReverted: out.NotReverted}
		res.Rollouts = append(res.Rollouts, rr)
		t.update(func(*applyProgress) {
			t.cur = nil
			for _, h := range out.Done {
				ar.Nodes[h].State, ar.Nodes[h].Detail, ar.Nodes[h].Until = "done", "", time.Time{}
			}
			for _, h := range out.Skipped {
				ar.Nodes[h].State, ar.Nodes[h].Detail = "skipped", "already had it"
			}
			for _, h := range out.Left {
				ar.Nodes[h].State = "left"
			}
			for _, h := range out.Reverted {
				ar.Nodes[h].State = "reverted"
			}
			switch {
			case err == nil:
				ar.State = "done"
				ar.Outcome = fmt.Sprintf("%d changed and checked, %d already had it", len(out.Done), len(out.Skipped))
			case errors.Is(err, fleet.ErrStopped):
				ar.State, ar.Outcome = "stopped", "stopped on request"
			default:
				ar.State, ar.Outcome = "failed", err.Error()
				if out.Failed != "" {
					ar.Nodes[out.Failed].State, ar.Nodes[out.Failed].Detail = "failed", err.Error()
				}
			}
		})
		if err != nil {
			if errors.Is(err, fleet.ErrStopped) {
				return err
			}
			return fmt.Errorf("%s: %w", r.what, err)
		}
	}
	t.step("push", "done", "")
	return nil
}

// check reads the files and the nodes and says what to do; nothing is written.
func (a applyKind) check(ctx context.Context, c *fleet.Client, cs []changes.Change, res *applyResult) (applyPlan, error) {
	pl := applyPlan{listTo: map[string][]string{}, configTo: map[string]string{}, statuses: map[string]release.NodeStatus{}}
	s, err := settings.Load(settings.Path(a.dataDir))
	if err != nil {
		return pl, err
	}
	if len(s.Nodes) == 0 {
		return pl, errors.New("no nodes in settings.json")
	}
	var unread []string
	for _, h := range s.Nodes {
		st, err := c.Status(ctx, h)
		if err != nil {
			unread = append(unread, fmt.Sprintf("%s (%v)", h, err))
			continue
		}
		pl.statuses[h] = st
	}
	if len(unread) > 0 {
		return pl, fmt.Errorf("every node in settings.json must answer before a change; these don't: %s", strings.Join(unread, ", "))
	}

	// Each file: on the version its first change edits, or one an apply that stopped wrote.
	final := map[string]fileWrite{}
	for _, chain := range changes.Chains(cs) {
		head, last := chain[0], chain[len(chain)-1]
		cur, err := changes.Current(a.dataDir, head.Kind, head.Name)
		if err != nil {
			return pl, err
		}
		ok := cur.Hash == head.Base
		for _, x := range chain {
			if x.Written && cur.Hash == x.Hash {
				ok = true
			}
		}
		if !ok {
			return pl, fmt.Errorf("%s (%s): the file changed since the change was made (by hand, or by another page): "+
				"discard the change and make it again", head.Name, head.Summary)
		}
		text, err := a.store.Text(last)
		if err != nil {
			return pl, err
		}
		w := fileWrite{kind: head.Kind, name: head.Name, cur: cur, text: text, exists: !last.Delete, hash: last.Hash,
			base: !head.Written, head: head.ID}
		for _, x := range chain {
			w.ids = append(w.ids, x.ID)
			w.redo = w.redo || x.Written || x.PutBack
		}
		pl.writes = append(pl.writes, w)
		final[string(head.Kind)+"/"+head.Name] = w
	}

	// The hosted zones, as one set.
	for _, w := range pl.writes {
		if w.kind == changes.Zone {
			pl.zones = true
		}
	}
	if pl.zones {
		files, err := zonefiles.List(a.dataDir)
		if err != nil {
			return pl, err
		}
		texts := map[string][]byte{}
		for _, f := range files {
			texts[f.Name] = f.Text
		}
		for _, w := range pl.writes {
			if w.kind == changes.Zone {
				delete(texts, w.name)
				if w.exists {
					texts[w.name] = w.text
				}
			}
		}
		set := &zones.Set{}
		for name, text := range texts {
			z, err := zonefiles.Parse(name, text)
			if err != nil {
				return pl, fmt.Errorf("%s: %v", name, err)
			}
			set.Zones = append(set.Zones, z)
		}
		if err := set.Validate(); err != nil {
			return pl, fmt.Errorf("the hosted zones together: %v", err)
		}
	}

	// The configs: each to the node that runs it.
	for _, w := range pl.writes {
		if w.kind != changes.Config {
			continue
		}
		if !w.exists {
			res.Notes = append(res.Notes, fmt.Sprintf("%s deleted: no node changes", w.name))
			continue
		}
		if _, err := nodecfg.Parse(w.text); err != nil {
			return pl, fmt.Errorf("%s: %v", w.name, err)
		}
		// The node of the config as it becomes, as it is, or as it was before an apply
		// that stopped wrote it (a change that renames the node, or moves its address).
		to := configNodes(a.dataDir, w.name, [][]byte{w.text, w.cur.Text, a.store.Base(w.head)}, s.Nodes, pl.statuses)
		if len(to) == 0 {
			res.Notes = append(res.Notes, fmt.Sprintf("%s: no node in settings.json runs it (by its name or address): saved, sent to none", w.name))
		}
		for _, h := range to {
			// The config rollout refuses a config that moves its node (configs.Payloads):
			// refused here, before any file is written.
			if sp, err := configs.ParseSpec(h, w.name, w.text); err == nil {
				if a, ok := sp.Moves(); ok {
					return pl, fmt.Errorf("%s moves %s to %s, which an apply doesn't do: discard the change, and push the config "+
						"from the Configs page, which confirms the node on its new address", w.name, h, a)
				}
			}
			if o, ok := pl.configTo[h]; ok {
				return pl, fmt.Errorf("%s and %s are both %s's config", o, w.name, h)
			}
			pl.configTo[h] = w.name
		}
	}

	// The blocklists: the definitions and the sources as the changes make them.
	var srcChanged []string
	defsChanged := false
	for _, w := range pl.writes {
		switch w.kind {
		case changes.Source:
			srcChanged = append(srcChanged, w.name)
		case changes.Lists:
			defsChanged = true
		}
	}
	if defsChanged || len(srcChanged) > 0 {
		if err := a.checkLists(pl.statuses, s.Nodes, final, srcChanged, &pl, res); err != nil {
			return pl, err
		}
	}

	// The firmware updates.
	for _, ch := range cs {
		if ch.Kind != changes.Firmware {
			continue
		}
		if err := firmwareThere(a.dataDir, a.catalog, ch.Firmware); err != nil {
			return pl, fmt.Errorf("%s: %v", ch.Summary, err)
		}
		for _, h := range ch.Nodes {
			if !slices.Contains(s.Nodes, h) {
				return pl, fmt.Errorf("%s: %s is not in settings.json", ch.Summary, h)
			}
		}
		pl.firmware = append(pl.firmware, ch)
	}
	return pl, nil
}

// checkLists finds the lists to compile again and their nodes.
func (a applyKind) checkLists(sts map[string]release.NodeStatus, hosts []string, final map[string]fileWrite,
	srcChanged []string, pl *applyPlan, res *applyResult) error {
	oldDefs, _, err := blocking.Load(a.dataDir)
	if _, ok := final["lists/"+blocking.DefsFile]; err != nil && !ok {
		return err
	}
	defs := oldDefs
	// Definitions an earlier apply wrote (or put back): the file is what the nodes should
	// have already, so every list is compiled and sent again.
	redoDefs := false
	if w, ok := final["lists/"+blocking.DefsFile]; ok {
		redoDefs = w.redo
		defs = blocking.Defs{}
		if w.exists {
			if defs, err = blocking.Parse(w.text); err != nil {
				return fmt.Errorf("%s: %v", blocking.DefsFile, err)
			}
		}
	}
	// The source files there after the write.
	have := func(name string) bool {
		if w, ok := final["source/"+name]; ok {
			return w.exists
		}
		_, err := os.Stat(blocking.SourcePath(a.dataDir, name))
		return err == nil
	}
	if slices.Contains(srcChanged, blocking.OverridesBlock) || slices.Contains(srcChanged, blocking.OverridesAllow) {
		if !have(blocking.OverridesBlock) && !have(blocking.OverridesAllow) {
			return fmt.Errorf("the overrides would have no file: keep %s or %s, empty, rather than delete both",
				blocking.OverridesBlock, blocking.OverridesAllow)
		}
		pl.compile = append(pl.compile, blocking.List{Name: blocking.OverridesName})
		pl.listTo[blocking.OverridesName] = slices.Clone(hosts)
	}
	same := func(x, y blocking.List) bool {
		bx, _ := json.Marshal(x)
		by, _ := json.Marshal(y)
		return bytes.Equal(bx, by)
	}
	for _, l := range defs.Lists {
		old, had := oldDefs.Lookup(a.dataDir, l.Name)
		touched := redoDefs || !had || !same(old, l)
		for _, f := range l.Files() {
			if slices.Contains(srcChanged, f) {
				touched = true
			}
		}
		if !touched {
			continue
		}
		for _, f := range l.Files() {
			if !have(f) {
				return fmt.Errorf("the list %s reads %s, which would not be there", l.Name, f)
			}
		}
		// Its nodes: those that run its compiled file now, or one an apply that stopped
		// compiled it from.
		to := a.runs(sts, hosts, l.Name)
		if len(to) == 0 && len(defs.Lists) == 1 && !a.anyRuns(sts, hosts, oldDefs) {
			to = slices.Clone(hosts)
		}
		if len(to) == 0 {
			res.Notes = append(res.Notes, fmt.Sprintf("the list %s is on no node: compiled, sent to none", l.Name))
		}
		pl.compile = append(pl.compile, l)
		pl.listTo[l.Name] = to
	}
	// Source files no list reads: written only.
	for _, f := range srcChanged {
		used := f == blocking.OverridesBlock || f == blocking.OverridesAllow
		for _, l := range defs.Lists {
			used = used || l.Uses(f)
		}
		if !used {
			res.Notes = append(res.Notes, fmt.Sprintf("%s: no list reads it: saved only", f))
		}
	}
	return nil
}

// runs are the hosts that run the list: its compiled file, or one remembered for it.
func (a applyKind) runs(sts map[string]release.NodeStatus, hosts []string, list string) []string {
	sums := a.store.ListSums(list)
	if sum := fileSHA256(blocking.Out(a.dataDir, list)); sum != "" {
		sums = append(sums, sum)
	}
	var to []string
	for _, h := range hosts {
		if st := sts[h]; st.Blocking != nil && st.Blocking.List.SHA256 != "" && slices.Contains(sums, st.Blocking.List.SHA256) {
			to = append(to, h)
		}
	}
	return to
}

// anyRuns says whether a node runs one of the lists defined.
func (a applyKind) anyRuns(sts map[string]release.NodeStatus, hosts []string, defs blocking.Defs) bool {
	for _, l := range defs.Lists {
		if len(a.runs(sts, hosts, l.Name)) > 0 {
			return true
		}
	}
	return false
}

func fileSHA256(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// write writes the files, each marked written (with what it replaces) first. It returns
// how many it wrote.
func (a applyKind) write(ws []fileWrite) (int, error) {
	n := 0
	for _, w := range ws {
		if w.same() {
			continue
		}
		bases := map[string][]byte{}
		if w.base && w.cur.Exists {
			bases[w.head] = w.cur.Text
		}
		if err := a.store.MarkWritten(w.ids, bases); err != nil {
			return n, err
		}
		st, err := changes.FileStore(a.dataDir, w.kind)
		if err != nil {
			return n, err
		}
		if w.exists {
			err = st.Save(w.name, w.text, w.cur.Hash)
		} else {
			err = st.Delete(w.name, w.cur.Hash)
		}
		if err != nil {
			// Not written: a discard leaves the file as it is (another page may have saved
			// it since the check). One an earlier apply wrote stays written.
			if w.base {
				if uerr := a.store.Unwritten(w.ids); uerr != nil {
					return n, fmt.Errorf("%s: %w (and still marked written: %v)", w.name, err, uerr)
				}
			}
			return n, fmt.Errorf("%s: %w", w.name, err)
		}
		n++
	}
	return n, nil
}

// compileLists compiles the lists; those the size-change check refuses are asked about,
// all at once.
func (a applyKind) compileLists(ctx context.Context, run *jobs.Run, p applyParams, pl applyPlan, res *applyResult) error {
	ck := compileKind{dataDir: a.dataDir, fetch: a.fetch}
	defs, _, err := blocking.Load(a.dataDir)
	if err != nil && len(defs.Lists) > 0 {
		return err
	}
	var asks []string
	for _, want := range pl.compile {
		l, ok := defs.Lookup(a.dataDir, want.Name)
		if !ok {
			return fmt.Errorf("no list %s", want.Name)
		}
		if err := l.Ready(a.dataDir); err != nil {
			return fmt.Errorf("%s: %v", l.Name, err)
		}
		_, sc, err := ck.compile(ctx, run, l, slices.Contains(p.AcceptChange, l.Name))
		if sc != nil {
			q := question{Kind: "size-change", List: l.Name,
				Text: fmt.Sprintf("%s changed more than its limit (%s): apply it anyway, or discard the change and keep the list the nodes have",
					l.Name, strings.Join(sc.Change.Over, ", "))}
			q.Params = p
			q.Params.AcceptChange = append(slices.Clone(p.AcceptChange), l.Name)
			res.Questions = append(res.Questions, q)
			asks = append(asks, q.Text)
			continue
		}
		if err != nil {
			return fmt.Errorf("compiling %s: %w", l.Name, err)
		}
	}
	if len(asks) > 0 {
		// Every question takes the others' answers too.
		var all []string
		for _, q := range res.Questions {
			all = append(all, q.List)
		}
		for i := range res.Questions {
			res.Questions[i].Params.AcceptChange = append(slices.Clone(p.AcceptChange), all...)
			slices.Sort(res.Questions[i].Params.AcceptChange)
			res.Questions[i].Params.AcceptChange = slices.Compact(res.Questions[i].Params.AcceptChange)
		}
		return askError{strings.Join(asks, "; ")}
	}
	return nil
}

// applyReq is one rollout of an apply.
type applyReq struct {
	what string
	req  rolling.Request
}

// requests are the rollouts, in the order they go: configs, hosted zones, overrides,
// blocklists, firmware; each a dry run (pushed as the same request, DryRun off).
func (a applyKind) requests(p applyParams, pl applyPlan) ([]applyReq, error) {
	s, err := settings.Load(settings.Path(a.dataDir))
	if err != nil {
		return nil, err
	}
	inOrder := func(hs []string) []string {
		var out []string
		for _, h := range s.Nodes {
			if slices.Contains(hs, h) {
				out = append(out, h)
			}
		}
		return out
	}
	var out []applyReq
	add := func(what string, w rolling.Web) error {
		w.Nodes = inOrder(w.Nodes)
		if len(w.Nodes) == 0 {
			return nil
		}
		if slices.Contains(w.Nodes, p.Canary) {
			w.Canary = p.Canary
		}
		w.SoakS, w.DryRun = p.SoakS, true
		r, err := w.Request(a.dataDir, a.catalog)
		if err != nil {
			return fmt.Errorf("%s: %w", what, err)
		}
		out = append(out, applyReq{what: what, req: r})
		return nil
	}
	if len(pl.configTo) > 0 {
		var hs []string
		for h := range pl.configTo {
			hs = append(hs, h)
		}
		if err := add("node configs", rolling.Web{Kind: "config", Nodes: hs, Configs: pl.configTo}); err != nil {
			return nil, err
		}
	}
	if pl.zones {
		files, err := zonefiles.List(a.dataDir)
		if err != nil {
			return nil, err
		}
		var names []string
		for _, f := range files {
			names = append(names, f.Name)
		}
		if err := add("hosted zones", rolling.Web{Kind: "zones", Nodes: s.Nodes, Zones: names, EmptyZones: len(names) == 0}); err != nil {
			return nil, err
		}
	}
	for _, l := range pl.compile {
		kind, what := "blocklist", "blocklist "+l.Name
		if l.IsOverrides() {
			kind, what = "overrides", "allowed and blocked sites"
		}
		if err := add(what, rolling.Web{Kind: kind, Nodes: pl.listTo[l.Name], File: l.Name + ".bin"}); err != nil {
			return nil, err
		}
	}
	for _, f := range pl.firmware {
		if err := add("firmware "+f.Firmware, rolling.Web{Kind: "firmware", Nodes: f.Nodes, Firmware: []string{f.Firmware}}); err != nil {
			return nil, err
		}
	}
	return out, nil
}
