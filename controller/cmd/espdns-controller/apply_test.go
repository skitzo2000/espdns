package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/actionlog"
	"github.com/skitzo2000/espdns/controller/internal/changes"
	"github.com/skitzo2000/espdns/controller/internal/fleet"
	"github.com/skitzo2000/espdns/controller/internal/jobs"
	"github.com/skitzo2000/espdns/controller/internal/keys"
	"github.com/skitzo2000/espdns/controller/internal/settings"
)

// applyEnv is a rolling push's environment with the pending changes and the apply.
type applyEnv struct {
	*rollEnv
	store *changes.Store
	apply *applyKind
}

func newApplyEnv(t *testing.T, n int) *applyEnv {
	e := &applyEnv{rollEnv: newRollEnv(t, n)}
	e.store = changes.New(e.dir)
	e.apply = &applyKind{actions: e.push.actions, catalog: e.catalog, store: e.store, adjust: e.push.adjust}
	e.kinds["apply"] = func(raw json.RawMessage) (jobs.Func, error) { return e.apply.kind(raw) }
	return e
}

// add adds a change on the file as the pending changes make it.
func (e *applyEnv) add(k changes.Kind, name, text string) changes.Change {
	e.t.Helper()
	v, err := e.store.Effective(k, name)
	if err != nil {
		e.t.Fatal(err)
	}
	ed := changes.Edit{Kind: k, Name: name, Hash: v.Hash, Who: "admin"}
	if text == "" {
		ed.Delete = true
	} else {
		ed.Text = []byte(text)
	}
	c, err := e.store.Add(ed)
	if err != nil {
		e.t.Fatalf("add %s: %v", name, err)
	}
	return c
}

// runApply runs an apply to its end.
func (e *applyEnv) runApply(params map[string]any) (jobs.Job, applyResult, applyProgress) {
	e.t.Helper()
	b, _ := json.Marshal(params)
	j, err := e.runner.Start("apply", "admin", b)
	if err != nil {
		e.t.Fatalf("refused: %v", err)
	}
	j = e.wait(j, nil)
	var r applyResult
	var p applyProgress
	json.Unmarshal(j.Result, &r)
	json.Unmarshal(j.Progress, &p)
	return j, r, p
}

func (e *applyEnv) pending() []changes.Change {
	cs, err := e.store.List()
	if err != nil {
		e.t.Fatal(err)
	}
	return cs
}

func nameLines(prefix string, n int) string {
	var b strings.Builder
	for i := range n {
		fmt.Fprintf(&b, "%s%d.example.org\n", prefix, i)
	}
	return b.String()
}

// A new zone and the allowed and blocked sites, applied: checked, written, the overrides
// compiled, every node checked before any is touched, then one rollout after the other,
// one node at a time. The changes are no longer pending.
func TestApplyZoneAndOverrides(t *testing.T) {
	e := newApplyEnv(t, 2)
	z := e.add(changes.Zone, "example.com.zone", zoneOther)
	o := e.add(changes.Source, "overrides.txt", "ads.example.org\n")
	before := map[string]int{}
	for _, n := range e.nodes {
		before[n.Name] = len(n.Events())
	}
	j, r, p := e.runApply(nil)
	if j.State != jobs.Done || !r.Applied || !r.Written || !slices.Equal(r.Changes, []string{z.ID, o.ID}) {
		t.Fatalf("apply %+v %+v %+v", j, r, p)
	}
	for i, n := range e.nodes {
		if ev := n.Events()[before[n.Name]:]; !slices.Equal(ev, []string{"push zones", "push overrides"}) {
			t.Errorf("%s: %v (zones first, then the overrides, live)", e.addrs[i], ev)
		}
		st := fakeStatus(n)
		hz, _ := json.Marshal(st["hosted"])
		if !strings.Contains(string(hz), `"example.com"`) || !strings.Contains(string(hz), `"home.example"`) {
			t.Errorf("%s serves %s", e.addrs[i], hz)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(e.dir, "zones/example.com.zone")); string(b) != zoneOther {
		t.Errorf("zone file %q", b)
	}
	if _, err := os.Stat(filepath.Join(e.dir, "lists/overrides.bin")); err != nil {
		t.Errorf("overrides not compiled: %v", err)
	}
	if cs := e.pending(); len(cs) != 0 {
		t.Errorf("still pending: %+v", cs)
	}
	var steps []string
	for _, s := range p.Steps {
		steps = append(steps, s.Name+":"+s.State)
	}
	if !slices.Equal(steps, []string{"check:done", "write:done", "compile:done", "dry run:done", "push:done"}) {
		t.Errorf("steps %v", steps)
	}
	if len(p.Rollouts) != 2 || p.Rollouts[0].Kind != "zones" || p.Rollouts[1].Kind != "overrides" ||
		p.Rollouts[0].State != "done" || p.Rollouts[1].Nodes[e.addrs[1]].State != "done" || !strings.HasPrefix(p.Outcome, "done") {
		t.Errorf("progress %+v", p)
	}
	// In the action log, by the user.
	es, _ := actionlog.Tail(e.dir, 0)
	if len(es) != 2 || es[0].Action != "job apply" || es[1].Who != "admin" || es[1].Result != "ok" {
		t.Errorf("action log %+v", es)
	}
	// Nothing left: refused before it is queued.
	if _, err := e.runner.Start("apply", "admin", nil); err == nil || !strings.Contains(err.Error(), "nothing to apply") {
		t.Errorf("nothing pending: %v", err)
	}
}

// A node config goes only to the node that runs it.
func TestApplyConfigToItsNode(t *testing.T) {
	e := newApplyEnv(t, 2)
	e.add(changes.Config, "fake-a.json", `{"name": "fake-a", "forwarders": ["192.0.2.53"]}`)
	j, r, p := e.runApply(map[string]any{"soak_s": 60})
	if j.State != jobs.Done || len(r.Rollouts) != 1 || !slices.Equal(r.Rollouts[0].Done, []string{e.addrs[0]}) {
		t.Fatalf("apply %+v %+v %+v", j, r, p)
	}
	if ev := e.nodes[0].Events(); !slices.Equal(ev, []string{"push config"}) {
		t.Errorf("its node: %v", ev)
	}
	if ev := e.nodes[1].Events(); len(ev) != 0 {
		t.Errorf("the other node: %v", ev)
	}
	// A config no node runs: saved, sent to none, said so.
	e.add(changes.Config, "fake-z.json", `{"name": "fake-z"}`)
	j, r, _ = e.runApply(nil)
	if j.State != jobs.Done || len(r.Rollouts) != 0 || len(r.Notes) != 1 || !strings.Contains(r.Notes[0], "no node in settings.json runs it") {
		t.Errorf("a config of no node: %+v %+v", j, r)
	}
	if _, err := os.Stat(filepath.Join(e.dir, "configs/fake-z.json")); err != nil {
		t.Errorf("not saved: %v", err)
	}
}

// A config change that renames its node goes to the node that runs the file now.
func TestApplyConfigRename(t *testing.T) {
	e := newApplyEnv(t, 2)
	e.add(changes.Config, "fake-a.json", `{"name": "fake-x", "forwarders": ["9.9.9.9"]}`)
	j, r, p := e.runApply(nil)
	if j.State != jobs.Done || len(r.Rollouts) != 1 || !slices.Equal(r.Rollouts[0].Done, []string{e.addrs[0]}) {
		t.Fatalf("apply %+v %+v %+v", j, r, p)
	}
	if ev := e.nodes[1].Events(); len(ev) != 0 {
		t.Errorf("the other node: %v", ev)
	}
}

// The size-change check asks, rather than fails: the apply stops with the question and
// the params that take the change; nothing is pushed. Applying with them takes it.
func TestApplySizeChangeAsks(t *testing.T) {
	e := newApplyEnv(t, 2)
	e.add(changes.Source, "overrides.txt", nameLines("ads", 300))
	if j, _, p := e.runApply(nil); j.State != jobs.Done {
		t.Fatalf("first apply %+v %+v", j, p)
	}
	e.add(changes.Source, "overrides.txt", nameLines("ads", 10))
	before := len(e.nodes[0].Events())
	j, r, p := e.runApply(nil)
	if j.State != jobs.Stopped || !strings.Contains(j.Error, "waiting for an answer") || len(r.Questions) != 1 {
		t.Fatalf("apply %+v %+v %+v", j, r, p)
	}
	q := r.Questions[0]
	if q.Kind != "size-change" || q.List != "overrides" || !slices.Equal(q.Params.AcceptChange, []string{"overrides"}) ||
		!strings.Contains(q.Text, "blocked") || len(p.Questions) != 1 || p.Outcome != "stopped to ask: nothing was pushed" {
		t.Errorf("question %+v %+v", q, p)
	}
	if len(e.nodes[0].Events()) != before {
		t.Errorf("pushed while asking: %v", e.nodes[0].Events())
	}
	if cs := e.pending(); len(cs) != 1 || !cs[0].Written {
		t.Errorf("pending %+v", cs)
	}
	b, _ := json.Marshal(q.Params)
	var params map[string]any
	json.Unmarshal(b, &params)
	j, r, _ = e.runApply(params)
	if j.State != jobs.Done || !r.Applied || len(e.pending()) != 0 {
		t.Errorf("taken: %+v %+v", j, r)
	}
	if ev := e.nodes[0].Events()[before:]; !slices.Equal(ev, []string{"push overrides"}) {
		t.Errorf("after the answer: %v", ev)
	}
}

// A node that fails stops the apply: the nodes after it untouched, the changes still
// pending, written; discarding then puts the files back and leaves a change that sends
// them as they are again.
func TestApplyFailureKeepsPending(t *testing.T) {
	e := newApplyEnv(t, 3)
	e.nodes[1].Rollback = true
	z := e.add(changes.Zone, "example.com.zone", zoneOther)
	f, err := e.store.Add(changes.Edit{Kind: changes.Firmware, Firmware: "images/esp32p4-rev1", Nodes: e.addrs, Who: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	j, r, p := e.runApply(nil)
	if j.State != jobs.Failed || r.Applied || !r.Written || len(r.Rollouts) != 2 {
		t.Fatalf("apply %+v %+v %+v", j, r, p)
	}
	fw := r.Rollouts[1]
	if fw.Kind != "firmware" || fw.Failed != e.addrs[1] || !slices.Equal(fw.Left, []string{e.addrs[2]}) {
		t.Errorf("firmware %+v", fw)
	}
	if !slices.Equal(r.Rollouts[0].Done, e.addrs) {
		t.Errorf("zones %+v", r.Rollouts[0])
	}
	if ev := e.nodes[2].Events(); !slices.Equal(ev, []string{"push zones"}) {
		t.Errorf("the node after the failure: %v", ev)
	}
	cs := e.pending()
	if len(cs) != 2 || !cs[0].Written || cs[1].ID != f.ID {
		t.Errorf("pending %+v", cs)
	}
	if !strings.Contains(strings.Join(p.Hints, " "), "apply again to finish") {
		t.Errorf("hints %v", p.Hints)
	}
	// Discarded: the zone file gone again, and a change that sends the zones as they are.
	d, err := e.store.Discard(z.ID)
	if err != nil || len(d.PutBack) != 1 {
		t.Fatalf("discard %+v %v", d, err)
	}
	if _, err := os.Stat(filepath.Join(e.dir, "zones/example.com.zone")); !os.IsNotExist(err) {
		t.Errorf("the zone file is still there: %v", err)
	}
	e.store.Discard(f.ID)
	e.nodes[1].Rollback = false
	j, r, _ = e.runApply(nil)
	if j.State != jobs.Done || len(r.Rollouts) != 1 || r.Rollouts[0].Kind != "zones" || len(e.pending()) != 0 {
		t.Fatalf("put back %+v %+v", j, r)
	}
	hz, _ := json.Marshal(fakeStatus(e.nodes[0])["hosted"])
	if strings.Contains(string(hz), `"example.com"`) {
		t.Errorf("still serves the discarded zone: %s", hz)
	}
}

// The check refuses before anything is written: a file changed since the change was
// made, a node that doesn't answer, zones that clash.
func TestApplyCheckRefuses(t *testing.T) {
	e := newApplyEnv(t, 2)
	e.add(changes.Zone, "home.example.zone", strings.Replace(zoneText, "192.0.2.20", "192.0.2.21", 1))
	writeFile(t, filepath.Join(e.dir, "zones/home.example.zone"), []byte(strings.Replace(zoneText, "192.0.2.20", "192.0.2.22", 1)))
	j, r, p := e.runApply(nil)
	if j.State != jobs.Failed || !strings.Contains(j.Error, "the file changed since") || r.Written || p.Steps[0].State != "failed" {
		t.Fatalf("a file changed by hand: %+v %+v %+v", j, r, p)
	}
	for _, n := range e.nodes {
		if len(n.Events()) != 0 {
			t.Errorf("%s touched: %v", n.Name, n.Events())
		}
	}
	e.store.DiscardAll()

	// A node that doesn't answer: refused at the check, nothing written.
	e.add(changes.Zone, "example.com.zone", zoneOther)
	if err := settings.Save(settings.Path(e.dir), settings.Settings{Nodes: append(slices.Clone(e.addrs), "127.0.0.1:1")}); err != nil {
		t.Fatal(err)
	}
	j, r, _ = e.runApply(nil)
	if j.State != jobs.Failed || !strings.Contains(j.Error, "must answer") || r.Written {
		t.Errorf("a node down: %+v %+v", j, r)
	}
	if _, err := os.Stat(filepath.Join(e.dir, "zones/example.com.zone")); err == nil {
		t.Error("written before the check passed")
	}
	settings.Save(settings.Path(e.dir), settings.Settings{Nodes: e.addrs})

	// A node in a fault: the dry run refuses before any node is touched; the files are
	// written, the change pending.
	e.nodes[1].Break(true)
	j, r, p = e.runApply(nil)
	if j.State != jobs.Failed || !strings.Contains(j.Error, "the check before any push") || !r.Written || p.Rollouts[0].State != "failed" {
		t.Errorf("a node in a fault: %+v %+v %+v", j, r, p)
	}
	for _, n := range e.nodes {
		if len(n.Events()) != 0 {
			t.Errorf("%s touched: %v", n.Name, n.Events())
		}
	}
	if cs := e.pending(); len(cs) != 1 || !cs[0].Written {
		t.Errorf("pending %+v", cs)
	}
	e.nodes[1].Break(false)

	// Refused before it is queued.
	for _, params := range []string{`{"canary": "192.0.2.99:80"}`, `{"soak_s": 1}`, `{"nope": 1}`, `{"accept_change": ["Bad"]}`} {
		if _, err := e.runner.Start("apply", "admin", json.RawMessage(params)); err == nil {
			t.Errorf("%s: queued", params)
		}
	}
	e.apply.key = keys.FileSource{Path: filepath.Join(t.TempDir(), "none.pem")}
	if _, err := e.runner.Start("apply", "admin", nil); err == nil || !strings.Contains(err.Error(), "release key") {
		t.Errorf("no key: %v", err)
	}
}

// Every hosted zone deleted: the nodes serve none.
func TestApplyDeleteEveryZone(t *testing.T) {
	e := newApplyEnv(t, 2)
	e.add(changes.Zone, "home.example.zone", strings.Replace(zoneText, "2026100301", "2026100302", 1))
	if j, _, p := e.runApply(nil); j.State != jobs.Done {
		t.Fatalf("first %+v %+v", j, p)
	}
	if hz, _ := json.Marshal(fakeStatus(e.nodes[0])["hosted"]); !strings.Contains(string(hz), "home.example") {
		t.Fatalf("serves %s", hz)
	}
	e.add(changes.Zone, "home.example.zone", "")
	j, r, p := e.runApply(nil)
	if j.State != jobs.Done || len(r.Rollouts) != 1 {
		t.Fatalf("apply %+v %+v %+v", j, r, p)
	}
	hz, _ := json.Marshal(fakeStatus(e.nodes[0])["hosted"])
	if strings.Contains(string(hz), "home.example") {
		t.Errorf("serves %s", hz)
	}
}

// A stop asked for while a node is watched ends the apply there: the next node untouched,
// the changes pending, written.
func TestApplyStop(t *testing.T) {
	e := newApplyEnv(t, 2)
	e.soak = 5 * time.Second
	e.add(changes.Zone, "example.com.zone", zoneOther)
	j, err := e.runner.Start("apply", "admin", nil)
	if err != nil {
		t.Fatal(err)
	}
	for range 4000 {
		j, _ = e.runner.Get(j.ID)
		var p applyProgress
		if json.Unmarshal(j.Progress, &p) == nil && len(p.Rollouts) == 1 && p.Rollouts[0].Nodes[e.addrs[0]].State == string(fleet.StepSoaking) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, err := e.runner.Stop(j.ID); err != nil {
		t.Fatal(err)
	}
	j = e.wait(j, nil)
	var r applyResult
	json.Unmarshal(j.Result, &r)
	if j.State != jobs.Stopped || r.Applied || !r.Written {
		t.Fatalf("stopped %+v %+v", j, r)
	}
	if ev := e.nodes[1].Events(); len(ev) != 0 {
		t.Errorf("the second node: %v", ev)
	}
	if cs := e.pending(); len(cs) != 1 || !cs[0].Written {
		t.Errorf("pending %+v", cs)
	}
}

// A blocklist goes to the nodes that run it; the only list, run by no node, to every node.
func TestApplyBlocklistNodes(t *testing.T) {
	e := newApplyEnv(t, 2)
	e.add(changes.Source, "ads.txt", nameLines("ads", 50))
	e.add(changes.Lists, "lists.json", `{"lists": [{"name": "main", "sources": ["domains:ads.txt"]}]}`)
	j, r, p := e.runApply(nil)
	if j.State != jobs.Done || len(r.Rollouts) != 1 || r.Rollouts[0].Kind != "blocklist" || !slices.Equal(r.Rollouts[0].Done, e.addrs) {
		t.Fatalf("the only list %+v %+v %+v", j, r, p)
	}
	// A second list, on no node: compiled, sent to none; the first, changed, to the nodes
	// that run it.
	e.add(changes.Lists, "lists.json", `{"lists": [{"name": "main", "sources": ["domains:ads.txt"]}, {"name": "kids", "sources": ["domains:kids.txt"]}]}`)
	e.add(changes.Source, "kids.txt", nameLines("kids", 20))
	e.add(changes.Source, "ads.txt", nameLines("ads", 60))
	j, r, p = e.runApply(nil)
	if j.State != jobs.Done || len(r.Rollouts) != 1 || !slices.Equal(r.Rollouts[0].Done, e.addrs) ||
		!slices.ContainsFunc(r.Notes, func(n string) bool { return strings.Contains(n, "kids is on no node") }) {
		t.Fatalf("two lists %+v %+v %+v", j, r, p)
	}
	if _, err := os.Stat(filepath.Join(e.dir, "lists/kids.bin")); err != nil {
		t.Errorf("kids not compiled: %v", err)
	}
	// A list that reads a file no longer there: refused at the check.
	e.add(changes.Source, "kids.txt", "")
	j, _, _ = e.runApply(nil)
	if j.State != jobs.Failed || !strings.Contains(j.Error, "reads kids.txt") {
		t.Errorf("a missing source: %+v", j)
	}
}

// An apply that compiled a list, then stopped before any node took it (a node in a fault
// at the dry run): applying again still sends the list to the nodes that run the old one,
// though its compiled file is the new one already.
func TestApplyListAfterStopReachesItsNodes(t *testing.T) {
	e := newApplyEnv(t, 2)
	e.add(changes.Source, "ads.txt", nameLines("ads", 50))
	e.add(changes.Source, "kids.txt", nameLines("kids", 20))
	e.add(changes.Lists, "lists.json", `{"lists": [{"name": "main", "sources": ["domains:ads.txt"]}, {"name": "kids", "sources": ["domains:kids.txt"]}]}`)
	if j, r, p := e.runApply(nil); j.State != jobs.Done || len(r.Rollouts) != 0 {
		t.Fatalf("first %+v %+v %+v", j, r, p)
	}
	// main on both nodes, by the Push page.
	if j, _, p := e.dryThenPush(map[string]any{"kind": "blocklist", "nodes": e.addrs, "file": "main.bin"}); j.State != jobs.Done {
		t.Fatalf("push main %+v %+v", j, p)
	}
	e.add(changes.Source, "ads.txt", nameLines("ads", 55))
	e.nodes[1].Break(true)
	if j, r, _ := e.runApply(nil); j.State != jobs.Failed || !strings.Contains(j.Error, "the check before any push") || !r.Written {
		t.Fatalf("a node in a fault: %+v %+v", j, r)
	}
	e.nodes[1].Break(false)
	j, r, p := e.runApply(nil)
	if j.State != jobs.Done || len(r.Rollouts) != 1 || !slices.Equal(r.Rollouts[0].Done, e.addrs) {
		t.Fatalf("again: %+v %+v %+v", j, r, p)
	}
	// Done: what the nodes may still run is forgotten.
	if sums := e.store.ListSums("main"); len(sums) != 0 {
		t.Errorf("remembered %v", sums)
	}

	// The definitions changed, the same: written, compiled, stopped at the dry run. Applied
	// again, the lists file is already the new one, and main still goes to its nodes.
	e.add(changes.Lists, "lists.json", `{"lists": [{"name": "main", "sources": ["domains:ads.txt", "domains:kids.txt"]}, {"name": "kids", "sources": ["domains:kids.txt"]}]}`)
	e.nodes[0].Break(true)
	if j, r, _ := e.runApply(nil); j.State != jobs.Failed || !r.Written {
		t.Fatalf("a node in a fault: %+v %+v", j, r)
	}
	e.nodes[0].Break(false)
	j, r, p = e.runApply(nil)
	if j.State != jobs.Done || len(r.Rollouts) != 1 || r.Rollouts[0].Kind != "blocklist" || !slices.Equal(r.Rollouts[0].Done, e.addrs) {
		t.Fatalf("definitions again: %+v %+v %+v", j, r, p)
	}
}
