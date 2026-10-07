package main

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/fleet"
	"github.com/skitzo2000/espdns/controller/internal/jobs"
	"github.com/skitzo2000/espdns/controller/internal/settings"
)

// A list from the Push page: settings.json's canary first when none is chosen, every node
// soaked (the last one too), the plan said by the dry run; then a list whose canary fails
// CHECK_BLOCKED is sent back there, the rest untouched, the page saying what went back.
func TestPushListCanaryAndRevert(t *testing.T) {
	e := newRollEnv(t, 3)
	quickChecks(e)
	a, b, c := e.addrs[0], e.addrs[1], e.addrs[2]
	if err := settings.Save(settings.Path(e.dir), settings.Settings{Nodes: e.addrs, Canary: c}); err != nil {
		t.Fatal(err)
	}
	// The dry run: the plan for a list (canary, soak, revert), and the node that has no
	// list now named (nothing older to go back to there).
	e.nodes[1].NoList = true
	j, r, p := e.run(map[string]any{"kind": "blocklist", "nodes": e.addrs, "file": "list.bin",
		"check_blocked": []string{"doubleclick.net"}, "dry_run": true})
	if j.State != jobs.Done || !slices.Equal(r.Order, []string{c, a, b}) || p.Canary != c || !p.Revert {
		t.Fatalf("dry run %+v %+v %+v", j, r, p)
	}
	plan := strings.Join(p.Plan, "\n")
	for _, want := range []string{"canary " + c + " first", "the last node too", "every node that took this blocklist goes back"} {
		if !strings.Contains(plan, want) {
			t.Errorf("no %q in the plan %q", want, plan)
		}
	}
	if !strings.Contains(p.Nodes[b].Note, "it has no blocklist in use now") || p.Nodes[a].Note != "" {
		t.Errorf("notes %q / %q", p.Nodes[b].Note, p.Nodes[a].Note)
	}
	logs := ""
	for _, l := range j.Log {
		logs += l.Text + "\n"
	}
	if !strings.Contains(logs, "plan: canary "+c+" first") || !strings.Contains(logs, b+": would push blocklist now: it has no blocklist in use now") {
		t.Errorf("dry run log %q", logs)
	}

	// The push, the same: each node done, each soaked.
	j, r, p = e.dryThenPush(map[string]any{"kind": "blocklist", "nodes": e.addrs, "file": "list.bin",
		"check_blocked": []string{"doubleclick.net"}})
	if j.State != jobs.Done || !slices.Equal(r.Done, []string{c, a, b}) || len(r.Reverted) != 0 {
		t.Fatalf("push %+v %+v %+v", j, r, p)
	}

	// A name this list doesn't block: the canary goes back, the others are left alone.
	before := map[string]int{}
	for _, n := range e.nodes {
		before[n.Addr] = len(n.Events())
	}
	j, r, p = e.dryThenPush(map[string]any{"kind": "blocklist", "nodes": e.addrs, "file": "list.bin",
		"check_blocked": []string{"tracker.example"}})
	if j.State != jobs.Failed || !strings.Contains(j.Error, "tracker.example: not blocked") {
		t.Fatalf("job %+v", j)
	}
	if r.Failed != c || !slices.Equal(r.Reverted, []string{c}) || len(r.Done) != 0 || !slices.Equal(r.Left, []string{a, b}) {
		t.Errorf("result %+v", r)
	}
	if n := p.Nodes[c]; n.State != "reverted" || !strings.Contains(n.Revert, "back to seq") || !strings.Contains(n.Detail, "not blocked") {
		t.Errorf("canary %+v", n)
	}
	if p.Nodes[a].State != "left" || p.Nodes[b].State != "left" || !strings.Contains(p.Outcome, "reverted on "+c) {
		t.Errorf("progress %+v %+v %q", p.Nodes[a], p.Nodes[b], p.Outcome)
	}
	for _, n := range e.nodes[:2] {
		if len(n.Events()) != before[n.Addr] {
			t.Errorf("%s touched: %v", n.Addr, n.Events())
		}
	}
	hints := strings.Join(p.Hints, "\n")
	if !strings.Contains(hints, "Sent back to the blocklist each had before: "+c) || !strings.Contains(hints, "Not touched: "+a+", "+b) {
		t.Errorf("hints %q", hints)
	}
}

// The second node fails after the canary passed: both go back, the third is untouched; a
// node whose revert is refused (it had no list) is named with the way on.
func TestPushListSecondFailsRevertRefused(t *testing.T) {
	e := newRollEnv(t, 3)
	quickChecks(e)
	a, b, c := e.addrs[0], e.addrs[1], e.addrs[2]
	// b blocks nothing of this list's but never had one: it fails the check, and its
	// revert is refused (nothing older); the canary a goes back.
	e.nodes[1].NoList = true
	e.nodes[1].Blocked = nil
	j, r, p := e.dryThenPush(map[string]any{"kind": "blocklist", "nodes": e.addrs, "canary": a, "file": "list.bin",
		"check_blocked": []string{"doubleclick.net"}})
	if j.State != jobs.Failed {
		t.Fatalf("job %+v", j)
	}
	if r.Failed != b || !slices.Equal(r.Reverted, []string{a}) || len(r.NotReverted) != 1 || r.NotReverted[0].Host != b ||
		!slices.Equal(r.Left, []string{c}) {
		t.Errorf("result %+v", r)
	}
	if p.Nodes[a].State != "reverted" || p.Nodes[b].State != "failed" || !strings.HasPrefix(p.Nodes[b].Revert, "not reverted: ") ||
		p.Nodes[c].State != "left" {
		t.Errorf("progress %+v %+v %+v", p.Nodes[a], p.Nodes[b], p.Nodes[c])
	}
	hints := strings.Join(p.Hints, "\n")
	if !strings.Contains(hints, b+" keeps the new blocklist, not reverted") || !strings.Contains(hints, "espdns pause -host "+b) ||
		!strings.Contains(p.Outcome, "NOT reverted on "+b) {
		t.Errorf("hints %q, outcome %q", hints, p.Outcome)
	}
	if len(e.nodes[2].Events()) != 0 {
		t.Errorf("third touched: %v", e.nodes[2].Events())
	}
}

// quickChecks shortens the wait for a node to pass its checks: a list that fails them here
// fails at once, not after the default wait.
func quickChecks(e *rollEnv) {
	e.push.adjust = func(p *fleet.Plan) {
		p.Soak, p.ConfirmWait = e.soak, 300*time.Millisecond
	}
}
