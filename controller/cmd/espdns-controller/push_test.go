package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/actionlog"
	"github.com/skitzo2000/espdns/controller/internal/blocklist"
	"github.com/skitzo2000/espdns/controller/internal/configs"
	"github.com/skitzo2000/espdns/controller/internal/fakenode"
	"github.com/skitzo2000/espdns/controller/internal/fleet"
	"github.com/skitzo2000/espdns/controller/internal/jobs"
	"github.com/skitzo2000/espdns/controller/internal/memplan"
	"github.com/skitzo2000/espdns/controller/internal/nodecfg"
	"github.com/skitzo2000/espdns/controller/internal/pins"
	"github.com/skitzo2000/espdns/controller/internal/release"
	"github.com/skitzo2000/espdns/controller/internal/settings"
	"github.com/skitzo2000/espdns/controller/internal/zonefiles"
)

// rollEnv is a data directory with what a rolling push takes, fake nodes in settings.json,
// and the job runner with the rollout kind, as the controller has them.
type rollEnv struct {
	t      *testing.T
	dir    string
	key    *ecdsa.PrivateKey
	nodes  []*fakenode.Node
	addrs  []string
	runner *jobs.Runner
	push   *pushKind
	soak   time.Duration // the plan's soak after it is built (adjust); <0: as built
	// kinds are the runner's job kinds: a test adds its own before it starts a job.
	kinds   map[string]jobs.Kind
	catalog string
}

func writeFile(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// listFile is a blocklist file that blocks names.
func listFile(t *testing.T, names ...string) []byte {
	var es []blocklist.Entry
	for _, n := range names {
		es = append(es, blocklist.Entry{Name: n})
	}
	for i := range 2000 {
		es = append(es, blocklist.Entry{Name: fmt.Sprintf("ads%d.example.net", i)})
	}
	b, _, err := blocklist.Build(blocklist.Compile(es), blocklist.BuildOptions{Bits: 44, XorBits: 8, Keys: 1})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

const zoneText = `$ORIGIN home.example.
$TTL 300
@ IN SOA ns.home.example. admin.home.example. 2026100301 3600 600 86400 300
@ IN NS ns.home.example.
ns IN A 192.0.2.10
nas IN A 192.0.2.20
`

func newRollEnv(t *testing.T, n int) *rollEnv {
	e := &rollEnv{t: t, dir: t.TempDir(), key: newTestKey(t), soak: 20 * time.Millisecond}
	catalog := t.TempDir()
	e.catalog = catalog
	writeFile(t, filepath.Join(catalog, "p4-ip101.json"), []byte(`{"name": "p4-ip101", "image": "esp32p4-rev1"}`))
	fl := fakenode.Fleet{}
	for i := range n {
		fn := fakenode.New(fmt.Sprintf("fake-%c", 'a'+i), [6]byte{0x02, 0, 0, 0, 0, byte(0x11 + i)}, "esp32p4-rev1", "p4-ip101",
			nil)
		fn.Pub = release.PublicRaw(e.key)
		fn.DownFor = 30 * time.Millisecond
		srv := httptest.NewServer(fn)
		t.Cleanup(srv.Close)
		fn.Addr = strings.TrimPrefix(srv.URL, "http://")
		fl[fn.Addr] = fn
		e.nodes = append(e.nodes, fn)
		e.addrs = append(e.addrs, fn.Addr)
		if _, err := pins.Open(e.dir).Pin(fn.ID(), fn.Addr); err != nil { // adopted
			t.Fatal(err)
		}
	}
	if err := settings.Save(settings.Path(e.dir), settings.Settings{Nodes: e.addrs}); err != nil {
		t.Fatal(err)
	}
	// What there is to push.
	writeFile(t, filepath.Join(e.dir, "firmware/images/esp32p4-rev1/image.json"), []byte(`{"image": "esp32p4-rev1", "chip": "esp32p4"}`))
	writeFile(t, filepath.Join(e.dir, "firmware/images/esp32p4-rev1/app.bin"), fakenode.App("2", "0000000000000002"))
	writeFile(t, filepath.Join(e.dir, "firmware/builds/p4-ip101/dns2.bin"), fakenode.App("3", "0000000000000003"))
	writeFile(t, filepath.Join(e.dir, "lists/list.bin"), listFile(t, "doubleclick.net"))
	writeFile(t, filepath.Join(e.dir, "lists/must-resolve.txt"), []byte("example.org\nwikipedia.org\n"))
	writeFile(t, filepath.Join(e.dir, "zones/home.example.zone"), []byte(zoneText))
	for i := range n {
		writeFile(t, filepath.Join(configs.Path(e.dir), fmt.Sprintf("fake-%c.json", 'a'+i)),
			[]byte(fmt.Sprintf(`{"name": "fake-%c", "forwarders": ["9.9.9.9"]}`, 'a'+i)))
	}
	act := actions{dataDir: e.dir, key: keyOf{e.key}, known: func() []string { return e.addrs },
		client: func() *fleet.Client { return &fleet.Client{DNS: fl, PeerDNS: fl, Poll: 5 * time.Millisecond} }}
	e.push = &pushKind{actions: act, catalog: catalog, secret: newSecret(), used: &usedRuns{},
		job: func(id string) (jobs.Job, bool) { return e.runner.Get(id) },
		adjust: func(p *fleet.Plan) {
			if e.soak >= 0 {
				p.Soak = e.soak
			}
		}}
	e.kinds = map[string]jobs.Kind{"rollout": func(raw json.RawMessage) (jobs.Func, error) { return e.push.kind(raw) }}
	e.runner = jobs.New(e.dir, e.kinds)
	e.runner.Logf = t.Logf
	runJobs(t, e.runner)
	return e
}

// runJobs runs r until the test ends, and at its end stops it and waits for it to return
// before the test's earlier cleanups (its fake nodes, its temporary directory): a job still
// running as a test ends would otherwise log after the test (a panic) and write its record
// and the action log into a directory being removed.
func runJobs(t *testing.T, r *jobs.Runner) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
}

// start queues a rollout job.
func (e *rollEnv) start(params map[string]any) (jobs.Job, error) {
	b, _ := json.Marshal(params)
	return e.runner.Start("rollout", "admin", b)
}

// wait waits for the job to end (or until cond holds for its progress, if given).
func (e *rollEnv) wait(j jobs.Job, cond func(pushProgress) bool) jobs.Job {
	e.t.Helper()
	for range 4000 {
		j, _ = e.runner.Get(j.ID)
		if cond != nil {
			var p pushProgress
			if json.Unmarshal(j.Progress, &p) == nil && p.Nodes != nil && cond(p) {
				return j
			}
		}
		if j.State.Ended() {
			return j
		}
		time.Sleep(5 * time.Millisecond)
	}
	e.t.Fatalf("job %s didn't end: %+v", j.ID, j)
	return j
}

// run runs a job to its end; the refusal to queue it is a test failure.
func (e *rollEnv) run(params map[string]any) (jobs.Job, rolloutResult, pushProgress) {
	e.t.Helper()
	j, err := e.start(params)
	if err != nil {
		e.t.Fatalf("refused: %v", err)
	}
	j = e.wait(j, nil)
	var r rolloutResult
	var p pushProgress
	json.Unmarshal(j.Result, &r)
	json.Unmarshal(j.Progress, &p)
	return j, r, p
}

// dryThenPush runs the dry run, then the push after it.
func (e *rollEnv) dryThenPush(params map[string]any) (jobs.Job, rolloutResult, pushProgress) {
	e.t.Helper()
	dry := map[string]any{"dry_run": true}
	for k, v := range params {
		dry[k] = v
	}
	before := map[string]int{}
	for _, n := range e.nodes {
		before[n.Name] = len(n.Events())
	}
	j, r, p := e.run(dry)
	if j.State != jobs.Done || !r.DryRun {
		e.t.Fatalf("dry run: %+v %+v", j, p)
	}
	for _, n := range e.nodes {
		if len(n.Events()) != before[n.Name] {
			e.t.Fatalf("the dry run touched %s: %v", n.Name, n.Events())
		}
	}
	params["after"] = j.ID
	return e.run(params)
}

func fakeStatus(n *fakenode.Node) map[string]any {
	var st map[string]any
	n.Do(func(*fakenode.Node) {})
	rec := httptest.NewRecorder()
	n.ServeHTTP(rec, httptest.NewRequest("GET", "http://"+n.Addr+"/status", nil)) // its address, as the controller sends it
	json.Unmarshal(rec.Body.Bytes(), &st)
	return st
}

func TestPushFirmware(t *testing.T) {
	e := newRollEnv(t, 3)
	// The third already runs the build: skipped.
	e.nodes[2].Do(func(n *fakenode.Node) { n.Elf, n.Version = "0000000000000002", "2" })
	a, b, c := e.addrs[0], e.addrs[1], e.addrs[2]
	j, r, p := e.dryThenPush(map[string]any{"kind": "firmware", "nodes": e.addrs, "canary": b,
		"firmware": []string{"images/esp32p4-rev1"}, "check_blocked": []string{"doubleclick.net"}, "must_resolve": "must-resolve.txt"})
	if j.State != jobs.Done || r.DryRun {
		t.Fatalf("push: %+v %+v", j, p)
	}
	if !slices.Equal(r.Order, []string{b, a, c}) || !slices.Equal(r.Done, []string{b, a}) || !slices.Equal(r.Skipped, []string{c}) {
		t.Errorf("result %+v", r)
	}
	for i, n := range e.nodes[:2] {
		if ev := n.Events(); !slices.Equal(ev, []string{"push firmware", "push control", "reboot", "up"}) {
			t.Errorf("%s: %v", e.addrs[i], ev)
		}
		if st := fakeStatus(n); st["elf_sha256"] != "0000000000000002" || st["slot"] != "ota_1" {
			t.Errorf("%s runs %v on %v", e.addrs[i], st["elf_sha256"], st["slot"])
		}
	}
	if ev := e.nodes[2].Events(); len(ev) != 0 {
		t.Errorf("the node already on it: %v", ev)
	}
	if p.Nodes[a].State != "done" || p.Nodes[b].State != "done" || p.Nodes[c].State != "skipped" ||
		!strings.Contains(p.Nodes[b].Checks, "doubleclick.net blocked") || !strings.Contains(p.Nodes[b].Checks, "2 must-resolve names") ||
		!strings.Contains(p.Nodes[a].Expect, "firmware espdns 2 (elf 0000000000000002") || !strings.Contains(p.Nodes[c].Expect, "already runs") {
		t.Errorf("progress %+v", p)
	}
	// Both jobs in the action log, by the user.
	es, _ := actionlog.Tail(e.dir, 0)
	if len(es) != 4 || es[2].Who != "admin" || es[2].Action != "job rollout" || es[3].Result != "ok" {
		t.Errorf("action log %+v", es)
	}
	// The board's build: its chip image from the catalog.
	e.nodes[0].Do(func(n *fakenode.Node) {})
	j, r, _ = e.dryThenPush(map[string]any{"kind": "firmware", "nodes": []string{a}, "firmware": []string{"builds/p4-ip101"}})
	if j.State != jobs.Done || fakeStatus(e.nodes[0])["elf_sha256"] != "0000000000000003" {
		t.Errorf("a board build: %+v %+v", j, r)
	}
}

// A node whose new build rolls back stops the rollout there: the node after it isn't
// touched, the page lists it, and a node left with a reboot pending is named with its
// recovery.
func TestPushFailureLeavesNodes(t *testing.T) {
	e := newRollEnv(t, 3)
	a, b, c := e.addrs[0], e.addrs[1], e.addrs[2]
	e.nodes[1].Rollback = true
	e.nodes[2].Do(func(n *fakenode.Node) {})
	j, r, p := e.dryThenPush(map[string]any{"kind": "firmware", "nodes": e.addrs, "firmware": []string{"images/esp32p4-rev1"}})
	if j.State != jobs.Failed || !strings.Contains(j.Error, "rolled back") {
		t.Fatalf("job %+v", j)
	}
	if !slices.Equal(r.Done, []string{a}) || r.Failed != b || !slices.Equal(r.Left, []string{c}) {
		t.Errorf("result %+v", r)
	}
	if p.Nodes[a].State != "done" || p.Nodes[b].State != "failed" || p.Nodes[c].State != "left" || !slices.Equal(p.Left, []string{c}) {
		t.Errorf("progress %+v", p.Nodes)
	}
	if len(e.nodes[2].Events()) != 0 {
		t.Errorf("the node after the failure was touched: %v", e.nodes[2].Events())
	}
	hints := strings.Join(p.Hints, "\n")
	if !strings.Contains(hints, "Not touched: "+c) || !strings.Contains(hints, "rolled back") {
		t.Errorf("hints %q", hints)
	}
}

// A node left waiting for a reboot (a run stopped between its push and its reboot) is
// named with the way back: the reboot-pending action.
func TestPushHintsPendingReboot(t *testing.T) {
	e := newRollEnv(t, 2)
	a, b := e.addrs[0], e.addrs[1]
	e.nodes[1].Rollback = true
	e.nodes[0].SetPending("firmware")
	j, _, p := e.dryThenPush(map[string]any{"kind": "firmware", "nodes": []string{b}, "firmware": []string{"images/esp32p4-rev1"}})
	if j.State != jobs.Failed || p.Nodes[b].State != "failed" {
		t.Fatalf("job %+v %+v", j, p)
	}
	hints := strings.Join(p.Hints, "\n")
	if !strings.Contains(hints, a+" is left with a reboot pending (firmware)") || !strings.Contains(hints, "espdns reboot -host "+a+" -if-pending") {
		t.Errorf("hints %q", hints)
	}
}

func TestPushConfigLive(t *testing.T) {
	e := newRollEnv(t, 2)
	a, b := e.addrs[0], e.addrs[1]
	j, r, p := e.dryThenPush(map[string]any{"kind": "config", "nodes": e.addrs, "configs": map[string]string{a: "fake-a.json", b: "fake-b.json"}})
	if j.State != jobs.Done || !slices.Equal(r.Done, e.addrs) {
		t.Fatalf("job %+v %+v %+v", j, r, p)
	}
	for i, n := range e.nodes {
		if ev := n.Events(); !slices.Equal(ev, []string{"push config"}) {
			t.Errorf("%s: %v (a live config: no reboot)", e.addrs[i], ev)
		}
		st := fakeStatus(n)
		pushed, err := configs.LoadPushed(e.dir, n.ID())
		if err != nil || pushed == nil || pushed.File != fmt.Sprintf("fake-%c.json", 'a'+i) || pushed.By != "controller" ||
			float64(pushed.Seq) != st["config"].(map[string]any)["seq"].(float64) {
			t.Errorf("%s: recorded %+v %v", e.addrs[i], pushed, err)
		}
	}
	if !strings.HasPrefix(p.Nodes[a].Expect, "fake-a.json: ") {
		t.Errorf("expect %q", p.Nodes[a].Expect)
	}
	// A config for each node, and none for another.
	if _, err := e.start(map[string]any{"kind": "config", "nodes": e.addrs, "configs": map[string]string{a: "fake-a.json"}, "dry_run": true}); err == nil ||
		!strings.Contains(err.Error(), "no config for "+b) {
		t.Errorf("a node without a config: %v", err)
	}
	if _, err := e.start(map[string]any{"kind": "config", "nodes": []string{a}, "configs": map[string]string{a: "fake-a.json", b: "fake-b.json"}, "dry_run": true}); err == nil {
		t.Error("a config for a node not changed: queued")
	}
}

func TestPushBlocklistRefusedNode(t *testing.T) {
	e := newRollEnv(t, 3)
	a, b, c := e.addrs[0], e.addrs[1], e.addrs[2]
	big := memplan.Board{PSRAMKB: 32768, BlocklistKB: 20480, BlocklistIndexKB: 160}
	tiny := memplan.Board{PSRAMKB: 8192, BlocklistKB: 1}
	e.nodes[0].Memory, e.nodes[1].Memory, e.nodes[2].Memory = &big, &big, &tiny
	// The node that can't hold it stops the rollout before any node is touched; the dry
	// run says so for that node, and where the list goes on the others.
	j, _, p := e.run(map[string]any{"kind": "blocklist", "nodes": e.addrs, "file": "list.bin",
		"check_blocked": []string{"doubleclick.net"}, "dry_run": true})
	if j.State != jobs.Failed || !strings.Contains(j.Error, c+": the list needs") {
		t.Fatalf("job %+v", j)
	}
	if p.Nodes[c].State != "refused" || !strings.Contains(p.Nodes[c].Refused, "would refuse it") ||
		!strings.Contains(p.Nodes[a].Expect, "RAM tier, live swap") || p.Nodes[a].State != "left" {
		t.Errorf("progress %+v %+v %+v", p.Nodes[a], p.Nodes[b], p.Nodes[c])
	}
	for _, n := range e.nodes {
		if len(n.Events()) != 0 {
			t.Fatalf("%s touched: %v", n.Name, n.Events())
		}
	}
	// Without it: pushed, each node blocking the name before the next.
	j, r, p := e.dryThenPush(map[string]any{"kind": "blocklist", "nodes": []string{a, b}, "file": "list.bin",
		"check_blocked": []string{"doubleclick.net"}})
	if j.State != jobs.Done || !slices.Equal(r.Done, []string{a, b}) {
		t.Fatalf("job %+v %+v", j, p)
	}
	for _, n := range e.nodes[:2] {
		if list := fakeStatus(n)["blocking"].(map[string]any)["list"].(map[string]any); list["seq"].(float64) < 1e9 {
			t.Errorf("%s: list %v", n.Name, list)
		}
	}
	// Overrides take the same files.
	j, _, _ = e.dryThenPush(map[string]any{"kind": "overrides", "nodes": []string{a}, "file": "list.bin"})
	if j.State != jobs.Done {
		t.Errorf("overrides: %+v", j)
	}
	// A list file that isn't one: refused before it is queued.
	writeFile(t, filepath.Join(e.dir, "lists/bad.bin"), []byte("not a list"))
	if _, err := e.start(map[string]any{"kind": "blocklist", "nodes": []string{a}, "file": "bad.bin", "dry_run": true}); err == nil {
		t.Error("a bad list: queued")
	} else if j, _ := e.start(map[string]any{"kind": "blocklist", "nodes": []string{a}, "file": "list.bin", "dry_run": true}); j.ID == "" {
		t.Error("the good one refused")
	} else if j = e.wait(j, nil); j.State != jobs.Done {
		t.Errorf("the good one's dry run: %+v", j)
	}
}

func TestPushZones(t *testing.T) {
	e := newRollEnv(t, 2)
	j, r, p := e.dryThenPush(map[string]any{"kind": "zones", "nodes": e.addrs, "zones": []string{"home.example.zone"}})
	if j.State != jobs.Done || !slices.Equal(r.Done, e.addrs) {
		t.Fatalf("job %+v %+v", j, p)
	}
	for _, n := range e.nodes {
		hosted := fakeStatus(n)["hosted"].(map[string]any)
		zs, _ := hosted["zones"].([]any)
		if len(zs) != 1 || zs[0].(map[string]any)["name"] != "home.example" {
			t.Errorf("%s hosts %v", n.Name, hosted)
		}
	}
	if !strings.Contains(p.Nodes[e.addrs[0]].Expect, "hosted zones") {
		t.Errorf("expect %q", p.Nodes[e.addrs[0]].Expect)
	}
	// Recorded as the set each node serves (the zone editor's "serves it"), at its hosted seq.
	f, err := zonefiles.Read(e.dir, "home.example.zone")
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range e.nodes {
		var st release.NodeStatus
		b, _ := json.Marshal(fakeStatus(n))
		json.Unmarshal(b, &st)
		rec, err := zonefiles.LoadPushed(e.dir, n.ID())
		if err != nil || rec == nil || rec.Seq != st.Hosted.Seq || rec.Files["home.example.zone"] != f.Hash || rec.By != "controller" {
			t.Errorf("%s: recorded %+v %v (hosted seq %d)", n.Name, rec, err, st.Hosted.Seq)
		}
		if s, ok := zonefiles.Serves(e.dir, f, n.Addr, st, zonefiles.MatchUnknown); !ok || s.State != "file" {
			t.Errorf("%s serves %+v", n.Name, s)
		}
		// And by the hash of the bundle it reports, with no record.
		if m := zonefiles.SetMatch([]zonefiles.File{f}, st); m != zonefiles.MatchFiles {
			t.Errorf("%s: set match %v", n.Name, m)
		}
	}
	// A node that has the zone as one of its secondary zones (its /status): it would refuse
	// the bundle, so its dry run (which a push needs) fails before any node is touched,
	// naming it.
	e.nodes[1].Do(func(n *fakenode.Node) { n.Secondary = []string{"Home.Example."} })
	before := len(e.nodes[0].Events())
	j, _, p = e.run(map[string]any{"kind": "zones", "nodes": e.addrs, "zones": []string{"home.example.zone"}, "dry_run": true})
	if j.State != jobs.Failed || !strings.Contains(p.Nodes[e.addrs[1]].Refused, "home.example is both a hosted zone and a secondary zone of "+e.addrs[1]) ||
		len(e.nodes[0].Events()) != before {
		t.Errorf("secondary zone: %+v %+v %v", j, p.Nodes[e.addrs[1]], e.nodes[0].Events())
	}
	e.nodes[1].Do(func(n *fakenode.Node) { n.Secondary = nil })
	// A node with hosted zones off: refused before any node is touched.
	e.nodes[1].Off = []string{"hosted"}
	j, _, p = e.run(map[string]any{"kind": "zones", "nodes": e.addrs, "zones": []string{"home.example.zone"}, "dry_run": true})
	if j.State != jobs.Failed || !strings.Contains(p.Nodes[e.addrs[1]].Refused, "hosted is off") {
		t.Errorf("hosted off: %+v %+v", j, p.Nodes[e.addrs[1]])
	}
}

// A zones push's dry run says what each node would stop serving (the zones it serves now
// that the set drops), and refuses a node where a zone would be both hosted and a forward
// zone as its /status reports them (a config file naming one is not read for it: the
// node's /status says what it runs).
func TestPushZonesForwardAndDrops(t *testing.T) {
	e := newRollEnv(t, 2)
	a, b := e.addrs[0], e.addrs[1]
	writeFile(t, filepath.Join(e.dir, "zones/other.example.zone"), []byte(strings.ReplaceAll(zoneText, "home.example", "other.example")))
	both := []string{"home.example.zone", "other.example.zone"}
	if j, _, p := e.dryThenPush(map[string]any{"kind": "zones", "nodes": e.addrs, "zones": both}); j.State != jobs.Done {
		t.Fatalf("both zones: %+v %+v", j, p)
	}
	// The set without other.example: each node would stop serving it.
	j, _, p := e.run(map[string]any{"kind": "zones", "nodes": e.addrs, "zones": []string{"home.example.zone"}, "dry_run": true})
	if j.State != jobs.Done {
		t.Fatalf("dry run: %+v %+v", j, p)
	}
	for _, h := range e.addrs {
		if !strings.Contains(p.Nodes[h].Note, "it stops serving other.example") {
			t.Errorf("%s: note %q", h, p.Nodes[h].Note)
		}
	}
	// The same set again: nothing dropped, nothing said.
	_, _, p = e.run(map[string]any{"kind": "zones", "nodes": e.addrs, "zones": both, "dry_run": true})
	if p.Nodes[a].Note != "" {
		t.Errorf("same set: note %q", p.Nodes[a].Note)
	}

	// A forward zone in the node's /status (forward_zones): refused before any node is touched.
	e.nodes[1].Do(func(n *fakenode.Node) {
		n.Forward = []nodecfg.ForwardZone{{Zone: "Other.Example.", Forwarder: "192.0.2.53"}}
	})
	before := len(e.nodes[0].Events())
	j, _, p = e.run(map[string]any{"kind": "zones", "nodes": e.addrs, "zones": both, "dry_run": true})
	if j.State != jobs.Failed || !strings.Contains(p.Nodes[b].Refused, "other.example is both a hosted zone and a forward zone of "+b+" (its /status)") ||
		len(e.nodes[0].Events()) != before {
		t.Errorf("forward zone in /status: %+v %+v", j, p.Nodes[b])
	}
	// Left out of the set, it passes, and says the node stops serving it.
	j, _, p = e.run(map[string]any{"kind": "zones", "nodes": e.addrs, "zones": []string{"home.example.zone"}, "dry_run": true})
	if j.State != jobs.Done || !strings.Contains(p.Nodes[b].Note, "it stops serving other.example") {
		t.Errorf("without the forward zone: %+v %+v", j, p.Nodes[b])
	}
	// No forward zone in its /status: a config file here (by its name) that has one is not
	// taken for what the node runs.
	e.nodes[1].Do(func(n *fakenode.Node) { n.Forward = nil })
	writeFile(t, filepath.Join(configs.Path(e.dir), "fake-b.json"),
		[]byte(`{"name": "fake-b", "forwarders": ["9.9.9.9"], "forward_zones": [{"zone": "other.example", "forwarder": "192.0.2.53"}]}`))
	if j, _, p = e.run(map[string]any{"kind": "zones", "nodes": e.addrs, "zones": both, "dry_run": true}); j.State != jobs.Done {
		t.Errorf("a config file's forward zone taken: %+v %+v", j, p.Nodes[b])
	}
}

// Stop: at the next safe point. Asked while the first node is checked, the rollout ends
// before the second starts; asked during a soak, at once, the soaking node done.
func TestPushStop(t *testing.T) {
	for _, during := range []string{"checking", "soaking"} {
		t.Run(during, func(t *testing.T) {
			e := newRollEnv(t, 3)
			a, b, c := e.addrs[0], e.addrs[1], e.addrs[2]
			if during == "checking" {
				e.soak = 0
				e.nodes[0].TrialFor = 300 * time.Millisecond // its checks wait out the trial
			} else {
				e.soak = -1 // the default minute: the stop ends it
			}
			params := map[string]any{"kind": "firmware", "nodes": e.addrs, "firmware": []string{"images/esp32p4-rev1"}, "dry_run": true}
			j, _, _ := e.run(params)
			delete(params, "dry_run")
			params["after"] = j.ID
			j, err := e.start(params)
			if err != nil {
				t.Fatal(err)
			}
			j = e.wait(j, func(p pushProgress) bool { return p.Nodes[a].State == during })
			if _, err := e.runner.Stop(j.ID); err != nil {
				t.Fatal(err)
			}
			t0 := time.Now()
			j = e.wait(j, nil)
			var r rolloutResult
			var p pushProgress
			json.Unmarshal(j.Result, &r)
			json.Unmarshal(j.Progress, &p)
			if j.State != jobs.Stopped || !slices.Equal(r.Done, []string{a}) || !slices.Equal(r.Left, []string{b, c}) {
				t.Errorf("job %+v result %+v", j, r)
			}
			if p.Outcome != "stopped on request" || p.Nodes[b].State != "left" || p.Nodes[c].State != "left" || p.Nodes[a].State != "done" {
				t.Errorf("progress %+v", p)
			}
			if len(e.nodes[1].Events()) != 0 || time.Since(t0) > 5*time.Second {
				t.Errorf("after the stop: %v, %v", e.nodes[1].Events(), time.Since(t0))
			}
		})
	}
}

// The push needs a dry run of the same push that passed in the last 15 minutes, with the
// same files.
func TestPushDryRunGate(t *testing.T) {
	e := newRollEnv(t, 2)
	a, b := e.addrs[0], e.addrs[1]
	fw := map[string]any{"kind": "firmware", "nodes": e.addrs, "firmware": []string{"images/esp32p4-rev1"}}
	with := func(extra map[string]any) map[string]any {
		out := map[string]any{}
		for k, v := range fw {
			out[k] = v
		}
		for k, v := range extra {
			out[k] = v
		}
		return out
	}
	refused := func(what string, params map[string]any, want string) {
		t.Helper()
		if _, err := e.start(params); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", what, err, want)
		}
	}
	refused("no dry run", fw, "needs a dry run first")
	refused("no such job", with(map[string]any{"after": "nope"}), "no rollout dry run")
	// A dry run that failed (a node unhealthy).
	e.nodes[1].Break(true)
	j, _, _ := e.run(with(map[string]any{"dry_run": true}))
	if j.State != jobs.Failed {
		t.Fatalf("dry run with a node down: %+v", j)
	}
	refused("a failed dry run", with(map[string]any{"after": j.ID}), "didn't pass")
	e.nodes[1].Break(false)
	dry, _, _ := e.run(with(map[string]any{"dry_run": true}))
	if dry.State != jobs.Done {
		t.Fatalf("dry run %+v", dry)
	}
	refused("other nodes", with(map[string]any{"after": dry.ID, "nodes": []string{a}}), "isn't the one the dry run")
	refused("another canary", with(map[string]any{"after": dry.ID, "canary": b}), "isn't the one the dry run")
	refused("a longer soak", with(map[string]any{"after": dry.ID, "soak_s": 120}), "isn't the one the dry run")
	refused("an added check", with(map[string]any{"after": dry.ID, "check_blocked": []string{"doubleclick.net"}}), "isn't the one the dry run")
	refused("after on a dry run", with(map[string]any{"after": dry.ID, "dry_run": true}), `"after" is for the push`)
	// The firmware changed since.
	app := filepath.Join(e.dir, "firmware/images/esp32p4-rev1/app.bin")
	orig, _ := os.ReadFile(app)
	writeFile(t, app, fakenode.App("2", "0000000000000009"))
	refused("the file changed", with(map[string]any{"after": dry.ID}), "isn't the one the dry run")
	writeFile(t, app, orig)
	// settings.json changed since (another DNS peer zone: the rule's input).
	sp := settings.Path(e.dir)
	sorig, _ := os.ReadFile(sp)
	if err := settings.Save(sp, settings.Settings{Nodes: e.addrs, DNSPeerZones: []string{"home.example"}}); err != nil {
		t.Fatal(err)
	}
	refused("the settings changed", with(map[string]any{"after": dry.ID}), "isn't the one the dry run")
	writeFile(t, sp, sorig)
	// A dry run from before the controller restarted (a new secret).
	secret := e.push.secret
	e.push.secret = newSecret()
	refused("a restart", with(map[string]any{"after": dry.ID}), "isn't the one the dry run")
	e.push.secret = secret
	// Old.
	job := e.push.job
	e.push.job = func(id string) (jobs.Job, bool) {
		j, ok := job(id)
		j.Ended = j.Ended.Add(-16 * time.Minute)
		return j, ok
	}
	refused("an old dry run", with(map[string]any{"after": dry.ID}), "over 15m0s old")
	e.push.job = job
	// No key: the dry run goes on without one, the push doesn't.
	e.push.key = keyOf{}
	refused("no key", with(map[string]any{"after": dry.ID}), "no release key")
	if j, _, _ := e.run(with(map[string]any{"dry_run": true})); j.State != jobs.Done {
		t.Errorf("a dry run without a key: %+v", j)
	}
	e.push.key = keyOf{e.key}
	if j, _, _ := e.run(with(map[string]any{"after": dry.ID})); j.State != jobs.Done {
		t.Errorf("the push after its dry run: %+v", j)
	}
	// One push per dry run.
	refused("a second push", with(map[string]any{"after": dry.ID}), "already followed by a push")
}

// The page's request is checked as strictly as the Makefile's variables: the nodes in
// settings.json only, the canary one of them, no soak below the default, one firmware per
// chip image, names inside the data directory, nothing a kind doesn't take.
func TestPushRefusals(t *testing.T) {
	e := newRollEnv(t, 2)
	a := e.addrs[0]
	for what, c := range map[string]struct {
		params map[string]any
		want   string
	}{
		"not in settings":  {map[string]any{"kind": "zones", "nodes": []string{"192.0.2.99"}, "zones": []string{"home.example.zone"}}, "not in settings.json"},
		"no nodes":         {map[string]any{"kind": "zones", "zones": []string{"home.example.zone"}}, "choose the nodes"},
		"twice":            {map[string]any{"kind": "zones", "nodes": []string{a, a}, "zones": []string{"home.example.zone"}}, "twice"},
		"canary":           {map[string]any{"kind": "zones", "nodes": []string{a}, "canary": e.addrs[1], "zones": []string{"home.example.zone"}}, "never adds a node"},
		"short soak":       {map[string]any{"kind": "zones", "nodes": []string{a}, "soak_s": 10, "zones": []string{"home.example.zone"}}, "soak"},
		"long soak":        {map[string]any{"kind": "zones", "nodes": []string{a}, "soak_s": 3601, "zones": []string{"home.example.zone"}}, "soak"},
		"overflowing soak": {map[string]any{"kind": "zones", "nodes": []string{a}, "soak_s": 9223372037, "zones": []string{"home.example.zone"}}, "soak"},
		"control":          {map[string]any{"kind": "control", "nodes": []string{a}}, `"kind"`},
		"unknown field":    {map[string]any{"kind": "firmware", "nodes": []string{a}, "force": true}, "unknown field"},
		"two images":       {map[string]any{"kind": "firmware", "nodes": []string{a}, "firmware": []string{"images/esp32p4-rev1", "builds/p4-ip101"}}, "both chip image"},
		"image path":       {map[string]any{"kind": "firmware", "nodes": []string{a}, "firmware": []string{"images/../../etc"}}, "a board or chip image"},
		"list path":        {map[string]any{"kind": "blocklist", "nodes": []string{a}, "file": "../auth.json"}, "a list file"},
		"zone path":        {map[string]any{"kind": "zones", "nodes": []string{a}, "zones": []string{"/etc/passwd"}}, "a zone file"},
		"config path":      {map[string]any{"kind": "config", "nodes": []string{a}, "configs": map[string]string{a: "../settings.json"}}, "a config"},
		"must path":        {map[string]any{"kind": "zones", "nodes": []string{a}, "zones": []string{"home.example.zone"}, "must_resolve": "hagezi.txt"}, "must-resolve"},
		"blocked name":     {map[string]any{"kind": "zones", "nodes": []string{a}, "zones": []string{"home.example.zone"}, "check_blocked": []string{"not a name"}}, "check_blocked"},
		"wrong kind":       {map[string]any{"kind": "zones", "nodes": []string{a}, "zones": []string{"home.example.zone"}, "file": "list.bin"}, `"file" is not for a zones push`},
		"no firmware":      {map[string]any{"kind": "firmware", "nodes": []string{a}}, "choose the firmware"},
		"missing file":     {map[string]any{"kind": "blocklist", "nodes": []string{a}, "file": "nope.bin", "dry_run": true}, "no such file"},
	} {
		c.params["dry_run"] = true
		_, err := e.start(c.params)
		if err == nil {
			// Checked when it runs (the files are read then): the job fails.
			j, _, _ := e.run(c.params)
			if j.State != jobs.Failed || !strings.Contains(j.Error, c.want) {
				t.Errorf("%s: %+v, want %q", what, j, c.want)
			}
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", what, err, c.want)
		}
	}
}
