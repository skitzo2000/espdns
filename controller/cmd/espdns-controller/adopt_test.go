package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/actionlog"
	"github.com/skitzo2000/espdns/controller/internal/configs"
	"github.com/skitzo2000/espdns/controller/internal/fakenode"
	"github.com/skitzo2000/espdns/controller/internal/faketech"
	"github.com/skitzo2000/espdns/controller/internal/fleet"
	"github.com/skitzo2000/espdns/controller/internal/jobs"
	"github.com/skitzo2000/espdns/controller/internal/keys"
	"github.com/skitzo2000/espdns/controller/internal/nodes"
	"github.com/skitzo2000/espdns/controller/internal/primary"
	"github.com/skitzo2000/espdns/controller/internal/release"
	"github.com/skitzo2000/espdns/controller/internal/settings"
)

const techToken = "0123456789abcdef-test-token"

// adoptEnv is the controller's adoption on a fake network: a node in service in
// settings.json (203.0.113.51), one to adopt (203.0.113.52), a fake Technitium in settings.json
// with its token imported, the job runner with the adoption's kinds.
type adoptEnv struct {
	t      *testing.T
	dir    string
	lan    *fakenode.Lan
	peer   *fakenode.Node
	node   *fakenode.Node
	tech   *faketech.Server
	key    *ecdsa.PrivateKey
	runner *jobs.Runner
	adopt  *adoptKind
	seen   []string // the addresses the "registry" polls
}

func newAdoptEnv(t *testing.T) *adoptEnv {
	e := &adoptEnv{t: t, dir: t.TempDir(), lan: fakenode.NewLan(), key: newTestKey(t),
		seen: []string{"203.0.113.51", "203.0.113.52", "203.0.113.60"}}
	t.Cleanup(e.lan.Close)
	for i, name := range []string{"dns1", "new"} {
		n := fakenode.New(name, [6]byte{2, 0, 0, 0, 0, byte(0x51 + i)}, "esp32p4-rev1", "p4-ip101", release.PublicRaw(e.key))
		n.Addr, n.Gateway, n.Unadopted, n.DownFor = []string{"203.0.113.51", "203.0.113.52"}[i], "203.0.113.1", i == 1, 20*time.Millisecond
		n.Secondary = []string{"home.example"} // its board's settings: the zone from Technitium
		e.lan.Add(n)
		if i == 0 {
			e.peer = n
		} else {
			e.node = n
		}
	}
	e.tech = faketech.New(techToken, "home.example", "lab.example")
	ts := httptest.NewTLSServer(e.tech) // its own certificate, pinned below
	t.Cleanup(ts.Close)
	if err := settings.Save(settings.Path(e.dir), settings.Settings{Nodes: []string{"203.0.113.51"},
		Primary: &primary.Config{Kind: primary.KindTechnitium, URL: ts.URL,
			CertSHA256: primary.Fingerprint(ts.Certificate())}}); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(configs.Path(e.dir), "n2.json"), []byte(`{"name": "dns2", "forwarders": ["9.9.9.9"], `+
		`"secondary": {"primary": "203.0.113.254", "zones": ["home.example", "lab.example"]}}`))
	writeFile(t, filepath.Join(configs.Path(e.dir), "n1.json"), []byte(`{"name": "dns1", "secondary": {"zones": ["home.example"]}}`))
	if _, err := keys.ImportToken(keys.TokenPath(e.dir), techToken, false); err != nil {
		t.Fatal(err)
	}
	hc := e.lan.HTTP()
	act := actions{dataDir: e.dir, key: keyOf{e.key}, known: func() []string { return e.seen },
		client: func() *fleet.Client {
			return &fleet.Client{HTTP: hc, DNS: e.lan, PeerDNS: e.lan, Poll: 10 * time.Millisecond}
		}}
	e.adopt = &adoptKind{actions: act, secret: newSecret(), used: &usedRuns{}, nodes: e.found,
		token: keys.DataTokenSource{DataDir: e.dir},
		job:   func(id string) (jobs.Job, bool) { return e.runner.Get(id) },
		adjust: func(a *fleet.Adopt) {
			a.ConfirmWait = 5 * time.Second
		}}
	e.runner = jobs.New(e.dir, map[string]jobs.Kind{
		"adopt":        func(raw json.RawMessage) (jobs.Func, error) { return e.adopt.kind(raw) },
		"primary":      func(raw json.RawMessage) (jobs.Func, error) { return e.adopt.primaryKind(raw) },
		"settings-add": func(raw json.RawMessage) (jobs.Func, error) { return e.adopt.settingsAdd(raw) }})
	e.runner.Logf = t.Logf
	runJobs(t, e.runner)
	return e
}

// found is what the node registry would have: each address polled, its /status.
func (e *adoptEnv) found() []nodes.Node {
	c := &fleet.Client{HTTP: e.lan.HTTP()}
	var out []nodes.Node
	for _, a := range e.seen {
		st, err := c.Status(context.Background(), a)
		if err != nil {
			continue
		}
		b, _ := json.Marshal(st)
		var m map[string]any
		json.Unmarshal(b, &m)
		out = append(out, nodes.Node{ID: st.NodeID, Addr: a, Source: "mdns", Online: true, Status: m})
	}
	return out
}

func (e *adoptEnv) start(kind string, params map[string]any) (jobs.Job, error) {
	b, _ := json.Marshal(params)
	return e.runner.Start(kind, "admin", b)
}

func (e *adoptEnv) wait(j jobs.Job) jobs.Job {
	e.t.Helper()
	for range 2000 {
		j, _ = e.runner.Get(j.ID)
		if j.State.Ended() {
			return j
		}
		time.Sleep(5 * time.Millisecond)
	}
	e.t.Fatal("job didn't end")
	return j
}

func (e *adoptEnv) run(kind string, params map[string]any) jobs.Job {
	e.t.Helper()
	j, err := e.start(kind, params)
	if err != nil {
		e.t.Fatal(err)
	}
	return e.wait(j)
}

func (e *adoptEnv) web(extra map[string]any) map[string]any {
	p := map[string]any{"node": "203.0.113.52", "node_id": e.node.ID(), "config": "n2.json"}
	for k, v := range extra {
		p[k] = v
	}
	return p
}

func progressOf(t *testing.T, j jobs.Job) adoptProgress {
	var p adoptProgress
	if err := json.Unmarshal(j.Progress, &p); err != nil {
		t.Fatal(err, string(j.Progress))
	}
	return p
}

// The Adopt page's flow: a dry run (Technitium read, what it would change shown per zone,
// nothing changed), then the adoption after it: each step followed, the zones' lists
// changed, the node moved and confirmed, the config it runs recorded by the controller,
// its address added to settings.json as asked. The token is nowhere in the job's record,
// its log or the action log.
func TestAdoptPage(t *testing.T) {
	e := newAdoptEnv(t)
	addr := map[string]any{"address": "203.0.113.60/24"}
	// No adoption without a dry run first.
	if _, err := e.start("adopt", e.web(addr)); err == nil || !strings.Contains(err.Error(), "dry run first") {
		t.Fatal(err)
	}
	dry := e.run("adopt", e.web(map[string]any{"address": "203.0.113.60/24", "dry_run": true}))
	if dry.State != jobs.Done {
		t.Fatal(dry.State, dry.Error, dry.Log)
	}
	p := progressOf(t, dry)
	if !p.DryRun || p.Address != "203.0.113.60" || len(p.Primary.Edits) != 2 || p.Primary.Edits[0].Applied ||
		!strings.Contains(strings.Join(p.Primary.Edits[0].Changes, "; "), "zone transfer name servers 203.0.113.60") {
		t.Fatalf("%+v", p)
	}
	for _, s := range p.Steps {
		if s.State != map[bool]string{true: "skipped", false: "done"}[s.N > 5] {
			t.Errorf("dry run step %d: %s", s.N, s.State)
		}
	}
	if len(e.tech.Sets()) != 0 || slices.Contains(e.node.Events(), "push config") {
		t.Fatal("the dry run changed something")
	}
	// The dry run is of this request only.
	if _, err := e.start("adopt", e.web(map[string]any{"address": "203.0.113.61/24", "after": dry.ID})); err == nil ||
		!strings.Contains(err.Error(), "isn't the one the dry run") {
		t.Fatal(err)
	}
	j := e.run("adopt", e.web(map[string]any{"address": "203.0.113.60/24", "after": dry.ID, "add_to_settings": true}))
	if j.State != jobs.Done {
		t.Fatal(j.State, j.Error, j.Log)
	}
	p = progressOf(t, j)
	for _, s := range p.Steps {
		if s.State != "done" {
			t.Errorf("step %d: %s %s", s.N, s.State, s.Detail)
		}
	}
	if !strings.HasPrefix(p.Outcome, "adopted: node "+e.node.ID()+" on 203.0.113.60") || len(p.Primary.Edits) != 2 ||
		!p.Primary.Edits[1].Applied {
		t.Fatalf("%+v", p)
	}
	var res adoptResult
	json.Unmarshal(j.Result, &res)
	if res.Address != "203.0.113.60" || !res.Recorded || !res.AddedToSettings {
		t.Fatalf("%+v", res)
	}
	pr, _ := configs.LoadPushed(e.dir, e.node.ID())
	if pr == nil || pr.By != "controller" || pr.File != "n2.json" || pr.Seq != res.Seq {
		t.Fatalf("%+v", pr)
	}
	s, _ := settings.Load(settings.Path(e.dir))
	if !slices.Equal(s.Nodes, []string{"203.0.113.51", "203.0.113.60"}) {
		t.Fatal(s.Nodes)
	}
	// One adoption per dry run.
	if _, err := e.start("adopt", e.web(map[string]any{"address": "203.0.113.60/24", "after": dry.ID})); err == nil {
		t.Fatal("a dry run followed twice")
	}
	// The token: never in a record or a log.
	for _, jj := range e.runner.List() {
		full, _ := e.runner.Get(jj.ID)
		b, _ := json.Marshal(full)
		if strings.Contains(string(b), techToken) {
			t.Fatalf("job %s holds the token", jj.ID)
		}
	}
	recs, _ := os.ReadDir(filepath.Join(e.dir, actionlog.Dir, jobs.JobsDir))
	for _, r := range recs {
		b, _ := os.ReadFile(filepath.Join(e.dir, actionlog.Dir, jobs.JobsDir, r.Name()))
		if strings.Contains(string(b), techToken) {
			t.Fatal(r.Name(), "holds the token")
		}
	}
	al, _ := actionlog.Tail(e.dir, 100)
	b, _ := json.Marshal(al)
	if strings.Contains(string(b), techToken) || !strings.Contains(string(b), "job adopt") {
		t.Fatal("action log:", string(b))
	}
}

// A config with a Wi-Fi password: the dry run shows the payload it would push with the
// password hidden; the job's record never holds it.
func TestAdoptHidesWifiPassword(t *testing.T) {
	e := newAdoptEnv(t)
	const pw = "wifi-secret-pass-123"
	writeFile(t, filepath.Join(configs.Path(e.dir), "w.json"), []byte(`{"name": "dns2", "wifi": {"ssid": "home", "password": "`+pw+`"}}`))
	j := e.run("adopt", e.web(map[string]any{"config": "w.json", "dry_run": true}))
	b, _ := json.Marshal(j)
	if j.State != jobs.Done || strings.Contains(string(b), pw) || !strings.Contains(string(b), configs.Hidden) {
		t.Fatal(j.State, j.Error, string(b))
	}
}

// Who the page may adopt: a node found, not adopted, under the ID the page showed, and an
// ID no other node known has; a config that fails its checks for the node fails the dry
// run at step 3 with nothing changed.
func TestAdoptPageRefuses(t *testing.T) {
	e := newAdoptEnv(t)
	for _, tc := range []struct {
		params map[string]any
		want   string
	}{
		{map[string]any{"node": "203.0.113.51", "node_id": e.peer.ID(), "config": "n2.json", "dry_run": true}, "adopted already"},
		{map[string]any{"node": "203.0.113.70", "node_id": e.node.ID(), "config": "n2.json", "dry_run": true}, "not a node the controller has found"},
		{e.web(map[string]any{"node_id": "02:00:00:00:00:99", "dry_run": true}), "is node " + e.node.ID() + " now"},
		{e.web(map[string]any{"config": "fleet.json", "dry_run": true}), "settings"},
		{e.web(map[string]any{"address": "dhcp", "gateway": "203.0.113.1", "dry_run": true}), "only with a static address"},
		{e.web(map[string]any{"dry_run": true, "add_to_settings": true}), "for the adoption after a dry run"},
		{e.web(map[string]any{"dry_run": true, "force": true}), "unknown field"},
	} {
		if _, err := e.start("adopt", tc.params); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v: %v, want %q", tc.params, err, tc.want)
		}
	}
	// A node answering with the ID of another node the controller knows.
	e.node.Do(func(n *fakenode.Node) { n.MAC = e.peer.MAC })
	if _, err := e.start("adopt", e.web(map[string]any{"node_id": e.peer.ID(), "dry_run": true})); err == nil ||
		!strings.Contains(err.Error(), "which the controller knows at 203.0.113.51") {
		t.Fatal(err)
	}
	e.node.Do(func(n *fakenode.Node) { n.MAC = [6]byte{2, 0, 0, 0, 0, 0x52} })
	// The config's checks for the node, at step 3 of the dry run.
	writeFile(t, filepath.Join(configs.Path(e.dir), "cpu.json"), []byte(`{"name": "dns2", "cpu": {"dfs": true}}`))
	j := e.run("adopt", e.web(map[string]any{"config": "cpu.json", "dry_run": true}))
	p := progressOf(t, j)
	if j.State != jobs.Failed || p.Steps[1].State != "failed" || !strings.Contains(p.Steps[1].Detail, `sets "cpu"`) {
		t.Fatalf("%s %+v", j.State, p.Steps)
	}
	// An address something else answers on: the dry run says so at step 3.
	e.lan.Other("203.0.113.99", http.NotFoundHandler())
	j = e.run("adopt", e.web(map[string]any{"address": "203.0.113.99/24", "dry_run": true}))
	if p := progressOf(t, j); j.State != jobs.Failed || p.Steps[1].State != "failed" || !strings.Contains(j.Error, "in use") {
		t.Fatalf("%s %s %+v", j.State, j.Error, p.Steps)
	}
	if slices.Contains(e.node.Events(), "push config") || len(e.tech.Sets()) != 0 {
		t.Fatal("changed:", e.node.Events())
	}
}

// A node that took a config before and runs its board's settings now (in service, its
// config refused) looks unadopted: it is listed, but not adopted from the page.
func TestAdoptPageRefusesFellBack(t *testing.T) {
	e := newAdoptEnv(t)
	n := fakenode.New("fell", [6]byte{2, 0, 0, 0, 0, 0x60}, "esp32p4-rev1", "p4-ip101", release.PublicRaw(e.key))
	n.Addr, n.Gateway, n.Unadopted, n.FellBack = "203.0.113.60", "203.0.113.1", true, true
	e.lan.Add(n)
	w := httptest.NewRecorder()
	e.adopt.list(w, httptest.NewRequest("GET", "/api/adopt", nil))
	var out struct{ Nodes []adoptNode }
	json.Unmarshal(w.Body.Bytes(), &out)
	i := slices.IndexFunc(out.Nodes, func(a adoptNode) bool { return a.Host == "203.0.113.60" })
	if i < 0 || out.Nodes[i].Adopted || len(out.Nodes[i].Refusals) != 1 ||
		!strings.Contains(out.Nodes[i].Refusals[0], "took a node config before (config seq 5)") {
		t.Fatalf("%+v", out.Nodes)
	}
	if _, err := e.start("adopt", map[string]any{"node": "203.0.113.60", "node_id": n.ID(), "config": "n2.json", "dry_run": true}); err == nil ||
		!strings.Contains(err.Error(), "config seq 5") {
		t.Fatal(err)
	}
	// An ID a config was pushed to before, answering as not adopted: wiped, or claimed.
	if err := configs.RecordPushed(e.dir, configs.Pushed{NodeID: e.node.ID(), Host: "203.0.113.70", File: "n2.json", Seq: 9}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.start("adopt", e.web(map[string]any{"dry_run": true})); err == nil || !strings.Contains(err.Error(), "was given n2.json at 203.0.113.70") {
		t.Fatal(err)
	}
	os.Remove(filepath.Join(configs.Path(e.dir), configs.PushedDir, strings.ReplaceAll(e.node.ID(), ":", "")+".json"))
	// The registry's read is old (the node in service, 203.0.113.51, read as not adopted): step
	// 3 refuses on the node as it reads it now, before anything changes.
	stale := e.found()
	for _, f := range stale {
		if f.Addr == "203.0.113.51" {
			c := f.Status["config"].(map[string]any)
			c["source"], c["seq"] = "defaults", 0
			f.Status["seq"].(map[string]any)["config"] = 0
		}
	}
	e.adopt.nodes = func() []nodes.Node { return stale }
	j := e.run("adopt", map[string]any{"node": "203.0.113.51", "node_id": e.peer.ID(), "config": "n2.json", "dry_run": true})
	if p := progressOf(t, j); j.State != jobs.Failed || p.Steps[1].State != "failed" || !strings.Contains(j.Error, "adopted already") {
		t.Fatalf("%s %s %+v", j.State, j.Error, p.Steps)
	}
	if len(e.tech.Calls()) != 0 || slices.Contains(e.peer.Events(), "push config") {
		t.Fatal("changed:", e.tech.Calls(), e.peer.Events())
	}
}

// Without a token: the dry run names the changes per zone to make by hand; the adoption is
// refused until the page says they are done, then goes ahead without calling Technitium.
func TestAdoptPageManual(t *testing.T) {
	e := newAdoptEnv(t)
	os.Remove(keys.TokenPath(e.dir))
	dry := e.run("adopt", e.web(map[string]any{"dry_run": true}))
	p := progressOf(t, dry)
	if dry.State != jobs.Done || len(p.Primary.Manual) != 2 || p.Primary.API != "" ||
		!strings.Contains(p.Primary.Manual[1], "zone lab.example, Zone Options: add 203.0.113.52 to Zone Transfer") ||
		!strings.Contains(p.Primary.Why, "no zone primary API token") {
		t.Fatalf("%s %+v", dry.State, p.Primary)
	}
	if _, err := e.start("adopt", e.web(map[string]any{"after": dry.ID})); err == nil ||
		!strings.Contains(err.Error(), "make them, then say they are done") {
		t.Fatal(err)
	}
	j := e.run("adopt", e.web(map[string]any{"after": dry.ID, "primary_done": true}))
	if j.State != jobs.Done || len(e.tech.Calls()) != 0 || !progressOf(t, j).Primary.Done {
		t.Fatal(j.State, j.Error, e.tech.Calls())
	}
}

// The Technitium view: each secondary zone of the configs, its lists, and whether each node
// in settings.json carrying it is in them; a missing one allowed as a job (the adoption's
// edit), an entry that is no node in settings.json removed only when asked, never a node
// in settings.json; no token in the reply.
func TestTechnitiumLists(t *testing.T) {
	e := newAdoptEnv(t)
	e.tech.SetZone("home.example", faketech.Zone{Transfer: "AllowOnlySpecifiedNameServers", TransferList: []string{"203.0.113.40"},
		Notify: "SpecifiedNameServers", NotifyList: []string{"203.0.113.40"}})
	get := func() map[string]any {
		w := httptest.NewRecorder()
		e.adopt.lists(w, httptest.NewRequest("GET", "/api/primary", nil))
		if strings.Contains(w.Body.String(), techToken) {
			t.Fatal("the token in the reply")
		}
		var out map[string]any
		json.Unmarshal(w.Body.Bytes(), &out)
		return out
	}
	out := get()
	zs, _ := out["zones"].([]any)
	if len(zs) != 2 || out["error"] != nil {
		t.Fatalf("%v", out)
	}
	home := zs[0].(map[string]any)
	ns := home["nodes"].([]any)
	if home["zone"] != "home.example" || len(ns) != 1 || ns[0].(map[string]any)["transfer"] != false ||
		len(home["extra"].([]any)) != 1 || home["extra"].([]any)[0].(map[string]any)["addr"] != "203.0.113.40" {
		t.Fatalf("%v", home)
	}
	// Fix: the node in settings.json allowed in (the job kind "primary"; its old name,
	// "technitium", is no kind).
	if _, err := e.start("technitium", map[string]any{"zone": "home.example", "address": "203.0.113.51", "action": "allow"}); err == nil {
		t.Fatal(`the old job kind "technitium" taken`)
	}
	j := e.run("primary", map[string]any{"zone": "home.example", "address": "203.0.113.51", "action": "allow"})
	if j.State != jobs.Done || j.Kind != "primary" {
		t.Fatal(j.Error)
	}
	if z, _ := e.tech.Zone("home.example"); !slices.Equal(z.TransferList, []string{"203.0.113.40", "203.0.113.51"}) ||
		!slices.Equal(z.NotifyList, []string{"203.0.113.40", "203.0.113.51"}) {
		t.Fatal(z)
	}
	ns = get()["zones"].([]any)[0].(map[string]any)["nodes"].([]any)
	if ns[0].(map[string]any)["transfer"] != true || ns[0].(map[string]any)["notify"] != true {
		t.Fatal(ns)
	}
	for _, tc := range []struct {
		params map[string]any
		want   string
	}{
		{map[string]any{"zone": "home.example", "address": "203.0.113.40", "action": "allow"}, "not a node in settings.json"},
		{map[string]any{"zone": "home.example", "address": "203.0.113.51", "action": "remove"}, "take it out of settings.json first"},
		{map[string]any{"zone": "other.example", "address": "203.0.113.51", "action": "allow"}, "no secondary zone"},
		{map[string]any{"zone": "home.example", "address": "203.0.113.051", "action": "allow"}, "not an IPv4"},
		{map[string]any{"zone": "home.example", "address": "203.0.113.51", "action": "add"}, `"allow" or "remove"`},
	} {
		if _, err := e.start("primary", tc.params); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v: %v", tc.params, err)
		}
	}
	j = e.run("primary", map[string]any{"zone": "home.example", "address": "203.0.113.40", "action": "remove"})
	if z, _ := e.tech.Zone("home.example"); j.State != jobs.Done || !slices.Equal(z.TransferList, []string{"203.0.113.51"}) {
		t.Fatal(j.Error, z)
	}
	// Never removed from here, though not in settings.json: a node the controller finds (the
	// one being adopted, or one adopted and not listed yet), a DNS peer, the zone's primary.
	e.tech.SetZone("home.example", faketech.Zone{Transfer: "AllowOnlySpecifiedNameServers",
		TransferList: []string{"203.0.113.51", "203.0.113.52", "203.0.113.53", "203.0.113.254"}, Notify: "SpecifiedNameServers"})
	s, _ := settings.Load(settings.Path(e.dir))
	s.DNSPeers = []string{"203.0.113.53"}
	if err := settings.Save(settings.Path(e.dir), s); err != nil {
		t.Fatal(err)
	}
	for addr, want := range map[string]string{"203.0.113.52": "a node the controller finds", "203.0.113.53": "a DNS peer",
		"203.0.113.254": "the zone's primary"} {
		if _, err := e.start("primary", map[string]any{"zone": "home.example", "address": addr, "action": "remove"}); err == nil ||
			!strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", addr, err, want)
		}
	}
	for _, x := range get()["zones"].([]any)[0].(map[string]any)["extra"].([]any) {
		if x.(map[string]any)["in_use"] == nil {
			t.Errorf("%v: offered for removal", x)
		}
	}
	// Without a token: the view says why, and no job is queued.
	os.Remove(keys.TokenPath(e.dir))
	if out := get(); !strings.Contains(out["by_hand"].(string), "no zone primary API token") {
		t.Fatal(out)
	}
	if _, err := e.start("primary", map[string]any{"zone": "home.example", "address": "203.0.113.51", "action": "allow"}); err == nil {
		t.Fatal("queued without a token")
	}
}

// An adopted node not in settings.json added from the page; nothing else is.
func TestSettingsAdd(t *testing.T) {
	e := newAdoptEnv(t)
	if _, err := e.start("settings-add", map[string]any{"node": "203.0.113.52"}); err == nil || !strings.Contains(err.Error(), "not adopted") {
		t.Fatal(err)
	}
	if _, err := e.start("settings-add", map[string]any{"node": "203.0.113.51"}); err == nil || !strings.Contains(err.Error(), "already") {
		t.Fatal(err)
	}
	// A node adopted (by the CLI, without -add-to-settings), found over mDNS.
	e2 := newAdoptEnv(t)
	e2.node.Unadopted = false
	j := e2.run("settings-add", map[string]any{"node": "203.0.113.52"})
	s, _ := settings.Load(settings.Path(e2.dir))
	if j.State != jobs.Done || !slices.Equal(s.Nodes, []string{"203.0.113.51", "203.0.113.52"}) || s.ZonePrimary().Kind != "technitium" {
		t.Fatal(j.Error, s)
	}
}

// settings.json's no_dhcp on the page: listed for it; with none, DHCP is offered (with its
// reservation); on a network named there the preview refuses it and so does the dry run,
// as the CLI does (internal/adoption).
func TestAdoptPageNoDHCP(t *testing.T) {
	e := newAdoptEnv(t)
	page := func() (noDHCP []string, refusal string) {
		w := httptest.NewRecorder()
		e.adopt.list(w, httptest.NewRequest("GET", "/api/adopt", nil))
		var l struct {
			NoDHCP []string `json:"no_dhcp"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &l); err != nil || w.Code != 200 || l.NoDHCP == nil {
			t.Fatalf("%d %s", w.Code, w.Body)
		}
		w = httptest.NewRecorder()
		b, _ := json.Marshal(e.web(map[string]any{"address": "dhcp", "reserved": true}))
		e.adopt.preview(w, httptest.NewRequest("POST", "/api/adopt/preview", strings.NewReader(string(b))))
		var pv adoptPreview
		if err := json.Unmarshal(w.Body.Bytes(), &pv); err != nil || w.Code != 200 {
			t.Fatalf("%d %s", w.Code, w.Body)
		}
		return l.NoDHCP, pv.Refusal
	}
	if n, r := page(); len(n) != 0 || r != "" {
		t.Fatal("no no_dhcp, yet:", n, r)
	}
	s, _ := settings.Load(settings.Path(e.dir))
	s.NoDHCP = []string{"192.0.2.0/24", "203.0.113.0/24"}
	if err := settings.Save(settings.Path(e.dir), s); err != nil {
		t.Fatal(err)
	}
	if n, r := page(); !slices.Equal(n, s.NoDHCP) || !strings.Contains(r, "203.0.113.0/24 has no DHCP server") {
		t.Fatal(n, r)
	}
	j := e.run("adopt", e.web(map[string]any{"address": "dhcp", "reserved": true, "dry_run": true}))
	if j.State != jobs.Failed || !strings.Contains(j.Error, "203.0.113.52 is on 203.0.113.0/24, which has no DHCP server") {
		t.Fatal(j.State, j.Error)
	}
}

// The manual kind (any primary), end to end on the page: the preview and the dry run list
// the change per zone in any primary's terms, the adoption is refused until the page says
// it is made ("primary_done"), then goes ahead with nothing called; the Zone primary view
// reads no lists, shows what each node in settings.json carrying a zone needs, and queues
// no job. The token (still imported) is never used.
func TestAdoptPageManualKind(t *testing.T) {
	e := newAdoptEnv(t)
	if err := settings.Save(settings.Path(e.dir), settings.Settings{Nodes: []string{"203.0.113.51"},
		Primary: &primary.Config{Kind: primary.KindManual}}); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	b, _ := json.Marshal(e.web(nil))
	e.adopt.preview(w, httptest.NewRequest("POST", "/api/adopt/preview", strings.NewReader(string(b))))
	var pv adoptPreview
	json.Unmarshal(w.Body.Bytes(), &pv)
	if w.Code != 200 || pv.PrimaryKind != "manual" || pv.PrimaryAPI != "" || len(pv.Manual) != 2 ||
		!strings.Contains(pv.Manual[0], "zone home.example: allow 203.0.113.52 to transfer the zone (AXFR/IXFR)") ||
		!strings.Contains(pv.PrimaryWhy, "kind manual") {
		t.Fatalf("%d %+v %s", w.Code, pv, w.Body)
	}
	dry := e.run("adopt", e.web(map[string]any{"dry_run": true}))
	p := progressOf(t, dry)
	if dry.State != jobs.Done || p.Primary.Kind != "manual" || len(p.Primary.Manual) != 2 || p.Primary.API != "" ||
		len(p.Primary.Edits) != 0 || !strings.Contains(p.Primary.Manual[1], "zone lab.example: allow 203.0.113.52") {
		t.Fatalf("%s %+v", dry.State, p.Primary)
	}
	if _, err := e.start("adopt", e.web(map[string]any{"after": dry.ID})); err == nil ||
		!strings.Contains(err.Error(), "make them, then say they are done") {
		t.Fatal(err)
	}
	j := e.run("adopt", e.web(map[string]any{"after": dry.ID, "primary_done": true}))
	if j.State != jobs.Done || len(e.tech.Calls()) != 0 || !progressOf(t, j).Primary.Done {
		t.Fatal(j.State, j.Error, e.tech.Calls())
	}
	// The view: no lists, what each node needs. dns1 (203.0.113.51) carries home.example.
	w = httptest.NewRecorder()
	e.adopt.lists(w, httptest.NewRequest("GET", "/api/primary", nil))
	var out struct {
		Primary map[string]any `json:"primary"`
		ByHand  string         `json:"by_hand"`
		Zones   []primaryZone  `json:"zones"`
	}
	json.Unmarshal(w.Body.Bytes(), &out)
	if out.Primary["kind"] != "manual" || out.Primary["api"] != false || !strings.Contains(out.ByHand, "kind manual") ||
		len(out.Zones) != 2 || out.Zones[0].Lists != nil || len(out.Zones[0].Nodes) != 1 ||
		!strings.Contains(out.Zones[0].Nodes[0].Manual, "zone home.example: allow 203.0.113.51 to transfer") {
		t.Fatalf("%s", w.Body)
	}
	if _, err := e.start("primary", map[string]any{"zone": "home.example", "address": "203.0.113.51", "action": "allow"}); err == nil ||
		!strings.Contains(err.Error(), "by hand") {
		t.Fatal(err)
	}
	if len(e.tech.Calls()) != 0 {
		t.Fatal(e.tech.Calls())
	}
	// No "primary" at all is the manual kind too (a fresh install), saying so.
	settings.Save(settings.Path(e.dir), settings.Settings{Nodes: []string{"203.0.113.51"}})
	os.Remove(keys.TokenPath(e.dir))
	w = httptest.NewRecorder()
	e.adopt.lists(w, httptest.NewRequest("GET", "/api/primary", nil))
	json.Unmarshal(w.Body.Bytes(), &out)
	if out.Primary["kind"] != "manual" || out.Primary["set"] != false || !strings.Contains(out.ByHand, `no zone primary in settings.json`) {
		t.Fatalf("%s", w.Body)
	}
}
