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

	"github.com/skitzo2000/espdns/controller/internal/auth"
	"github.com/skitzo2000/espdns/controller/internal/changes"
	"github.com/skitzo2000/espdns/controller/internal/configs"
	"github.com/skitzo2000/espdns/controller/internal/fleet"
	"github.com/skitzo2000/espdns/controller/internal/jobs"
	"github.com/skitzo2000/espdns/controller/internal/nodecfg"
	"github.com/skitzo2000/espdns/controller/internal/nodes"
	"github.com/skitzo2000/espdns/controller/internal/settings"
)

// settingsEnv is a controller with a login, fake nodes polled live, and its pending changes.
type settingsEnv struct {
	t      *testing.T
	dir    string
	h      http.Handler
	store  *changes.Store
	cookie string
	tok    string
}

// liveNodes is the node list as the registry has it, each node's /status read now (fake
// nodes only: test servers on this host).
func liveNodes(addrs ...string) func() []nodes.Node {
	return func() []nodes.Node {
		var out []nodes.Node
		for _, a := range addrs {
			nd := nodes.Node{Addr: a}
			if st, err := (&fleet.Client{}).Status(context.Background(), a); err == nil {
				b, _ := json.Marshal(st)
				json.Unmarshal(b, &nd.Status)
				nd.ID, nd.Online = st.NodeID, true
			}
			out = append(out, nd)
		}
		return out
	}
}

// newSettingsHandler is the controller's handler on dir, logged in.
func newSettingsHandler(t *testing.T, dir string, srv *server) (http.Handler, string, string) {
	if err := auth.SetPassword(auth.Path(dir), "admin", testPassword); err != nil {
		t.Fatal(err)
	}
	srv.dataDir, srv.auth = dir, auth.New(auth.Path(dir))
	srv.builder = newBuilder(t.TempDir(), t.TempDir(), t.TempDir())
	h, _ := srv.handler()
	cookie, tok := login(t, h)
	return h, cookie, tok
}

func newSettingsEnv(t *testing.T, k *ecdsa.PrivateKey, s settings.Settings, cfgs map[string]string, ns ...*cfgNode) *settingsEnv {
	dir := t.TempDir()
	if err := settings.Save(settings.Path(dir), s); err != nil {
		t.Fatal(err)
	}
	for name, text := range cfgs {
		if _, err := configs.Save(dir, name, []byte(text), ""); err != nil {
			t.Fatal(err)
		}
	}
	e := &settingsEnv{t: t, dir: dir, store: changes.New(dir)}
	var addrs []string
	for _, n := range ns {
		addrs = append(addrs, n.addr)
	}
	act := actions{dataDir: dir, key: keyOf{k}, known: func() []string { return s.Nodes },
		client: func() *fleet.Client { return &fleet.Client{} }}
	e.h, e.cookie, e.tok = newSettingsHandler(t, dir, &server{runner: jobs.New(dir, map[string]jobs.Kind{}), key: keyOf{k},
		catalog: "../../../boards", nodes: liveNodes(addrs...), changes: e.store, push: pushKind{actions: act}})
	return e
}

func (e *settingsEnv) do(method, path, body string) (int, string) {
	return settingsDo(e.t, e.h, e.cookie, e.tok, method, path, body)
}

// settingsDo sends a request in the session; no reply may hold the Wi-Fi password.
func settingsDo(t *testing.T, h http.Handler, cookie, tok, method, path, body string) (int, string) {
	r := httptest.NewRequest(method, "http://127.0.0.1:8480"+path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "http://127.0.0.1:8480")
	withSession(r, cookie, tok)
	w := serve(h, r)
	if strings.Contains(w.Body.String(), "a secret pass") {
		t.Errorf("%s %s: the Wi-Fi password in the reply", method, path)
	}
	return w.Code, w.Body.String()
}

// get reads a node's settings.
func (e *settingsEnv) get(id string) settingsReply {
	e.t.Helper()
	code, b := e.do("GET", "/api/nodes/"+id+"/settings", "")
	var r settingsReply
	if err := json.Unmarshal([]byte(b), &r); code != 200 || err != nil {
		e.t.Fatalf("GET %s: %d %s", id, code, b)
	}
	return r
}

// edit posts an edit of a node's settings with the version read last.
func (e *settingsEnv) edit(id, version, edit string) (int, string) {
	return e.do("POST", "/api/nodes/"+id+"/settings", `{"version":"`+version+`","settings":`+edit+`}`)
}

// changes is GET /api/changes.
func (e *settingsEnv) changes() []changeView {
	e.t.Helper()
	code, b := e.do("GET", "/api/changes", "")
	var r changesReply
	if err := json.Unmarshal([]byte(b), &r); code != 200 || err != nil {
		e.t.Fatalf("GET /api/changes: %d %s", code, b)
	}
	return r.Changes
}

const nsWifi = `"wifi":{"ssid":"net","password":"a secret pass"}`

// The form; an edit becomes a pending change of the node's config file (GET /api/changes),
// on the version the form was read from, so a second stacks on the first and a form read
// before either is refused; the refusals with the field they are about; a discard through
// /api/changes.
func TestNodeSettingsAPI(t *testing.T) {
	k := newTestKey(t)
	n, peer := newCfgNode(t, k), newCfgNode(t, k)
	n.cfg.Name, peer.cfg.Name = "dns-a", "dns-b"
	e := newSettingsEnv(t, k, settings.Settings{Nodes: []string{n.addr, peer.addr}, NoDHCP: []string{"192.0.2.0/23"}},
		map[string]string{"dns-a.json": `{"name":"dns-a",` + nsWifi + `,"forwarders":["198.51.100.1"],"time":{"tz":"UTC0"}}`,
			"dns-b.json": `{"name":"dns-b"}`}, n, peer)

	r := e.get(n.id())
	fl, _ := configs.Read(e.dir, "dns-a.json")
	if r.Node.Host != n.addr || r.Node.Name != "dns-a" || !r.Node.Listed || r.Config.File != "dns-a.json" || !r.Config.Exists ||
		r.Pending != nil || r.Version != fl.Hash || len(r.TimeZones) < 20 || len(r.QueryLogClients) != 3 {
		t.Fatalf("form %+v", r)
	}
	// Its interface's MAC, in lower case, beside the address set here (a DHCP reservation).
	if want := strings.ToLower(n.ifaceMAC()); r.Node.MAC != want || r.Node.MAC == n.id() {
		t.Fatalf("mac %q, want %q", r.Node.MAC, want)
	}
	f := r.Settings
	if f.Name.Value != "dns-a" || f.Name.From != "config" || !slices.Equal(f.Forwarders.Value, []string{"198.51.100.1"}) ||
		f.TZ.Value.Name != "UTC" || f.Network.From != "node" || f.Network.Value.Address != "192.0.2.250/23" || f.Network.Applies != "restart" {
		t.Errorf("settings %+v", f)
	}
	if code, b := e.do("GET", "/api/nodes/02:00:00:00:00:99/settings", ""); code != 404 || !strings.Contains(b, "no node") {
		t.Errorf("unknown node: %d %s", code, b)
	}

	// An edit: checked, a pending change of dns-a.json on the file as it is; nothing saved
	// or pushed.
	code, b := e.edit(n.id(), r.Version, `{"forwarders":["198.51.100.2","198.51.100.3"]}`)
	var after settingsReply
	json.Unmarshal([]byte(b), &after)
	if code != 200 || after.Pending == nil || after.Pending.Restart != "no" || !slices.Equal(after.Pending.Fields, []string{"forwarders"}) ||
		len(after.Pending.Changes) != 1 || after.Pending.Changes[0].Summary != "dns-a: upstream DNS" ||
		after.Pending.Changes[0].Who != "admin" || !strings.Contains(after.Pending.Effect, "live") ||
		!slices.Equal(after.Pending.Settings.Forwarders.Value, []string{"198.51.100.2", "198.51.100.3"}) ||
		!slices.Equal(after.Settings.Forwarders.Value, []string{"198.51.100.1"}) || after.Version == r.Version {
		t.Fatalf("edit: %d %s", code, b)
	}
	cs := e.changes()
	if len(cs) != 1 || cs[0].Kind != changes.Config || cs[0].Name != "dns-a.json" || cs[0].Base != fl.Hash ||
		cs[0].Hash != after.Version || cs[0].Summary != "dns-a: upstream DNS" || !strings.Contains(cs[0].Effect, "live") {
		t.Fatalf("/api/changes %+v", cs)
	}
	if fl, _ := configs.Read(e.dir, "dns-a.json"); !strings.Contains(string(fl.Text), "198.51.100.1") || len(n.took()) != 0 {
		t.Fatalf("saved or pushed at an edit: %s %v", fl.Text, n.took())
	}
	if text, err := e.store.Text(cs[0].Change); err != nil || !strings.Contains(string(text), "a secret pass") ||
		!strings.Contains(string(text), "198.51.100.3") {
		t.Fatalf("the change's text keeps the password: %s %v", text, err)
	}
	// A form read before it: refused.
	if code, b := e.edit(n.id(), r.Version, `{"tz":"Europe/Paris"}`); code != http.StatusConflict || !strings.Contains(b, "read them again") {
		t.Errorf("stale version: %d %s", code, b)
	}
	// A second edit stacks on the first.
	code, b = e.edit(n.id(), after.Version, `{"tz":"Europe/Paris"}`)
	json.Unmarshal([]byte(b), &after)
	if code != 200 || !slices.Equal(after.Pending.Fields, []string{"forwarders", "tz"}) || after.Pending.Settings.TZ.Value.Name != "Europe/Paris" ||
		!slices.Equal(after.Pending.Settings.Forwarders.Value, []string{"198.51.100.2", "198.51.100.3"}) || len(after.Pending.Changes) != 2 {
		t.Fatalf("second edit: %d %s", code, b)
	}
	if cs = e.changes(); len(cs) != 2 || cs[1].Base != cs[0].Hash || cs[1].Summary != "dns-a: time zone" {
		t.Fatalf("stacked %+v", cs)
	}

	// Refused, with the field: the node's checks, a name taken, DHCP on a network without,
	// a setting its firmware doesn't take (no query log in its /status).
	for edit, want := range map[string][2]string{
		`{"forwarders":["dns.example.com"]}`:                               {"forwarders", "not an IPv4"},
		`{"tz":"Mars/Olympus_Mons"}`:                                       {"tz", "not a time zone"},
		`{"name":"dns-b"}`:                                                 {"name", "called dns-b already"},
		`{"network":{"address":"dhcp"}}`:                                   {"network", "no DHCP server"},
		`{"network":{"address":"192.0.2.60/23","gateway":"198.51.100.1"}}`: {"network", "another address in the node's network"},
		`{"reset":["wifi"]}`:                                               {"wifi", "no field"},
	} {
		code, b := e.edit(n.id(), after.Version, edit)
		var er struct{ Error, Field string }
		json.Unmarshal([]byte(b), &er)
		if code != 400 || er.Field != want[0] || !strings.Contains(er.Error, want[1]) {
			t.Errorf("%s: %d %s", edit, code, b)
		}
	}
	if code, b := e.edit(n.id(), after.Version, `{"querylog":{"client":"hidden"}}`); code != 400 || !strings.Contains(b, "firmware doesn't take") {
		t.Errorf("querylog on firmware without it: %d %s", code, b)
	}
	if code, b := e.edit(n.id(), after.Version, `{"fowarders":[]}`); code != 400 || !strings.Contains(b, "unknown field") {
		t.Errorf("unknown field: %d %s", code, b)
	}
	if code, b := e.edit(n.id(), after.Version, `{}`); code != 400 || !strings.Contains(b, "changes nothing") {
		t.Errorf("empty: %d %s", code, b)
	}
	// What the pending changes make it already: nothing to change.
	if code, b := e.edit(n.id(), after.Version, `{"tz":"Europe/Paris"}`); code != 400 || !strings.Contains(b, "nothing to change") {
		t.Errorf("the same: %d %s", code, b)
	}
	if got := e.changes(); len(got) != 2 || got[1].ID != cs[1].ID {
		t.Errorf("a refused edit changed the pending ones: %+v", got)
	}

	// A move to another address: refused, as the apply's config rollout refuses it (the
	// Configs page's push moves a node and confirms it there).
	if code, b := e.edit(n.id(), after.Version, `{"network":{"address":"192.0.2.60/23","gateway":"192.0.2.1"}}`); code != 400 ||
		!strings.Contains(b, `"field":"network"`) || !strings.Contains(b, "Configs page") {
		t.Errorf("move: %d %s", code, b)
	}
	// A third edit stacks too (live: blocking switched off).
	code, b = e.edit(n.id(), after.Version, `{"blocking":false}`)
	json.Unmarshal([]byte(b), &after)
	if code != 200 || after.Pending.Restart != "no" || !slices.Equal(after.Pending.Fields, []string{"forwarders", "tz", "blocking"}) {
		t.Fatalf("blocking: %d %s", code, b)
	}
	if cs = e.changes(); len(cs) != 3 || !strings.Contains(cs[2].Effect, n.addr+": live") {
		t.Errorf("live in /api/changes: %+v", cs)
	}

	// Another change of the file (the Configs page, say) after the form was read: refused.
	v, _ := e.store.Effective(changes.Config, "dns-a.json")
	if _, err := e.store.Add(changes.Edit{Kind: changes.Config, Name: "dns-a.json", Hash: v.Hash, Who: "admin",
		Text: []byte(strings.Replace(string(v.Text), "198.51.100.3", "198.51.100.4", 1))}); err != nil {
		t.Fatal(err)
	}
	if code, b := e.edit(n.id(), after.Version, `{"tz":"UTC"}`); code != http.StatusConflict || !strings.Contains(b, "read them again") {
		t.Errorf("changed elsewhere: %d %s", code, b)
	}

	// Discarded as any pending change: the first, and the ones stacked on it.
	if code, b := e.do("POST", "/api/changes/"+cs[0].ID+"/discard", ""); code != 200 {
		t.Fatalf("discard: %d %s", code, b)
	}
	if r = e.get(n.id()); r.Pending != nil || r.Version != fl.Hash || len(e.changes()) != 0 {
		t.Errorf("after the discard: %+v", r.Pending)
	}

	// The config file changed since a change was made on it: refused until discarded.
	if code, b := e.edit(n.id(), r.Version, `{"name":"dns-c"}`); code != 200 {
		t.Fatalf("rename: %d %s", code, b)
	}
	if _, err := configs.Save(e.dir, "dns-a.json", []byte(strings.Replace(string(fl.Text), "198.51.100.1", "198.51.100.9", 1)), fl.Hash); err != nil {
		t.Fatal(err)
	}
	r = e.get(n.id())
	if r.Config.File != "dns-a.json" || r.Pending == nil {
		t.Fatalf("after the file changed: %+v %+v", r.Config, r.Pending)
	}
	if code, b := e.edit(n.id(), r.Version, `{"tz":"UTC"}`); code != http.StatusConflict || !strings.Contains(b, "discard them") {
		t.Errorf("file changed: %d %s", code, b)
	}
}

// Which file is the node's: none yet (a new one, named for the node, made by the change,
// found again through it); one it runs without a record here (refused: a new file would
// drop what it sets); a node not in settings.json (read, not changed).
func TestNodeSettingsWhichFile(t *testing.T) {
	k := newTestKey(t)
	n, peer, other := newCfgNode(t, k), newCfgNode(t, k), newCfgNode(t, k)
	n.cfg.Name, n.source = "dns-new", "defaults"
	peer.cfg.Name = "dns-b"
	other.cfg.Name = "dns-x"
	e := newSettingsEnv(t, k, settings.Settings{Nodes: []string{n.addr, peer.addr}}, nil, n, peer, other)
	r := e.get(n.id())
	if r.Config.File != "dns-new.json" || r.Config.Exists || r.Config.Runs.State != "defaults" || r.Version != "" {
		t.Fatalf("no file: %+v %q", r.Config, r.Version)
	}
	code, b := e.edit(n.id(), r.Version, `{"tz":"America/Chicago"}`)
	if code != 200 {
		t.Fatalf("new file: %d %s", code, b)
	}
	cs := e.changes()
	if len(cs) != 1 || cs[0].Name != "dns-new.json" || cs[0].Base != "" || cs[0].Summary != "dns-new: time zone" {
		t.Fatalf("the change %+v", cs)
	}
	// The new file names the node, so the apply finds it.
	if text, _ := e.store.Text(cs[0].Change); !strings.Contains(string(text), `"name": "dns-new"`) {
		t.Errorf("new file %s", text)
	}
	if _, err := configs.Read(e.dir, "dns-new.json"); err == nil {
		t.Error("a file made at the edit")
	}
	// Read again: the file the pending change makes; an edit stacks on it.
	r = e.get(n.id())
	if r.Config.File != "dns-new.json" || r.Config.Exists || r.Pending == nil || r.Pending.Settings.TZ.Value.Name != "America/Chicago" {
		t.Fatalf("again: %+v %+v", r.Config, r.Pending)
	}
	if code, b := e.edit(n.id(), r.Version, `{"forwarders":["198.51.100.2"]}`); code != 200 || len(e.changes()) != 2 {
		t.Fatalf("stacked on a new file: %d %s", code, b)
	}
	// peer runs a pushed config (source "node") and no file here is its.
	if code, b := e.do("GET", "/api/nodes/"+peer.id()+"/settings", ""); code != http.StatusConflict || !strings.Contains(b, "Configs page") {
		t.Errorf("unrecorded: %d %s", code, b)
	}
	// other is known (found over mDNS) but not in settings.json: read, not changed.
	other.source = "defaults"
	r = e.get(other.id())
	if r.Node.Listed {
		t.Error("listed")
	}
	if code, b := e.edit(other.id(), r.Version, `{"tz":"UTC"}`); code != 400 || !strings.Contains(b, "not in settings.json") {
		t.Errorf("unlisted: %d %s", code, b)
	}
}

// Applied by the one apply job: a settings edit sent to its node only, live, the file
// written (the Wi-Fi password kept), the change no longer pending.
func TestNodeSettingsApply(t *testing.T) {
	e := newApplyEnv(t, 2)
	text := `{"name": "fake-a", "forwarders": ["9.9.9.9"], ` + nsWifi + `}`
	writeFile(t, filepath.Join(configs.Path(e.dir), "fake-a.json"), []byte(text))
	h, cookie, tok := newSettingsHandler(t, e.dir, &server{runner: e.runner, key: keyOf{e.key}, catalog: e.catalog,
		nodes: liveNodes(e.addrs...), changes: e.store, push: pushKind{actions: e.push.actions}})
	do := func(method, path, body string) (int, string) {
		return settingsDo(t, h, cookie, tok, method, path, body)
	}
	id := e.nodes[0].ID()

	code, b := do("GET", "/api/nodes/"+id+"/settings", "")
	var r settingsReply
	if json.Unmarshal([]byte(b), &r); code != 200 || r.Config.File != "fake-a.json" {
		t.Fatalf("form: %d %s", code, b)
	}
	if code, b = do("POST", "/api/nodes/"+id+"/settings", `{"version":"`+r.Version+`","settings":{"forwarders":["192.0.2.53"]}}`); code != 200 {
		t.Fatalf("edit: %d %s", code, b)
	}
	code, b = do("GET", "/api/changes", "")
	var cr changesReply
	if json.Unmarshal([]byte(b), &cr); code != 200 || len(cr.Changes) != 1 || cr.Changes[0].Name != "fake-a.json" ||
		!strings.Contains(cr.Changes[0].Effect, e.addrs[0]+": live") {
		t.Fatalf("pending: %d %s", code, b)
	}

	j, res, p := e.runApply(nil)
	if j.State != jobs.Done || !res.Applied || len(res.Rollouts) != 1 || !slices.Equal(res.Rollouts[0].Done, []string{e.addrs[0]}) {
		t.Fatalf("apply %+v %+v %+v", j, res, p)
	}
	if ev := e.nodes[0].Events(); !slices.Equal(ev, []string{"push config"}) {
		t.Errorf("its node: %v", ev)
	}
	if ev := e.nodes[1].Events(); len(ev) != 0 {
		t.Errorf("the other node: %v", ev)
	}
	saved, _ := os.ReadFile(filepath.Join(configs.Path(e.dir), "fake-a.json"))
	if !strings.Contains(string(saved), "192.0.2.53") || strings.Contains(string(saved), "9.9.9.9") || !strings.Contains(string(saved), "a secret pass") {
		t.Errorf("saved %s", saved)
	}
	if cs := e.pending(); len(cs) != 0 {
		t.Errorf("still pending %+v", cs)
	}
	code, b = do("GET", "/api/nodes/"+id+"/settings", "")
	if json.Unmarshal([]byte(b), &r); code != 200 || r.Pending != nil || !slices.Equal(r.Settings.Forwarders.Value, []string{"192.0.2.53"}) {
		t.Errorf("after: %d %s", code, b)
	}
}

// A config change that moves its node (through /api/changes): the apply's config rollout
// refuses it, so the apply refuses it at its check, before any file is written.
func TestApplyRefusesMoveBeforeWrite(t *testing.T) {
	e := newApplyEnv(t, 2)
	text := `{"name": "fake-a"}`
	path := filepath.Join(configs.Path(e.dir), "fake-a.json")
	writeFile(t, path, []byte(text))
	e.add(changes.Config, "fake-a.json", `{"name": "fake-a", "network": {"address": "192.0.2.60/24", "gateway": "192.0.2.1"}}`)
	j, res, _ := e.runApply(nil)
	if j.State != jobs.Failed || !strings.Contains(j.Error, "which an apply doesn't do") || res.Written {
		t.Fatalf("apply %+v %+v", j, res)
	}
	if b, _ := os.ReadFile(path); string(b) != text {
		t.Errorf("written: %s", b)
	}
	if ev := e.nodes[0].Events(); len(ev) != 0 {
		t.Errorf("pushed: %v", ev)
	}
	if cs := e.pending(); len(cs) != 1 || cs[0].Written {
		t.Errorf("pending %+v", cs)
	}
}

// Two nodes that report the same name: a config named so would go to both, so an edit
// that makes one is refused; a name another config has as its pending changes make it is
// refused too.
func TestNodeSettingsOneNode(t *testing.T) {
	k := newTestKey(t)
	n, peer := newCfgNode(t, k), newCfgNode(t, k)
	n.cfg.Name, peer.cfg.Name = "espdns", "espdns"
	n.source, peer.source = "defaults", "defaults"
	e := newSettingsEnv(t, k, settings.Settings{Nodes: []string{n.addr, peer.addr}}, nil, n, peer)
	r := e.get(n.id())
	if code, b := e.edit(n.id(), r.Version, `{"tz":"UTC"}`); code != http.StatusConflict || !strings.Contains(b, peer.addr) {
		t.Errorf("same name: %d %s", code, b)
	}
	if len(e.changes()) != 0 {
		t.Error("added")
	}

	n.cfg.Name, peer.cfg.Name = "dns-a", "dns-b"
	e = newSettingsEnv(t, k, settings.Settings{Nodes: []string{n.addr, peer.addr}},
		map[string]string{"dns-a.json": `{"name":"dns-a"}`, "dns-b.json": `{"name":"dns-b"}`}, n, peer)
	r = e.get(peer.id())
	if code, b := e.edit(peer.id(), r.Version, `{"name":"dns-c"}`); code != 200 {
		t.Fatalf("rename: %d %s", code, b)
	}
	r = e.get(n.id())
	code, b := e.edit(n.id(), r.Version, `{"name":"dns-c"}`)
	if code != 400 || !strings.Contains(b, `"field":"name"`) || !strings.Contains(b, "dns-b.json") {
		t.Errorf("a name pending for another: %d %s", code, b)
	}
}

// A node running a pushed config without a record here is taken to run the file; when an
// apply that stopped wrote the file's changes, the file as it was before them.
func TestAssumedFile(t *testing.T) {
	dir := t.TempDir()
	store := changes.New(dir)
	before := `{"name":"dns-a","network":{"address":"192.0.2.10/24","gateway":"192.0.2.1"}}`
	f, err := configs.Save(dir, "dns-a.json", []byte(before), "")
	if err != nil {
		t.Fatal(err)
	}
	after := `{"name":"dns-a","network":{"address":"192.0.2.10/24","gateway":"192.0.2.2"}}`
	ch, err := store.Add(changes.Edit{Kind: changes.Config, Name: "dns-a.json", Text: []byte(after), Hash: f.Hash, Who: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	cs, _ := store.List()
	if a := assumedFile(dir, store, cs, "dns-a.json"); a == nil || a.Config.Network.Gateway != "192.0.2.1" {
		t.Fatalf("not written: %+v", a)
	}
	// Written by an apply that stopped: the file is the change's text now.
	if _, err := configs.Save(dir, "dns-a.json", []byte(after), f.Hash); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkWritten([]string{ch.ID}, map[string][]byte{ch.ID: []byte(before)}); err != nil {
		t.Fatal(err)
	}
	cs, _ = store.List()
	a := assumedFile(dir, store, cs, "dns-a.json")
	if a == nil || a.Config.Network.Gateway != "192.0.2.1" {
		t.Fatalf("written: %+v", a)
	}
	if d := nodecfg.Compare(a.Config, mustParse(t, after), nil); !slices.Contains(d.Reboot, nodecfg.ReasonAddress) {
		t.Errorf("compare %+v", d)
	}
}

func mustParse(t *testing.T, s string) *nodecfg.Config {
	t.Helper()
	c, err := nodecfg.Parse([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return c
}
