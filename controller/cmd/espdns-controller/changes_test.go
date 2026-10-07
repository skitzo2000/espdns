package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skitzo2000/espdns/controller/internal/actionlog"
	"github.com/skitzo2000/espdns/controller/internal/changes"
	"github.com/skitzo2000/espdns/controller/internal/configs"
	"github.com/skitzo2000/espdns/controller/internal/fakenode"
	"github.com/skitzo2000/espdns/controller/internal/nodes"
	"github.com/skitzo2000/espdns/controller/internal/settings"
)

// changesEnv is the controller with a login, its data directory and its pending changes.
type changesEnv struct {
	t             *testing.T
	h             http.Handler
	dir           string
	store         *changes.Store
	cookie, token string
}

func newChangesEnv(t *testing.T, ns ...nodes.Node) *changesEnv {
	e := &changesEnv{t: t}
	e.h, _ = testServer(t, true, func(s *server) {
		e.dir, e.store = s.dataDir, changes.New(s.dataDir)
		s.changes = e.store
		s.nodes = func() []nodes.Node { return ns }
	})
	e.cookie, e.token = login(t, e.h)
	return e
}

// do sends a request in the session; body "" is none.
func (e *changesEnv) do(method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://127.0.0.1:8480"+path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "http://127.0.0.1:8480")
	return serve(e.h, withSession(r, e.cookie, e.token))
}

func (e *changesEnv) json(w *httptest.ResponseRecorder, code int, v any) {
	e.t.Helper()
	if w.Code != code {
		e.t.Fatalf("%d, want %d: %s", w.Code, code, w.Body)
	}
	if err := json.Unmarshal(w.Body.Bytes(), v); err != nil {
		e.t.Fatalf("%v: %s", err, w.Body)
	}
}

func jsonBody(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

const zoneOther = `$ORIGIN example.com.
$TTL 300
@ IN SOA ns.example.com. admin.example.com. 2026100701 3600 600 86400 300
@ IN NS ns.example.com.
ns IN A 192.0.2.30
`

type changesReply struct {
	Changes  []changeView `json:"changes"`
	Restarts []string     `json:"restarts"`
}

type fileReply struct {
	Text    string   `json:"text"`
	Hash    string   `json:"hash"`
	Exists  bool     `json:"exists"`
	Pending []string `json:"pending"`
}

// A change waits, listed with what applying it does; an edit of the same file starts from
// it; a discard takes it and the ones stacked on it.
func TestChangesAddListDiscard(t *testing.T) {
	e := newChangesEnv(t)
	var f fileReply
	e.json(e.do("GET", "/api/changes/file?kind=zone&name=example.com.zone", ""), http.StatusOK, &f)
	if f.Exists || f.Hash != "" || len(f.Pending) != 0 {
		t.Errorf("no file yet: %+v", f)
	}
	var a changes.Change
	e.json(e.do("POST", "/api/changes", jsonBody(map[string]any{"kind": "zone", "name": "example.com.zone", "text": zoneOther,
		"summary": "Add zone example.com"})), http.StatusCreated, &a)
	if a.ID == "" || a.Who != "admin" || a.Summary != "Add zone example.com" {
		t.Errorf("added %+v", a)
	}
	e.json(e.do("GET", "/api/changes/file?kind=zone&name=example.com.zone", ""), http.StatusOK, &f)
	if !f.Exists || f.Text != zoneOther || f.Hash != a.Hash || len(f.Pending) != 1 {
		t.Errorf("as the change makes it: %+v", f)
	}
	// On the version before it: refused.
	if w := e.do("POST", "/api/changes", jsonBody(map[string]any{"kind": "zone", "name": "example.com.zone", "text": zoneOther + "x IN A 192.0.2.9\n"})); w.Code != http.StatusConflict {
		t.Errorf("stale: %d %s", w.Code, w.Body)
	}
	var b changes.Change
	e.json(e.do("POST", "/api/changes", jsonBody(map[string]any{"kind": "zone", "name": "example.com.zone", "text": zoneOther + "x IN A 192.0.2.9\n",
		"hash": f.Hash})), http.StatusCreated, &b)
	for _, bad := range []map[string]any{
		{"kind": "zone", "name": "bad.zone", "text": "not a zone"},
		{"kind": "zone", "name": "../x.zone", "text": zoneOther},
		{"kind": "zone", "name": "example.org.zone"},
		{"kind": "zone", "name": "example.org.zone", "delete": true, "text": "x"},
		{"kind": "nope", "name": "x", "text": "x"},
		{"kind": "zone", "name": "example.org.zone", "text": zoneOther, "extra": 1},
	} {
		if w := e.do("POST", "/api/changes", jsonBody(bad)); w.Code != http.StatusBadRequest {
			t.Errorf("%v: %d %s", bad, w.Code, w.Body)
		}
	}
	// An unknown kind says which there are.
	if w := e.do("POST", "/api/changes", jsonBody(map[string]any{"kind": "nope", "name": "x", "text": "x"})); !strings.Contains(w.Body.String(), "config, zone, source, lists or firmware") {
		t.Errorf("unknown kind: %d %s", w.Code, w.Body)
	}
	var l changesReply
	e.json(e.do("GET", "/api/changes", ""), http.StatusOK, &l)
	if len(l.Changes) != 2 || l.Changes[0].ID != a.ID || !strings.Contains(l.Changes[0].Effect, "live (no restart)") || len(l.Restarts) != 0 {
		t.Errorf("list %+v", l)
	}
	// Held by an apply: not discarded.
	e.store.Hold([]string{b.ID})
	if w := e.do("POST", "/api/changes/"+a.ID+"/discard", "{}"); w.Code != http.StatusConflict {
		t.Errorf("held: %d %s", w.Code, w.Body)
	}
	if w := e.do("POST", "/api/changes/discard", "{}"); w.Code != http.StatusConflict {
		t.Errorf("all, held: %d %s", w.Code, w.Body)
	}
	e.json(e.do("GET", "/api/changes", ""), http.StatusOK, &l)
	if !l.Changes[1].Applying || l.Changes[0].Applying {
		t.Errorf("applying %+v", l.Changes)
	}
	e.store.Release([]string{b.ID})
	var d changes.Discarded
	e.json(e.do("POST", "/api/changes/"+a.ID+"/discard", "{}"), http.StatusOK, &d)
	if len(d.IDs) != 2 {
		t.Errorf("discarded %+v", d)
	}
	if w := e.do("POST", "/api/changes/"+a.ID+"/discard", "{}"); w.Code != http.StatusNotFound {
		t.Errorf("again: %d %s", w.Code, w.Body)
	}
	e.json(e.do("POST", "/api/changes", jsonBody(map[string]any{"kind": "source", "name": "overrides.txt", "text": "ads.example.org\n"})), http.StatusCreated, &a)
	e.json(e.do("POST", "/api/changes/discard", "{}"), http.StatusOK, &d)
	if len(d.IDs) != 1 {
		t.Errorf("all %+v", d)
	}
	e.json(e.do("GET", "/api/changes", ""), http.StatusOK, &l)
	if len(l.Changes) != 0 {
		t.Errorf("left %+v", l)
	}
	// Each add and discard in the action log, by the user.
	es, _ := actionlog.Tail(e.dir, 0)
	var acts []string
	for _, x := range es {
		if x.Who != "admin" {
			t.Errorf("by %q", x.Who)
		}
		acts = append(acts, x.Action)
	}
	if strings.Join(acts, ",") != "change add,change add,change discard,change add,change discard" {
		t.Errorf("action log %v", acts)
	}
}

// A config's Wi-Fi password is never in a reply; a text that still has it hidden keeps it.
func TestChangesConfigPassword(t *testing.T) {
	e := newChangesEnv(t)
	const secret = "a-wifi-secret"
	text := `{"name": "dns2", "wifi": {"ssid": "example", "password": "` + secret + `"}}`
	if _, err := configs.Save(e.dir, "dns2.json", []byte(text), ""); err != nil {
		t.Fatal(err)
	}
	var f fileReply
	e.json(e.do("GET", "/api/changes/file?kind=config&name=dns2.json", ""), http.StatusOK, &f)
	if strings.Contains(f.Text, secret) || !strings.Contains(f.Text, configs.Hidden) {
		t.Fatalf("shown %q", f.Text)
	}
	edited := strings.Replace(f.Text, `"dns2"`, `"dns2", "forwarders": ["192.0.2.53"]`, 1)
	var c changes.Change
	e.json(e.do("POST", "/api/changes", jsonBody(map[string]any{"kind": "config", "name": "dns2.json", "text": edited, "hash": f.Hash})), http.StatusCreated, &c)
	saved, err := e.store.Text(c)
	if err != nil || !strings.Contains(string(saved), secret) || !strings.Contains(string(saved), "192.0.2.53") {
		t.Errorf("kept %q %v", saved, err)
	}
	for _, p := range []string{"/api/changes", "/api/changes/file?kind=config&name=dns2.json"} {
		if w := e.do("GET", p, ""); strings.Contains(w.Body.String(), secret) {
			t.Errorf("%s shows the password", p)
		}
	}
	// A new config can't keep a password it doesn't have.
	if w := e.do("POST", "/api/changes", jsonBody(map[string]any{"kind": "config", "name": "dns3.json", "text": strings.Replace(edited, "dns2", "dns3", 1)})); w.Code != http.StatusBadRequest {
		t.Errorf("hidden, none saved: %d %s", w.Code, w.Body)
	}
}

// What applying a change does: a node config live or with a restart of its node, a
// firmware update restarts its nodes; the firmware must be there and the nodes listed.
func TestChangesEffects(t *testing.T) {
	st := map[string]any{"node_id": "02:00:00:00:00:11", "config": map[string]any{"source": "defaults", "seq": 0, "name": "dns2",
		"address": "static", "ip": "192.0.2.52/24", "gateway": "192.0.2.1"}}
	e := newChangesEnv(t, nodes.Node{Addr: "192.0.2.52", Online: true, Status: st})
	if err := settings.Save(settings.Path(e.dir), settings.Settings{Nodes: []string{"192.0.2.52"}}); err != nil {
		t.Fatal(err)
	}
	var c changes.Change
	e.json(e.do("POST", "/api/changes", jsonBody(map[string]any{"kind": "config", "name": "dns2.json",
		"text": `{"name": "dns2", "network": {"address": "192.0.2.60/24", "gateway": "192.0.2.1"}}`})), http.StatusCreated, &c)
	e.json(e.do("POST", "/api/changes", jsonBody(map[string]any{"kind": "config", "name": "dns9.json", "text": `{"name": "dns9"}`})), http.StatusCreated, &c)
	writeFile(t, filepath.Join(e.dir, "firmware/images/esp32p4-rev1/image.json"), []byte(`{"image": "esp32p4-rev1", "chip": "esp32p4"}`))
	writeFile(t, filepath.Join(e.dir, "firmware/images/esp32p4-rev1/app.bin"), fakenode.App("2", "0000000000000002"))
	for _, bad := range []map[string]any{
		{"kind": "firmware", "firmware": "images/esp32p4-rev1", "nodes": []string{"192.0.2.99"}},
		{"kind": "firmware", "firmware": "images/none", "nodes": []string{"192.0.2.52"}},
		{"kind": "firmware", "firmware": "elsewhere", "nodes": []string{"192.0.2.52"}},
		{"kind": "firmware", "firmware": "images/esp32p4-rev1", "nodes": []string{"192.0.2.52"}, "text": "x"},
	} {
		if w := e.do("POST", "/api/changes", jsonBody(bad)); w.Code != http.StatusBadRequest {
			t.Errorf("%v: %d %s", bad, w.Code, w.Body)
		}
	}
	e.json(e.do("POST", "/api/changes", jsonBody(map[string]any{"kind": "firmware", "firmware": "images/esp32p4-rev1", "nodes": []string{"192.0.2.52"}})),
		http.StatusCreated, &c)
	if c.Summary != "Update 192.0.2.52 to images/esp32p4-rev1" {
		t.Errorf("summary %q", c.Summary)
	}
	var l changesReply
	e.json(e.do("GET", "/api/changes", ""), http.StatusOK, &l)
	if len(l.Changes) != 3 {
		t.Fatalf("list %+v", l)
	}
	if ch := l.Changes[0]; !strings.Contains(ch.Effect, "192.0.2.52 restarts") || len(ch.Restarts) != 1 {
		t.Errorf("a new address: %+v", ch)
	}
	if ch := l.Changes[1]; !strings.Contains(ch.Effect, "No node in settings.json runs it") {
		t.Errorf("no node's: %+v", ch)
	}
	if ch := l.Changes[2]; !strings.Contains(ch.Effect, "Restarts 192.0.2.52, one at a time") || len(l.Restarts) != 1 {
		t.Errorf("firmware: %+v %v", ch, l.Restarts)
	}
	// One update per node.
	if w := e.do("POST", "/api/changes", jsonBody(map[string]any{"kind": "firmware", "firmware": "images/esp32p4-rev1", "nodes": []string{"192.0.2.52"}})); w.Code != http.StatusBadRequest {
		t.Errorf("a second update: %d %s", w.Code, w.Body)
	}
}
