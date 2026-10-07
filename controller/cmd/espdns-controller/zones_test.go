package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/actionlog"
	"github.com/skitzo2000/espdns/controller/internal/auth"
	"github.com/skitzo2000/espdns/controller/internal/fakenode"
	"github.com/skitzo2000/espdns/controller/internal/jobs"
	"github.com/skitzo2000/espdns/controller/internal/keys"
	"github.com/skitzo2000/espdns/controller/internal/nodes"
	"github.com/skitzo2000/espdns/controller/internal/settings"
	"github.com/skitzo2000/espdns/controller/internal/zonefiles"
)

// The zone editor's API: a new zone from the template, checked (alone, as espdns zones
// -check, and against each node: over a node's limit, a node's secondary zone), the serial
// raised, saved with its history, a stale save refused, a kept version read back, deleted
// and kept; names that aren't a zone file never reach the disk.
func TestZonesAPI(t *testing.T) {
	dir := t.TempDir()
	if err := auth.SetPassword(auth.Path(dir), "admin", testPassword); err != nil {
		t.Fatal(err)
	}
	var ns []nodes.Node
	var addrs []string
	for i, f := range []func(*fakenode.Node){
		func(n *fakenode.Node) { n.Secondary = []string{} },
		func(n *fakenode.Node) { n.Secondary, n.HostedLimitKB = []string{}, 1 },
		func(n *fakenode.Node) { n.Secondary = []string{"lab.example"} },
	} {
		fn := fakenode.New(fmt.Sprintf("z%d", i), [6]byte{0x02, 0, 0, 0, 0x7, byte(i)}, "esp32p4-rev1", "p4-ip101", nil)
		fn.Addr = fmt.Sprintf("192.0.2.%d", 11+i)
		f(fn)
		ns = append(ns, nodes.Node{Addr: fn.Addr, ID: fn.ID(), Online: true, Status: fakeStatus(fn)})
		addrs = append(addrs, fn.Addr)
	}
	if err := settings.Save(settings.Path(dir), settings.Settings{Nodes: addrs}); err != nil {
		t.Fatal(err)
	}
	s := &server{dataDir: dir, auth: auth.New(auth.Path(dir)), runner: jobs.New(dir, map[string]jobs.Kind{}),
		key: keys.FileSource{Path: keys.Path(dir)}, builder: newBuilder(t.TempDir(), t.TempDir(), t.TempDir()),
		nodes: func() []nodes.Node { return ns }}
	h, _ := s.handler()
	cookie, tok := login(t, h)
	do := func(method, path string, body any) (int, string) {
		b, _ := json.Marshal(body)
		if body == nil {
			b = nil
		}
		r := httptest.NewRequest(method, "http://127.0.0.1:8480"+path, strings.NewReader(string(b)))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", "http://127.0.0.1:8480")
		r.AddCookie(&http.Cookie{Name: auth.CookieName(r.Host), Value: cookie})
		r.Header.Set(auth.TokenHeader, tok)
		w := serve(h, r)
		return w.Code, w.Body.String()
	}
	var res zonefiles.Result
	check := func(name, text string) {
		t.Helper()
		code, b := do("POST", "/api/zones/"+name+"/check", map[string]string{"text": text})
		res = zonefiles.Result{}
		if code != 200 || json.Unmarshal([]byte(b), &res) != nil {
			t.Fatalf("check: %d %s", code, b)
		}
	}
	refused := func(host string) string {
		for _, n := range res.Nodes {
			if n.Host == host {
				return n.Refused
			}
		}
		return "not checked"
	}

	// A new zone from the template: the SOA, an NS and A for each node in settings.json.
	code, b := do("GET", "/api/zones/home.example.zone/new", nil)
	var tmpl struct{ Text string }
	json.Unmarshal([]byte(b), &tmpl)
	if code != 200 || !strings.Contains(tmpl.Text, "IN SOA  ns1.home.example. hostmaster.home.example.") ||
		strings.Count(tmpl.Text, "IN NS") != 3 || !strings.Contains(tmpl.Text, "192.0.2.13") {
		t.Fatalf("template: %d %s", code, b)
	}
	if _, err := zonefiles.Parse("home.example.zone", []byte(tmpl.Text)); err != nil {
		t.Fatalf("the template doesn't pass: %v\n%s", err, tmpl.Text)
	}
	check("home.example.zone", tmpl.Text)
	if !res.OK || res.Error != "" || len(res.Nodes) != 3 || res.SerialWarn != "" || len(res.Lines) != 2 || res.Records != 7 {
		t.Fatalf("the template checked: %+v", res)
	}
	// A bad zone: the CLI's error, nothing against the nodes.
	check("home.example.zone", "@ IN NS ns1\n")
	if res.OK || !strings.Contains(res.Error, "SOA") || len(res.Nodes) != 0 {
		t.Errorf("bad: %+v", res)
	}
	// Over the second node's limit (1 KB): refused for it alone.
	big := tmpl.Text
	for i := range 40 {
		big += fmt.Sprintf("host%d IN A 192.0.2.%d\n", i, i+1)
	}
	check("home.example.zone", big)
	if res.OK || res.Error != "" || refused(addrs[0]) != "" || !strings.Contains(refused(addrs[1]), "hosted_zones_kb") || refused(addrs[2]) != "" {
		t.Errorf("over a node's limit: %+v", res.Nodes)
	}
	// A secondary zone of the third node.
	lab := strings.ReplaceAll(tmpl.Text, "home.example", "lab.example")
	check("lab.example.zone", lab)
	if res.OK || !strings.Contains(refused(addrs[2]), "secondary zone of "+addrs[2]) || refused(addrs[0]) != "" {
		t.Errorf("a secondary zone: %+v", res.Nodes)
	}

	// Saved new; a second "new" of the same name refused; a zone that doesn't pass never saved.
	if code, b := do("POST", "/api/zones/home.example.zone", map[string]string{"text": "@ IN NS ns1\n", "hash": ""}); code != 400 {
		t.Errorf("bad saved: %d %s", code, b)
	}
	code, b = do("POST", "/api/zones/home.example.zone", map[string]string{"text": tmpl.Text, "hash": ""})
	var saved struct {
		Hash   string
		Serial uint32
	}
	json.Unmarshal([]byte(b), &saved)
	if code != 200 || saved.Hash == "" {
		t.Fatalf("save: %d %s", code, b)
	}
	if code, _ := do("POST", "/api/zones/home.example.zone", map[string]string{"text": tmpl.Text, "hash": ""}); code == 200 {
		t.Error("a new file over one")
	}
	// An edit without the serial raised: warned, and the serial route raises it, nothing else.
	edited := tmpl.Text + "www IN A 192.0.2.80\n"
	check("home.example.zone", edited)
	if !res.OK || !strings.Contains(res.SerialWarn, "not above the saved file's") || res.NextSerial != saved.Serial+1 || len(res.Diff) == 0 {
		t.Fatalf("serial not raised: %+v", res)
	}
	code, b = do("POST", "/api/zones/home.example.zone/serial", map[string]string{"text": edited})
	var bumped struct {
		Text   string
		Serial uint32
	}
	json.Unmarshal([]byte(b), &bumped)
	if code != 200 || bumped.Serial != saved.Serial+1 || bumped.Text != strings.Replace(edited, fmt.Sprint(saved.Serial), fmt.Sprint(bumped.Serial), 1) {
		t.Fatalf("bump: %d %s", code, b)
	}
	check("home.example.zone", bumped.Text)
	if res.SerialWarn != "" || res.Serial != bumped.Serial {
		t.Errorf("after the bump: %+v", res)
	}
	if code, b := do("POST", "/api/zones/home.example.zone/serial", map[string]string{"text": "x"}); code != 400 {
		t.Errorf("bump of a bad zone: %d %s", code, b)
	}
	// Saved over the version edited only.
	if code, _ := do("POST", "/api/zones/home.example.zone", map[string]string{"text": bumped.Text, "hash": "0000"}); code != 409 {
		t.Errorf("stale: %d", code)
	}
	if code, b := do("POST", "/api/zones/home.example.zone", map[string]string{"text": bumped.Text, "hash": saved.Hash}); code != 200 {
		t.Fatalf("save: %d %s", code, b)
	}
	code, b = do("GET", "/api/zones/home.example.zone", nil)
	var got struct {
		Text, Hash string
		History    []zonefiles.Version
	}
	json.Unmarshal([]byte(b), &got)
	if code != 200 || got.Text != bumped.Text || len(got.History) != 1 {
		t.Fatalf("get: %d %s", code, b)
	}
	if code, b := do("GET", "/api/zones/home.example.zone?version="+got.History[0].File, nil); code != 200 || !strings.Contains(b, `IN SOA`) ||
		strings.Contains(b, "www IN A") {
		t.Errorf("a kept version: %d %s", code, b)
	}
	code, b = do("GET", "/api/zones", nil)
	if code != 200 || !strings.Contains(b, `"name":"home.example.zone"`) || !strings.Contains(b, `"max_zones":32`) {
		t.Errorf("list: %d %s", code, b)
	}
	// Each node's hosted zones as its /status says them: the slot in use, for the revert.
	if !strings.Contains(b, `"hosted":{"state":"on","seq":1,"sha256":"","bytes":0,"limit_bytes":65536,"slot":0,`) {
		t.Errorf("list: the nodes' hosted zones: %s", b)
	}
	// Deleted: only the version shown, kept in the history, listed as deleted.
	if code, _ := do("POST", "/api/zones/home.example.zone/delete", map[string]string{"hash": saved.Hash}); code != 409 {
		t.Errorf("delete of another version: %d", code)
	}
	if code, b := do("POST", "/api/zones/home.example.zone/delete", map[string]string{"hash": got.Hash}); code != 200 {
		t.Fatalf("delete: %d %s", code, b)
	}
	if code, _ := do("GET", "/api/zones/home.example.zone", nil); code != 404 {
		t.Errorf("after delete: %d", code)
	}
	code, b = do("GET", "/api/zones", nil)
	if code != 200 || !strings.Contains(b, `"deleted":[{"file":"home.example.zone.`) {
		t.Errorf("list after delete: %s", b)
	}
	es, _ := actionlog.Tail(dir, 0)
	var acts []string
	for _, e := range es {
		acts = append(acts, e.Action+" "+e.Args[0])
		if e.Who != "admin" {
			t.Errorf("who: %+v", e)
		}
	}
	if !slices.Equal(acts, []string{"zone save home.example.zone", "zone save home.example.zone", "zone delete home.example.zone"}) {
		t.Errorf("action log %v", acts)
	}

	// Names that aren't a zone file in the directory: never read or written outside it.
	os.WriteFile(filepath.Join(dir, "outside.zone"), []byte("x"), 0o600)
	for _, p := range []string{"..%2Foutside.zone", "%2E%2E%2Foutside.zone", ".history", ".pushed", "%2Fetc%2Fpasswd", "x.json",
		"Home.example.zone", "a..b.zone", "-a.zone", "home.example.zone%00", strings.Repeat("a", 70) + ".zone", "settings.json"} {
		for _, m := range []string{"GET /api/zones/%s", "GET /api/zones/%s/new", "POST /api/zones/%s", "POST /api/zones/%s/check",
			"POST /api/zones/%s/serial", "POST /api/zones/%s/delete"} {
			method, path, _ := strings.Cut(fmt.Sprintf(m, p), " ")
			if code, _ := do(method, path, map[string]string{"text": tmpl.Text}); code == 200 {
				t.Errorf("%s %s: %d", method, path, code)
			}
		}
	}
	if code, _ := do("GET", "/api/zones/home.example.zone?version=../../outside.zone", nil); code == 200 {
		t.Error("a version outside the history")
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "outside.zone")); string(b) != "x" {
		t.Errorf("outside the directory: %s", b)
	}
}

var testNow = time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)

// The template for a deployment without nodes in settings.json still passes.
func TestZoneTemplate(t *testing.T) {
	for _, listed := range [][]string{nil, {"192.0.2.252", "[fd00::1]:80", "node.local"}} {
		text := zoneTemplate("x.example", listed, testNow)
		if _, err := zonefiles.Parse("x.example.zone", []byte(text)); err != nil {
			t.Errorf("%v: %v\n%s", listed, err, text)
		}
	}
}
