package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/skitzo2000/espdns/controller/internal/auth"
	"github.com/skitzo2000/espdns/controller/internal/fakenode"
	"github.com/skitzo2000/espdns/controller/internal/fleet"
	"github.com/skitzo2000/espdns/controller/internal/jobs"
	"github.com/skitzo2000/espdns/controller/internal/keys"
	"github.com/skitzo2000/espdns/controller/internal/nodes"
	"github.com/skitzo2000/espdns/controller/internal/observe"
	"github.com/skitzo2000/espdns/controller/internal/primary"
	"github.com/skitzo2000/espdns/controller/internal/search"
	"github.com/skitzo2000/espdns/controller/internal/settings"
	"github.com/skitzo2000/espdns/controller/internal/zonefiles"
)

// noDNS fails a test that sends any DNS query: a search asks no one.
type noDNS struct{ t *testing.T }

func (n noDNS) Exchange(context.Context, string, *dns.Msg) (*dns.Msg, error) {
	n.t.Error("a search sent a DNS query")
	return nil, errors.New("no")
}

// The search over HTTP: a login (its session token) needed; a query that isn't one
// refused; a node, a zone of the fleet (settings.json's), a record, a device and a site
// from a fake node's query log found, each with where it lives; nothing sent to a primary.
func TestSearchAPI(t *testing.T) {
	dir := t.TempDir()
	if err := auth.SetPassword(auth.Path(dir), "admin", testPassword); err != nil {
		t.Fatal(err)
	}
	if err := settings.Save(settings.Path(dir), settings.Settings{Nodes: []string{"192.0.2.11"},
		Primary: &primary.Config{Kind: primary.KindTechnitium, URL: "https://192.0.2.254:53443"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := zonefiles.Save(dir, "home.example.zone", []byte("$TTL 3600\n@ IN SOA ns1.home.example. hostmaster.home.example. "+
		"( 5 3600 600 604800 300 )\n  IN NS ns1\nns1 IN A 192.0.2.53\nprinter IN A 192.0.2.40\n"), ""); err != nil {
		t.Fatal(err)
	}

	fn := fakenode.New("dns2", [6]byte{2, 0, 0, 0, 0, 1}, "esp32p4-rev1", "p4-ip101", nil)
	srv := httptest.NewServer(fn)
	t.Cleanup(srv.Close)
	fake := nodes.Node{ID: fn.ID(), Addr: strings.TrimPrefix(srv.URL, "http://"), Online: true,
		Status: map[string]any{"health": map[string]any{"state": "healthy"}}}
	store := observe.New(&fleet.Client{})
	store.Scrape(context.Background(), []nodes.Node{fake})
	fn.LogQuery("192.0.2.40", "printer-cloud.example", "A", "blocked", "NOERROR")
	store.Scrape(context.Background(), []nodes.Node{fake})

	ns := []nodes.Node{{ID: "020000000001", Addr: "192.0.2.11", Source: "settings", Online: true, Status: map[string]any{
		"config": map[string]any{"name": "dns2"}, "health": map[string]any{"state": "healthy"},
		"hosted": map[string]any{"state": "on", "zones": []any{map[string]any{"name": "home.example", "serial": 5, "records": 4}}}}}}
	s := &server{dataDir: dir, auth: auth.New(auth.Path(dir)), runner: jobs.New(dir, map[string]jobs.Kind{}),
		key: keys.FileSource{Path: keys.Path(dir)}, builder: newBuilder(t.TempDir(), t.TempDir(), t.TempDir()),
		nodes: func() []nodes.Node { return ns }, observe: store, zoneDNS: noDNS{t}}
	h, _ := s.handler()
	cookie, tok := login(t, h)
	get := func(q string, session bool) *httptest.ResponseRecorder {
		r := request("GET /api/search?q=" + url.QueryEscape(q))
		if session {
			withSession(r, cookie, tok)
		}
		return serve(h, r)
	}

	if w := get("dns2", false); !refusedByLogin(w) {
		t.Errorf("without a session: %d", w.Code)
	}
	if w := serve(h, withSession(request("GET /api/search?q=dns2"), cookie, "")); w.Code != http.StatusUnauthorized {
		t.Errorf("without the token: %d", w.Code)
	}
	for _, bad := range []string{"", " ", strings.Repeat("x", search.MaxQuery+1), "a\x01b"} {
		if w := get(bad, true); w.Code != http.StatusBadRequest {
			t.Errorf("%q: %d %s", bad, w.Code, w.Body)
		}
	}

	answer := func(q string) search.Answer {
		t.Helper()
		w := get(q, true)
		var a search.Answer
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &a) != nil || a.Partial || len(a.Problems) != 0 {
			t.Fatalf("%s: %d %s", q, w.Code, w.Body)
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("cached: %v", w.Header())
		}
		return a
	}
	has := func(a search.Answer, typ, title, link string) {
		t.Helper()
		for _, r := range a.Results {
			if r.Type == typ && r.Title == title {
				if r.Link != link {
					t.Errorf("%s %s: link %s, want %s", typ, title, r.Link, link)
				}
				return
			}
		}
		t.Errorf("no %s %s in %+v", typ, title, a.Results)
	}
	has(answer("dns2"), search.TypeNode, "dns2", "#node-020000000001")
	a := answer("Home.Example")
	has(a, search.TypeZone, "home.example", "#zone-home.example")
	if a.Results[0].Type != search.TypeZone || a.Results[0].State != "ok" {
		t.Errorf("the zone first, served: %+v", a.Results[0])
	}
	a = answer("printer")
	has(a, search.TypeRecord, "printer.home.example", "#zone-home.example")
	has(a, search.TypeDevice, "printer.home.example", "#query-log?client=192.0.2.40")
	has(a, search.TypeSite, "printer-cloud.example", "#query-log?name=printer-cloud.example")
	// A hostile query comes back as text in the JSON.
	w := get("<img src=x onerror=alert(1)>", true)
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), "<img") {
		t.Errorf("hostile: %d %s", w.Code, w.Body)
	}
}
