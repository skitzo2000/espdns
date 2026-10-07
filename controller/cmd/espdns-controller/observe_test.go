package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/skitzo2000/espdns/controller/internal/fakenode"
	"github.com/skitzo2000/espdns/controller/internal/fleet"
	"github.com/skitzo2000/espdns/controller/internal/nodes"
	"github.com/skitzo2000/espdns/controller/internal/observe"
)

// The dashboard's and the query log's APIs, on a fake node read twice: JSON, the query log
// behind the login, its filters, and a hostile name kept as text (escaped in the JSON).
func TestObserveAPI(t *testing.T) {
	n := fakenode.New("dns-a", [6]byte{2, 0, 0, 0, 0, 1}, "esp32p4-rev1", "p4-ip101", nil)
	srv := httptest.NewServer(n)
	t.Cleanup(srv.Close)
	node := nodes.Node{ID: n.ID(), Addr: strings.TrimPrefix(srv.URL, "http://"), Online: true,
		Status: map[string]any{"health": map[string]any{"state": "healthy"}}}
	store := observe.New(&fleet.Client{})
	ctx := context.Background()
	store.Scrape(ctx, []nodes.Node{node})
	n.LogQuery("192.0.2.10", "<img src=x onerror=alert(1)>.example", "A", "blocked", "NOERROR")
	n.LogQuery("192.0.2.10", "ok.example", "AAAA", "cache", "NOERROR")
	store.Scrape(ctx, []nodes.Node{node})

	h, _ := testServer(t, true, func(s *server) { s.observe = store })
	cookie, tok := login(t, h)
	get := func(path string, session bool) *httptest.ResponseRecorder {
		r := request("GET " + path)
		if session {
			withSession(r, cookie, tok)
		}
		return serve(h, r)
	}

	w := get("/api/dashboard", true)
	var d observe.Dashboard
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &d) != nil || len(d.Nodes) != 1 || d.Bins != 60 {
		t.Fatalf("dashboard: %d %s", w.Code, w.Body)
	}
	if d.Nodes[0].Metrics.State != "ok" || len(d.Fleet.QPS) != 60 {
		t.Errorf("dashboard: %+v", d.Nodes[0])
	}

	if w := get("/api/querylog", false); !refusedByLogin(w) {
		t.Errorf("query log without a session: %d", w.Code)
	}
	w = get("/api/querylog?result=blocked", true)
	if strings.Contains(w.Body.String(), "<img") {
		t.Errorf("a name's markup in the JSON as is: %s", w.Body)
	}
	var l observe.LogView
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &l) != nil || len(l.Entries) != 1 ||
		l.Entries[0].QName != "<img src=x onerror=alert(1)>.example" || l.Entries[0].Node != n.ID() {
		t.Fatalf("query log: %d %s", w.Code, w.Body)
	}
	w = get("/api/querylog?qtype=aaaa&after=0&limit=5", true)
	if json.Unmarshal(w.Body.Bytes(), &l) != nil || len(l.Entries) != 1 || l.Entries[0].QName != "ok.example" {
		t.Errorf("qtype: %s", w.Body)
	}
	for _, bad := range []string{"after=x", "limit=0", "limit=-1"} {
		if w := get("/api/querylog?"+bad, true); w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", bad, w.Code)
		}
	}
	var top observe.Top
	w = get("/api/querylog/top?node="+n.ID(), true)
	if json.Unmarshal(w.Body.Bytes(), &top) != nil || top.Entries != 2 || len(top.Blocked) != 1 {
		t.Errorf("top: %s", w.Body)
	}
}
