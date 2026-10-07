package nodes

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeNode serves a /status that the test changes as it goes, and records every request.
type fakeNode struct {
	mu     sync.Mutex
	status map[string]any
	reqs   []string
	srv    *httptest.Server
}

func newFakeNode(t *testing.T, status map[string]any) *fakeNode {
	f := &fakeNode{status: status}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.reqs = append(f.reqs, r.Method+" "+r.URL.Path)
		if r.URL.Path != "/status" {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(f.status)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeNode) addr() string { return strings.TrimPrefix(f.srv.URL, "http://") }

func (f *fakeNode) set(k string, v any) {
	f.mu.Lock()
	f.status[k] = v
	f.mu.Unlock()
}

// clock is a fake time the registry reads.
type clock struct{ t time.Time }

func (c *clock) now() time.Time      { return c.t }
func (c *clock) add(d time.Duration) { c.t = c.t.Add(d) }
func newClock() *clock               { return &clock{t: time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)} }
func node(r *Registry, addr string) Node {
	for _, n := range r.List() {
		if n.Addr == addr {
			return n
		}
	}
	return Node{}
}

func TestPollStatusAndQPS(t *testing.T) {
	f := newFakeNode(t, map[string]any{
		"node_id": "30:ed:a0:ea:bf:a2", "net": map[string]any{"hostname": "espdns-eabfa2.local"},
		"queries": map[string]any{"total": 1000},
		"health":  map[string]any{"state": "healthy", "answering": true, "reasons": []string{}},
	})
	c := newClock()
	r := New([]string{f.addr()})
	r.now = c.now
	ctx := context.Background()

	r.pollAll(ctx)
	n := node(r, f.addr())
	if !n.Online || n.ID != "30:ed:a0:ea:bf:a2" || n.Hostname != "espdns-eabfa2.local" || n.Source != "settings" {
		t.Fatalf("after one poll: %+v", n)
	}
	if n.QPS != nil {
		t.Fatalf("QPS from one poll: %v", *n.QPS)
	}
	if !n.Polled.Equal(c.t) || !n.LastSeen.Equal(c.t) {
		t.Fatalf("polled %v, last seen %v, want %v", n.Polled, n.LastSeen, c.t)
	}
	if h, _ := n.Status["health"].(map[string]any); h["state"] != "healthy" {
		t.Fatalf("status health not passed on: %v", n.Status["health"])
	}

	c.add(10 * time.Second)
	f.set("queries", map[string]any{"total": 1250})
	r.pollAll(ctx)
	if n = node(r, f.addr()); n.QPS == nil || *n.QPS != 25 {
		t.Fatalf("QPS after 250 queries in 10 s: %v", n.QPS)
	}

	// A reboot starts the count over: no rate from a smaller total.
	c.add(10 * time.Second)
	f.set("queries", map[string]any{"total": 40})
	r.pollAll(ctx)
	if n = node(r, f.addr()); n.QPS != nil {
		t.Fatalf("QPS across a reboot: %v", *n.QPS)
	}
	c.add(10 * time.Second)
	f.set("queries", map[string]any{"total": 60})
	r.pollAll(ctx)
	if n = node(r, f.addr()); n.QPS == nil || *n.QPS != 2 {
		t.Fatalf("QPS after the reboot: %v", n.QPS)
	}

	// The poller only reads.
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, q := range f.reqs {
		if q != "GET /status" {
			t.Fatalf("request %q: the poller only GETs /status", q)
		}
	}
}

// Older firmware: no queries, health or anything newer. Listed, no QPS, no error.
func TestPollOlderFirmware(t *testing.T) {
	f := newFakeNode(t, map[string]any{"node_id": "10:b4:1d:cd:e8:68", "version": "0.9", "degraded": true})
	c := newClock()
	r := New([]string{f.addr()})
	r.now = c.now
	r.pollAll(context.Background())
	c.add(10 * time.Second)
	r.pollAll(context.Background())
	n := node(r, f.addr())
	if !n.Online || n.Error != "" || n.QPS != nil || n.Status["version"] != "0.9" {
		t.Fatalf("older firmware: %+v", n)
	}
}

// A node that stops answering keeps its last /status, with the error; it goes offline after
// three missed polls.
func TestPollOffline(t *testing.T) {
	f := newFakeNode(t, map[string]any{"node_id": "aa", "queries": map[string]any{"total": 5}})
	c := newClock()
	r := New([]string{f.addr(), "127.0.0.1:1"}) // the second never answers
	r.now = c.now
	r.pollAll(context.Background())
	seen := c.t

	never := node(r, "127.0.0.1:1")
	if never.Online || never.Error == "" || never.Status != nil || !never.LastSeen.IsZero() || never.Polled.IsZero() {
		t.Fatalf("a node that never answered: %+v", never)
	}

	f.srv.Close()
	c.add(10 * time.Second)
	r.pollAll(context.Background())
	n := node(r, f.addr())
	if !n.Online || n.Error == "" || n.Status["node_id"] != "aa" || !n.LastSeen.Equal(seen) {
		t.Fatalf("one missed poll: still online with the error and the old status: %+v", n)
	}
	c.add(25 * time.Second)
	r.pollAll(context.Background())
	if n = node(r, f.addr()); n.Online || n.Status == nil || n.QPS != nil {
		t.Fatalf("35 s without an answer: offline, status kept: %+v", n)
	}
}

// The API's JSON: the fields the page reads.
func TestNodeJSON(t *testing.T) {
	q := 1.5
	b, err := json.Marshal(Node{Addr: "192.0.2.253", Source: "settings", QPS: &q, Status: map[string]any{"version": "1"}})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	json.Unmarshal(b, &m)
	for _, k := range []string{"id", "addr", "hostname", "source", "online", "last_seen", "polled", "qps", "status"} {
		if _, ok := m[k]; !ok {
			t.Errorf("no %q in %s", k, b)
		}
	}
	if _, ok := m["total"]; ok {
		t.Errorf("internal field in %s", b)
	}
}

// A /status over the cap, or not an object, is a failed poll; the last good one is kept.
func TestPollHostileStatus(t *testing.T) {
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(body) }))
	t.Cleanup(srv.Close)
	addr := strings.TrimPrefix(srv.URL, "http://")
	r := New([]string{addr})
	body = []byte(`{"version":"1"}`)
	r.pollAll(context.Background())
	for _, b := range [][]byte{
		[]byte(`{"pad":"` + strings.Repeat("x", maxStatus) + `"}`),
		[]byte(`null`),
		[]byte(`[1,2]`),
	} {
		body = b
		r.pollAll(context.Background())
		if n := node(r, addr); n.Error == "" || n.Status["version"] != "1" {
			t.Fatalf("%.20s…: a failed poll with the last status kept: %+v", b, n)
		}
	}
}

// A node that rebooted between two polls has no rate, even when its new count is higher.
func TestQPSAfterReboot(t *testing.T) {
	f := newFakeNode(t, map[string]any{"uptime_s": 500, "queries": map[string]any{"total": 100}})
	c := newClock()
	r := New([]string{f.addr()})
	r.now = c.now
	r.pollAll(context.Background())
	f.set("uptime_s", 3)
	f.set("queries", map[string]any{"total": 400})
	c.add(10 * time.Second)
	r.pollAll(context.Background())
	if n := node(r, f.addr()); n.QPS != nil {
		t.Fatalf("a rate across a reboot: %v", *n.QPS)
	}
	f.set("uptime_s", 13)
	f.set("queries", map[string]any{"total": 450})
	c.add(10 * time.Second)
	r.pollAll(context.Background())
	if n := node(r, f.addr()); n.QPS == nil || *n.QPS != 5 {
		t.Fatalf("the rate after the reboot: %+v", n)
	}
}

// A node moved to a new address (mDNS) while its poll ran: the poll's answer is dropped.
func TestPollNodeMoved(t *testing.T) {
	var r *Registry
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		for a := range r.byAddr {
			delete(r.byAddr, a)
		}
		r.mu.Unlock()
		w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)
	r = New([]string{strings.TrimPrefix(srv.URL, "http://")})
	r.pollAll(context.Background()) // panicked on the missing node
}

// settings.json read again: a node added is polled, one taken out is dropped unless mDNS
// found it, and one mDNS found counts as listed once it is.
func TestSetListed(t *testing.T) {
	r := New([]string{"198.51.100.1", "198.51.100.2"})
	r.byAddr["198.51.100.5"] = &Node{Addr: "198.51.100.5", Source: "mdns"}
	r.SetListed([]string{"198.51.100.2", "198.51.100.3", "198.51.100.5"})
	var got []string
	for _, n := range r.List() {
		got = append(got, n.Addr+" "+n.Source)
	}
	if strings.Join(got, ", ") != "198.51.100.2 settings, 198.51.100.3 settings, 198.51.100.5 settings" {
		t.Fatal(got)
	}
}

// The MAC of the interface a node uses (/status net.mac) is the node's MAC in /api/nodes:
// lower case, "" for none or for what isn't a MAC, and kept while the node is offline.
func TestPollMAC(t *testing.T) {
	f := newFakeNode(t, map[string]any{
		"node_id": "aa:bb:cc:00:00:01", "net": map[string]any{"kind": "ethernet", "mac": "AA:BB:CC:00:00:04"},
	})
	r := New([]string{f.addr()})
	ctx := context.Background()
	r.pollAll(ctx)
	if n := node(r, f.addr()); n.MAC != "aa:bb:cc:00:00:04" {
		t.Fatalf("mac %q, want aa:bb:cc:00:00:04", n.MAC)
	}
	b, _ := json.Marshal(node(r, f.addr()))
	if !strings.Contains(string(b), `"mac":"aa:bb:cc:00:00:04"`) {
		t.Fatalf("/api/nodes has no mac: %s", b)
	}
	f.srv.Close()
	r.pollAll(ctx)
	if n := node(r, f.addr()); n.Error == "" || n.MAC != "aa:bb:cc:00:00:04" {
		t.Fatalf("offline: error %q, mac %q: want the last one kept", n.Error, n.MAC)
	}

	for _, bad := range []any{"00:00:00:00:00:00", "<img>", 7, nil} {
		g := newFakeNode(t, map[string]any{"node_id": "aa:bb:cc:00:00:01", "net": map[string]any{"mac": bad}})
		r := New([]string{g.addr()})
		r.pollAll(ctx)
		if n := node(r, g.addr()); n.MAC != "" {
			t.Errorf("net.mac %v: mac %q, want none", bad, n.MAC)
		}
	}
}
