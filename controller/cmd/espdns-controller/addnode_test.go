package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/fakenode"
	"github.com/skitzo2000/espdns/controller/internal/jobs"
	"github.com/skitzo2000/espdns/controller/internal/nodes"
	"github.com/skitzo2000/espdns/controller/internal/release"
)

// recorder is an HTTP transport that notes each request (method, host, path) before the
// fake network takes it.
type recorder struct {
	mu   sync.Mutex
	reqs []string
	next http.RoundTripper
}

func (r *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	r.reqs = append(r.reqs, req.Method+" "+req.URL.Host+req.URL.Path)
	r.mu.Unlock()
	return r.next.RoundTrip(req)
}

func (r *recorder) take() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.reqs
	r.reqs = nil
	return out
}

// addNodeEnv is adoption's fake network (adoptEnv: 203.0.113.51 in settings.json, 203.0.113.52
// found over mDNS and not adopted) with a node registry for lookups, on that network only:
// a node mDNS doesn't find, not adopted, at 203.0.113.70; another host's web server at
// 203.0.113.71; nothing at 203.0.113.72.
type addNodeEnv struct {
	*adoptEnv
	reg   *nodes.Registry
	rec   *recorder
	typed *fakenode.Node
	add   addNodeServer
}

func newAddNodeEnv(t *testing.T) *addNodeEnv {
	e := &addNodeEnv{adoptEnv: newAdoptEnv(t), reg: nodes.New(nil)}
	e.typed = fakenode.New("typed", [6]byte{2, 0, 0, 0, 0, 0x70}, "esp32p4-rev1", "p4-ip101", release.PublicRaw(e.key))
	e.typed.Addr, e.typed.Gateway, e.typed.Unadopted, e.typed.DownFor = "203.0.113.70", "203.0.113.1", true, 20*time.Millisecond
	e.typed.Secondary = []string{"home.example"}
	e.lan.Add(e.typed)
	e.lan.Other("203.0.113.71", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("<html>")) }))
	hc := e.lan.HTTP()
	e.rec = &recorder{next: hc.Transport}
	hc.Transport = e.rec
	e.reg.SetClient(hc)
	// What the controller knows: the nodes found over mDNS (adoptEnv's), and the registry's.
	e.adopt.nodes = func() []nodes.Node { return append(e.found(), e.reg.List()...) }
	e.add = addNodeServer{adopt: *e.adopt, lookup: e.reg.Lookup}
	return e
}

func (e *addNodeEnv) lookup(address string) (int, lookupReply) {
	e.t.Helper()
	b, _ := json.Marshal(map[string]string{"address": address})
	w := httptest.NewRecorder()
	e.add.lookupNode(w, httptest.NewRequest("POST", "/api/nodes/lookup", strings.NewReader(string(b))))
	var out lookupReply
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			e.t.Fatalf("%v: %s", err, w.Body)
		}
	}
	return w.Code, out
}

func (e *addNodeEnv) foundList() []foundNode {
	e.t.Helper()
	w := httptest.NewRecorder()
	e.add.found(w, httptest.NewRequest("GET", "/api/nodes/found", nil))
	var out struct{ Nodes []foundNode }
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || w.Code != http.StatusOK {
		e.t.Fatalf("%d %s", w.Code, w.Body)
	}
	return out.Nodes
}

func hosts(fs []foundNode) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Host)
	}
	return out
}

// The nodes found over mDNS and not in settings.json, each as what it is and what adds it;
// the listed one isn't among them, and one adopted already is added to settings.json.
func TestAddNodeFound(t *testing.T) {
	e := newAddNodeEnv(t)
	got := e.foundList()
	if !slices.Equal(hosts(got), []string{"203.0.113.52"}) {
		t.Fatalf("found %+v", got)
	}
	n := got[0]
	if n.Next != nextAdopt || n.ID != e.node.ID() || n.Board != "p4-ip101" || n.Image != "esp32p4-rev1" || n.Version != "1" ||
		n.Name != "new" || n.Source != nodes.SourceMDNS || n.Listed || n.Adopted || n.Net != "ethernet" {
		t.Fatalf("%+v", n)
	}
	// Its interface's MAC, for a DHCP reservation or a static address.
	if n.MAC != e.node.ID() {
		t.Fatalf("mac %q, want %q", n.MAC, e.node.ID())
	}
	// Adopted, not listed (adopted by the CLI without -add-to-settings): settings-add.
	e.node.Do(func(n *fakenode.Node) { n.Unadopted = false })
	adopted := fakenode.New("dns5", [6]byte{2, 0, 0, 0, 0, 0x55}, "esp32p4-rev1", "p4-ip101", release.PublicRaw(e.key))
	adopted.Addr = "203.0.113.55"
	e.lan.Add(adopted)
	e.seen = append(e.seen, "203.0.113.55")
	got = e.foundList()
	if !slices.Equal(hosts(got), []string{"203.0.113.52", "203.0.113.55"}) || got[1].Next != nextSettingsAdd || !got[1].Adopted {
		t.Fatalf("found %+v", got)
	}
	// One that says it is a node the controller knows elsewhere: nothing adds it, and why.
	adopted.Do(func(n *fakenode.Node) { n.MAC = e.peer.MAC })
	got = e.foundList()
	if got[1].Next != "" || len(got[1].Refusals) == 0 || !strings.Contains(got[1].Refusals[0], "same ID") {
		t.Fatalf("found %+v", got[1])
	}
	if reqs := e.rec.take(); len(reqs) != 0 {
		t.Errorf("the list sent %v", reqs)
	}
}

// A node at an address typed: read there, and only there, listed from then on, and adopted
// through the Adopt flow as a node found over mDNS is (the preview, the dry run).
func TestAddNodeLookup(t *testing.T) {
	e := newAddNodeEnv(t)
	code, r := e.lookup("203.0.113.70")
	if code != http.StatusOK || !r.Found || r.Listed || r.Node == nil {
		t.Fatalf("%d %+v", code, r)
	}
	n := r.Node
	if n.Host != "203.0.113.70" || n.ID != e.typed.ID() || n.Source != nodes.SourceLookup || n.Next != nextAdopt || n.Name != "typed" ||
		n.Board != "p4-ip101" || n.Version != "1" || n.Address != "203.0.113.70/24" || !n.Online || len(n.Refusals) != 0 ||
		n.MAC != e.typed.ID() {
		t.Fatalf("%+v", n)
	}
	if reqs := e.rec.take(); !slices.Equal(reqs, []string{"GET 203.0.113.70/status"}) {
		t.Fatalf("requests %v", reqs)
	}
	// Found from now on, beside the mDNS ones.
	if got := e.foundList(); !slices.Equal(hosts(got), []string{"203.0.113.52", "203.0.113.70"}) {
		t.Fatalf("found %+v", got)
	}
	// The Adopt flow takes it: the preview, then the dry run.
	web := map[string]any{"node": "203.0.113.70", "node_id": e.typed.ID(), "config": "n2.json"}
	b, _ := json.Marshal(web)
	w := httptest.NewRecorder()
	e.adopt.preview(w, httptest.NewRequest("POST", "/api/adopt/preview", strings.NewReader(string(b))))
	var pv adoptPreview
	if json.Unmarshal(w.Body.Bytes(), &pv); w.Code != http.StatusOK || pv.Refusal != "" || pv.Address != "203.0.113.70/24" {
		t.Fatalf("preview %d %s", w.Code, w.Body)
	}
	web["dry_run"] = true
	if j := e.run("adopt", web); j.State != jobs.Done {
		t.Fatalf("dry run %s: %s", j.State, j.Error)
	}
}

// Nothing there, or something that isn't a node: said so, and nothing listed.
func TestAddNodeLookupNoNode(t *testing.T) {
	e := newAddNodeEnv(t)
	for _, c := range []struct {
		addr     string
		answered bool
	}{{"203.0.113.72", false}, {"203.0.113.71", true}} {
		code, r := e.lookup(c.addr)
		if code != http.StatusOK || r.Found || r.Node != nil || r.Answered != c.answered || !strings.Contains(r.Error, c.addr) {
			t.Errorf("%s: %d %+v", c.addr, code, r)
		}
		if reqs := e.rec.take(); !slices.Equal(reqs, []string{"GET " + c.addr + "/status"}) {
			t.Errorf("%s: requests %v", c.addr, reqs)
		}
	}
	if l := e.reg.List(); len(l) != 0 {
		t.Fatalf("listed %+v", l)
	}
}

// An address in settings.json is one of the nodes already: said so, not read (it is polled
// already). An address that is no node's (a name, a port, loopback, ...) is refused, and
// nothing is sent anywhere.
func TestAddNodeLookupListedAndRefused(t *testing.T) {
	e := newAddNodeEnv(t)
	code, r := e.lookup("203.0.113.51")
	if code != http.StatusOK || !r.Listed || r.Found || r.Node == nil || r.Node.ID != e.peer.ID() || r.Node.Next != "" {
		t.Fatalf("%d %+v", code, r)
	}
	for _, a := range []string{"", "dns.example.com", "203.0.113.70:80", "0203.0.113.70", "::1", "2001:db8::1", "127.0.0.1", "0.0.0.0",
		"224.0.0.251", "255.255.255.255", " 203.0.113.70", "169.254.169.254"} {
		if code, _ := e.lookup(a); code != http.StatusBadRequest {
			t.Errorf("%q: %d", a, code)
		}
	}
	w := httptest.NewRecorder()
	e.add.lookupNode(w, httptest.NewRequest("POST", "/api/nodes/lookup", strings.NewReader(`{"address": "203.0.113.70", "port": 80}`)))
	if w.Code != http.StatusBadRequest {
		t.Errorf("an unknown field: %d", w.Code)
	}
	if reqs := e.rec.take(); len(reqs) != 0 {
		t.Errorf("sent %v", reqs)
	}
	if l := e.reg.List(); len(l) != 0 {
		t.Fatalf("listed %+v", l)
	}
}

// lookupAddress takes a LAN (or test) unicast address and refuses what can't be a node's,
// naming the field.
func TestLookupAddress(t *testing.T) {
	for _, c := range []struct {
		in string
		ok bool
	}{
		{"192.0.2.10", true},
		{"203.0.113.70", true},
		// Private and shared ranges built from bytes: no such literal goes in a test.
		{netip.AddrFrom4([4]byte{172, 16, 0, 1}).String(), true},
		{netip.AddrFrom4([4]byte{192, 168, 1, 10}).String(), true},
		{netip.AddrFrom4([4]byte{100, 64, 0, 1}).String(), true},
		{"1.0.0.1", true},
		{"169.254.169.254", false},
		{"169.254.0.1", false},
		{"127.0.0.1", false},
		{"127.255.255.254", false},
		{"0.0.0.0", false},
		{"0.1.2.3", false},
		{"224.0.0.251", false},
		{"239.255.255.250", false},
		{"240.0.0.1", false},
		{"255.255.255.255", false},
		{"::1", false},
		{"fe80::1", false},
		{"::ffff:192.0.2.10", false},
		{"", false},
	} {
		got, err := lookupAddress(c.in)
		switch {
		case c.ok && (err != nil || got != c.in):
			t.Errorf("%q: %q %v", c.in, got, err)
		case !c.ok && err == nil:
			t.Errorf("%q: taken as %q", c.in, got)
		case !c.ok && !strings.HasPrefix(err.Error(), "address: "):
			t.Errorf("%q: %v names no field", c.in, err)
		}
	}
}

// Through the whole server: both routes need a login (the route walk checks every route
// too), and the lookup there is the one the server was given.
func TestAddNodeRoutes(t *testing.T) {
	var asked []string
	h, _ := testServer(t, true, func(s *server) {
		s.lookup = func(_ context.Context, addr string) (nodes.Node, error) {
			asked = append(asked, addr)
			return nodes.Node{}, nodes.ErrNoAnswer
		}
	})
	e := &changesEnv{t: t, h: h}
	if w := e.do("POST", "/api/nodes/lookup", `{"address": "192.0.2.10"}`); w.Code != http.StatusUnauthorized && w.Code != http.StatusForbidden {
		t.Fatalf("no session: %d %s", w.Code, w.Body)
	}
	e.cookie, e.token = login(t, h)
	var r lookupReply
	e.json(e.do("POST", "/api/nodes/lookup", `{"address": "192.0.2.10"}`), http.StatusOK, &r)
	if r.Found || r.Answered || !slices.Equal(asked, []string{"192.0.2.10"}) {
		t.Fatalf("%+v %v", r, asked)
	}
	var f struct{ Nodes []foundNode }
	e.json(e.do("GET", "/api/nodes/found", ""), http.StatusOK, &f)
	if f.Nodes == nil || len(f.Nodes) != 0 {
		t.Fatalf("%+v", f)
	}
}
