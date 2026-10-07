package nodes

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A node looked up at an address answers /status there, and only there: it is listed from
// then on (source lookup), polled as the others and pruned as one found over mDNS is.
func TestLookupListsTheNode(t *testing.T) {
	f := newFakeNode(t, map[string]any{"node_id": "02:00:00:00:00:41", "board": "p4-board",
		"net": map[string]any{"hostname": "espdns-000041.local"}})
	other := newFakeNode(t, map[string]any{"node_id": "02:00:00:00:00:42"})
	c := newClock()
	r := New(nil)
	r.now = c.now
	n, err := r.Lookup(context.Background(), f.addr())
	if err != nil {
		t.Fatal(err)
	}
	if n.Addr != f.addr() || n.ID != "02:00:00:00:00:41" || n.Source != SourceLookup || !n.Online || n.Hostname != "espdns-000041.local" ||
		n.Status["board"] != "p4-board" {
		t.Fatalf("looked up: %+v", n)
	}
	if l := r.List(); len(l) != 1 || l[0].Addr != f.addr() {
		t.Fatalf("list %+v", l)
	}
	if len(f.reqs) != 1 || f.reqs[0] != "GET /status" || len(other.reqs) != 0 {
		t.Fatalf("requests: %v, the other node %v", f.reqs, other.reqs)
	}
	// Polled as the others; pruned once gone for pruneAfter.
	r.pollAll(context.Background())
	if len(f.reqs) != 2 {
		t.Fatalf("not polled: %v", f.reqs)
	}
	f.srv.Close()
	c.add(pruneAfter - time.Second)
	r.pollAll(context.Background())
	if node(r, f.addr()).Addr == "" {
		t.Fatal("pruned too soon")
	}
	c.add(time.Second)
	r.pollAll(context.Background())
	if len(r.List()) != 0 {
		t.Fatalf("not pruned: %+v", r.List())
	}
}

// Nothing answering, or something that isn't a node: an error saying which, and nothing
// listed.
func TestLookupNoNode(t *testing.T) {
	gone := httptest.NewServer(http.NotFoundHandler())
	goneAddr := strings.TrimPrefix(gone.URL, "http://")
	gone.Close()
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "<html>") }))
	t.Cleanup(web.Close)
	noID := newFakeNode(t, map[string]any{"board": "x"})
	r := New(nil)
	for _, c := range []struct {
		addr string
		want error
	}{{goneAddr, ErrNoAnswer}, {strings.TrimPrefix(web.URL, "http://"), ErrNotNode}, {noID.addr(), ErrNotNode}} {
		if _, err := r.Lookup(context.Background(), c.addr); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.addr, err, c.want)
		}
	}
	if len(r.List()) != 0 {
		t.Fatalf("listed: %+v", r.List())
	}
}

// A lookup gives up after its wait (pollTimeout): a host that takes the connection and never answers
// doesn't hold the request.
func TestLookupTimesOut(t *testing.T) {
	stall := make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-stall:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() { close(stall); slow.Close() })
	r := New(nil)
	r.wait = 100 * time.Millisecond
	start := time.Now()
	_, err := r.Lookup(context.Background(), strings.TrimPrefix(slow.URL, "http://"))
	if !errors.Is(err, ErrNoAnswer) {
		t.Fatalf("err %v", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("took %v", d)
	}
}

// A listed node, or one found over mDNS, keeps its source when looked up; one looked up
// and then seen over mDNS counts as found over mDNS; one looked up and then listed counts
// as listed.
func TestLookupSources(t *testing.T) {
	listed := newFakeNode(t, map[string]any{"node_id": "02:00:00:00:00:51"})
	seen := newFakeNode(t, map[string]any{"node_id": "02:00:00:00:00:52"})
	typed := newFakeNode(t, map[string]any{"node_id": "02:00:00:00:00:53"})
	typed2 := newFakeNode(t, map[string]any{"node_id": "02:00:00:00:00:54"})
	r := New([]string{listed.addr()})
	r.seen(seen.addr(), "espdns-52", "espdns-52.local.", []string{"node=02:00:00:00:00:52"})
	ctx := context.Background()
	for _, a := range []string{listed.addr(), seen.addr(), typed.addr(), typed2.addr()} {
		if _, err := r.Lookup(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	r.seen(typed.addr(), "espdns-53", "espdns-53.local.", []string{"node=02:00:00:00:00:53"})
	r.SetListed([]string{listed.addr(), typed2.addr()})
	want := map[string]string{listed.addr(): SourceSettings, seen.addr(): SourceMDNS, typed.addr(): SourceMDNS, typed2.addr(): SourceSettings}
	for a, src := range want {
		if got := node(r, a).Source; got != src {
			t.Errorf("%s: source %q, want %q", a, got, src)
		}
	}
}

// At most maxLookedUp nodes are kept from lookups: one more drops the one looked up
// longest ago.
func TestLookupCap(t *testing.T) {
	c := newClock()
	r := New(nil)
	r.now = c.now
	var addrs []string
	for i := range maxLookedUp + 1 {
		f := newFakeNode(t, map[string]any{"node_id": fmt.Sprintf("02:00:00:00:01:%02x", i)})
		addrs = append(addrs, f.addr())
		if _, err := r.Lookup(context.Background(), f.addr()); err != nil {
			t.Fatal(err)
		}
		c.add(time.Second)
	}
	if l := r.List(); len(l) != maxLookedUp || node(r, addrs[0]).Addr != "" || node(r, addrs[maxLookedUp]).Addr == "" {
		t.Fatalf("list %+v", l)
	}
}

// A redirect is not followed, by a lookup or a poll: /status is read at the address typed
// (or listed) only, and one that redirects elsewhere is no node.
func TestStatusFollowsNoRedirect(t *testing.T) {
	target := newFakeNode(t, map[string]any{"node_id": "02:00:00:00:00:43"})
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, "http://"+target.addr()+"/status", http.StatusFound)
	}))
	t.Cleanup(redir.Close)
	addr := strings.TrimPrefix(redir.URL, "http://")
	r := New(nil)
	if _, err := r.Lookup(context.Background(), addr); !errors.Is(err, ErrNotNode) {
		t.Fatalf("lookup: %v, want %v", err, ErrNotNode)
	}
	r.SetListed([]string{addr})
	r.pollAll(context.Background())
	if n := node(r, addr); n.Online || !strings.Contains(n.Error, "302") {
		t.Fatalf("polled: %+v", n)
	}
	if len(target.reqs) != 0 {
		t.Fatalf("the redirect was followed: %v", target.reqs)
	}
}

// A node found before at another address (over mDNS, or looked up), now looked up at its new
// one, moves there rather than being listed twice with the same ID; a listed one stays.
func TestLookupMovesAFoundNode(t *testing.T) {
	listed := newFakeNode(t, map[string]any{"node_id": "02:00:00:00:00:61"})
	moved := newFakeNode(t, map[string]any{"node_id": "02:00:00:00:00:62"})
	listedNew := newFakeNode(t, map[string]any{"node_id": "02:00:00:00:00:61"})
	r := New([]string{listed.addr()})
	r.seen("192.0.2.62", "espdns-62", "espdns-62.local.", []string{"node=02:00:00:00:00:62"})
	ctx := context.Background()
	for _, a := range []string{moved.addr(), listedNew.addr()} {
		if _, err := r.Lookup(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	if n := node(r, "192.0.2.62"); n.Addr != "" {
		t.Fatalf("still at its old address: %+v", n)
	}
	if n := node(r, moved.addr()); n.ID != "02:00:00:00:00:62" || n.Source != SourceMDNS {
		t.Fatalf("moved: %+v", n)
	}
	if node(r, listed.addr()).Source != SourceSettings || node(r, listedNew.addr()).Source != SourceLookup {
		t.Fatalf("list %+v", r.List())
	}
}
