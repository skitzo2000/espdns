package nodes

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// An mDNS answer's address is one a node can have: loopback, link-local, multicast,
// unspecified, 0/8 and broadcast are skipped, the first usable one taken.
func TestNodeAddr(t *testing.T) {
	ips := func(s ...string) []net.IP {
		var out []net.IP
		for _, a := range s {
			out = append(out, net.ParseIP(a))
		}
		return out
	}
	for _, c := range []struct {
		in   []net.IP
		want string
	}{
		{ips("192.0.2.53"), "192.0.2.53"},
		{ips("127.0.0.1", "192.0.2.53"), "192.0.2.53"},
		{ips("169.254.1.1", "224.0.0.251", "0.0.0.0", "0.1.2.3", "255.255.255.255", "198.51.100.7"), "198.51.100.7"},
		{ips("203.0.113.9"), "203.0.113.9"},
		{ips("127.0.0.1"), ""},
		{ips("169.254.169.254"), ""},
		{ips("::1", "fe80::1"), ""},
		{[]net.IP{{1, 2}}, ""},
		{nil, ""},
	} {
		got, ok := nodeAddr(c.in)
		if got != c.want || ok != (c.want != "") {
			t.Errorf("%v: %q %v, want %q", c.in, got, ok, c.want)
		}
	}
}

// At most maxFound nodes are listed from mDNS alone; one past it is ignored until one
// leaves the list. A node in settings.json doesn't count, and one already listed is still
// seen.
func TestSeenCap(t *testing.T) {
	c := newClock()
	r := New([]string{"192.0.2.1"})
	r.now = c.now
	addr := func(i int) string { return fmt.Sprintf("198.51.100.%d", i+1) }
	for i := range maxFound {
		r.seen(addr(i), "n", "n.local.", []string{fmt.Sprintf("node=02:00:00:00:01:%02x", i)})
	}
	if len(r.List()) != maxFound+1 {
		t.Fatalf("%d listed, want %d", len(r.List()), maxFound+1)
	}
	r.seen("203.0.113.9", "extra", "extra.local.", []string{"node=02:00:00:00:02:01"})
	if node(r, "203.0.113.9").Addr != "" || !r.full {
		t.Fatal("one past the cap listed")
	}
	c.add(time.Minute)
	r.seen(addr(0), "n", "n.local.", nil) // one listed: still seen
	if n := node(r, addr(0)); !n.found.Equal(c.t) {
		t.Fatal("a listed node not seen again at the cap")
	}
	r.SetListed([]string{"192.0.2.1", addr(1)}) // listed in settings.json: no longer counted
	r.seen("203.0.113.9", "extra", "extra.local.", []string{"node=02:00:00:00:02:01"})
	if node(r, "203.0.113.9").Addr == "" || r.full {
		t.Fatal("below the cap again, not listed")
	}
}

// An mDNS answer never renames a node: one known at the address under another ID keeps it.
func TestSeenNoRename(t *testing.T) {
	r := New([]string{"192.0.2.53"})
	r.byAddr["192.0.2.53"].ID = "02:00:00:00:00:01"
	r.seen("192.0.2.53", "evil", "evil.local.", []string{"node=02:00:00:00:00:99"})
	if n := node(r, "192.0.2.53"); n.ID != "02:00:00:00:00:01" || n.Hostname != "" {
		t.Fatalf("renamed: %+v", n)
	}
	// The same ID (any case), or none: taken, the hostname with it.
	r.seen("192.0.2.53", "espdns", "espdns-000001.local.", []string{"node=02:00:00:00:00:01"})
	if n := node(r, "192.0.2.53"); n.Hostname != "espdns-000001.local" {
		t.Fatalf("its own answer: %+v", n)
	}
}

// An mDNS answer never moves a node: a new address announced under a known node's ID is
// listed apart, without the ID. A node found over mDNS alone moves once its new address's
// own /status gives its ID and the old address has stopped answering; one still answering,
// and a node in settings.json, never move.
func TestSeenNoMove(t *testing.T) {
	const id = "02:00:00:00:00:07"
	old := newFakeNode(t, map[string]any{"node_id": id})
	impostor := newFakeNode(t, map[string]any{"node_id": id})
	c := newClock()
	r := New(nil)
	r.now = c.now
	ctx := context.Background()
	r.seen(old.addr(), "espdns", "espdns.local.", []string{"node=" + id})
	r.pollAll(ctx)

	r.seen(impostor.addr(), "espdns", "espdns.local.", []string{"node=" + id})
	if n := node(r, old.addr()); n.ID != id {
		t.Fatalf("the known node moved or renamed: %+v", r.List())
	}
	if n := node(r, impostor.addr()); n.Addr == "" || n.ID != "" {
		t.Fatalf("the new address: listed apart, without the ID: %+v", n)
	}
	// Announced again (the next browse): still without the ID.
	r.seen(impostor.addr(), "espdns", "espdns.local.", []string{"node=" + id})
	if n := node(r, impostor.addr()); n.Addr == "" || n.ID != "" {
		t.Fatalf("announced again: took the known node's ID: %+v", n)
	}
	r.pollAll(ctx) // both answer as the node: both stay
	if node(r, old.addr()).Addr == "" || node(r, impostor.addr()).ID != id {
		t.Fatalf("both answering: %+v", r.List())
	}

	// The old address stops answering: once it is offline, the new one is the node.
	old.srv.Close()
	c.add(offlineAfter - time.Second)
	r.pollAll(ctx)
	if node(r, old.addr()).Addr == "" {
		t.Fatal("moved while the old address was still online")
	}
	c.add(time.Second)
	r.pollAll(ctx)
	if node(r, old.addr()).Addr != "" || node(r, impostor.addr()).ID != id || len(r.List()) != 1 {
		t.Fatalf("not moved once offline: %+v", r.List())
	}
}

// A node in settings.json is never moved or dropped for another address's answer or
// /status, online or not.
func TestListedNeverMoves(t *testing.T) {
	const id = "02:00:00:00:00:08"
	gone := httptest.NewServer(http.NotFoundHandler())
	listed := strings.TrimPrefix(gone.URL, "http://")
	gone.Close()
	other := newFakeNode(t, map[string]any{"node_id": id})
	c := newClock()
	r := New([]string{listed})
	r.now = c.now
	r.byAddr[listed].ID = id
	r.seen(other.addr(), "espdns", "espdns.local.", []string{"node=" + id})
	c.add(time.Hour)
	r.pollAll(context.Background())
	if n := node(r, listed); n.Addr == "" || n.Source != "settings" || n.ID != id {
		t.Fatalf("the listed node: %+v", r.List())
	}
	if node(r, other.addr()).ID != id {
		t.Fatalf("the other address: %+v", r.List())
	}
}
