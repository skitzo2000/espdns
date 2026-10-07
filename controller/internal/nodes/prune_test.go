package nodes

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A node found over mDNS only is dropped once it has neither answered a poll nor been seen
// over mDNS for pruneAfter; one that answers, one seen again and one in settings.json stay.
func TestPruneMDNS(t *testing.T) {
	gone := httptest.NewServer(http.NotFoundHandler())
	goneAddr := strings.TrimPrefix(gone.URL, "http://")
	gone.Close() // nothing answers there now
	live := newFakeNode(t, map[string]any{"node_id": "02:00:00:00:00:01"})
	c := newClock()
	r := New([]string{"127.0.0.1:1"}) // listed, never answers
	r.now = c.now
	r.seen(goneAddr, "espdns-gone", "espdns-gone.local.", []string{"node=02:00:00:00:00:09"})
	r.seen(live.addr(), "espdns-live", "espdns-live.local.", []string{"node=02:00:00:00:00:01"})
	r.seen("127.0.0.1:2", "espdns-quiet", "espdns-quiet.local.", []string{"node=02:00:00:00:00:02"})
	ctx := context.Background()
	r.pollAll(ctx)
	if len(r.List()) != 4 {
		t.Fatalf("after one poll: %+v", r.List())
	}
	c.add(pruneAfter - time.Second)
	r.seen("127.0.0.1:2", "espdns-quiet", "espdns-quiet.local.", []string{"node=02:00:00:00:00:02"}) // still advertising
	r.pollAll(ctx)
	if len(r.List()) != 4 {
		t.Fatalf("before pruneAfter: %+v", r.List())
	}
	c.add(time.Second)
	r.pollAll(ctx)
	if node(r, goneAddr).Addr != "" || node(r, live.addr()).Addr == "" || node(r, "127.0.0.1:2").Addr == "" ||
		node(r, "127.0.0.1:1").Addr == "" {
		t.Fatalf("after pruneAfter: %+v", r.List())
	}
	c.add(pruneAfter)
	r.pollAll(ctx)
	if node(r, "127.0.0.1:2").Addr != "" || node(r, live.addr()).Addr == "" || node(r, "127.0.0.1:1").Addr == "" {
		t.Fatalf("the quiet one, later: %+v", r.List())
	}
}
