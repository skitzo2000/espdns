package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/skitzo2000/espdns/controller/internal/fleet"
	"github.com/skitzo2000/espdns/controller/internal/pins"
)

// espdns pin pins the node named to the address only when the node there answers as it,
// and moves the address off a node pinned there before.
func TestPinNode(t *testing.T) {
	id := "30:ed:a0:00:00:01"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"node_id": id})
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	l := pins.Open(t.TempDir())
	ctx := context.Background()

	if _, err := pinNode(ctx, l, &fleet.Client{}, host, "30:ed:a0:00:00:02"); err == nil || !strings.Contains(err.Error(), "not pinned") {
		t.Fatalf("another node's ID: %v", err)
	}
	if _, err := pinNode(ctx, l, &fleet.Client{}, host, "not-an-id"); err == nil {
		t.Fatal("a bad ID pinned")
	}
	if _, err := pinNode(ctx, l, &fleet.Client{}, "127.0.0.1:1", id); err == nil {
		t.Fatal("pinned with no node answering")
	}
	if _, err := l.Pinned(host); err == nil {
		t.Fatal("pinned on a refusal")
	}
	if r, err := pinNode(ctx, l, &fleet.Client{}, host, strings.ToUpper(id)); err != nil || r != "" {
		t.Fatal(r, err)
	}
	if got, _ := l.Pinned(host); got != id {
		t.Fatalf("pinned %q", got)
	}
	// A replaced board: the new one takes the address.
	id = "30:ed:a0:00:00:02"
	if r, err := pinNode(ctx, l, &fleet.Client{}, host, id); err != nil || r != "30:ed:a0:00:00:01" {
		t.Fatal(r, err)
	}
	if got, _ := l.Pinned(host); got != id {
		t.Fatalf("pinned %q", got)
	}
}
