package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The builder refuses an image without the node's address (a node never asks DHCP for one
// on its own) and checks the address as the node does; with a good one it goes on to the
// chip image, which isn't imported here.
func TestBuildNeedsAddress(t *testing.T) {
	b := newBuilder("../../../boards", t.TempDir(), t.TempDir())
	mux := http.NewServeMux()
	b.routes(mux)
	for _, c := range []struct{ body, want string }{
		{`{"name":"ws-s3-eth"}`, "network: the node's address"},
		{`{"name":"ws-s3-eth","network":{"address":"192.0.2.60"}}`, "prefix length"},
		{`{"name":"ws-s3-eth","network":{"address":"192.0.2.60/23"}}`, "gateway: required"},
		{`{"name":"ws-s3-eth","network":{"address":"192.0.2.60/23","gateway":"198.51.100.1"}}`, "in the node's network"},
		{`{"name":"ws-s3-eth","network":{"address":"dhcp","gateway":"192.0.2.1"}}`, "only with a static address"},
		{`{"name":"ws-s3-eth","network":{"address":"192.0.2.60/23","gateway":"192.0.2.1"}}`, "isn't imported"},
		{`{"name":"ws-s3-eth","network":{"address":"dhcp"}}`, "isn't imported"},
	} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest("POST", "/api/build", strings.NewReader(c.body)))
		if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), c.want) {
			t.Errorf("%s: %d %s, want %q", c.body, rec.Code, rec.Body.String(), c.want)
		}
	}
}
