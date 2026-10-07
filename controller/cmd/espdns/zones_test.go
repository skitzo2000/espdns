package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/skitzo2000/espdns/controller/internal/release"
	"github.com/skitzo2000/espdns/controller/internal/zones"
)

// The bundle is checked against the limit the node reports, and only a node that takes
// hosted zones gets one.
func TestZonesPayload(t *testing.T) {
	var hosted *release.HostedStatus
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(release.NodeStatus{NodeID: "aa:bb:cc:dd:ee:01", Hosted: hosted})
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	z, err := zones.LoadFile("../../internal/zones/testdata/home.example.zone")
	if err != nil {
		t.Fatal(err)
	}
	set := &zones.Set{Zones: []*zones.Zone{z}}
	p := &release.Pusher{}
	ctx := context.Background()
	if _, _, err := zonesPayload(ctx, p, host, set); err == nil || !strings.Contains(err.Error(), "update its firmware") {
		t.Errorf("old firmware: %v", err)
	}
	hosted = &release.HostedStatus{LimitBytes: 1024}
	if _, _, err := zonesPayload(ctx, p, host, set); err == nil || !strings.Contains(err.Error(), "hosted_zones_kb") {
		t.Errorf("over the limit: %v", err)
	}
	hosted.LimitBytes = 64 * 1024
	b, _, err := zonesPayload(ctx, p, host, set)
	if err != nil || !strings.HasPrefix(string(b), zones.Magic) {
		t.Errorf("payload: %v", err)
	}
}
