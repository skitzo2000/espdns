package rolling

import (
	"strings"
	"testing"

	"github.com/skitzo2000/espdns/controller/internal/settings"
)

// No hosted zones at all (EmptyZones) only from the controller's apply, never from the
// Push page's JSON; and never with zones named.
func TestWebEmptyZones(t *testing.T) {
	dir := t.TempDir()
	if err := settings.Save(settings.Path(dir), settings.Settings{Nodes: []string{"192.0.2.2"}}); err != nil {
		t.Fatal(err)
	}
	r, err := Web{Kind: "zones", Nodes: []string{"192.0.2.2"}, EmptyZones: true}.Request(dir, "")
	if err != nil || !r.EmptyZones || len(r.Zones) != 0 {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := (Web{Kind: "zones", Nodes: []string{"192.0.2.2"}}).Request(dir, ""); err == nil || !strings.Contains(err.Error(), `"zones"`) {
		t.Errorf("no zones: %v", err)
	}
	if _, err := (Web{Kind: "zones", Nodes: []string{"192.0.2.2"}, Zones: []string{"example.com.zone"}, EmptyZones: true}).Request(dir, ""); err == nil {
		t.Error("both")
	}
	if _, err := ParseWeb([]byte(`{"kind": "zones", "nodes": ["192.0.2.2"], "EmptyZones": true}`)); err == nil {
		t.Error("EmptyZones from JSON")
	}
}
