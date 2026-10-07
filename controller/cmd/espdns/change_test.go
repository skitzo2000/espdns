package main

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skitzo2000/espdns/controller/internal/actionlog"
	"github.com/skitzo2000/espdns/controller/internal/fleetlock"
)

// A change holds the fleet lock from begin to end and is logged; a second one meanwhile
// is refused with who has it; a dry run takes no lock and isn't logged.
func TestBegin(t *testing.T) {
	dir := t.TempDir()
	args := []string{"-kind", "config", "-host", "198.51.100.2"}
	_, end, err := begin(dir, "rollout", args, false)
	if err != nil {
		t.Fatal(err)
	}
	h, held, _ := fleetlock.Held(fleetlock.Path(dir))
	if !held || h.Who != "espdns rollout" || h.What != "-kind config -host 198.51.100.2" {
		t.Fatal(h, held)
	}
	if _, _, err := begin(dir, "reboot", nil, false); !errors.Is(err, fleetlock.ErrLocked) ||
		!strings.Contains(err.Error(), "espdns rollout (-kind config -host 198.51.100.2)") {
		t.Fatal(err)
	}
	// A dry run goes on while the lock is held.
	ctx, dryEnd, err := begin(dir, "rollout", append(args, "-dry-run"), true)
	if err != nil || ctx == nil {
		t.Fatal(err)
	}
	dryEnd(nil)
	end(errors.New("198.51.100.2: not started: another node is unhealthy"))
	if _, held, _ := fleetlock.Held(fleetlock.Path(dir)); held {
		t.Fatal("lock held after the end")
	}
	es, _ := actionlog.Tail(dir, 0)
	var got []string
	for _, e := range es {
		got = append(got, e.Event+" "+e.Action+" "+e.Result)
		if e.Source != "cli" || !strings.HasPrefix(e.ID, "cli-") {
			t.Fatalf("%+v", e)
		}
	}
	if strings.Join(got, ", ") != "start rollout , refused reboot failed, end rollout failed" ||
		es[0].ID != es[2].ID || !strings.Contains(es[2].Error, "unhealthy") {
		t.Fatalf("%v %+v", got, es)
	}

	_, end, err = begin(dir, "identify", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	end(nil)
	if es, _ := actionlog.Tail(dir, 1); es[0].Result != "ok" {
		t.Fatalf("%+v", es)
	}

	if _, _, err := begin(filepath.Join(dir, "none"), "rollout", nil, false); err == nil ||
		!strings.Contains(err.Error(), "-data") {
		t.Fatal(err)
	}
}
