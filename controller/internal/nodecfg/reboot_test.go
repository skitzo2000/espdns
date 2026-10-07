package nodecfg

import (
	"encoding/json"
	"os"
	"slices"
	"testing"
)

// The vectors the firmware's host tests check cfg_reboot_reasons on too
// (firmware/tests/cfg_reboot_vectors.json): the node's reboot reasons are always among
// Reboot and Maybe, and include every one in Reboot.
func TestCompareVectors(t *testing.T) {
	raw, err := os.ReadFile("../../../firmware/tests/cfg_reboot_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vec []struct {
		Name                string
		From, To            json.RawMessage
		Reboot, Maybe, Live []string
	}
	if err := json.Unmarshal(raw, &vec); err != nil {
		t.Fatal(err)
	}
	if len(vec) < 20 {
		t.Fatalf("%d vectors", len(vec))
	}
	for _, v := range vec {
		from, err := Parse(v.From)
		if err != nil {
			t.Fatalf("%s: from: %v", v.Name, err)
		}
		to, err := Parse(v.To)
		if err != nil {
			t.Fatalf("%s: to: %v", v.Name, err)
		}
		ch := Compare(from, to, nil)
		if !slices.Equal(ch.Reboot, v.Reboot) || !slices.Equal(ch.Maybe, v.Maybe) || !slices.Equal(ch.Live, v.Live) {
			t.Errorf("%s: reboot %q maybe %q live %q; want %q %q %q", v.Name, ch.Reboot, ch.Maybe, ch.Live, v.Reboot, v.Maybe, v.Live)
		}
		if ch.NeedsReboot() != (len(v.Reboot) > 0) {
			t.Errorf("%s: NeedsReboot %v", v.Name, ch.NeedsReboot())
		}
	}
}

// The address the node reports stands in for a config that leaves it out.
func TestCompareRunning(t *testing.T) {
	from, _ := Parse([]byte(`{}`))
	to, _ := Parse([]byte(`{"network":{"address":"192.0.2.253/23","gateway":"192.0.2.1"}}`))
	run := &Network{Address: "192.0.2.253/23", Gateway: "192.0.2.1"}
	if ch := Compare(from, to, run); len(ch.Reboot) != 0 || len(ch.Maybe) != 0 {
		t.Errorf("same address as running: %+v", ch)
	}
	run.Address = "192.0.2.9/23"
	if ch := Compare(from, to, run); !slices.Equal(ch.Reboot, []string{ReasonAddress}) {
		t.Errorf("other address than running: %+v", ch)
	}
	if ch := Compare(nil, nil, run); len(ch.Reboot)+len(ch.Maybe)+len(ch.Live) != 0 {
		t.Errorf("nil configs: %+v", ch)
	}
}
