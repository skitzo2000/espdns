package memplan_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/skitzo2000/espdns/controller/internal/boards"
	"github.com/skitzo2000/espdns/controller/internal/memplan"
	"github.com/skitzo2000/espdns/controller/internal/nodecfg"
)

// The vectors the firmware's host tests check too (firmware/tests/gen_memplan_vectors.py):
// the controller and the node agree on every plan.
func TestVectors(t *testing.T) {
	raw, err := os.ReadFile("../../../firmware/tests/memplan_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vec []struct {
		Name        string          `json:"name"`
		Image       string          `json:"image"`
		ChipPSRAMKB int             `json:"chip_psram_kb"`
		Board       json.RawMessage `json:"board"`
		Services    []string        `json:"services"`
		Want        struct {
			Board    memplan.Board       `json:"board"`
			Fits     bool                `json:"fits"`
			Error    string              `json:"error"`
			Capacity [2]int64            `json:"capacity"`
			Total    [2]int64            `json:"total"`
			Shares   map[string][2]int64 `json:"shares"`
		} `json:"want"`
	}
	if err := json.Unmarshal(raw, &vec); err != nil {
		t.Fatal(err)
	}
	if len(vec) < 10 {
		t.Fatalf("%d vectors", len(vec))
	}
	for _, v := range vec {
		var k memplan.Keys
		if string(v.Board) != "null" {
			b, err := boards.Parse(v.Board)
			if err != nil {
				t.Fatalf("%s: %v", v.Name, err)
			}
			k = b.MemoryKeys()
		}
		got := memplan.Values(k, v.Image, v.ChipPSRAMKB)
		if got != v.Want.Board {
			t.Errorf("%s: board %+v, want %+v", v.Name, got, v.Want.Board)
		}
		p, err := memplan.Make(got, v.Services)
		msg := ""
		if err != nil {
			msg = err.Error()
		}
		if (err == nil) != v.Want.Fits || msg != v.Want.Error {
			t.Errorf("%s: %q, want %q", v.Name, msg, v.Want.Error)
		}
		if p.Capacity != v.Want.Capacity || p.Total != v.Want.Total {
			t.Errorf("%s: capacity %v total %v, want %v %v", v.Name, p.Capacity, p.Total, v.Want.Capacity, v.Want.Total)
		}
		for s, want := range v.Want.Shares {
			if p.Shares[s] != want {
				t.Errorf("%s: %s %v, want %v", v.Name, s, p.Shares[s], want)
			}
		}
	}
}

// What a node config runs, as the node works it out (svc_enabled), with the firmware's
// defaults for what the config leaves out.
func TestConfigServices(t *testing.T) {
	cases := []struct {
		json string
		want []string
	}{
		{`{}`, []string{"dns", "forwarding", "forward_zones", "secondary", "hosted", "blocking", "querylog"}},
		{`{"forwarders":[],"forward_zones":[],"secondary":{"zones":[]},"hosted":{"enabled":false},` +
			`"blocking":{"enabled":false},"querylog":{"enabled":false}}`, []string{"dns"}},
		{`{"blocking":{"enabled":false},"secondary":{"zones":["local"]}}`,
			[]string{"dns", "forwarding", "forward_zones", "secondary", "hosted", "querylog"}},
		{`{"querylog":{"client":"hidden"}}`,
			[]string{"dns", "forwarding", "forward_zones", "secondary", "hosted", "blocking", "querylog"}},
	}
	for _, c := range cases {
		cfg, err := nodecfg.Parse([]byte(c.json))
		if err != nil {
			t.Fatal(err)
		}
		got := cfg.Services()
		if len(got) != len(c.want) {
			t.Errorf("%s: %v, want %v", c.json, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%s: %v, want %v", c.json, got, c.want)
			}
		}
	}
}
