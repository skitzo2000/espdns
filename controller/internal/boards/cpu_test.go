package boards

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// The vectors the firmware's host tests check too (firmware/tests/cpu_vectors.json): the
// same defaults, and the same boards refused.
func TestCPUVectors(t *testing.T) {
	raw, err := os.ReadFile("../../../firmware/tests/cpu_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vec []struct {
		Name  string          `json:"name"`
		Image string          `json:"image"`
		CPU   json.RawMessage `json:"cpu"`
		Error string          `json:"error"`
		Want  struct {
			DFS    bool `json:"dfs"`
			MaxMHz int  `json:"max_mhz"`
			MinMHz int  `json:"min_mhz"`
			APBMHz int  `json:"apb_mhz"`
		} `json:"want"`
	}
	if err := json.Unmarshal(raw, &vec); err != nil {
		t.Fatal(err)
	}
	if len(vec) < 10 {
		t.Fatalf("%d vectors", len(vec))
	}
	for _, v := range vec {
		b := Board{Name: "x", Image: v.Image, FlashMB: 8}
		if string(v.CPU) != "null" {
			b.CPU = &CPU{}
			if err := json.Unmarshal(v.CPU, b.CPU); err != nil {
				t.Fatal(v.Name, err)
			}
		}
		errs, _ := Check(b)
		if v.Error != "" {
			if !has(errs, "cpu "+v.Error) {
				t.Errorf("%s: %v", v.Name, errs)
			}
			continue
		}
		if has(errs, "cpu") {
			t.Errorf("%s: %v", v.Name, errs)
		}
		dfs, maxMHz, minMHz := b.CPUPlan()
		if dfs != v.Want.DFS || maxMHz != v.Want.MaxMHz || minMHz != v.Want.MinMHz || Clocks[v.Image].APBMHz != v.Want.APBMHz {
			t.Errorf("%s: dfs %v, %d/%d MHz, APB %d", v.Name, dfs, maxMHz, minMHz, Clocks[v.Image].APBMHz)
		}
	}
}

// Every chip image has its clocks, and the firmware's message for a clock it hasn't.
func TestCPUClocks(t *testing.T) {
	for im := range Images {
		if _, ok := Clocks[im]; !ok {
			t.Errorf("%s: no clocks", im)
		}
	}
	err := checkCPU(Board{Image: "esp32p4-rev1", CPU: &CPU{MinMHz: p(100)}})
	if err == nil || !strings.Contains(err.Error(), "cpu min_mhz: 90, 180 on esp32p4-rev1, or leave it out for the image's 180") {
		t.Fatal(err)
	}
	if _, err := Parse([]byte(`{"name":"x","image":"esp32","cpu":{"dfs":true,"idle":1}}`)); err == nil {
		t.Fatal("an unknown cpu key was taken")
	}
}
