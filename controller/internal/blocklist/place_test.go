package blocklist

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// The vectors the firmware's host tests check too (firmware/tests/gen_place_vectors.py):
// the controller places a list as the node does.
func TestPlaceVectors(t *testing.T) {
	raw, err := os.ReadFile("../../../firmware/tests/place_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vec []struct {
		Name    string `json:"name"`
		Header  string `json:"header"`
		FileLen int64  `json:"file_len"`
		Room    struct {
			Budget      int64 `json:"budget"`
			Used        int64 `json:"used"`
			Held        int64 `json:"held"`
			IndexBudget int64 `json:"index_budget"`
			IndexUsed   int64 `json:"index_used"`
			IndexHeld   int64 `json:"index_held"`
			RAMTier     bool  `json:"ram_tier"`
			Overrides   bool  `json:"overrides"`
		} `json:"room"`
		Want struct {
			Error string `json:"error"`
			Need  *struct {
				Front, Index, Sectors int64
				Entries               uint32
			} `json:"need"`
			Tier          string `json:"tier"`
			Now           bool   `json:"now"`
			IndexInternal bool   `json:"index_internal"`
		} `json:"want"`
	}
	if err := json.Unmarshal(raw, &vec); err != nil {
		t.Fatal(err)
	}
	if len(vec) < 20 {
		t.Fatalf("%d vectors", len(vec))
	}
	for _, v := range vec {
		hdr, err := hex.DecodeString(v.Header)
		if err != nil {
			t.Fatal(err)
		}
		n, err := PlanNeed(hdr, v.FileLen)
		if v.Want.Need == nil {
			if err == nil || err.Error() != v.Want.Error {
				t.Errorf("%s: plan %v, want %q", v.Name, err, v.Want.Error)
			}
			continue
		}
		w := v.Want.Need
		if err != nil || n != (Need{w.Front, w.Index, w.Sectors, w.Entries}) {
			t.Errorf("%s: need %+v (%v), want %+v", v.Name, n, err, *w)
			continue
		}
		r := v.Room
		pl, err := Place(n, Room{r.Budget, r.Used, r.Held, r.IndexBudget, r.IndexUsed, r.IndexHeld, r.RAMTier, r.Overrides})
		msg := ""
		if err != nil {
			msg = err.Error()
		}
		if msg != v.Want.Error {
			t.Errorf("%s: %q, want %q", v.Name, msg, v.Want.Error)
			continue
		}
		tier := map[Tier]string{RAMTier: "ram", SDTier: "sd"}[pl.Tier]
		if err == nil && (tier != v.Want.Tier || pl.Now != v.Want.Now || pl.IndexInternal != v.Want.IndexInternal) {
			t.Errorf("%s: %+v, want %s now %v index internal %v", v.Name, pl, v.Want.Tier, v.Want.Now, v.Want.IndexInternal)
		}
	}
}
