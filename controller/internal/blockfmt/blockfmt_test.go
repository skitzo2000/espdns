package blockfmt

import (
	"math/rand/v2"
	"slices"
	"testing"
)

func randomSet(r *rand.Rand, n, w int) []uint64 {
	hs := make([]uint64, n)
	for i := range hs {
		hs[i] = r.Uint64() >> (64 - w)
	}
	slices.Sort(hs)
	return slices.Compact(hs)
}

func TestEFSector(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for _, w := range []int{40, 44} {
		for _, n := range []int{0, 1, 2, 101, 5000, 200000} {
			hs := randomSet(r, n, w)
			in := make(map[uint64]bool, len(hs))
			for _, h := range hs {
				in[h] = true
			}
			tb := NewEFSector(hs)
			for _, h := range hs {
				if !tb.Contains(h) {
					t.Fatalf("w=%d n=%d: member %#x missing", w, n, h)
				}
				// Neighbours of members are the hard non-members.
				for _, d := range []uint64{h - 1, h + 1} {
					if d>>w == 0 && tb.Contains(d) != in[d] {
						t.Fatalf("w=%d n=%d: %#x wrong", w, n, d)
					}
				}
			}
			for range 20000 {
				h := r.Uint64() >> (64 - w)
				if tb.Contains(h) != in[h] {
					t.Fatalf("w=%d n=%d: random %#x wrong", w, n, h)
				}
			}
		}
	}
}

func TestXorHasNoFalseNegatives(t *testing.T) {
	r := rand.New(rand.NewPCG(3, 4))
	hs := randomSet(r, 100000, 40)
	x, err := NewXor(hs, 8)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range hs {
		if !x.Contains(h) {
			t.Fatalf("member %#x missing", h)
		}
	}
	fp := 0
	for range 100000 {
		if x.Contains(r.Uint64() >> 24) {
			fp++
		}
	}
	if fp < 200 || fp > 600 { // expect 1 in 256: ~390
		t.Errorf("false positives %d in 100000", fp)
	}
}
