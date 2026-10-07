package blocklist

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
)

func randomNames(r *rand.Rand, n int, tld string) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("n%x-%d.%s", r.Uint64(), i, tld)
	}
	return out
}

// With 16-bit hashes, popular names collide with the list; Build drops exactly the hashes
// they hit, so none is blocked and every other entry still is.
func TestBuildDropsCollisions(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	blocked := randomNames(r, 2000, "com")
	var entries []Entry
	for i, n := range blocked {
		entries = append(entries, Entry{Name: n, Suffix: i%2 == 0})
	}
	popular := randomNames(r, 5000, "net")
	popular = append(popular, "www."+blocked[0]) // blocked on purpose: not protected
	c := Compile(entries)

	const w = 16
	k := Key{1, 2}
	ts := c.Hashes(k, w)
	var hits []string
	for _, n := range popular[:len(popular)-1] {
		if ts.Verdict(k, w, n) == Block {
			hits = append(hits, n)
		}
	}
	if len(hits) == 0 {
		t.Fatal("expected collisions at 16 bits")
	}
	before := ts
	before[TExact], before[TSuffix] = slices.Clone(ts[TExact]), slices.Clone(ts[TSuffix])
	dropped := dropCollisions(c, &ts, k, w, hits)
	if dropped == 0 {
		t.Fatal("nothing dropped")
	}
	for _, n := range popular[:len(popular)-1] {
		if ts.Verdict(k, w, n) == Block {
			t.Fatalf("%s still blocked", n)
		}
	}
	// An entry goes unblocked only if its own hash went (at 16 bits, a hash is often
	// shared by several entries).
	lost := 0
	for i, n := range blocked {
		tb := TExact
		if i%2 == 0 {
			tb = TSuffix
		}
		h := Hash(k, n, w)
		_, was := slices.BinarySearch(before[tb], h)
		_, is := slices.BinarySearch(ts[tb], h)
		if !was {
			t.Fatalf("%s not in its table", n)
		}
		if !is {
			lost++
		} else if ts.Verdict(k, w, n) != Block {
			t.Fatalf("%s kept its hash but isn't blocked", n)
		}
	}
	if lost < dropped/2 || lost > len(blocked)/5 {
		t.Errorf("%d entries lost their hash for %d hashes dropped", lost, dropped)
	}

	// The whole build: the key it reports is the one in the file.
	file, st, err := Build(c, BuildOptions{Bits: w, XorBits: 8, Popular: popular, Keys: 3,
		Rand: rand.NewChaCha8([32]byte{7})})
	if err != nil {
		t.Fatal(err)
	}
	if st.Tries != 3 || st.Dropped == 0 || !bytes.HasPrefix(file, []byte(FileMagic)) || file[9] != w || file[10] != 8 {
		t.Errorf("stats %+v, header %x", st, file[:16])
	}
	if binary.LittleEndian.Uint64(file[16:]) != st.Key.K0 || binary.LittleEndian.Uint64(file[24:]) != st.Key.K1 {
		t.Error("key in the file differs")
	}
}

func TestBuildMustResolve(t *testing.T) {
	c := Compile([]Entry{{Name: "ads.example.com", Suffix: true}, {Name: "tracker.example.org"}})
	if _, _, err := Build(c, BuildOptions{Bits: 44, MustResolve: []string{"x.ads.example.com"}}); err == nil ||
		!strings.Contains(err.Error(), "x.ads.example.com") {
		t.Errorf("must-resolve name blocked on purpose: %v", err)
	}
	file, st, err := Build(c, BuildOptions{Bits: 44, XorBits: 0, MustResolve: []string{"example.com"}, Keys: 5})
	if err != nil || st.Tries != 1 || st.Dropped != 0 || file[10] != 0 {
		t.Errorf("clean build: %v %+v", err, st)
	}
}
