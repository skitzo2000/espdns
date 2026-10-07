package blocklist

import (
	"crypto/rand"
	"fmt"
	"io"
	"slices"
)

// BuildOptions are the choices that turn a compiled list into the file a node loads.
type BuildOptions struct {
	Bits    int // hash width (44 is the chosen format)
	XorBits int // xor filter fingerprint bits for the SD tier; 0 for none (the overrides)
	// Popular names (canonical) the list must never block by accident; names the list
	// blocks on purpose are left out of the check.
	Popular []string
	// The must-resolve list: local zones, forwarders, NTP, update hosts, everyday sites.
	// A list that blocks one on purpose is refused; accidental matches are dropped.
	MustResolve []string
	Keys        int       // keys to try before dropping entries (at least 1)
	Rand        io.Reader // nil: crypto/rand
}

// BuildStats says how the build went.
type BuildStats struct {
	Key     Key
	Tries   int // keys tried
	Dropped int // block hashes dropped because a protected name matched them by accident
	File    FileStats
}

// Build draws a SipHash key, checks every protected name (Popular and MustResolve)
// against the hashed tables, tries up to Keys keys for one that blocks none of them by
// accident, and then drops each block hash a protected name still matches: a handful of
// rare blocked names go unblocked instead of a popular one being blocked
// (docs/design.md, "No collisions on popular names"). Returns the file.
func Build(c *Compiled, o BuildOptions) ([]byte, BuildStats, error) {
	var st BuildStats
	if err := c.CheckMustResolve(o.MustResolve); err != nil {
		return nil, st, err
	}
	if o.Bits < 16 || o.Bits > 64 {
		return nil, st, fmt.Errorf("bad hash width %d", o.Bits)
	}
	w := uint(o.Bits)
	verdict := c.Verdict()
	var protect []string
	for _, l := range [][]string{o.Popular, o.MustResolve} {
		for _, n := range l {
			if cn, ok := Canon(n); ok && verdict(cn) != Block {
				protect = append(protect, cn)
			}
		}
	}
	rnd := o.Rand
	if rnd == nil {
		rnd = rand.Reader
	}
	var ts Tables
	var hits []string
	for st.Tries < max(o.Keys, 1) {
		var b [16]byte
		if _, err := io.ReadFull(rnd, b[:]); err != nil {
			return nil, st, err
		}
		st.Tries++
		k := KeyFromBytes(b)
		t := c.Hashes(k, w)
		var h []string
		for _, n := range protect {
			if t.Verdict(k, w, n) == Block {
				h = append(h, n)
			}
		}
		if st.Tries == 1 || len(h) < len(hits) {
			st.Key, ts, hits = k, t, h
		}
		if len(hits) == 0 {
			break
		}
	}
	st.Dropped = dropCollisions(c, &ts, st.Key, w, hits)
	file, fs, err := WriteFile(st.Key, o.Bits, o.XorBits, ts)
	st.File = fs
	return file, st, err
}

// dropCollisions removes, for each name, the block hashes it matches without the list
// naming it: at its own name in the exact table, and at it and each parent in the suffix
// table. Returns how many hashes went.
func dropCollisions(c *Compiled, ts *Tables, k Key, w uint, names []string) int {
	exact, suffix := set(c.Exact), set(c.Suffix)
	drop := [2]map[uint64]bool{{}, {}}
	for _, n := range names {
		for i, s := range Suffixes(n) {
			if _, ok := suffix[s]; !ok {
				drop[TSuffix][Hash(k, s, w)] = true
			}
			if _, ok := exact[s]; i == 0 && !ok {
				drop[TExact][Hash(k, s, w)] = true
			}
		}
	}
	n := 0
	for t := range drop {
		before := len(ts[t])
		ts[t] = slices.DeleteFunc(ts[t], func(h uint64) bool { return drop[t][h] })
		n += before - len(ts[t])
	}
	return n
}

func set(l []string) map[string]struct{} {
	m := make(map[string]struct{}, len(l))
	for _, n := range l {
		m[n] = struct{}{}
	}
	return m
}
