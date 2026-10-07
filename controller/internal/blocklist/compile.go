package blocklist

import (
	"fmt"
	"math/bits"
	"slices"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// Compiled is a deduplicated list: names blocked exactly, names blocked with their
// subdomains, and the same two kinds of allowed names. A name's verdict comes from the most
// specific entry that matches it (an exact entry matches only its own name, a suffix entry
// the name and its subdomains); at the same name, allow beats block (see Verdict).
type Compiled struct {
	Exact, Suffix           []string
	AllowExact, AllowSuffix []string
	Stats                   CompileStats
}

type CompileStats struct {
	In           int // entries read from all lists
	Duplicates   int // same name and kind more than once
	Covered      int // a parent's suffix entry already gives the same verdict
	PublicSuffix int // a public suffix or TLD (com, co.uk, github.io): never blocked or allowed
	Overruled    int // block entries dropped for an allow entry for the same name
}

// An entry's kind, as bits of the kinds a name has.
const (
	kExact uint8 = 1 << iota
	kSuffix
	kAllowExact
	kAllowSuffix
)

func kindOf(e Entry) uint8 {
	switch {
	case e.Allow && e.Suffix:
		return kAllowSuffix
	case e.Allow:
		return kAllowExact
	case e.Suffix:
		return kSuffix
	}
	return kExact
}

// Compile merges entries from any number of lists, block and allow alike. It keeps every
// answer Verdict gives and drops what can't change one: an entry whose nearest parent
// suffix entry (or, for an exact entry, a suffix entry for the same name) gives the same
// verdict, and a block entry for a name with an allow entry that matches the same names.
func Compile(entries []Entry) *Compiled {
	c := &Compiled{Stats: CompileStats{In: len(entries)}}
	kinds := make(map[string]uint8, len(entries))
	for _, e := range entries {
		if ps, _ := publicsuffix.PublicSuffix(e.Name); ps == e.Name {
			c.Stats.PublicSuffix++
			continue
		}
		k := kindOf(e)
		if kinds[e.Name]&k != 0 {
			c.Stats.Duplicates++
			continue
		}
		kinds[e.Name] |= k
	}
	// At one name, allow beats block: an allow suffix entry overrules both block entries,
	// an allow exact entry the block exact one. (An allow exact entry and a block suffix
	// entry both stay: the name is allowed, its subdomains blocked.)
	for n, k := range kinds {
		drop := uint8(0)
		if k&kAllowSuffix != 0 {
			drop = k & (kExact | kSuffix)
		} else if k&kAllowExact != 0 {
			drop = k & kExact
		}
		if drop != 0 {
			c.Stats.Overruled += bits.OnesCount8(drop)
			kinds[n] = k &^ drop
		}
	}
	// The suffix entry (kSuffix or kAllowSuffix, never both now) nearest above n, or 0.
	above := func(n string) uint8 {
		for i := strings.IndexByte(n, '.'); i >= 0; i = strings.IndexByte(n, '.') {
			n = n[i+1:]
			if k := kinds[n] & (kSuffix | kAllowSuffix); k != 0 {
				return k
			}
		}
		return 0
	}
	keep := func(out *[]string, n string, k, inherited uint8) {
		if k == inherited {
			c.Stats.Covered++
		} else {
			*out = append(*out, n)
		}
	}
	for n, k := range kinds {
		up := above(n)
		here := k & (kSuffix | kAllowSuffix)
		if here == 0 {
			here = up
		}
		if k&kSuffix != 0 {
			keep(&c.Suffix, n, kSuffix, up)
		}
		if k&kAllowSuffix != 0 {
			keep(&c.AllowSuffix, n, kAllowSuffix, up)
		}
		if k&kExact != 0 {
			keep(&c.Exact, n, kSuffix, here)
		}
		if k&kAllowExact != 0 {
			keep(&c.AllowExact, n, kAllowSuffix, here)
		}
	}
	for _, l := range [][]string{c.Exact, c.Suffix, c.AllowExact, c.AllowSuffix} {
		slices.Sort(l)
	}
	return c
}

// Verdict is what a list says about a name.
type Verdict uint8

const (
	None  Verdict = iota // no entry matches
	Block                // blocked
	Allow                // allowed: for overrides, the main lists are not checked
)

// The tables of a list file, in file order.
const (
	TExact = iota
	TSuffix
	TAllowExact
	TAllowSuffix
	NTables
)

// decide is the lookup the node makes: the canonical name and each parent with two labels
// or more, most specific first; the first that matches decides, allow before block.
// Exact entries match only the name itself.
func decide(name string, in func(table int, n string) bool) Verdict {
	for i, s := range Suffixes(name) {
		if in(TAllowSuffix, s) || i == 0 && in(TAllowExact, s) {
			return Allow
		}
		if in(TSuffix, s) || i == 0 && in(TExact, s) {
			return Block
		}
	}
	return None
}

// Verdict judges names by the entries themselves (no hashes): what the list means.
// The names must be canonical (Canon).
func (c *Compiled) Verdict() func(name string) Verdict {
	var sets [NTables]map[string]struct{}
	for t, l := range [NTables][]string{c.Exact, c.Suffix, c.AllowExact, c.AllowSuffix} {
		sets[t] = make(map[string]struct{}, len(l))
		for _, n := range l {
			sets[t][n] = struct{}{}
		}
	}
	return func(name string) Verdict {
		return decide(name, func(t int, n string) bool { _, ok := sets[t][n]; return ok })
	}
}

// CheckMustResolve refuses a list that blocks any of names (the must-resolve list: local
// zones, forwarders, NTP, OS update hosts, everyday sites), naming the ones it blocks.
// Names that aren't valid names for a list are ignored.
func (c *Compiled) CheckMustResolve(names []string) error {
	v := c.Verdict()
	var bad []string
	for _, n := range names {
		if cn, ok := Canon(n); ok && v(cn) == Block {
			bad = append(bad, cn)
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("the list blocks %d must-resolve name(s): %s", len(bad), strings.Join(bad, ", "))
	}
	return nil
}

// Tables are a list's four hash sets (TExact..TAllowSuffix), each sorted, as WriteFile
// takes them.
type Tables [NTables][]uint64

// Hashes hashes all four sets with one key and width.
func (c *Compiled) Hashes(k Key, w uint) Tables {
	return Tables{Hashes(k, c.Exact, w), Hashes(k, c.Suffix, w), Hashes(k, c.AllowExact, w), Hashes(k, c.AllowSuffix, w)}
}

// Verdict judges a canonical name by hashes, as the node does (bl_verdict); it differs from
// Compiled.Verdict only where hashes collide.
func (t *Tables) Verdict(k Key, w uint, name string) Verdict {
	return decide(name, func(i int, n string) bool { _, ok := slices.BinarySearch(t[i], Hash(k, n, w)); return ok })
}

// Reversed puts a name's labels in reverse order ("ads.example.com" → "com.example.ads"),
// the form that is hashed. Every suffix of a name is then a prefix of its reversed form,
// so the node can hash all of a query's suffixes in one pass from the right.
func Reversed(name string) string {
	var b strings.Builder
	b.Grow(len(name))
	for end := len(name); end > 0; {
		i := strings.LastIndexByte(name[:end], '.')
		if b.Len() > 0 {
			b.WriteByte('.')
		}
		b.WriteString(name[i+1 : end])
		end = i
	}
	return b.String()
}

// Hash is the top w bits of the keyed hash of a canonical name.
func Hash(k Key, name string, w uint) uint64 {
	return SipHash(k, []byte(Reversed(name))) >> (64 - w)
}

// Suffixes lists the names a query is checked against in the suffix table: the name and
// each parent with at least two labels.
func Suffixes(name string) []string {
	out := []string{name}
	for {
		i := strings.IndexByte(name, '.')
		name = name[i+1:]
		if strings.IndexByte(name, '.') < 0 {
			return out
		}
		out = append(out, name)
	}
}

// Hashes hashes names into a sorted set with no repeats (two names can share a hash).
func Hashes(k Key, names []string, w uint) []uint64 {
	hs := make([]uint64, len(names))
	for i, n := range names {
		hs[i] = Hash(k, n, w)
	}
	slices.Sort(hs)
	return slices.Compact(hs)
}
