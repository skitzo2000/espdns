package blocklist

import (
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
)

// Vectors from the SipHash reference implementation: key 00..0f, message 00..n-1.
func TestSipHashVectors(t *testing.T) {
	var kb [16]byte
	for i := range kb {
		kb[i] = byte(i)
	}
	k := KeyFromBytes(kb)
	want := map[int]uint64{
		0:  0x726fdb47dd0e0e31,
		1:  0x74f839c593dc67fd,
		2:  0x0d6c8009d9a94f5a,
		3:  0x85676696d7fb7e2d,
		8:  0x93f5f5799a932462,
		15: 0xa129ca6149be45e5,
	}
	msg := make([]byte, 64)
	for i := range msg {
		msg[i] = byte(i)
	}
	for n, w := range want {
		if got := SipHash(k, msg[:n]); got != w {
			t.Errorf("len %d: got %#x, want %#x", n, got, w)
		}
	}
}

func TestCanon(t *testing.T) {
	for in, want := range map[string]string{
		"Ads.Example.COM.": "ads.example.com",
		" x_y.example.org": "x_y.example.org",
		"localhost":        "",
		"0.0.0.0":          "",
		"a..b":             "",
		"ex*mple.com":      "",
		"example.":         "",
	} {
		got, ok := Canon(in)
		if (want == "") == ok || got != want {
			t.Errorf("Canon(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
}

func TestParseAndCompile(t *testing.T) {
	var es []Entry
	add := func(k Kind, s string) {
		if _, err := Parse(strings.NewReader(s), k, func(e Entry) { es = append(es, e) }); err != nil {
			t.Fatal(err)
		}
	}
	add(Hosts, "# c\n127.0.0.1 localhost\n0.0.0.0 ads.example.com t.example.com\n0.0.0.0 keep.example.net\n")
	add(Adblock, "! c\n||example.com^\n||x.y.com/path^$third-party\n||github.io^\n")
	add(Wildcard, "*.tracker.org\ntracker.org\nsub.tracker.org\n")
	c := Compile(es)
	if !slices.Equal(c.Exact, []string{"keep.example.net"}) {
		t.Errorf("exact = %v", c.Exact)
	}
	if !slices.Equal(c.Suffix, []string{"example.com", "tracker.org"}) {
		t.Errorf("suffix = %v", c.Suffix)
	}
	if c.Stats.PublicSuffix != 1 || c.Stats.Duplicates != 1 || c.Stats.Covered != 3 {
		t.Errorf("stats = %+v", c.Stats)
	}
}

func TestReversedSuffixes(t *testing.T) {
	if got := Reversed("a.b.example.com"); got != "com.example.b.a" {
		t.Errorf("Reversed = %q", got)
	}
	if got := Suffixes("a.b.example.com"); !slices.Equal(got, []string{"a.b.example.com", "b.example.com", "example.com"}) {
		t.Errorf("Suffixes = %v", got)
	}
}

// The precedence rules: the most specific match decides, allow beats block at one name.
func TestAllowPrecedence(t *testing.T) {
	var es []Entry
	add := func(k Kind, allow bool, s string) {
		if _, err := Parse(strings.NewReader(s), k, func(e Entry) { e.Allow = e.Allow || allow; es = append(es, e) }); err != nil {
			t.Fatal(err)
		}
	}
	add(Adblock, false, "||ads.com^\n||track.net^\n@@||ok.track.net^\n||deep.ok.track.net^\n")
	add(Hosts, false, "0.0.0.0 x.site.org y.site.org Both.Org.\n")
	add(Wildcard, false, "pair.io\n")
	add(Domains, true, "WWW.Ads.COM.\nnowhere.example\nboth.org\npair.io\n")
	add(Wildcard, true, "site.org\nfree.example\n")
	add(Wildcard, false, "deny.site.org\n")
	c := Compile(es)
	key := KeyFromBytes([16]byte{1, 2, 3})
	ts := c.Hashes(key, 64)
	v := c.Verdict()
	for q, want := range map[string]Verdict{
		"ads.com":             Block, // block suffix
		"www.ads.com":         Allow, // allow exact beats the blocked parent
		"a.www.ads.com":       Block, // ... but only that name
		"x.ads.com":           Block,
		"track.net":           Block,
		"ok.track.net":        Allow, // allow suffix under a block suffix
		"z.ok.track.net":      Allow,
		"deep.ok.track.net":   Block, // block suffix deeper again
		"a.deep.ok.track.net": Block,
		"x.site.org":          Block, // block exact deeper than an allow suffix
		"z.x.site.org":        Allow, //   covers only that name
		"y.site.org":          Block,
		"site.org":            Allow,
		"deny.site.org":       Block, // block suffix deeper than the allow suffix
		"q.deny.site.org":     Block,
		"nowhere.example":     Allow, // allow entry for a name no list blocks
		"x.nowhere.example":   None,
		"q.free.example":      Allow,
		"both.org":            Allow, // allow exact and block exact for one name: allow
		"pair.io":             Allow, // allow exact and block suffix for one name: the name is allowed,
		"sub.pair.io":         Block, //   its subdomains blocked
		"unrelated.com":       None,
	} {
		if got := v(q); got != want {
			t.Errorf("Verdict(%q) = %d, want %d", q, got, want)
		}
		if got := ts.Verdict(key, 64, q); got != want {
			t.Errorf("hashed Verdict(%q) = %d, want %d", q, got, want)
		}
	}
	// both.org: block exact overruled by allow exact; pair.io keeps both.
	if c.Stats.Overruled != 1 || !slices.Contains(c.Suffix, "pair.io") || !slices.Contains(c.AllowExact, "pair.io") {
		t.Errorf("stats %+v, suffix %v, allow exact %v", c.Stats, c.Suffix, c.AllowExact)
	}
	if err := c.CheckMustResolve([]string{"www.ads.com", "ok.track.net", "Example.COM."}); err != nil {
		t.Error(err)
	}
	if err := c.CheckMustResolve([]string{"www.ads.com", "Deep.OK.track.net."}); err == nil || !strings.Contains(err.Error(), "deep.ok.track.net") {
		t.Errorf("must-resolve: %v", err)
	}
}

// Compile drops only entries that can't change a verdict: on random overlapping lists,
// every name gets the same verdict as from all the entries.
func TestCompileKeepsVerdicts(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	labels := []string{"a", "b", "c"}
	var names []string
	var walk func(n string, depth int)
	walk = func(n string, depth int) {
		names = append(names, n)
		if depth < 4 {
			for _, l := range labels {
				walk(l+"."+n, depth+1)
			}
		}
	}
	walk("x.com", 0)
	for round := range 200 {
		var es []Entry
		for range 1 + r.IntN(25) {
			es = append(es, Entry{Name: names[r.IntN(len(names))], Suffix: r.IntN(2) == 0, Allow: r.IntN(3) == 0})
		}
		all := Compiled{}
		for _, e := range es {
			l := map[[2]bool]*[]string{{false, false}: &all.Exact, {true, false}: &all.Suffix, {false, true}: &all.AllowExact, {true, true}: &all.AllowSuffix}[[2]bool{e.Suffix, e.Allow}]
			*l = append(*l, e.Name)
		}
		want, got := all.Verdict(), Compile(es).Verdict()
		for _, n := range names {
			if want(n) != got(n) {
				t.Fatalf("round %d: %s: compiled %d, entries %d (entries %+v)", round, n, got(n), want(n), es)
			}
		}
	}
}
