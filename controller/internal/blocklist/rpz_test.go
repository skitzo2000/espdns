package blocklist

import (
	"os"
	"slices"
	"strings"
	"testing"
)

func parseRPZFile(t *testing.T, path string) (ParseStats, []Entry) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var es []Entry
	st, err := Parse(f, RPZ, func(e Entry) { es = append(es, e) })
	if err != nil {
		t.Fatal(err)
	}
	return st, es
}

func TestParseKindRPZ(t *testing.T) {
	k, err := ParseKind("rpz")
	if err != nil || k != RPZ || k.String() != "rpz" {
		t.Fatalf("ParseKind(rpz) = %v, %v", k, err)
	}
}

func TestRPZFeed(t *testing.T) {
	st, es := parseRPZFile(t, "testdata/feed.rpz")
	want := []Entry{
		{"ads.example.com", false, false},
		{"ads.example.com", true, false},
		{"tracker.example.net", false, false},
		{"metrics.example.net", true, false},
		{"nodata.example.org", false, false},
		{"drop.example.com", false, false},
		{"ok.ads.example.com", false, true},
		{"cdn.example.net", true, true},
	}
	if !slices.Equal(es, want) {
		t.Errorf("entries:\n got %v\nwant %v", es, want)
	}
	wantRPZ := RPZStats{Blocked: 5, Drop: 1, Allowed: 2, Wildcard: 3, LocalData: 4, TCPOnly: 1,
		IP: 1, ClientIP: 1, NSDName: 1, NSIP: 1, Zone: 2, BadName: 3, Includes: 1}
	if *st.RPZ != wantRPZ {
		t.Errorf("rpz stats:\n got %+v\nwant %+v", *st.RPZ, wantRPZ)
	}
	if st.Entries != 8 || st.Skipped != 13 {
		t.Errorf("entries %d skipped %d, want 8 and 13", st.Entries, st.Skipped)
	}
}

func TestRPZOrigin(t *testing.T) {
	st, es := parseRPZFile(t, "testdata/origin.rpz")
	want := []Entry{
		{"ads.example.com", false, false},
		{"ads.example.com", false, false},
		{"track.example.net", true, false},
		{"beacon.example.com", false, false},
		{"pixel.example.com", true, false},
	}
	if !slices.Equal(es, want) {
		t.Errorf("entries:\n got %v\nwant %v", es, want)
	}
	wantRPZ := RPZStats{Blocked: 4, Drop: 1, Wildcard: 2, Zone: 2, Outside: 1, LocalData: 1}
	if *st.RPZ != wantRPZ {
		t.Errorf("rpz stats:\n got %+v\nwant %+v", *st.RPZ, wantRPZ)
	}
}

// The zone's apex without an SOA: the first $ORIGIN; without either, the names as written.
func TestRPZApex(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"$ORIGIN rpz.example.org.\nads.example.com CNAME .\n", "ads.example.com"},
		{"ads.example.com CNAME .\n", "ads.example.com"},
		{"ads.example.com. CNAME .\n", "ads.example.com"},
		// An SOA after the records still sets the apex
		{"ads.example.com.rpz.example.org. CNAME .\nrpz.example.org. SOA a. b. 1 2 3 4 5\n", "ads.example.com"},
	} {
		var es []Entry
		if _, err := Parse(strings.NewReader(tc.in), RPZ, func(e Entry) { es = append(es, e) }); err != nil {
			t.Fatal(err)
		}
		if len(es) != 1 || es[0].Name != tc.want {
			t.Errorf("%q: got %v, want %s", tc.in, es, tc.want)
		}
	}
}

// The RPZ's actions compile as the other kinds do: passthru under a wildcard block leaves
// the name allowed and its subdomains blocked.
func TestRPZCompile(t *testing.T) {
	_, es := parseRPZFile(t, "testdata/feed.rpz")
	c := Compile(es)
	v := c.Verdict()
	for name, want := range map[string]Verdict{
		"ads.example.com":         Block,
		"x.ads.example.com":       Block,
		"ok.ads.example.com":      Allow,
		"tracker.example.net":     Block,
		"a.tracker.example.net":   None,
		"metrics.example.net":     Block,
		"a.b.metrics.example.net": Block,
		"cdn.example.net":         Allow,
		"walled.example.com":      None, // local data: skipped
	} {
		if got := v(name); got != want {
			t.Errorf("%s: %v, want %v", name, got, want)
		}
	}
}

// The older passthru: a CNAME to the trigger's own name allows it (and only that: a CNAME
// to another name is local data).
func TestRPZOldPassthru(t *testing.T) {
	in := "$ORIGIN rpz.example.org.\n@ SOA a. b. 1 2 3 4 5\n" +
		"ok.example.com CNAME ok.example.com.\n" +
		"*.cdn.example.net CNAME *.cdn.example.net.\n" +
		"other.example.com CNAME ok.example.com.\n"
	var es []Entry
	st, err := Parse(strings.NewReader(in), RPZ, func(e Entry) { es = append(es, e) })
	if err != nil {
		t.Fatal(err)
	}
	want := []Entry{{"ok.example.com", false, true}, {"cdn.example.net", true, true}}
	if !slices.Equal(es, want) || st.RPZ.Allowed != 2 || st.RPZ.LocalData != 1 {
		t.Fatalf("got %v %+v, want %v", es, *st.RPZ, want)
	}
}

// What the suffix entry for *.name can't say: a passthru *.name beside a block for name
// allows name too (allow beats block at one name; RPZ would block it). Pinned, as documented.
func TestRPZWildcardPassthruOverExact(t *testing.T) {
	in := "bad.example.com CNAME .\n*.bad.example.com CNAME rpz-passthru.\n"
	var es []Entry
	if _, err := Parse(strings.NewReader(in), RPZ, func(e Entry) { es = append(es, e) }); err != nil {
		t.Fatal(err)
	}
	v := Compile(es).Verdict()
	if v("bad.example.com") != Allow || v("x.bad.example.com") != Allow {
		t.Fatalf("bad.example.com %v, x.bad.example.com %v", v("bad.example.com"), v("x.bad.example.com"))
	}
}
