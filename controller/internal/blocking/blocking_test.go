package blocking

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/skitzo2000/espdns/controller/internal/blocklist"
	"github.com/skitzo2000/espdns/controller/internal/filestore"
	"github.com/skitzo2000/espdns/controller/internal/settings"
)

func ptr[T any](v T) *T { return &v }

// The definitions are read strictly, as settings.json is: an unknown field, a second value,
// a bad name, kind, file, URL or limit, a list twice, and the overrides' name are refused.
func TestParse(t *testing.T) {
	good := `{"lists":[{"name":"list","sources":["adblock:pro.txt","rpz:https://feeds.example/rpz.zone"],` +
		`"allow":["domains:ok.txt"],"popular":"top.csv","must_resolve":"must.txt","xor":10,"max_change":35.5,"min_change":0}]}`
	d, err := Parse([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Lists) != 1 || d.Lists[0].Name != "list" || *d.Lists[0].MaxChange != 35.5 || *d.Lists[0].MinChange != 0 {
		t.Errorf("%+v", d)
	}
	// 0 is a limit (no change), kept apart from unset (the default)
	if d, err := Parse([]byte(`{"lists":[{"name":"a","sources":["domains:a.txt"],"max_change":0},{"name":"b","sources":["domains:a.txt"]}]}`)); err != nil ||
		d.Lists[0].MaxChange == nil || *d.Lists[0].MaxChange != 0 || d.Lists[0].MinChange != nil || d.Lists[1].MaxChange != nil {
		t.Errorf("max_change 0: %+v %v", d, err)
	}
	if d, err := Parse([]byte(`{}`)); err != nil || d.Lists == nil {
		t.Errorf("empty: %+v %v", d, err)
	}
	for name, text := range map[string]string{
		"unknown field":   `{"lists":[],"extra":1}`,
		"unknown in list": `{"lists":[{"name":"a","sources":["domains:a.txt"],"bits":40}]}`,
		"two values":      `{"lists":[]} {}`,
		"no name":         `{"lists":[{"sources":["domains:a.txt"]}]}`,
		"upper name":      `{"lists":[{"name":"List","sources":["domains:a.txt"]}]}`,
		"path name":       `{"lists":[{"name":"../x","sources":["domains:a.txt"]}]}`,
		"overrides":       `{"lists":[{"name":"overrides","sources":["domains:a.txt"]}]}`,
		"no sources":      `{"lists":[{"name":"a"}]}`,
		"bad kind":        `{"lists":[{"name":"a","sources":["zone:a.txt"]}]}`,
		"no kind":         `{"lists":[{"name":"a","sources":["a.txt"]}]}`,
		"a path":          `{"lists":[{"name":"a","sources":["domains:/etc/passwd"]}]}`,
		"up a dir":        `{"lists":[{"name":"a","sources":["domains:../a.txt"]}]}`,
		"no extension":    `{"lists":[{"name":"a","sources":["domains:a"]}]}`,
		"file URL":        `{"lists":[{"name":"a","sources":["domains:file:///etc/passwd"]}]}`,
		"no host":         `{"lists":[{"name":"a","sources":["domains:https:///x"]}]}`,
		"twice":           `{"lists":[{"name":"a","sources":["domains:a.txt"],"allow":["domains:a.txt"]}]}`,
		"list twice":      `{"lists":[{"name":"a","sources":["domains:a.txt"]},{"name":"a","sources":["domains:b.txt"]}]}`,
		"popular path":    `{"lists":[{"name":"a","sources":["domains:a.txt"],"popular":"../top.csv"}]}`,
		"xor":             `{"lists":[{"name":"a","sources":["domains:a.txt"],"xor":17}]}`,
		"max_change -1":   `{"lists":[{"name":"a","sources":["domains:a.txt"],"max_change":-1}]}`,
		"min_change":      `{"lists":[{"name":"a","sources":["domains:a.txt"],"min_change":-1}]}`,
	} {
		if _, err := Parse([]byte(text)); err == nil {
			t.Errorf("%s: taken", name)
		}
	}
}

// Saved whole, over the version edited only, the version before kept; Load reads it back.
func TestSaveLoad(t *testing.T) {
	dir := t.TempDir()
	d, hash, err := Load(dir)
	if err != nil || hash != "" || len(d.Lists) != 0 {
		t.Fatalf("no file: %+v %q %v", d, hash, err)
	}
	d.Lists = append(d.Lists, List{Name: "list", Sources: []string{"domains:a.txt"}})
	h1, err := Save(dir, d, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Save(dir, d, ""); err == nil {
		t.Error("a second first save taken")
	}
	d.Lists[0].Allow = []string{"wildcard:ok.txt"}
	h2, err := Save(dir, d, h1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Save(dir, d, h1); !errors.Is(err, filestore.ErrChanged) {
		t.Errorf("stale save: %v", err)
	}
	if _, err := Save(dir, Defs{Lists: []List{{Name: "x"}}}, h2); err == nil {
		t.Error("a list with no sources saved")
	}
	got, hash, err := Load(dir)
	if err != nil || hash != h2 || len(got.Lists) != 1 || len(got.Lists[0].Allow) != 1 {
		t.Errorf("%+v %q %v", got, hash, err)
	}
	h, _ := History(dir)
	if len(h) != 1 {
		t.Fatalf("history %+v", h)
	}
	if b, err := ReadVersion(dir, h[0].File); err != nil || strings.Contains(string(b), "ok.txt") {
		t.Errorf("kept version: %s %v", b, err)
	}
	// A file changed by hand that doesn't parse: an error, named.
	os.WriteFile(filepath.Join(Path(dir), DefsFile), []byte(`{"lists":[{"name":"a"}]}`), 0o600)
	if _, _, err := Load(dir); err == nil || !strings.Contains(err.Error(), DefsFile) {
		t.Errorf("bad file: %v", err)
	}
}

// The request: the files resolved in the data directory, URLs as they are, the CLI's
// widths, the limits as the CLI's flags take them, the popular and must-resolve names read.
func TestRequest(t *testing.T) {
	dir := t.TempDir()
	src := Sources(dir)
	for name, text := range map[string]string{"a.txt": "ads.example\n", "top.csv": "1,popular.example\n2,other.example\n",
		"must.txt": "# names\nmust.example\n"} {
		if err := src.Save(name, []byte(text), ""); err != nil {
			t.Fatal(err)
		}
	}
	l := List{Name: "list", Sources: []string{"domains:a.txt", "rpz:https://feeds.example/rpz.zone"}, Allow: []string{"wildcard:a.txt"},
		Popular: "top.csv", MustResolve: "must.txt", MinChange: ptr(0)}
	if err := l.Ready(dir); err != nil {
		t.Fatal(err)
	}
	r, err := l.Request(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	want := []blocklist.Source{{Kind: blocklist.Domains, Path: SourcePath(dir, "a.txt")},
		{Kind: blocklist.RPZ, Path: "https://feeds.example/rpz.zone"}, {Kind: blocklist.Wildcard, Path: SourcePath(dir, "a.txt"), Allow: true}}
	if len(r.Sources) != 3 || r.Sources[0] != want[0] || r.Sources[1] != want[1] || r.Sources[2] != want[2] {
		t.Errorf("sources %+v", r.Sources)
	}
	if r.Bits != 44 || r.XorBits != 10 || r.Keys != 10 || r.MinChange == nil || *r.MinChange != 0 || r.MaxChange != nil || !r.AcceptChange ||
		r.Out != filepath.Join(dir, "lists", "list.bin") || len(r.Popular) != 2 || len(r.MustResolve) != 1 {
		t.Errorf("request %+v", r)
	}
	if f := l.Files(); len(f) != 3 || !l.Uses("top.csv") || l.Uses("b.txt") {
		t.Errorf("files %v", f)
	}
	l.Sources = append(l.Sources, "hosts:gone.txt")
	if err := l.Ready(dir); err == nil || !strings.Contains(err.Error(), "gone.txt") {
		t.Errorf("a missing file: %v", err)
	}
	if c := l.Command("/data", false); !strings.HasPrefix(c, "espdns blocklist -list domains:/data/blocking/sources/a.txt -list rpz:https://feeds.example/rpz.zone") ||
		!strings.Contains(c, "-min-change 0 -out /data/lists/list.bin") {
		t.Errorf("command %s", c)
	}
	if c := (List{Name: "x", Sources: []string{"domains:https://feeds.example/l?a=1&b=it's"}}).Command("/data", true); !strings.Contains(c,
		`'domains:https://feeds.example/l?a=1&b=it'\''s'`) || !strings.HasSuffix(c, "-accept-change") {
		t.Errorf("quoted %s", c)
	}
}

// The overrides: the files there, wildcard, no xor filter; none there: not ready.
func TestOverrides(t *testing.T) {
	dir := t.TempDir()
	o, ok := (Defs{}).Lookup(dir, OverridesName)
	if !ok || !o.IsOverrides() || o.Ready(dir) == nil {
		t.Fatalf("%+v", o)
	}
	Sources(dir).Save(OverridesAllow, []byte("*.ok.example\n"), "")
	o = Overrides(dir)
	if len(o.Sources) != 0 || len(o.Allow) != 1 || o.Ready(dir) != nil {
		t.Errorf("%+v", o)
	}
	Sources(dir).Save(OverridesBlock, []byte("bad.example\n"), "")
	r, err := Overrides(dir).Request(dir, false)
	if err != nil || len(r.Sources) != 2 || r.XorBits != 0 || r.Sources[0].Kind != blocklist.Wildcard || !r.Sources[1].Allow ||
		r.Out != filepath.Join(dir, "lists", "overrides.bin") {
		t.Errorf("%+v %v", r, err)
	}
}

func TestSourceName(t *testing.T) {
	for _, ok := range []string{"a.txt", "feed.rpz", "top-1m.csv", "x_y.zone", "hosts.hosts", "a.b.list"} {
		if SourceName(ok) != nil {
			t.Errorf("%s refused", ok)
		}
	}
	for _, bad := range []string{"", "a", "A.txt", ".a.txt", "a/b.txt", "../a.txt", "a..b.txt", "a.json", "a.txt.bak", "a b.txt"} {
		if SourceName(bad) == nil {
			t.Errorf("%q taken", bad)
		}
	}
}

// A URL's user info and query values are hidden; the Redactor finds the URL as the
// definition writes it and as Go's HTTP client names it (password already hidden).
func TestRedact(t *testing.T) {
	for in, want := range map[string]string{
		"https://feeds.example/rpz.zone":                    "https://feeds.example/rpz.zone",
		"https://u:p@feeds.example/a.txt?key=k1&fmt=x&flag": "https://xxxxx@feeds.example/a.txt?key=xxxxx&fmt=xxxxx&xxxxx",
		"https://TOKEN@feeds.example/a.txt":                 "https://xxxxx@feeds.example/a.txt",
		"pro.txt":                                           "pro.txt",
	} {
		if got := RedactURL(in); got != want {
			t.Errorf("%s: %s, want %s", in, got, want)
		}
	}
	l := List{Name: "x", Sources: []string{"domains:https://u:pw@f.example/a?key=k1", "domains:a.txt"}}
	r := l.Redactor()
	for _, text := range []string{"domains:https://u:pw@f.example/a?key=k1: HTTP 404",
		`Get "https://u:xxxxx@f.example/a?key=k1": dial tcp: refused`, "the query alone ?key=k1"} {
		if got := r.Replace(text); strings.Contains(got, "k1") || strings.Contains(got, "pw") || strings.Contains(got, "u:") {
			t.Errorf("%s: %s", text, got)
		}
	}
}

// The internal allowlist a list's compile takes: the entries of settings.json's
// internal_sources its URL sources are fetched from, on its command line as -internal; a
// list without URL sources doesn't read settings.json.
func TestInternal(t *testing.T) {
	dir := t.TempDir()
	l := List{Name: "x", Sources: []string{"hosts:http://lists.example/h.txt", "domains:https://feeds.example/l"},
		Allow: []string{"domains:http://[2001:db8::10]/ok.txt"}}
	if got, err := l.Internal(dir); err != nil || got != nil {
		t.Fatal("no settings.json:", got, err)
	}
	if err := settings.Save(settings.Path(dir), settings.Settings{InternalSources: []string{"2001:db8::10", "other.example", "Lists.Example"}}); err != nil {
		t.Fatal(err)
	}
	got, err := l.Internal(dir)
	if err != nil || !slices.Equal(got, []string{"2001:db8::10", "Lists.Example"}) {
		t.Fatal(got, err)
	}
	if c := l.Command(dir, false); !strings.Contains(c, "-internal 2001:db8::10 -internal Lists.Example -out ") {
		t.Fatal(c)
	}
	r, err := l.Request(dir, false)
	if err != nil || !slices.Equal(r.Internal, got) {
		t.Fatal(r.Internal, err)
	}
	if err := os.WriteFile(settings.Path(dir), []byte(`{"internal_sources": ["http://x"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Request(dir, false); err == nil || !strings.Contains(err.Error(), "internal_sources") {
		t.Fatal("a broken settings.json:", err)
	}
	// A plain http source is a source: whether it is fetched is the allowlist's, when it is
	if err := CheckSource("hosts:http://lists.example/h.txt"); err != nil {
		t.Fatal(err)
	}
	files := List{Name: "f", Sources: []string{"domains:a.txt"}}
	if got, err := files.Internal(dir); err != nil || got != nil {
		t.Fatal("file sources read settings.json:", got, err)
	}
}
