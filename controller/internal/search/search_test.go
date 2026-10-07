package search

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/blocking"
	"github.com/skitzo2000/espdns/controller/internal/changes"
	"github.com/skitzo2000/espdns/controller/internal/fakenode"
	"github.com/skitzo2000/espdns/controller/internal/fleet"
	"github.com/skitzo2000/espdns/controller/internal/inventory"
	"github.com/skitzo2000/espdns/controller/internal/nodes"
	"github.com/skitzo2000/espdns/controller/internal/observe"
	"github.com/skitzo2000/espdns/controller/internal/zonefiles"
)

const zoneText = `$TTL 3600
@ IN SOA ns1.home.example. hostmaster.home.example. ( 5 3600 600 604800 300 )
  IN NS ns1
ns1 IN A 192.0.2.53
printer IN A 192.0.2.40
www IN CNAME printer
`

// fixture is a data directory with a hosted zone (and a pending edit of it adding a
// record), the overrides, a list whose URL holds a credential, a pending firmware update,
// two nodes (one found, not added) and a query log read from a fake node.
func fixture(t *testing.T) Input {
	t.Helper()
	dir := t.TempDir()
	if _, err := zonefiles.Save(dir, "home.example.zone", []byte(zoneText), ""); err != nil {
		t.Fatal(err)
	}
	src := blocking.Sources(dir)
	if err := src.Save(blocking.OverridesBlock, []byte("# blocked\nads.example.net\n"), ""); err != nil {
		t.Fatal(err)
	}
	if err := src.Save(blocking.OverridesAllow, []byte("good.example\n"), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := blocking.Save(dir, blocking.Defs{Lists: []blocking.List{{Name: "pro",
		Sources: []string{"adblock:https://user:hunter2@lists.example/pro.txt?key=abc123"}}}}, ""); err != nil {
		t.Fatal(err)
	}
	cs := changes.New(dir)
	v, err := cs.Effective(changes.Zone, "home.example.zone")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cs.Add(changes.Edit{Kind: changes.Zone, Name: "home.example.zone", Hash: v.Hash, Who: "admin",
		Text: []byte(zoneText + "laptop IN A 192.0.2.41\n"), Summary: "add the laptop"}); err != nil {
		t.Fatal(err)
	}
	if _, err := cs.Add(changes.Edit{Kind: changes.Firmware, Firmware: "builds/p4-ip101", Nodes: []string{"192.0.2.11"},
		Who: "admin", Summary: "update dns2"}); err != nil {
		t.Fatal(err)
	}

	// The query log: a fake node, read twice.
	fn := fakenode.New("dns2", [6]byte{2, 0, 0, 0, 0, 1}, "esp32p4-rev1", "p4-ip101", nil)
	srv := httptest.NewServer(fn)
	t.Cleanup(srv.Close)
	fake := nodes.Node{ID: fn.ID(), Addr: strings.TrimPrefix(srv.URL, "http://"), Online: true,
		Status: map[string]any{"health": map[string]any{"state": "healthy"}}}
	log := observe.New(&fleet.Client{})
	log.Scrape(context.Background(), []nodes.Node{fake})
	fn.LogQuery("192.0.2.40", "ads.example.net", "A", "blocked", "NOERROR")
	fn.LogQuery("192.0.2.40", "ads.example.net", "A", "blocked", "NOERROR")
	fn.LogQuery("192.0.2.40", "printer-driver.example", "A", "forwarded", "NOERROR")
	fn.LogQuery("192.0.2.99", "news.example", "A", "cache", "NOERROR")
	log.Scrape(context.Background(), []nodes.Node{fake})

	ns := []nodes.Node{
		{ID: "020000000001", Addr: "192.0.2.11", Hostname: "espdns-000001.local", Source: "settings", Online: true,
			Status: map[string]any{"board": "p4-ip101", "config": map[string]any{"name": "dns2"},
				"health": map[string]any{"state": "healthy"}}},
		{ID: "020000000002", Addr: "192.0.2.12", Hostname: "espdns-000002.local", Source: "mdns", Online: false},
	}
	inv, err := inventory.Build(dir, []inventory.Node{{Host: "192.0.2.11"}})
	if err != nil {
		t.Fatal(err)
	}
	return Input{DataDir: dir, Changes: cs, Log: log, Nodes: ns, Inventory: inv}
}

func find(a Answer, typ, title string) (Result, bool) {
	for _, r := range a.Results {
		if r.Type == typ && r.Title == title {
			return r, true
		}
	}
	return Result{}, false
}

func run(t *testing.T, in Input, raw string) Answer {
	t.Helper()
	q, err := CheckQuery(raw)
	if err != nil {
		t.Fatal(err)
	}
	a := Run(context.Background(), in, q)
	if a.Partial || len(a.Problems) != 0 {
		t.Fatalf("%q: partial %v, problems %v", raw, a.Partial, a.Problems)
	}
	return a
}

// A node by its name, its address, its ID and its mDNS name; one found and not added
// says so; each says where it lives.
func TestNodes(t *testing.T) {
	in := fixture(t)
	a := run(t, in, "DNS2")
	r, ok := find(a, TypeNode, "dns2")
	if !ok || r.rank != 0 || r.Match != "name" || r.Page != PageNodes || r.Key != "020000000001" ||
		r.Link != "#node-020000000001" || r.State != "healthy" || !strings.Contains(r.Text, "p4-ip101 at 192.0.2.11") ||
		strings.Contains(r.Text, "not added") {
		t.Errorf("dns2: %+v", r)
	}
	if a.Results[0].Type != TypeNode {
		t.Errorf("the exact match isn't first: %+v", a.Results[0])
	}
	if r, ok := find(run(t, in, "192.0.2.11"), TypeNode, "dns2"); !ok || r.Match != "address" || r.rank != 0 {
		t.Errorf("by address: %+v", r)
	}
	a = run(t, in, "espdns-000002")
	if r, ok := find(a, TypeNode, "espdns-000002"); !ok || r.State != "offline" || !strings.Contains(r.Text, "not added") {
		t.Errorf("the found node: %+v", a.Results)
	}
	if _, ok := find(run(t, in, "0200000000"), TypeNode, "dns2"); !ok {
		t.Error("by ID")
	}
}

// A zone by its name, and the zone a name is in; its records by owner and data, as the
// pending changes make them; a device named from a record, with its queries.
func TestZonesRecordsDevices(t *testing.T) {
	in := fixture(t)
	a := run(t, in, "home.example.")
	if r, ok := find(a, TypeZone, "home.example"); !ok || r.rank != 0 || r.Link != "#zone-home.example" ||
		!strings.HasPrefix(r.Text, "hosted here: ") {
		t.Errorf("zone: %+v", r)
	}
	if r, ok := find(run(t, in, "nas.home.example"), TypeZone, "home.example"); !ok || r.Match != "within" {
		t.Errorf("within: %+v", r)
	}

	a = run(t, in, "printer")
	rec, ok := find(a, TypeRecord, "printer.home.example")
	if !ok || rec.Match != "name" || rec.Zone != "home.example" || rec.Text != "A 192.0.2.40, in home.example" ||
		rec.Page != PageZones || rec.Link != "#zone-home.example" || rec.Pending {
		t.Errorf("record: %+v", rec)
	}
	if r, ok := find(a, TypeRecord, "www.home.example"); !ok || r.Match != "data" || r.Text != "CNAME printer.home.example, in home.example" {
		t.Errorf("by its data: %+v", r)
	}
	dev, ok := find(a, TypeDevice, "printer.home.example")
	if !ok || dev.Key != "192.0.2.40" || dev.Queries != 3 || dev.Blocked != 2 || dev.Last == nil || dev.Match != "name" ||
		dev.Link != "#query-log?client=192.0.2.40" {
		t.Errorf("device: %+v", dev)
	}
	if r, ok := find(a, TypeSite, "printer-driver.example"); !ok || r.Queries != 1 || r.Link != "#query-log?name=printer-driver.example" {
		t.Errorf("site: %+v", r)
	}
	// The record a pending change adds.
	if r, ok := find(run(t, in, "laptop"), TypeRecord, "laptop.home.example"); !ok || !r.Pending {
		t.Errorf("pending record: %+v", r)
	}
	// SOA records are left out; a device by its address, named from its record.
	a = run(t, in, "192.0.2.4")
	if d, ok := find(a, TypeDevice, "printer.home.example"); !ok || d.Match != "address" {
		t.Errorf("by address: %+v", a.Results)
	}
	if r, ok := find(run(t, in, "192.0.2.99"), TypeDevice, "192.0.2.99"); !ok || r.rank != 0 {
		t.Errorf("an unnamed device: %+v", r)
	}
	for _, r := range run(t, in, "hostmaster").Results {
		if r.Type == TypeRecord {
			t.Errorf("an SOA record: %+v", r)
		}
	}
}

// A site: the query log's, the rule that covers it, "check a site" for it; a list by its
// source, its credential never matched nor shown; the pending changes.
func TestBlockingAndChanges(t *testing.T) {
	in := fixture(t)
	a := run(t, in, "ads.example.net")
	if r, ok := find(a, TypeRule, "ads.example.net"); !ok || r.State != "block" || r.rank != 0 || r.Link != "#blocking?site=ads.example.net" {
		t.Errorf("rule: %+v", r)
	}
	if r, ok := find(a, TypeSite, "ads.example.net"); !ok || r.Blocked != 2 {
		t.Errorf("site: %+v", r)
	}
	if r, ok := find(a, TypeCheck, "ads.example.net"); !ok || r.Link != "#blocking?check=ads.example.net" || r.Page != PageBlocking {
		t.Errorf("check: %+v", r)
	}
	a = run(t, in, "cdn.good.example")
	if r, ok := find(a, TypeRule, "good.example"); !ok || r.State != "allow" || r.Match != "covers" {
		t.Errorf("covers: %+v", a.Results)
	}
	if _, ok := find(run(t, in, "192.0.2.40"), TypeCheck, "192.0.2.40"); ok {
		t.Error("an address offered as a site to check")
	}

	a = run(t, in, "lists.example")
	r, ok := find(a, TypeList, "pro")
	if !ok || r.Match != "source" || r.rank != 2 || r.Link != "#blocking?list=pro" {
		t.Errorf("list: %+v", a.Results)
	}
	if strings.Contains(r.Text, "hunter2") || strings.Contains(r.Text, "abc123") || !strings.Contains(r.Text, "xxxxx") {
		t.Errorf("the credential shown: %s", r.Text)
	}
	for _, q := range []string{"hunter2", "abc123"} {
		if a := run(t, in, q); len(a.Results) != 0 {
			t.Errorf("%s matched: %+v", q, a.Results)
		}
	}
	if r, ok := find(run(t, in, "pro"), TypeList, "pro"); !ok || r.rank != 0 {
		t.Errorf("by name: %+v", r)
	}

	a = run(t, in, "update")
	if r, ok := find(a, TypeChange, "update dns2"); !ok || !r.Pending || r.Page != PageChanges || !strings.Contains(r.Text, "firmware") {
		t.Errorf("change: %+v", a.Results)
	}
	if r, ok := find(run(t, in, "home.example.zone"), TypeChange, "add the laptop"); !ok || r.Match != "file" {
		t.Errorf("change by file: %+v", r)
	}
}

// The caps: PerType of a type, Max in all, Matched counting every one; More says so.
func TestCaps(t *testing.T) {
	dir := t.TempDir()
	var b strings.Builder
	b.WriteString("$TTL 3600\n@ IN SOA ns1 hostmaster ( 1 3600 600 604800 300 )\n  IN NS ns1\nns1 IN A 192.0.2.1\n")
	for i := range 30 {
		fmt.Fprintf(&b, "host%02d IN A 192.0.2.%d\n", i, 100+i)
	}
	if _, err := zonefiles.Save(dir, "lab.example.zone", []byte(b.String()), ""); err != nil {
		t.Fatal(err)
	}
	a := Run(context.Background(), Input{DataDir: dir}, "host")
	n := 0
	for _, r := range a.Results {
		if r.Type == TypeRecord {
			n++
		}
	}
	if n != PerType || a.Matched[TypeRecord] != 30 || !a.More || a.Results[0].Title != "host00.lab.example" {
		t.Errorf("%d records of %d, more %v: %+v", n, a.Matched[TypeRecord], a.More, a.Results)
	}
	a = Run(context.Background(), Input{DataDir: dir}, "host00")
	if a.More || len(a.Results) != 1 {
		t.Errorf("one: %+v", a)
	}
}

// Max in all: the best of every type, across types, in order; More says some were left out.
func TestMax(t *testing.T) {
	ans := Answer{Results: []Result{}, Matched: map[string]int{}}
	s := &search{ans: &ans, out: map[string][]Result{}}
	for _, typ := range typeOrder {
		for i := range PerType {
			s.add(Result{Type: typ, Title: fmt.Sprintf("%s%02d", typ, i), rank: i % 3})
		}
	}
	if ans.More {
		t.Fatal("more before the cap")
	}
	s.finish()
	if len(ans.Results) != Max || !ans.More || ans.Matched[TypeChange] != PerType {
		t.Fatalf("%d results, more %v, matched %v", len(ans.Results), ans.More, ans.Matched)
	}
	for i := 1; i < len(ans.Results); i++ {
		if order(ans.Results[i-1], ans.Results[i]) > 0 {
			t.Errorf("out of order at %d: %+v, %+v", i, ans.Results[i-1], ans.Results[i])
		}
	}
	if r := ans.Results[len(ans.Results)-1]; r.rank != 1 {
		t.Errorf("a part kept over a prefix: %+v", r)
	}
}

// A search out of time stops between places and says so, with what it found.
func TestDeadline(t *testing.T) {
	in := fixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	a := Run(ctx, in, "dns2")
	if !a.Partial || len(a.Searched) != 0 || len(a.Results) != 0 {
		t.Errorf("cancelled: %+v", a)
	}
	ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if a := Run(ctx, in, "dns2"); !a.Partial {
		t.Errorf("past its deadline: %+v", a)
	}
}

// Nothing to read is no problem: an empty data directory, no store, no query log.
func TestEmpty(t *testing.T) {
	a := Run(context.Background(), Input{DataDir: t.TempDir()}, "anything")
	if len(a.Results) != 0 || len(a.Problems) != 0 || a.Partial || len(a.Searched) != 8 {
		t.Errorf("%+v", a)
	}
}

func TestCheckQuery(t *testing.T) {
	if q, err := CheckQuery("  Printer.Home.Example. "); err != nil || q != "printer.home.example" {
		t.Errorf("%q %v", q, err)
	}
	for _, bad := range []string{"", "   ", ".", strings.Repeat("a", MaxQuery+1), "a\nb", "a\x00b"} {
		if _, err := CheckQuery(bad); err == nil {
			t.Errorf("%q taken", bad)
		}
	}
	if _, err := CheckQuery("add the laptop"); err != nil {
		t.Errorf("words: %v", err)
	}
}

// Pending marks only what the pending changes add or change, not the rest of the file
// they change: a record, a rule, a list.
func TestPendingOnlyWhatChanges(t *testing.T) {
	in := fixture(t)
	v, err := in.Changes.Effective(changes.Source, blocking.OverridesBlock)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := in.Changes.Add(changes.Edit{Kind: changes.Source, Name: blocking.OverridesBlock, Hash: v.Hash, Who: "admin",
		Text: []byte("# blocked\nads.example.net\ntracker.example.net\n"), Summary: "block a tracker"}); err != nil {
		t.Fatal(err)
	}
	v, err = in.Changes.Effective(changes.Lists, blocking.DefsFile)
	if err != nil {
		t.Fatal(err)
	}
	defs, err := blocking.Parse(v.Text)
	if err != nil {
		t.Fatal(err)
	}
	defs.Lists = append(defs.Lists, blocking.List{Name: "kids", Sources: []string{"domains:kids.txt"}})
	text, err := json.Marshal(defs)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := in.Changes.Add(changes.Edit{Kind: changes.Lists, Name: blocking.DefsFile, Hash: v.Hash, Who: "admin",
		Text: text, Summary: "a list for the kids"}); err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		q, typ, title string
		pending       bool
	}{
		{"printer", TypeRecord, "printer.home.example", false},
		{"laptop", TypeRecord, "laptop.home.example", true},
		{"ads.example.net", TypeRule, "ads.example.net", false},
		{"tracker", TypeRule, "tracker.example.net", true},
		{"pro", TypeList, "pro", false},
		{"kids", TypeList, "kids", true},
	} {
		r, ok := find(run(t, in, c.q), c.typ, c.title)
		if !ok || r.Pending != c.pending {
			t.Errorf("%s %s: found %v, pending %v, want %v", c.typ, c.title, ok, r.Pending, c.pending)
		}
	}
}

// A search keeps no more than PerType results of a type, the best, however many match.
func TestAddKeepsTheBest(t *testing.T) {
	s := &search{ans: &Answer{Matched: map[string]int{}}, out: map[string][]Result{}}
	for i := 999; i >= 0; i-- {
		s.add(Result{Type: TypeSite, Title: fmt.Sprintf("site%03d", i), rank: 2 - i%3})
	}
	l := s.out[TypeSite]
	if len(l) != PerType || s.ans.Matched[TypeSite] != 1000 || !s.ans.More {
		t.Fatalf("kept %d of %d, more %v", len(l), s.ans.Matched[TypeSite], s.ans.More)
	}
	for i, r := range l {
		if want := fmt.Sprintf("site%03d", 2+3*i); r.rank != 0 || r.Title != want {
			t.Errorf("%d: %+v, want %s", i, r, want)
		}
	}
}

// The zone a name is in, whatever case the inventory gives the zone's name.
func TestWithinAnyCase(t *testing.T) {
	in := Input{DataDir: t.TempDir(), Inventory: inventory.Inventory{Zones: []inventory.Zone{{Name: "Lab.Example"}}}}
	a := Run(context.Background(), in, "nas.lab.example")
	if r, ok := find(a, TypeZone, "Lab.Example"); !ok || r.Match != "within" {
		t.Errorf("%+v", a.Results)
	}
}
