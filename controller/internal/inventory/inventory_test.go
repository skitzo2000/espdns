package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/skitzo2000/espdns/controller/internal/configs"
	"github.com/skitzo2000/espdns/controller/internal/release"
	"github.com/skitzo2000/espdns/controller/internal/zonefiles"
)

const homeZone = `$TTL 3600
@ IN SOA ns1.home.example. hostmaster.home.example. ( 2026100701 3600 600 604800 300 )
  IN NS ns1
ns1 IN A 192.0.2.53
nas IN A 192.0.2.10
`

// status is a node's /status from JSON.
func status(t *testing.T, js string) *release.NodeStatus {
	t.Helper()
	var st release.NodeStatus
	if err := json.Unmarshal([]byte(js), &st); err != nil {
		t.Fatal(err)
	}
	return &st
}

// fleetDir is a data directory with one zone file (home.example) and two configs: copied
// zones from 192.0.2.254 and forward zones, one forward zone with a forwarder each.
func fleetDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if _, err := zonefiles.Save(dir, "home.example.zone", []byte(homeZone), ""); err != nil {
		t.Fatal(err)
	}
	for name, text := range map[string]string{
		"a.json": `{"name": "a", "secondary": {"primary": "192.0.2.254", "zones": ["lab.example", "iot.example"]},
			"forward_zones": [{"zone": "corp.example", "forwarder": "198.51.100.53"}]}`,
		"b.json": `{"name": "b", "secondary": {"primary": "192.0.2.254", "zones": ["lab.example"]},
			"forward_zones": [{"zone": "corp.example", "forwarder": "198.51.100.54"}]}`,
	} {
		if _, err := configs.Save(dir, name, []byte(text), ""); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func find(inv Inventory, name, kind string) (Zone, bool) {
	for _, z := range inv.Zones {
		if z.Name == name && z.Kind == kind {
			return z, true
		}
	}
	return Zone{}, false
}

// Every zone in one place: hosted (the file, as served or not, and a node's zone with no
// file), secondary (the configs' and the nodes', expired copies), forward (forwarders
// gathered); the state is the fleet's, as counts, never which node.
func TestBuild(t *testing.T) {
	dir := fleetDir(t)
	n1 := status(t, `{"zones": [{"name": "lab.example", "serial": 4294967295, "records": 11, "expired": false},
		{"name": "iot.example", "serial": 3, "records": 6, "expired": true}],
		"forward_zones": [{"name": "corp.example", "forwarder": "198.51.100.53"}],
		"hosted": {"state": "on", "seq": 3, "zones": [{"name": "home.example", "serial": 2026100701, "records": 4},
			{"name": "old.example", "serial": 1, "records": 2}]}}`)
	n2 := status(t, `{"zones": [{"name": "lab.example", "serial": 1, "records": 12, "expired": false},
		{"name": "extra.example", "serial": 0, "records": 0, "expired": false}],
		"forward_zones": [], "hosted": {"state": "on", "seq": 2, "zones": [{"name": "home.example", "serial": 2026100600, "records": 3}]}}`)
	inv, err := Build(dir, []Node{{Host: "192.0.2.11", Status: n1}, {Host: "192.0.2.12", Status: n2}, {Host: "192.0.2.13"}})
	if err != nil {
		t.Fatal(err)
	}
	if inv.Fleet != 3 || inv.Nodes != 2 {
		t.Errorf("fleet %d, read %d", inv.Fleet, inv.Nodes)
	}
	want := []struct{ name, kind, state string }{
		{"corp.example", KindForward, StatePartial},
		{"extra.example", KindSecondary, StatePartial},
		{"home.example", KindHosted, StatePartial},
		{"iot.example", KindSecondary, StateExpired},
		{"lab.example", KindSecondary, StateOK},
		{"old.example", KindHosted, StateNoFile},
	}
	if len(inv.Zones) != len(want) {
		t.Fatalf("zones: %+v", inv.Zones)
	}
	for i, w := range want {
		z := inv.Zones[i]
		if z.Name != w.name || z.Kind != w.kind || z.State != w.state {
			t.Errorf("zone %d: %s %s %s (%s), want %s %s %s", i, z.Name, z.Kind, z.State, z.Text, w.name, w.kind, w.state)
		}
		if z.Nodes != 2 {
			t.Errorf("%s: nodes %d", z.Name, z.Nodes)
		}
	}
	home, _ := find(inv, "home.example", KindHosted)
	if home.File != "home.example.zone" || home.Serial != 2026100701 || home.Records != 4 || home.Serving != 1 ||
		home.Text != "on 1 of 2 nodes, as saved; 1 node serves another version" {
		t.Errorf("home: %+v", home)
	}
	lab, _ := find(inv, "lab.example", KindSecondary)
	// The newest copy's serial and records, by serial arithmetic: 1 follows 4294967295.
	if lab.Primary != "192.0.2.254" || lab.Serving != 2 || len(lab.Configs) != 2 || lab.Text != "on every node" ||
		lab.Serial != 1 || lab.Records != 12 {
		t.Errorf("lab: %+v", lab)
	}
	iot, _ := find(inv, "iot.example", KindSecondary)
	if iot.Serving != 1 || iot.Serial != 3 || iot.Records != 6 || !strings.Contains(iot.Text, "1 node's copy expired") {
		t.Errorf("iot: %+v", iot)
	}
	corp, _ := find(inv, "corp.example", KindForward)
	if strings.Join(corp.Forwarders, ",") != "198.51.100.53,198.51.100.54" || corp.Serving != 1 || corp.Text != "on 1 of 2 nodes" {
		t.Errorf("corp: %+v", corp)
	}
	// A copy not made yet (extra.example) has no serial or records.
	if extra, _ := find(inv, "extra.example", KindSecondary); extra.Serial != 0 || extra.Records != 0 {
		t.Errorf("extra: %+v", extra)
	}
	if inv.Counts != (Counts{Hosted: 2, Secondary: 3, Forward: 1, Records: 4 + 12 + 6}) {
		t.Errorf("counts: %+v", inv.Counts)
	}
	if strings.Join(inv.Primaries, ",") != "192.0.2.254" {
		t.Errorf("primaries: %v", inv.Primaries)
	}
	// No JSON field names a node.
	b, _ := json.Marshal(inv)
	if strings.Contains(string(b), "192.0.2.11") || strings.Contains(string(b), "192.0.2.12") {
		t.Errorf("the inventory names a node: %s", b)
	}
}

// The states of a zone with every node, none, or no node read; a file that fails.
func TestBuildStates(t *testing.T) {
	dir := fleetDir(t)
	if inv, _ := Build(dir, nil); inv.Zones[0].State != StateUnknown {
		t.Errorf("no node: %+v", inv.Zones[0])
	}
	all := status(t, `{"zones": [{"name": "lab.example"}, {"name": "iot.example"}],
		"forward_zones": [{"name": "corp.example", "forwarder": "198.51.100.53"}],
		"hosted": {"state": "on", "zones": [{"name": "home.example", "serial": 2026100701, "records": 4}]}}`)
	inv, _ := Build(dir, []Node{{Host: "192.0.2.11", Status: all}, {Host: "192.0.2.12", Status: all}})
	for _, z := range inv.Zones {
		if z.State != StateOK || z.Serving != 2 {
			t.Errorf("%s %s: %s (%s)", z.Name, z.Kind, z.State, z.Text)
		}
	}
	if z, _ := find(inv, "home.example", KindHosted); z.Text != "on every node, as saved" {
		t.Errorf("home: %q", z.Text)
	}
	older := status(t, `{"hosted": {"state": "on", "zones": [{"name": "home.example", "serial": 2026100600, "records": 3}]}}`)
	inv, _ = Build(dir, []Node{{Host: "192.0.2.11", Status: older}})
	if z, _ := find(inv, "home.example", KindHosted); z.State != StatePartial || z.Text != "1 node serves another version, none the file as saved" {
		t.Errorf("older: %+v", z)
	}
	none := status(t, `{"zones": [], "forward_zones": []}`)
	inv, _ = Build(dir, []Node{{Host: "192.0.2.11", Status: none}})
	for _, z := range inv.Zones {
		if z.State != StateWaiting {
			t.Errorf("%s %s: %s", z.Name, z.Kind, z.State)
		}
	}
	// A file that doesn't pass its checks (written by hand: a save refuses it).
	if err := os.WriteFile(filepath.Join(zonefiles.Path(dir), "bad.example.zone"), []byte("@ IN A 192.0.2.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	inv, _ = Build(dir, []Node{{Host: "192.0.2.11", Status: none}})
	if z, _ := find(inv, "bad.example", KindHosted); z.State != StateError || !strings.Contains(z.Text, "doesn't pass") {
		t.Errorf("bad: %+v", z)
	}
}

// fakePrimary answers SOA queries as an authoritative server does, for the zones it holds;
// other servers are unreachable, refuse, or answer without authority.
type fakePrimary struct {
	zones map[string]map[string]uint32 // server: zone: serial
	down  map[string]bool
	asked []string
}

func (f *fakePrimary) Exchange(_ context.Context, host string, m *dns.Msg) (*dns.Msg, error) {
	f.asked = append(f.asked, host)
	if f.down[host] {
		return nil, errors.New("i/o timeout")
	}
	r := new(dns.Msg)
	r.SetReply(m)
	if m.RecursionDesired {
		r.Rcode = dns.RcodeRefused // a primary asked to recurse: the test wants none asked
		return r, nil
	}
	zs, ok := f.zones[host]
	if !ok {
		r.Rcode = dns.RcodeRefused
		return r, nil
	}
	q := strings.TrimSuffix(m.Question[0].Name, ".")
	for z, serial := range zs {
		soa := &dns.SOA{Hdr: dns.RR_Header{Name: dns.Fqdn(z), Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
			Ns: "ns1." + dns.Fqdn(z), Mbox: "hostmaster." + dns.Fqdn(z), Serial: serial}
		switch {
		case q == z:
			r.Authoritative = true
			r.Answer = append(r.Answer, soa)
			return r, nil
		case strings.HasSuffix(q, "."+z):
			r.Authoritative = true
			r.Rcode = dns.RcodeNameError
			r.Ns = append(r.Ns, soa)
			return r, nil
		}
	}
	return r, nil // not authoritative: it would have to ask elsewhere
}

func TestFind(t *testing.T) {
	inv, err := Build(fleetDir(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	fp := &fakePrimary{zones: map[string]map[string]uint32{
		"192.0.2.254": {"new.example": 7},
		"192.0.2.253": {"other.example": 9},
	}, down: map[string]bool{"192.0.2.250": true}}
	primaries := []string{"192.0.2.250", "192.0.2.252", "192.0.2.253", "192.0.2.254"}
	ctx := context.Background()
	for _, c := range []struct {
		name, found, primary, parent string
		serial                       uint32
		tried                        int
	}{
		{"lab.example", FoundZone, "", "", 0, 0},
		// Inside a fleet's zone: the primaries are still asked (TestFindDelegated).
		{"host.home.example", FoundWithin, "", "home.example", 0, 4},
		{"new.example", FoundPrimary, "192.0.2.254", "", 7, 4},
		{"other.example", FoundPrimary, "192.0.2.253", "", 9, 3},
		{"a.b.other.example", FoundPrimaryWithin, "192.0.2.253", "other.example", 9, 4},
		{"nowhere.example", FoundNone, "", "", 0, 4},
	} {
		fp.asked = nil
		l := Find(ctx, fp, inv, c.name, primaries)
		if l.Name != c.name || l.Found != c.found || l.Primary != c.primary || l.Parent != c.parent || l.Serial != c.serial ||
			len(l.Tried) != c.tried || len(fp.asked) != c.tried || l.Text == "" {
			t.Errorf("%s: %+v", c.name, l)
		}
		if c.found == FoundZone && (l.Zone == nil || l.Zone.Kind != KindSecondary) {
			t.Errorf("%s: zone %+v", c.name, l.Zone)
		}
	}
	l := Find(ctx, fp, inv, "nowhere.example", primaries)
	for _, w := range []string{"no answer: i/o timeout", "refused", "not authoritative", "not authoritative"} {
		if len(l.Tried) == 0 || !strings.HasPrefix(l.Tried[0].Answer, w) {
			t.Errorf("tried: %+v, want %q", l.Tried, w)
		}
		l.Tried = l.Tried[1:]
	}
	if l := Find(ctx, fp, inv, "nowhere.example", nil); l.Found != FoundNone || !strings.Contains(l.Text, "no primary is configured") {
		t.Errorf("no primaries: %+v", l)
	}
}

func TestCheckName(t *testing.T) {
	for in, want := range map[string]string{"Home.Example.": "home.example", " local ": "local", "_acme.example": "_acme.example"} {
		if got, err := CheckName(in); err != nil || got != want {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
	for _, bad := range []string{"", ".", "a..b", "-a.example", "a b", "a/b", "*.example", strings.Repeat("a.", 127) + "aa",
		strings.Repeat("a", 64) + ".example"} {
		if _, err := CheckName(bad); err == nil {
			t.Errorf("%q: accepted", bad)
		}
	}
}

// A zone inside one of the fleet's zones, delegated to a primary, is that primary's: the
// fleet's zone holding the name doesn't stop the primaries being asked.
func TestFindDelegated(t *testing.T) {
	inv := Inventory{Zones: []Zone{{Name: "home.example", Kind: KindHosted}}}
	fp := &fakePrimary{zones: map[string]map[string]uint32{"192.0.2.254": {"sub.home.example": 3}}}
	ctx := context.Background()
	if l := Find(ctx, fp, inv, "sub.home.example", []string{"192.0.2.254"}); l.Found != FoundPrimary ||
		l.Primary != "192.0.2.254" || l.Serial != 3 || l.Zone != nil || l.Parent != "" {
		t.Errorf("delegated: %+v", l)
	}
	// A name inside the delegated zone: the fleet's zone holding it is named first.
	if l := Find(ctx, fp, inv, "a.sub.home.example", []string{"192.0.2.254"}); l.Found != FoundWithin ||
		l.Parent != "home.example" || l.Zone == nil || len(l.Tried) != 1 {
		t.Errorf("inside delegated: %+v", l)
	}
	if l := Find(ctx, fp, inv, "host.home.example", nil); l.Found != FoundWithin || l.Parent != "home.example" {
		t.Errorf("no primaries: %+v", l)
	}
}
