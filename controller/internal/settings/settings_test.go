package settings

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/skitzo2000/espdns/controller/internal/primary"
)

// The repo's example (configs/example-settings.json, which make data never copies) loads,
// with every field it shows, on documentation addresses only (RFC 5737). The repo has no
// settings file to seed a data directory with: a fresh install starts with none.
func TestExample(t *testing.T) {
	repo := filepath.Join("..", "..", "..")
	s, err := Load(filepath.Join(repo, "configs", "example-settings.json"))
	if err != nil || len(s.Nodes) == 0 || len(s.DNSPeers) == 0 || s.Canary == "" || len(s.NoDHCP) == 0 ||
		s.ZonePrimary().Kind != primary.KindManual || len(s.InternalSources) == 0 {
		t.Fatal(s, err)
	}
	doc := netip.MustParsePrefix("192.0.2.0/24")
	for _, a := range append(append(append([]string{s.Canary}, s.Nodes...), s.DNSPeers...), s.InternalSources...) {
		if !doc.Contains(netip.MustParseAddr(a)) {
			t.Errorf("%s: not a documentation address", a)
		}
	}
	if _, err := os.Stat(filepath.Join(repo, "configs", "fleet.json")); err == nil {
		t.Error("configs/fleet.json is back: a deployment's settings live in its data directory")
	}
}

// no_dhcp: IPv4 networks, each as its network, none twice; NoDHCPAt finds the one an
// address is on. None (the default): DHCP anywhere.
func TestNoDHCP(t *testing.T) {
	for body, want := range map[string]string{
		`{"no_dhcp": ["192.0.2.0"]}`:                    "not an IPv4 network",
		`{"no_dhcp": [""]}`:                             "not an IPv4 network",
		`{"no_dhcp": ["2001:db8::/32"]}`:                "not an IPv4 network",
		`{"no_dhcp": ["192.0.2.1/24"]}`:                 "not a network (192.0.2.0/24 is)",
		`{"no_dhcp": [" 192.0.2.0/24"]}`:                "not an IPv4 network",
		`{"no_dhcp": ["192.0.2.0/24", "192.0.2.0/24"]}`: "twice",
		`{"no_dhcp": "192.0.2.0/24"}`:                   "cannot unmarshal",
	} {
		if _, err := Parse([]byte(body)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", body, err, want)
		}
	}
	s, err := Parse([]byte(`{"no_dhcp": ["192.0.2.0/23", "198.51.100.0/24"]}`))
	if err != nil {
		t.Fatal(err)
	}
	for a, want := range map[string]string{"192.0.3.9": "192.0.2.0/23", "198.51.100.1": "198.51.100.0/24",
		"192.0.4.1": "", "::ffff:192.0.2.9": "192.0.2.0/23"} {
		p, ok := s.NoDHCPAt(netip.MustParseAddr(a))
		if ok != (want != "") || (ok && p.String() != want) {
			t.Errorf("%s: %v %v, want %q", a, p, ok, want)
		}
	}
	if _, ok := (Settings{}).NoDHCPAt(netip.MustParseAddr("192.0.2.9")); ok {
		t.Error("no no_dhcp, yet a network without DHCP")
	}
	// Saved and read back as written.
	dir := t.TempDir()
	if err := Save(Path(dir), s); err != nil {
		t.Fatal(err)
	}
	if got, err := Load(Path(dir)); err != nil || !reflect.DeepEqual(got, s) {
		t.Fatal(got, err)
	}
}

// A settings file from before "primary" (as the repo's configs/fleet.json seeded one) loads as it is.
func TestLoad(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(Path(dir), []byte(`{
  "nodes": ["192.0.2.253", "192.0.2.252"],
  "dns_peers": ["192.0.2.254"],
  "dns_peer_zones": ["home.example"]
}`), 0o644)
	s, err := Load(Path(dir))
	if err != nil {
		t.Fatal(err)
	}
	want := Settings{Nodes: []string{"192.0.2.253", "192.0.2.252"}, DNSPeers: []string{"192.0.2.254"},
		DNSPeerZones: []string{"home.example"}}
	if !reflect.DeepEqual(s, want) {
		t.Fatalf("%+v", s)
	}
	// No file: no settings, no error.
	if s, err := Load(filepath.Join(dir, "none.json")); err != nil || !reflect.DeepEqual(s, Settings{}) {
		t.Fatal(s, err)
	}
}

func TestParseRefuses(t *testing.T) {
	for body, want := range map[string]string{
		`{"node": ["203.0.113.1"]}`:                 "unknown field",
		`{"dns_peer": ["203.0.113.254"]}`:           "unknown field",
		`{"nodes": ["203.0.113.1", "203.0.113.1"]}`: "twice",
		`{"nodes": [""]}`:                           "not a host",
		`{"nodes": [" 203.0.113.1"]}`:               "not a host",
		`{"dns_peers": ["203.0.113.254:"]}`:         "not a host",
		`{"dns_peer_zones": ["home example"]}`:      "not a zone",
		`{"nodes": []} {"nodes": []}`:               "more than one",
		`{"nodes": "203.0.113.1"}`:                  "cannot unmarshal",
	} {
		if _, err := Parse([]byte(body)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", body, err, want)
		}
	}
	if s, err := Parse([]byte(`{"nodes": ["203.0.113.1:8080"], "dns_peers": ["203.0.113.254:5353"]}`)); err != nil ||
		s.Nodes[0] != "203.0.113.1:8080" {
		t.Fatal(s, err)
	}
}

// Save writes what Load reads back, and refuses what Check refuses.
func TestSave(t *testing.T) {
	dir := t.TempDir()
	s := Settings{Nodes: []string{"203.0.113.1"}, DNSPeers: []string{"203.0.113.254"}}
	if err := Save(Path(dir), s); err != nil {
		t.Fatal(err)
	}
	got, err := Load(Path(dir))
	if err != nil || !reflect.DeepEqual(got, s) {
		t.Fatal(got, err)
	}
	if err := Save(Path(dir), Settings{Nodes: []string{"a", "a"}}); err == nil {
		t.Fatal("saved a repeated node")
	}
	if got, _ := Load(Path(dir)); !reflect.DeepEqual(got, s) {
		t.Fatal("a refused save changed the file:", got)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Fatalf("left behind: %v", ents)
	}
}

// The technitium kind's "url": https://host[:port] only. A plain http one (loopback too)
// already in the file still loads (the primary paused: primary.Config.CheckSaved); a save
// through POST /api/settings refuses it (primary.Config.Check, cmd/espdns-controller).
func TestTechnitium(t *testing.T) {
	for v, ok := range map[string]bool{"https://192.0.2.254:53443": true, "https://dns.example": true, "https://x:1/": true,
		"http://192.0.2.254:5380": true, "http://127.0.0.1:5380": true, "http://x:1/": true,
		"192.0.2.254:5380": false, "ftp://x": false, "https://u:p@x": false, "https://x/api": false,
		"https://x?token=1": false, "https://": false, "https://x#a": false} {
		if _, err := Parse([]byte(`{"primary": {"kind": "technitium", "url": "` + v + `"}}`)); (err == nil) != ok {
			t.Errorf("%s: %v", v, err)
		}
	}
}

// The zone primary: "primary" checked by kind (strictly: no field but kind, url and
// cert_sha256); the old key "technitium": "<url>" refused (greenfield); none: the zero
// Config.
func TestPrimary(t *testing.T) {
	for _, c := range []struct {
		json string
		want primary.Config
		bad  string
	}{
		{`{}`, primary.Config{}, ""},
		{`{"primary": {"kind": "manual"}}`, primary.Config{Kind: "manual"}, ""},
		{`{"primary": {"kind": "technitium", "url": "https://192.0.2.254:53443"}}`,
			primary.Config{Kind: "technitium", URL: "https://192.0.2.254:53443"}, ""},
		{`{"primary": {"kind": "technitium", "url": "https://192.0.2.254:53443", "cert_sha256": "` + strings.Repeat("0f", 32) + `"}}`,
			primary.Config{Kind: "technitium", URL: "https://192.0.2.254:53443", CertSHA256: strings.Repeat("0f", 32)}, ""},
		// Plain http in the file: loads (paused), so the controller starts
		{`{"primary": {"kind": "technitium", "url": "http://192.0.2.254:5380"}}`,
			primary.Config{Kind: "technitium", URL: "http://192.0.2.254:5380"}, ""},
		{`{"primary": {"kind": "technitium", "url": "https://192.0.2.254:53443", "cert_sha256": "0f"}}`, primary.Config{}, `"cert_sha256"`},
		// The old key, "technitium": "<url>", is no longer read (greenfield)
		{`{"technitium": "http://192.0.2.254:5380"}`, primary.Config{}, "unknown field"},
		{`{"primary": {"kind": "bind"}}`, primary.Config{}, `"kind": "bind" is not one of manual, technitium`},
		{`{"primary": {"kind": "technitium"}}`, primary.Config{}, `"url": the technitium kind needs`},
		{`{"primary": {"kind": "manual", "url": "http://x:1"}}`, primary.Config{}, "has no API"},
		{`{"primary": {"kind": "manual", "token": "x"}}`, primary.Config{}, "unknown field"},
		{`{"primary": {}}`, primary.Config{}, `"kind": one of`},
	} {
		s, err := Parse([]byte(c.json))
		switch {
		case c.bad != "" && (err == nil || !strings.Contains(err.Error(), c.bad)):
			t.Errorf("%s: %v, want %q", c.json, err, c.bad)
		case c.bad == "" && (err != nil || s.ZonePrimary() != c.want):
			t.Errorf("%s: %+v %v", c.json, s.ZonePrimary(), err)
		}
	}
}

// MoveNode: in its place, the canary with it.
func TestMoveNode(t *testing.T) {
	p := Path(t.TempDir())
	Save(p, Settings{Nodes: []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"}, Canary: "203.0.113.2"})
	if ok, err := MoveNode(p, "203.0.113.2", "203.0.113.9"); !ok || err != nil {
		t.Fatal(ok, err)
	}
	s, _ := Load(p)
	if !reflect.DeepEqual(s, Settings{Nodes: []string{"203.0.113.1", "203.0.113.9", "203.0.113.3"}, Canary: "203.0.113.9"}) {
		t.Fatal(s)
	}
	if ok, err := MoveNode(p, "203.0.113.1", "203.0.113.3"); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if s, _ := Load(p); !reflect.DeepEqual(s.Nodes, []string{"203.0.113.9", "203.0.113.3"}) {
		t.Fatal(s)
	}
	if ok, err := MoveNode(p, "203.0.113.7", "203.0.113.8"); ok || err != nil {
		t.Fatal(ok, err)
	}
}

// AddNode: appended, written whole and parsed again; there already, unchanged; a file that
// no longer parses is left alone.
func TestAddNode(t *testing.T) {
	dir := t.TempDir()
	p := Path(dir)
	if err := Save(p, Settings{Nodes: []string{"203.0.113.1"}, DNSPeers: []string{"203.0.113.254"}, Canary: "203.0.113.1"}); err != nil {
		t.Fatal(err)
	}
	if ok, err := AddNode(p, "203.0.113.2"); !ok || err != nil {
		t.Fatal(ok, err)
	}
	s, err := Load(p)
	want := Settings{Nodes: []string{"203.0.113.1", "203.0.113.2"}, DNSPeers: []string{"203.0.113.254"}, Canary: "203.0.113.1"}
	if err != nil || !reflect.DeepEqual(s, want) {
		t.Fatal(s, err)
	}
	if ok, err := AddNode(p, "203.0.113.2"); ok || err != nil {
		t.Fatal(ok, err)
	}
	if ok, err := AddNode(p, "203.0.113.3 x"); ok || err == nil {
		t.Fatal("a bad address added:", ok, err)
	}
	os.WriteFile(p, []byte(`{"nodes": ["203.0.113.1"], "nodez": []}`), 0o644)
	if ok, err := AddNode(p, "203.0.113.2"); ok || err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatal(ok, err)
	}
	if b, _ := os.ReadFile(p); !strings.Contains(string(b), "nodez") {
		t.Fatal("a file that doesn't parse was rewritten")
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Fatal("temporary files left:", ents)
	}
}

// Check's refusals name their field (FieldError), and say it first.
func TestFieldErrors(t *testing.T) {
	for body, field := range map[string]string{
		`{"nodes": ["192.0.2.1", "192.0.2.1"]}`:           "nodes",
		`{"dns_peers": [""]}`:                             "dns_peers",
		`{"dns_peer_zones": ["a b"]}`:                     "dns_peer_zones",
		`{"no_dhcp": ["192.0.2.1/24"]}`:                   "no_dhcp",
		`{"nodes": ["192.0.2.1"], "canary": "192.0.2.2"}`: "canary",
		`{"primary": {"kind": "technitium"}}`:             "primary",
	} {
		_, err := Parse([]byte(body))
		var fe *FieldError
		if !errors.As(err, &fe) || fe.Field != field || !strings.HasPrefix(err.Error(), field+": ") {
			t.Errorf("%s: %v, want field %s", body, err, field)
		}
	}
}

// Read gives the version (none: ""; a file that doesn't parse: its version and the error);
// SaveIf writes only on the version read, runs before ahead of the write (its error stops
// it) and after once it is written (its error returned, the file saved).
func TestSaveIf(t *testing.T) {
	p := Path(t.TempDir())
	if _, v, ok, err := Read(p); v != "" || ok || err != nil {
		t.Fatal(v, ok, err)
	}
	one := Settings{Nodes: []string{"192.0.2.1"}}
	if err := SaveIf(p, "x", one, nil, nil); !errors.Is(err, ErrChanged) {
		t.Fatalf("a version for no file: %v", err)
	}
	var order []string
	if err := SaveIf(p, "", one, func() error {
		if _, err := os.Stat(p); err == nil {
			t.Error("before ran after the write")
		}
		order = append(order, "before")
		return nil
	}, func() error {
		if s, _ := Load(p); !reflect.DeepEqual(s, one) {
			t.Error("after ran before the write")
		}
		order = append(order, "after")
		return nil
	}); err != nil || !slices.Equal(order, []string{"before", "after"}) {
		t.Fatal(err, order)
	}
	s, v, ok, err := Read(p)
	if err != nil || !ok || v == "" || !reflect.DeepEqual(s, one) {
		t.Fatal(s, v, ok, err)
	}
	if err := SaveIf(p, "", one, nil, nil); !errors.Is(err, ErrChanged) {
		t.Fatalf("no file, but there is one: %v", err)
	}
	// Changed since it was read (an adoption added a node): refused, neither run.
	AddNode(p, "192.0.2.2")
	ran := false
	if err := SaveIf(p, v, Settings{}, func() error { ran = true; return nil }, func() error { ran = true; return nil }); !errors.Is(err, ErrChanged) || ran {
		t.Fatal(err, ran)
	}
	_, v, _, _ = Read(p)
	if err := SaveIf(p, v, Settings{}, func() error { return errors.New("token") }, func() error { ran = true; return nil }); err == nil || err.Error() != "token" || ran {
		t.Fatal(err, ran)
	}
	if s, _ := Load(p); len(s.Nodes) != 2 {
		t.Fatal("saved though before failed:", s)
	}
	// after's error: returned, the file saved.
	if err := SaveIf(p, v, one, nil, func() error { return errors.New("token") }); err == nil || err.Error() != "token" {
		t.Fatal(err)
	}
	if s, _ := Load(p); !reflect.DeepEqual(s, one) {
		t.Fatal("not saved though only after failed:", s)
	}
	_, v, _, _ = Read(p)
	// Refused by Check: nothing runs.
	if err := SaveIf(p, v, Settings{Canary: "192.0.2.9"}, func() error { ran = true; return nil }, nil); err == nil || ran {
		t.Fatal(err)
	}
	// A file that doesn't parse: its version, so it can be replaced whole.
	os.WriteFile(p, []byte(`{"nodez": []}`), 0o600)
	if _, v, ok, err = Read(p); err == nil || !ok || v == "" {
		t.Fatal(v, ok, err)
	}
	if err := SaveIf(p, v, one, nil, nil); err != nil {
		t.Fatal(err)
	}
}

// internal_sources: hosts alone (a name or an IP address), none twice in any of its forms.
func TestInternalSources(t *testing.T) {
	for body, bad := range map[string]string{
		`{"internal_sources": ["lists.example", "192.0.2.10", "2001:db8::10"]}`: "",
		`{"internal_sources": ["http://lists.example"]}`:                        "not a host name",
		`{"internal_sources": ["lists.example:8080"]}`:                          "not a host name",
		`{"internal_sources": ["*.example"]}`:                                   "not a host name",
		`{"internal_sources": [""]}`:                                            "not a host name",
		`{"internal_sources": ["lists.example", "LISTS.example."]}`:             "twice",
		`{"internal_sources": ["192.0.2.10", "::ffff:192.0.2.10"]}`:             "twice",
	} {
		s, err := Parse([]byte(body))
		switch {
		case bad == "" && (err != nil || len(s.InternalSources) != 3):
			t.Errorf("%s: %v", body, err)
		case bad != "":
			var fe *FieldError
			if !errors.As(err, &fe) || fe.Field != "internal_sources" || !strings.Contains(err.Error(), bad) {
				t.Errorf("%s: %v", body, err)
			}
		}
	}
}

// SetPrimaryPin pins (or unpins) the certificate of the primary at the address it was read
// from, and only while settings.json still names that primary.
func TestSetPrimaryPin(t *testing.T) {
	path := filepath.Join(t.TempDir(), File)
	pin := strings.Repeat("0f", 32)
	if err := SetPrimaryPin(path, "https://192.0.2.254:53443", pin); !errors.Is(err, ErrNoPrimaryAPI) {
		t.Fatal("no file:", err)
	}
	if err := Save(path, Settings{Nodes: []string{"192.0.2.53"}, Primary: &primary.Config{Kind: "technitium", URL: "https://192.0.2.254:53443"}}); err != nil {
		t.Fatal(err)
	}
	if err := SetPrimaryPin(path, "https://192.0.2.9:53443", pin); !errors.Is(err, ErrNoPrimaryAPI) {
		t.Fatal("another address:", err)
	}
	if err := SetPrimaryPin(path, "https://192.0.2.254:53443", "0F"); err == nil {
		t.Fatal("a pin in another form taken")
	}
	if err := SetPrimaryPin(path, "https://192.0.2.254:53443", pin); err != nil {
		t.Fatal(err)
	}
	s, err := Load(path)
	if err != nil || s.ZonePrimary().CertSHA256 != pin || !slices.Equal(s.Nodes, []string{"192.0.2.53"}) {
		t.Fatal(s, err)
	}
	if err := SetPrimaryPin(path, "https://192.0.2.254:53443", ""); err != nil {
		t.Fatal(err)
	}
	if s, _ := Load(path); s.ZonePrimary().CertSHA256 != "" {
		t.Fatal("still pinned")
	}
}
