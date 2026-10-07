package zones

import (
	"bytes"
	"flag"
	"os"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/skitzo2000/espdns/controller/internal/nodecfg"
)

var update = flag.Bool("update", false, "rewrite firmware/tests/hosted_example.bin")

// The node's host tests answer from this bundle (firmware/tests/test_core.c, test_hosted).
const vector = "../../../firmware/tests/hosted_example.bin"

func exampleSet(t *testing.T) *Set {
	t.Helper()
	var s Set
	for _, f := range []string{"testdata/home.example.zone", "testdata/2.0.192.in-addr.arpa.zone"} {
		z, err := LoadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		s.Zones = append(s.Zones, z)
	}
	return &s
}

func TestExample(t *testing.T) {
	s := exampleSet(t)
	z := s.Zones[0]
	if z.Name() != "home.example" || z.Serial() != 2026100201 {
		t.Errorf("zone %s serial %d", z.Name(), z.Serial())
	}
	// 19 records in the file, one a duplicate in another case.
	if len(z.Records) != 18 {
		t.Errorf("%d records", len(z.Records))
	}
	b, err := s.Bundle(DefaultLimitKB)
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParseBundle(b)
	if err != nil || len(back.Zones) != 2 || back.Validate() != nil || back.Mem() != s.Mem() {
		t.Fatalf("round trip: %v", err)
	}
	if b2, _ := back.Bundle(0); !bytes.Equal(b, b2) {
		t.Error("round trip changed the bundle")
	}
	if *update {
		if err := os.WriteFile(vector, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(vector)
	if err != nil || !bytes.Equal(b, want) {
		t.Errorf("%s is stale: go test ./internal/zones -update (%v)", vector, err)
	}
	// Too big for a node's limit.
	if _, err := s.Bundle(1); err == nil || !strings.Contains(err.Error(), "hosted_zones_kb") {
		t.Errorf("limit: %v", err)
	}
	// No zones: a bundle that removes them all.
	if b, err := (&Set{}).Bundle(1); err != nil || string(b) != Magic+"\x00\x00" {
		t.Errorf("empty: %q %v", b, err)
	}
}

func zone(t *testing.T, text string) error {
	t.Helper()
	z, err := ParseMaster("t.example", strings.NewReader(text), "test")
	if err != nil {
		return err
	}
	return (&Set{Zones: []*Zone{z}}).Validate()
}

const soa = "@ 300 IN SOA ns hm 1 2 3 4 5\n"

// The node's refusals (firmware/tests/test_core.c, test_hosted).
func TestRefused(t *testing.T) {
	if err := zone(t, soa+"www 300 IN A 198.51.100.1\n"); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ text, why string }{
		{"www 300 IN A 198.51.100.1\n", "exactly one SOA"},
		{soa + "sub 300 IN SOA ns hm 1 2 3 4 5\n", "SOA only at the apex"},
		{soa + "www 300 IN A 198.51.100.1\nwww 300 IN CNAME other\n", "a CNAME and other records"},
		{soa + "www 300 IN CNAME a\nwww 300 IN CNAME b\n", "more than one CNAME"},
		{soa + "@ 300 IN CNAME a\n", "a CNAME and other records"},
		{soa + "lab 300 IN NS ns.lab\nlab 300 IN TXT \"x\"\n", "TXT at a delegation"},
		{soa + "lab 300 IN NS ns.lab\nhost.lab 300 IN MX 10 mx\n", "MX below a delegation"},
		{soa + "www.other.example. 300 IN A 198.51.100.1\n", "outside the zone"},
		{soa + "a.*.b 300 IN A 198.51.100.1\n", "first label"},
		{soa + "*.lab 300 IN NS ns\n", "*.lab.t.example: NS at a wildcard name"},
		{soa + "* 300 IN NS ns\n", "NS at a wildcard name"},
		{soa + "www 300 IN DNSKEY 256 3 8 AwEAAc==\n", "no DNSSEC"},
		{soa + "www 300 IN HINFO a b\n", "not supported"},
		{soa + "www 300 CH A 198.51.100.1\n", "class IN"},
		{soa + "www 2147483648 IN A 198.51.100.1\n", "TTL above"},
	} {
		if err := zone(t, c.text); err == nil || !strings.Contains(err.Error(), c.why) {
			t.Errorf("%q: %v, want %q", c.text, err, c.why)
		}
	}
	// Glue below a delegation is fine; so is a wildcard.
	if err := zone(t, soa+"lab 300 IN NS ns.lab\nns.lab 300 IN A 198.51.100.2\n*.dev 300 IN A 198.51.100.3\n"); err != nil {
		t.Error(err)
	}
}

func TestSetChecks(t *testing.T) {
	s := exampleSet(t)
	s.Zones = append(s.Zones, s.Zones[0])
	if err := s.Validate(); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Errorf("duplicate zone: %v", err)
	}
	s = exampleSet(t)
	for len(s.Zones) <= MaxZones {
		z := *s.Zones[1]
		apex, _ := wireName(dns.Fqdn(strings.Repeat("x", len(s.Zones)) + ".example"))
		z.Apex = apex
		s.Zones = append(s.Zones, &z)
	}
	if err := s.Validate(); err == nil || !strings.Contains(err.Error(), "at most") {
		t.Errorf("too many zones: %v", err)
	}
	// Malformed rdata never comes from the parser; check the node's rules directly.
	for _, c := range []struct {
		t  uint16
		rd []byte
		ok bool
	}{
		{dns.TypeA, []byte{1, 2, 3}, false},
		{dns.TypeAAAA, make([]byte, 16), true},
		{dns.TypeCNAME, []byte{1, 'a', 0}, true},
		{dns.TypeCNAME, []byte{1, 'a', 0, 0}, false},
		{dns.TypeCNAME, []byte{0xc0, 12}, false}, // compressed
		{dns.TypeMX, []byte{0, 10, 0}, true},
		{dns.TypeTXT, []byte{3, 'a', 'b'}, false},
		{dns.TypeTXT, []byte{0}, true},
		{dns.TypeCAA, []byte{0, 5, 'i', 's', 's', 'u', 'e', 'x'}, true},
		{dns.TypeCAA, []byte{0, 1, '-', 'x'}, false},
		{dns.TypeSRV, []byte{0, 0, 0, 0, 0, 80, 0}, true},
	} {
		if rdataOK(c.t, c.rd) != c.ok {
			t.Errorf("type %d rdata %v: want %v", c.t, c.rd, c.ok)
		}
	}
}

func TestClash(t *testing.T) {
	s := exampleSet(t)
	c, err := nodecfg.Parse([]byte(`{"secondary":{"zones":["local","Home.Example."]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Clash(c); err == nil || !strings.Contains(err.Error(), "home.example") {
		t.Errorf("secondary clash: %v", err)
	}
	c, _ = nodecfg.Parse([]byte(`{"forward_zones":[{"zone":"2.0.192.in-addr.arpa","forwarder":"198.51.100.1"}]}`))
	if err := s.Clash(c); err == nil {
		t.Error("forward zone clash not found")
	}
	c, _ = nodecfg.Parse([]byte(`{"secondary":{"zones":["sub.home.example"]}}`))
	if err := s.Clash(c); err != nil {
		t.Errorf("a zone below a hosted one is its own zone: %v", err)
	}
}
