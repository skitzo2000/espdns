package nodecfg

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// The site defaults example (firmware/site-defaults.h.example, the host tests' firmware
// defaults), spelled out as a config: what pushing it to a node on them changes is nothing.
func TestSiteDefaultsExample(t *testing.T) {
	b, err := os.ReadFile("../../../firmware/tests/config_example.json")
	if err != nil {
		t.Fatal(err)
	}
	c, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if a, ok := c.StaticAddr(); !ok || a.String() != "192.0.2.53" {
		t.Errorf("static address %v %v", a, ok)
	}
	p, err := c.Payload()
	if err != nil {
		t.Fatal(err)
	}
	if len(p) > MaxPayloadNVS {
		t.Errorf("payload %d bytes: doesn't fit a node that keeps its config in NVS", len(p))
	}
	var m map[string]any
	if err := json.Unmarshal(p, &m); err != nil || m["format"] != float64(1) || len(m["forward_zones"].([]any)) != 3 {
		t.Errorf("payload %s: %v", p, err)
	}
}

// The repo's example node config (configs/example-node.json) parses, on a documentation
// address; the repo holds no deployment's configs.
func TestExampleNode(t *testing.T) {
	b, err := os.ReadFile("../../../configs/example-node.json")
	if err != nil {
		t.Fatal(err)
	}
	c, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if a, ok := c.StaticAddr(); !ok || !strings.HasPrefix(a.String(), "192.0.2.") {
		t.Errorf("static address %v %v", a, ok)
	}
	if p, err := c.Payload(); err != nil || len(p) > MaxPayloadNVS {
		t.Errorf("payload %d bytes: %v", len(p), err)
	}
	ents, _ := os.ReadDir("../../../configs")
	for _, e := range ents {
		if !strings.HasPrefix(e.Name(), "example-") {
			t.Errorf("configs/%s: the repo's configs/ holds examples only (example-*.json)", e.Name())
		}
	}
}

func TestEmptyAndLists(t *testing.T) {
	c, err := Parse([]byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := c.StaticAddr(); ok || c.SetsAddress() {
		t.Error("an empty config sets an address")
	}
	p, _ := c.Payload()
	if string(p) != `{"format":1}` {
		t.Errorf("payload %s", p)
	}
	// An empty list stays in the payload: it means none, not the default.
	c, err = Parse([]byte(`{"network":{"address":"dhcp"},"forwarders":[],"forward_zones":[],"secondary":{"zones":[]},"time":{"ntp":[]}}`))
	if err != nil {
		t.Fatal(err)
	}
	p, _ = c.Payload()
	for _, want := range []string{`"forwarders":[]`, `"forward_zones":[]`, `"zones":[]`, `"ntp":[]`, `"address":"dhcp"`} {
		if !strings.Contains(string(p), want) {
			t.Errorf("payload %s lacks %s", p, want)
		}
	}
	if !c.SetsAddress() {
		t.Error("dhcp not an address setting")
	}
}

// The same refusals as the node's (firmware/tests/test_core.c, test_config).
func TestRefused(t *testing.T) {
	for _, c := range []struct{ json, why string }{
		{`[]`, "cannot unmarshal"},
		{`{"forwarders":["1.1.1.1"],}`, "invalid character"},
		{`{} {}`, "more after"},
		{`{"format":2}`, "format 2"},
		{`{"fowarders":["1.1.1.1"]}`, "unknown field"},
		{`{"network":{"address":"dhcp","mask":1}}`, "unknown field"},
		{`{"network":{"address":"198.51.100.5"}}`, "prefix length"},
		{`{"network":{"address":"198.51.100.5/24"}}`, "gateway: required"},
		{`{"network":{"address":"198.51.100.5/24","gateway":"192.0.2.1"}}`, "another address in the node's network"},
		{`{"network":{"address":"198.51.100.255/24","gateway":"198.51.100.1"}}`, "broadcast"},
		{`{"network":{"address":"198.51.100.0/24","gateway":"198.51.100.1"}}`, "network's own"},
		{`{"network":{"address":"dhcp","gateway":"198.51.100.1"}}`, "only with a static address"},
		{`{"forwarders":["1.1.1.1","1.1.1.2","1.1.1.3","1.1.1.4","1.1.1.5"]}`, "at most 4 addresses"},
		{`{"hosted":{"enabled":1}}`, "cannot unmarshal"},
		{`{"hosted":{"zones":[]}}`, "unknown field"},
		{`{"blocking":{"enabled":"no"}}`, "cannot unmarshal"},
		{`{"forwarders":["dns.google"]}`, "not an IPv4 address"},
		{`{"forwarders":["::1"]}`, "not an IPv4 address"},
		{`{"forwarders":["127.0.0.1"]}`, "can't be used"},
		{`{"upstream_timeout_ms":50}`, "from 100 to 10000"},
		{`{"upstream_timeout_ms":1500.5}`, "cannot unmarshal"},
		{`{"secondary":{"zones":["a/b"]}}`, "not a zone name"},
		{`{"secondary":{"zones":["a..b"]}}`, "not a zone name"},
		{`{"secondary":{"zones":["x.com","X.com."]}}`, "x.com twice"},
		{`{"secondary":{"zones":["x.com"]},"forward_zones":[{"zone":"x.com","forwarder":"1.1.1.1"}]}`, "both a secondary zone and a forward zone"},
		{`{"forward_zones":[{"zone":"x.com"}]}`, "forwarder: required"},
		{`{"wifi":{"password":"12345678"}}`, "only with wifi.ssid"},
		{`{"wifi":{"ssid":"x","password":"short"}}`, "8-63"},
		{`{"wifi":{"tx_power_dbm":21}}`, "from 2 to 20"},
		{`{"time":{"tz":"5EST"}}`, "POSIX TZ"},
		// Only the characters POSIX TZ uses, as the node: nothing that could break its /status
		{`{"time":{"tz":"EST5\"EDT"}}`, "POSIX TZ"},
		{`{"time":{"tz":"EST5\\EDT"}}`, "POSIX TZ"},
		{`{"time":{"tz":"EST5 EDT"}}`, "POSIX TZ"},
		{`{"time":{"tz":"EST5EDT;"}}`, "POSIX TZ"},
		{`{"time":{"tz":"America/New_York"}}`, "POSIX TZ"},
		{`{"time":{"tz":"<+0530-5:30"}}`, "POSIX TZ"},
		{`{"time":{"tz":"<<+05>>-5"}}`, "POSIX TZ"},
		{`{"time":{"tz":"UTC>0"}}`, "POSIX TZ"},
		{`{"time":{"ntp":["bad host"]}}`, "host names"},
		{`{"blocking":{"answer":"refused"}}`, `"null" or "nxdomain"`},
		{`{"name":"a\"b"}`, "printable ASCII"},
		{`{"secondary":{"zones":["a.."]}}`, "not a zone name"},
		{`{"network":{"address":"198.51.100.5/24","gateway":"198.51.100.1"},"secondary":{"primary":"198.51.100.5"}}`, "own address"},
	} {
		_, err := Parse([]byte(c.json))
		if err == nil || !strings.Contains(err.Error(), c.why) {
			t.Errorf("%s: %v, want %q", c.json, err, c.why)
		}
	}
}

func TestFull(t *testing.T) {
	c, err := Parse([]byte(`{"format":1,"name":"dns-a","network":{"address":"198.51.100.53/24","gateway":"198.51.100.1"},
		"wifi":{"ssid":"home","password":"secret123","power_save":true,"tx_power_dbm":11},
		"forwarders":["1.1.1.1","9.9.9.9"],"upstream_timeout_ms":900,
		"forward_zones":[{"zone":"Corp.Example.","forwarder":"198.51.100.2"}],
		"secondary":{"zones":["example.com"],"soa_poll_s":120},
		"time":{"ntp":["pool.ntp.org","198.51.100.1"],"tz":"EST5EDT,M3.2.0,M11.1.0"},
		"blocking":{"answer":"nxdomain","ttl":30}}`))
	if err != nil {
		t.Fatal(err)
	}
	if a, _ := c.StaticAddr(); a.String() != "198.51.100.53" {
		t.Error(a)
	}
	p, err := c.Payload()
	if err != nil {
		t.Fatal(err)
	}
	// What the node gets reads back the same.
	c2, err := Parse(p)
	if err != nil {
		t.Fatal(err)
	}
	p2, _ := c2.Payload()
	if string(p) != string(p2) {
		t.Errorf("round trip:\n%s\n%s", p, p2)
	}
}

// Services: off is kept in the payload (false is not left out), on or left out is the default.
func TestServices(t *testing.T) {
	c, err := Parse([]byte(`{"forwarders":[],"hosted":{"enabled":false},"blocking":{"enabled":false,"ttl":5}}`))
	if err != nil {
		t.Fatal(err)
	}
	p, _ := c.Payload()
	if string(p) != `{"format":1,"forwarders":[],"hosted":{"enabled":false},"blocking":{"enabled":false,"ttl":5}}` {
		t.Errorf("payload %s", p)
	}
	c, err = Parse([]byte(`{"hosted":{"enabled":true},"blocking":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	p, _ = c.Payload()
	if string(p) != `{"format":1,"hosted":{"enabled":true},"blocking":{}}` {
		t.Errorf("payload %s", p)
	}
}

// "cpu": {"dfs"} turns clock scaling on or off; the idle clock is the board's.
func TestCPU(t *testing.T) {
	c, err := Parse([]byte(`{"cpu":{"dfs":false}}`))
	if err != nil {
		t.Fatal(err)
	}
	if p, _ := c.Payload(); string(p) != `{"format":1,"cpu":{"dfs":false}}` || !c.SetsCPU() {
		t.Errorf("payload %s", p)
	}
	if c, err = Parse([]byte(`{"name":"a"}`)); err != nil || c.SetsCPU() {
		t.Fatal(err)
	}
	if _, err := Parse([]byte(`{"cpu":{"min_mhz":80}}`)); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatal(err)
	}
}

// The config payload the firmware's slot tests use (firmware/tests/release_vectors.h) is
// one this package accepts.
func TestFirmwareVector(t *testing.T) {
	_, err := Parse([]byte(`{"format":1,"name":"test","network":{"address":"192.0.2.3/24","gateway":"192.0.2.1"},` +
		`"forwarders":["9.9.9.9"],"time":{"tz":"EST5EDT,M3.2.0,M11.1.0"}}`))
	if err != nil {
		t.Fatal(err)
	}
}

// The POSIX TZ shapes the node takes (firmware/tests/test_core.c): a quoted name, offsets
// with minutes, rules with times.
func TestTZShapes(t *testing.T) {
	for _, tz := range []string{"UTC0", "EST5EDT,M3.2.0,M11.1.0", "<+0530>-5:30", "<-03>3<-02>,M3.5.0/-2,M10.5.0/-1",
		"NZST-12NZDT,M9.5.0,M4.1.0/3", "CET-1CEST,M3.5.0,M10.5.0/3"} {
		if _, err := Parse([]byte(`{"time":{"tz":"` + tz + `"}}`)); err != nil {
			t.Errorf("%s: %v", tz, err)
		}
	}
}
