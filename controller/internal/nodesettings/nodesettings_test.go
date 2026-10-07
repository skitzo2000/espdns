package nodesettings

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/nodecfg"
	"github.com/skitzo2000/espdns/controller/internal/release"
)

func parse(t *testing.T, s string) *nodecfg.Config {
	t.Helper()
	c, err := nodecfg.Parse([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func ptr[T any](v T) *T { return &v }

// The form from a config: what it sets is "config"; the rest is what the node reports, or
// the firmware's default, or unknown.
func TestRead(t *testing.T) {
	c := parse(t, `{"name":"dns-a","network":{"address":"192.0.2.53/24","gateway":"192.0.2.1"},"forwarders":["198.51.100.1"],
		"time":{"tz":"EST5EDT,M3.2.0,M11.1.0"},"blocking":{"enabled":false,"ttl":10},"querylog":{"client":"subnet"}}`)
	st := &release.NodeStatus{QueryLog: &release.QueryLogStatus{Enabled: true, Client: "full"}}
	f := Read(c, st)
	if f.Name.Value != "dns-a" || f.Name.From != FromConfig || f.Name.Applies != "live" {
		t.Errorf("name %+v", f.Name)
	}
	if f.Network.Value == nil || f.Network.Value.Address != "192.0.2.53/24" || f.Network.From != FromConfig || f.Network.Applies != "restart" {
		t.Errorf("network %+v", f.Network)
	}
	if !slices.Equal(f.Forwarders.Value, []string{"198.51.100.1"}) || f.Forwarders.From != FromConfig {
		t.Errorf("forwarders %+v", f.Forwarders)
	}
	if f.TZ.Value != (TimeZone{TZ: "EST5EDT,M3.2.0,M11.1.0", Name: "America/New_York"}) || f.TZ.From != FromConfig {
		t.Errorf("tz %+v", f.TZ)
	}
	if f.Blocking.Value || f.Blocking.From != FromConfig {
		t.Errorf("blocking %+v", f.Blocking)
	}
	if f.QueryLog.Value != (QueryLog{Enabled: true, Client: "subnet"}) || f.QueryLog.From != FromConfig {
		t.Errorf("querylog %+v", f.QueryLog)
	}

	// No config: what the node reports.
	st = &release.NodeStatus{Config: &release.ConfigStatus{Name: "dns-b", Address: "static", IP: "192.0.2.54/24", Gateway: "192.0.2.1"},
		Services: []release.ServiceStatus{{Name: "dns", State: "running"}, {Name: "blocking", State: "off"}},
		QueryLog: &release.QueryLogStatus{Enabled: false, Client: "hidden"}}
	f = Read(nil, st)
	if f.Name.Value != "dns-b" || f.Name.From != FromNode || f.Network.From != FromNode || f.Network.Value.Gateway != "192.0.2.1" ||
		f.Blocking.Value || f.Blocking.From != FromNode || f.QueryLog.Value != (QueryLog{Client: "hidden"}) || f.QueryLog.From != FromNode {
		t.Errorf("from the node: %+v", f)
	}
	if f.Forwarders.From != FromUnknown || f.Forwarders.Value != nil || f.TZ.From != FromUnknown {
		t.Errorf("unknown: %+v %+v", f.Forwarders, f.TZ)
	}
	// Nothing at all: the defaults nodecfg documents.
	f = Read(nil, nil)
	if !f.Blocking.Value || f.Blocking.From != FromDefault || f.QueryLog.Value != (QueryLog{Enabled: true, Client: "full"}) ||
		f.Name.From != FromUnknown || f.Network.From != FromUnknown {
		t.Errorf("none: %+v", f)
	}
}

// An edit changes what it names and keeps every other key, the Wi-Fi password too.
func TestApply(t *testing.T) {
	base := parse(t, `{"name":"dns-a","wifi":{"ssid":"net","password":"a secret pass"},"secondary":{"zones":["example.com"]},
		"blocking":{"answer":"nxdomain"},"time":{"ntp":["192.0.2.1"]}}`)
	keep, _ := json.Marshal(base)
	c, err := Apply(base, Edit{Name: ptr(" dns-b "), Network: &nodecfg.Network{Address: "192.0.2.60/24", Gateway: "192.0.2.1"},
		Forwarders: ptr([]string{"198.51.100.1", " 198.51.100.2"}), TZ: ptr("Europe/London"), Blocking: ptr(false),
		QueryLog: &QueryLogEdit{Client: ptr("hidden")}})
	if err != nil {
		t.Fatal(err)
	}
	if after, _ := json.Marshal(base); string(after) != string(keep) {
		t.Errorf("base changed: %s", after)
	}
	if c.Name != "dns-b" || c.Network.Address != "192.0.2.60/24" || !slices.Equal(*c.Forwarders, []string{"198.51.100.1", "198.51.100.2"}) ||
		c.Time.TZ != "GMT0BST,M3.5.0/1,M10.5.0" || !slices.Equal(*c.Time.NTP, []string{"192.0.2.1"}) || *c.Blocking.Enabled ||
		c.Blocking.Answer != "nxdomain" || c.QueryLog.Client != "hidden" || c.QueryLog.Enabled != nil {
		t.Errorf("applied %+v", c)
	}
	if *c.Wifi.Password != "a secret pass" || (*c.Secondary.Zones)[0] != "example.com" {
		t.Errorf("other keys: %+v", c)
	}
	if got := Changed(base, c); !slices.Equal(got, Fields) {
		t.Errorf("changed %v", got)
	}
	// Forwarding off: an empty list.
	c, err = Apply(base, Edit{Forwarders: ptr([]string{})})
	if err != nil || c.Forwarders == nil || len(*c.Forwarders) != 0 || slices.Contains(c.Services(), "forwarding") {
		t.Errorf("forwarders off: %+v %v", c, err)
	}

	// Reset: back to the board's or the firmware's, keys emptied away.
	full := parse(t, `{"name":"x","network":{"address":"dhcp"},"forwarders":["198.51.100.1"],"time":{"tz":"UTC0"},
		"blocking":{"enabled":false},"querylog":{"enabled":false}}`)
	c, err = Apply(full, Edit{Reset: Fields})
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := json.Marshal(c); string(b) != `{}` {
		t.Errorf("all reset: %s", b)
	}
	if got := Changed(full, c); !slices.Equal(got, Fields) {
		t.Errorf("changed %v", got)
	}
}

// Each refusal is the node's, and names the form's field.
func TestApplyRefused(t *testing.T) {
	base := parse(t, `{"name":"a"}`)
	for _, tc := range []struct {
		e     Edit
		field string
		want  string
	}{
		{Edit{Name: ptr(strings.Repeat("n", 32))}, "name", "at most 31"},
		{Edit{Name: ptr(`a"b`)}, "name", "printable ASCII"},
		{Edit{Name: ptr("  ")}, "name", "give one"},
		{Edit{Network: &nodecfg.Network{Address: "192.0.2.60"}}, "network", "prefix length"},
		{Edit{Network: &nodecfg.Network{Address: "192.0.2.60/24"}}, "network", "gateway: required"},
		{Edit{Network: &nodecfg.Network{Address: "192.0.2.60/24", Gateway: "198.51.100.1"}}, "network", "another address in the node's network"},
		{Edit{Network: &nodecfg.Network{Address: "dhcp", Gateway: "192.0.2.1"}}, "network", "only with a static"},
		{Edit{Forwarders: ptr([]string{"1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112", "8.8.8.8"})}, "forwarders", "at most 4"},
		{Edit{Forwarders: ptr([]string{"dns.example.com"})}, "forwarders", "not an IPv4"},
		{Edit{Forwarders: ptr([]string{"127.0.0.1"})}, "forwarders", "can't be used"},
		{Edit{TZ: ptr("Mars/Olympus_Mons")}, "tz", "not a time zone this controller knows"},
		{Edit{TZ: ptr(`EST5"`)}, "tz", "POSIX TZ"},
		{Edit{TZ: ptr("")}, "tz", "give a time zone"},
		{Edit{QueryLog: &QueryLogEdit{Client: ptr("some")}}, "querylog", `"full", "subnet" or "hidden"`},
		{Edit{QueryLog: &QueryLogEdit{Client: ptr("")}}, "querylog", `"full", "subnet" or "hidden"`},
		{Edit{QueryLog: &QueryLogEdit{}}, "querylog", `give "enabled"`},
		{Edit{Name: ptr("b"), Reset: []string{"name"}}, "name", "both set and reset"},
		{Edit{Reset: []string{"wifi"}}, "wifi", "no field"},
	} {
		_, err := Apply(base, tc.e)
		var fe *FieldError
		if !errors.As(err, &fe) || fe.Field != tc.field || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%+v: %v", tc.e, err)
		}
	}
	if _, err := Apply(base, Edit{}); err == nil || !strings.Contains(err.Error(), "changes nothing") {
		t.Errorf("empty edit: %v", err)
	}
}

// Applies says what the firmware does (nodecfg.Compare): a change of each field alone is
// live, or waits for a reboot.
func TestAppliesIsTheFirmwares(t *testing.T) {
	base := parse(t, `{"name":"a","network":{"address":"192.0.2.53/24","gateway":"192.0.2.1"},"forwarders":["198.51.100.1"],
		"time":{"tz":"UTC0"},"blocking":{"enabled":true},"querylog":{"enabled":true,"client":"full"}}`)
	edits := map[string]Edit{
		"name":       {Name: ptr("b")},
		"network":    {Network: &nodecfg.Network{Address: "192.0.2.54/24", Gateway: "192.0.2.1"}},
		"forwarders": {Forwarders: ptr([]string{"198.51.100.2"})},
		"tz":         {TZ: ptr("Europe/Paris")},
		"blocking":   {Blocking: ptr(false)},
		"querylog":   {QueryLog: &QueryLogEdit{Client: ptr("subnet")}},
	}
	if len(edits) != len(Fields) || len(Applies) != len(Fields) || len(Words) != len(Fields) {
		t.Fatal("a field without its edit, Applies or Words")
	}
	for f, e := range edits {
		c, err := Apply(base, e)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		ch := nodecfg.Compare(base, c, nil)
		got := "live"
		if ch.NeedsReboot() {
			got = "restart"
		}
		if got != Applies[f] || len(ch.Maybe) > 0 || got == "live" && len(ch.Live) == 0 {
			t.Errorf("%s: Applies %q, the firmware %+v", f, Applies[f], ch)
		}
		if Restart(ch) == "no" != (got == "live") {
			t.Errorf("%s: Restart %q", f, Restart(ch))
		}
		if !slices.Equal(Changed(base, c), []string{f}) {
			t.Errorf("%s: changed %v", f, Changed(base, c))
		}
	}
	if !strings.Contains(Effect("dns2", nodecfg.Change{Reboot: []string{nodecfg.ReasonAddress}}), "dns2 restarts") ||
		!strings.Contains(Effect("dns2", nodecfg.Change{Maybe: []string{nodecfg.ReasonAddress}}), "may restart") ||
		!strings.Contains(Effect("dns2", nodecfg.Change{Live: []string{"name"}}), "live") {
		t.Error("effect")
	}
	if s := Summary("dns2", []string{"forwarders", "tz"}); s != "dns2: upstream DNS, time zone" {
		t.Errorf("summary %q", s)
	}
}

// Every time zone is one the node takes, under a name of the tz database, once.
func TestTimeZones(t *testing.T) {
	if len(TimeZones) < 20 {
		t.Fatalf("%d time zones", len(TimeZones))
	}
	seen := map[string]bool{}
	for _, z := range TimeZones {
		if _, err := time.LoadLocation(z.Name); err != nil {
			t.Errorf("%s: %v", z.Name, err)
		}
		c := nodecfg.Config{Time: &nodecfg.Time{TZ: z.TZ}}
		if err := c.Validate(); err != nil {
			t.Errorf("%s: %v", z.Name, err)
		}
		if seen[z.Name] {
			t.Errorf("%s twice", z.Name)
		}
		seen[z.Name] = true
		if tz, err := PosixTZ(strings.ToLower(z.Name)); err != nil || tz != z.TZ {
			t.Errorf("%s: %q %v", z.Name, tz, err)
		}
	}
	if ZoneName("EST5EDT,M3.2.0,M11.1.0") != "America/New_York" || ZoneName("XYZ3") != "" {
		t.Error("ZoneName")
	}
	if tz, err := PosixTZ("CET-1CEST,M3.5.0,M10.5.0/3"); err != nil || tz != "CET-1CEST,M3.5.0,M10.5.0/3" {
		t.Errorf("a POSIX string: %q %v", tz, err)
	}
}

// Each time zone's POSIX TZ string is the footer of its TZif file in Go's
// lib/time/zoneinfo.zip, as timezones.go says.
func TestTimeZonesAreGos(t *testing.T) {
	zr, err := zip.OpenReader(filepath.Join(runtime.GOROOT(), "lib", "time", "zoneinfo.zip"))
	if err != nil {
		t.Skipf("no zoneinfo.zip: %v", err)
	}
	defer zr.Close()
	for _, z := range TimeZones {
		f, err := zr.Open(z.Name)
		if err != nil {
			t.Errorf("%s: %v", z.Name, err)
			continue
		}
		b, err := io.ReadAll(f)
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
		b = bytes.TrimRight(b, "\n")
		if foot := string(b[bytes.LastIndexByte(b, '\n')+1:]); foot != z.TZ {
			t.Errorf("%s: %q, the zoneinfo's %q", z.Name, z.TZ, foot)
		}
	}
}
