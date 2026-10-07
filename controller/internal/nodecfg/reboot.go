package nodecfg

import (
	"encoding/json"
	"net/netip"
	"slices"
	"strings"
)

// The reasons a config waits for a reboot, as /status names them (firmware reboot.c).
const (
	ReasonAddress = "config: address"
	ReasonWifi    = "config: wifi"
	ReasonZones   = "config: zones"
)

// Change is what going from one config to another does on a node: the firmware's
// cfg_reboot_reasons (what applies only at a boot) and cfg_copy_live (what applies live),
// on the shared vectors in firmware/tests/cfg_reboot_vectors.json.
//
// The node compares its settings resolved through the layers: a setting a config leaves
// out is the board's or the firmware's. Those aren't in the config, so where one side gives
// a setting the other leaves out, the reason is in Maybe: a reboot unless the lower layer
// has the same value. Running fills in the address the node reports for a side without one.
type Change struct {
	Reboot []string `json:"reboot"` // what needs a reboot, for certain
	Maybe  []string `json:"maybe"`  // what needs one unless the board's or firmware's value is the same
	Live   []string `json:"live"`   // the settings that change live
}

// NeedsReboot says whether the change certainly waits for a reboot.
func (c Change) NeedsReboot() bool { return len(c.Reboot) > 0 }

// net is a network setting as the node compares it: the address, prefix and gateway, or DHCP.
type netSetting struct {
	dhcp    bool
	addr    netip.Prefix
	gateway string
}

func netOf(n *Network) netSetting {
	if n.Address == "dhcp" {
		return netSetting{dhcp: true}
	}
	p, _ := netip.ParsePrefix(n.Address)
	return netSetting{addr: p, gateway: n.Gateway}
}

// zoneList is a zone list as the node keeps it: lowercased, without a trailing dot.
func zoneList(zs []string) []string {
	out := make([]string, len(zs))
	for i, z := range zs {
		out[i] = strings.ToLower(strings.TrimSuffix(z, "."))
	}
	return out
}

func fzoneList(fs []ForwardZone) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		a, _ := netip.ParseAddr(f.Forwarder)
		out[i] = strings.ToLower(strings.TrimSuffix(f.Zone, ".")) + " " + a.String()
	}
	return out
}

// wifiNet is the Wi-Fi network a config gives: its SSID and password, "" for the network
// saved over USB (no "ssid"); a password only with an SSID.
func wifiNet(c *Config) (string, string) {
	if c.Wifi == nil || c.Wifi.SSID == nil {
		return "", ""
	}
	pass := ""
	if c.Wifi.Password != nil {
		pass = *c.Wifi.Password
	}
	return *c.Wifi.SSID, pass
}

// cmp is one setting compared: the same, different, or unknown (one side leaves it to the
// lower layers).
type cmp int

const (
	same cmp = iota
	differs
	unknown
)

func compare[T any](a, b *T, eq func(T, T) bool) cmp {
	switch {
	case a == nil && b == nil:
		return same
	case a == nil || b == nil:
		return unknown
	case eq(*a, *b):
		return same
	}
	return differs
}

// Compare says what going from config from to config to does on a node. running, if not
// nil, is the network the node runs on now (its /status): it stands in for from's network
// when from leaves it out. nil configs are empty ones (the lower layers only).
func Compare(from, to *Config, running *Network) Change {
	if from == nil {
		from = &Config{}
	}
	if to == nil {
		to = &Config{}
	}
	var ch Change
	add := func(c cmp, reason string) {
		switch c {
		case differs:
			ch.Reboot = append(ch.Reboot, reason)
		case unknown:
			ch.Maybe = append(ch.Maybe, reason)
		}
	}

	// The address (cfg_reboot_reasons: ip, netmask, gateway, dhcp).
	fromNet := from.Network
	if fromNet == nil && to.Network != nil && running != nil {
		fromNet = running
	}
	add(compare(fromNet, to.Network, func(a, b Network) bool { return netOf(&a) == netOf(&b) }), ReasonAddress)

	// The Wi-Fi network: the SSID and password, "" when left out (no lower layer has them).
	fs, fp := wifiNet(from)
	ts, tp := wifiNet(to)
	if fs != ts || fp != tp {
		ch.Reboot = append(ch.Reboot, ReasonWifi)
	}

	// The zones: secondary zones, the primary, forward zones; the worst of the three.
	z := same
	for _, c := range []cmp{
		compare(secZones(from), secZones(to), func(a, b []string) bool { return slices.Equal(zoneList(a), zoneList(b)) }),
		compare(primary(from), primary(to), func(a, b netip.Addr) bool { return a == b }),
		compare(from.ForwardZones, to.ForwardZones, func(a, b []ForwardZone) bool { return slices.Equal(fzoneList(a), fzoneList(b)) }),
	} {
		if c == differs || c == unknown && z == same {
			z = c
		}
	}
	add(z, ReasonZones)

	// What changes live (cfg_copy_live): any of these given differently, or given on one
	// side only (the node goes to, or back to, the lower layer's value).
	live := []struct {
		name string
		a, b any
	}{
		{"name", from.Name, to.Name},
		{"wifi.tx_power_dbm", wifiField(from, func(w *Wifi) any { return w.TxPowerDBm }), wifiField(to, func(w *Wifi) any { return w.TxPowerDBm })},
		{"wifi.power_save", wifiField(from, func(w *Wifi) any { return w.PowerSave }), wifiField(to, func(w *Wifi) any { return w.PowerSave })},
		{"forwarders", from.Forwarders, to.Forwarders},
		{"upstream_timeout_ms", from.UpstreamTimeoutMS, to.UpstreamTimeoutMS},
		{"secondary.soa_poll_s", secField(from, func(s *Secondary) any { return s.SOAPollS }), secField(to, func(s *Secondary) any { return s.SOAPollS })},
		{"secondary.retry_s", secField(from, func(s *Secondary) any { return s.RetryS }), secField(to, func(s *Secondary) any { return s.RetryS })},
		{"hosted", from.Hosted, to.Hosted},
		{"time", from.Time, to.Time},
		{"blocking", from.Blocking, to.Blocking},
		{"cpu", from.CPU, to.CPU},
		{"querylog", from.QueryLog, to.QueryLog},
	}
	for _, l := range live {
		a, _ := json.Marshal(l.a)
		b, _ := json.Marshal(l.b)
		if string(a) != string(b) {
			ch.Live = append(ch.Live, l.name)
		}
	}
	return ch
}

func secZones(c *Config) *[]string {
	if c.Secondary == nil {
		return nil
	}
	return c.Secondary.Zones
}

func primary(c *Config) *netip.Addr {
	if c.Secondary == nil || c.Secondary.Primary == "" {
		return nil
	}
	a, _ := netip.ParseAddr(c.Secondary.Primary)
	return &a
}

func wifiField(c *Config, f func(*Wifi) any) any {
	if c.Wifi == nil {
		return nil
	}
	return f(c.Wifi)
}

func secField(c *Config, f func(*Secondary) any) any {
	if c.Secondary == nil {
		return nil
	}
	return f(c.Secondary)
}
