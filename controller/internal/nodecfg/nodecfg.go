// Package nodecfg reads and checks node configs: the JSON a REL_CONFIG release carries
// (docs/design.md, settings in layers; format in firmware/main/cfg.h). Every key is
// optional: a key left out keeps the board's or the firmware's default, and a list given
// replaces the default whole ("forward_zones": [] means none). The checks here are the
// node's, so a config this package accepts is one the node takes.
//
// The services a node runs follow from it (firmware/main/svc.h): forwarding while it has
// forwarders ("forwarders": [] turns it off), forward zones and secondary zones while it
// has any, hosted zones and blocking while "enabled" (true unless the config says false).
//
//	{
//	  "format": 1,
//	  "name": "dns-a",
//	  "network": { "address": "192.0.2.53/24", "gateway": "192.0.2.1" },
//	  "wifi": { "ssid": "home", "password": "...", "tx_power_dbm": 11, "power_save": false },
//	  "forwarders": [ "9.9.9.9", "1.1.1.1" ],
//	  "upstream_timeout_ms": 1500,
//	  "forward_zones": [ { "zone": "corp.example", "forwarder": "192.0.2.53" } ],
//	  "secondary": { "primary": "192.0.2.254", "zones": [ "local" ], "soa_poll_s": 60, "retry_s": 30 },
//	  "hosted": { "enabled": true },
//	  "time": { "ntp": [ "192.0.2.1" ], "tz": "EST5EDT,M3.2.0,M11.1.0" },
//	  "blocking": { "enabled": true, "answer": "null", "ttl": 10 },
//	  "cpu": { "dfs": false },
//	  "querylog": { "enabled": true, "client": "full" }
//	}
package nodecfg

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strings"
)

const (
	Format = 1
	// MaxPayload is what one slot of a node's config partition holds (16 KB less the
	// release header); a node without the partition yet keeps configs in NVS, up to
	// MaxPayloadNVS bytes.
	MaxPayload    = 16384 - 192
	MaxPayloadNVS = 4000

	maxForwarders = 4
	maxZones      = 32
	maxNTP        = 3
)

type Config struct {
	Format            int            `json:"format,omitempty"`
	Name              string         `json:"name,omitempty"`
	Network           *Network       `json:"network,omitempty"`
	Wifi              *Wifi          `json:"wifi,omitempty"`
	Forwarders        *[]string      `json:"forwarders,omitempty"`
	UpstreamTimeoutMS *int           `json:"upstream_timeout_ms,omitempty"`
	ForwardZones      *[]ForwardZone `json:"forward_zones,omitempty"`
	Secondary         *Secondary     `json:"secondary,omitempty"`
	Hosted            *Hosted        `json:"hosted,omitempty"`
	Time              *Time          `json:"time,omitempty"`
	Blocking          *Blocking      `json:"blocking,omitempty"`
	CPU               *CPU           `json:"cpu,omitempty"`
	QueryLog          *QueryLog      `json:"querylog,omitempty"`
}

// QueryLog: Enabled false turns the query log off (left out: on, on a board with
// memory.querylog_kb for it), live. Client is how much of a client's address it keeps:
// "full" (the default), "subnet" (its /24) or "hidden" (none), applied as each query is
// logged (firmware qlog.h).
type QueryLog struct {
	Enabled *bool  `json:"enabled,omitempty"`
	Client  string `json:"client,omitempty"`
}

// QueryLogClients are the values QueryLog.Client takes.
var QueryLogClients = []string{"full", "subnet", "hidden"}

// CPU: DFS turns the idle clock scaling on or off, live (left out: the board definition's,
// else the chip image's default; firmware cpuplan.h). The idle clock is the board's.
type CPU struct {
	DFS *bool `json:"dfs,omitempty"`
}

// Network: Address is the node's static address with its prefix length
// ("192.0.2.53/24"), which then needs Gateway, or "dhcp" for a network with a DHCP
// server (never one in settings.json's no_dhcp). Left out, the node keeps its board definition's address
// (written when it was flashed), else its firmware's; a node never asks DHCP on its own.
// The board definition's "network" (internal/boards) is the same setting.
type Network struct {
	Address string `json:"address"`
	Gateway string `json:"gateway,omitempty"`
}

// Check checks a network setting as the node does (cfg_parse_net).
func (n *Network) Check() error {
	if n.Address == "dhcp" {
		if n.Gateway != "" {
			return errors.New("network.gateway: only with a static address")
		}
		return nil
	}
	p, err := netip.ParsePrefix(n.Address)
	if err != nil || !p.Addr().Is4() || p.Bits() < 8 || p.Bits() > 30 {
		return fmt.Errorf("network.address: \"dhcp\", or an address with its prefix length (8-30), as 192.0.2.53/24; not %q", n.Address)
	}
	if n.Gateway == "" {
		return errors.New("network.gateway: required with a static address")
	}
	g, err := ipv4(n.Gateway, "network.gateway")
	if err != nil {
		return err
	}
	a := p.Addr()
	if a == p.Masked().Addr() || a == lastAddr(p) {
		return fmt.Errorf("network.address: %s is the network's own or broadcast address", a)
	}
	if !p.Contains(g) || g == a {
		return errors.New("network.gateway: must be another address in the node's network")
	}
	return nil
}

type Wifi struct {
	SSID       *string `json:"ssid,omitempty"`
	Password   *string `json:"password,omitempty"`
	TxPowerDBm *int    `json:"tx_power_dbm,omitempty"`
	PowerSave  *bool   `json:"power_save,omitempty"`
}

type ForwardZone struct {
	Zone      string `json:"zone"`
	Forwarder string `json:"forwarder"`
}

type Secondary struct {
	Primary  string    `json:"primary,omitempty"`
	Zones    *[]string `json:"zones,omitempty"`
	SOAPollS *int      `json:"soa_poll_s,omitempty"`
	RetryS   *int      `json:"retry_s,omitempty"`
}

type Time struct {
	NTP *[]string `json:"ntp,omitempty"`
	TZ  string    `json:"tz,omitempty"`
}

// Hosted: Enabled false turns the hosted zones service off (left out: on).
type Hosted struct {
	Enabled *bool `json:"enabled,omitempty"`
}

// Blocking: Enabled false turns the service off (left out: on). Answer is "null"
// (0.0.0.0, ::, NODATA) or "nxdomain".
type Blocking struct {
	Enabled *bool  `json:"enabled,omitempty"`
	Answer  string `json:"answer,omitempty"`
	TTL     *int   `json:"ttl,omitempty"`
}

// Parse reads a config file and checks it. Unknown keys are errors, as on the node.
func Parse(b []byte) (*Config, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	var c Config
	if err := d.Decode(&c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errors.New("config: more after the JSON object")
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Payload is the config as the node receives it: compact JSON with the format set.
func (c *Config) Payload() ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	cc := *c
	cc.Format = Format
	b, err := json.Marshal(&cc)
	if err != nil {
		return nil, err
	}
	if len(b) > MaxPayload {
		return nil, fmt.Errorf("config is %d bytes; a node holds at most %d", len(b), MaxPayload)
	}
	return b, nil
}

// StaticAddr is the node's static address, if the config gives one.
func (c *Config) StaticAddr() (netip.Addr, bool) {
	if c.Network == nil || c.Network.Address == "dhcp" {
		return netip.Addr{}, false
	}
	p, err := netip.ParsePrefix(c.Network.Address)
	return p.Addr(), err == nil
}

// SetsAddress: the config says static or DHCP (else the node keeps its board's or firmware's address).
func (c *Config) SetsAddress() bool { return c.Network != nil }

// SwitchesServices says whether the config uses what only firmware with services takes
// ("hosted", "blocking": {"enabled"}, "forwarders": []): firmware from before them refuses
// it, and a node rolled back to such firmware can't boot on it.
func (c *Config) SwitchesServices() bool {
	return c.Hosted != nil || c.Blocking != nil && c.Blocking.Enabled != nil ||
		c.Forwarders != nil && len(*c.Forwarders) == 0
}

// SetsCPU says whether the config has "cpu", which firmware from before clock scaling
// refuses (its /status has no "cpu").
func (c *Config) SetsCPU() bool { return c.CPU != nil }

// SetsQueryLog says whether the config has "querylog", which firmware from before the query
// log refuses (its /status has no "querylog").
func (c *Config) SetsQueryLog() bool { return c.QueryLog != nil }

// Services are the node services the config runs, in the node's order (firmware svc.h,
// svc_enabled): a list the config leaves out is the firmware's default, which has
// forwarders, forward zones and secondary zones.
func (c *Config) Services() []string {
	on := []string{"dns"}
	if c.Forwarders == nil || len(*c.Forwarders) > 0 {
		on = append(on, "forwarding")
	}
	if c.ForwardZones == nil || len(*c.ForwardZones) > 0 {
		on = append(on, "forward_zones")
	}
	if c.Secondary == nil || c.Secondary.Zones == nil || len(*c.Secondary.Zones) > 0 {
		on = append(on, "secondary")
	}
	if c.Hosted == nil || c.Hosted.Enabled == nil || *c.Hosted.Enabled {
		on = append(on, "hosted")
	}
	if c.Blocking == nil || c.Blocking.Enabled == nil || *c.Blocking.Enabled {
		on = append(on, "blocking")
	}
	if c.QueryLog == nil || c.QueryLog.Enabled == nil || *c.QueryLog.Enabled {
		on = append(on, "querylog")
	}
	return on
}

func ipv4(s, what string) (netip.Addr, error) {
	a, err := netip.ParseAddr(s)
	if err != nil || !a.Is4() || strings.Count(s, ".") != 3 {
		return a, fmt.Errorf("%s: not an IPv4 address: %q", what, s)
	}
	if a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() || a == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return a, fmt.Errorf("%s: %s can't be used", what, s)
	}
	return a, nil
}

// zoneName checks a zone name as the node does and returns it lowercased, without a trailing dot.
func zoneName(s, what string) (string, error) {
	n := strings.TrimSuffix(s, ".")
	ok := n != "" && len(n) <= 253 && n[0] != '.' && n[len(n)-1] != '.' && !strings.Contains(n, "..")
	for _, r := range n {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			ok = false
		}
	}
	for _, l := range strings.Split(n, ".") {
		if len(l) > 63 {
			ok = false
		}
	}
	if !ok {
		return "", fmt.Errorf("%s: not a zone name: %q", what, s)
	}
	return strings.ToLower(n), nil
}

func hostOK(s string) bool {
	if s == "" || len(s) > 63 || s[0] == '.' || s[0] == '-' {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '.') {
			return false
		}
	}
	return true
}

// tzOK is the node's check (firmware/main/cfg.c tz_ok): a POSIX TZ string's shape, with
// only the characters POSIX TZ uses (letters, digits, + - , . / : and < > around a quoted
// name, not nested), so no quote or backslash reaches the node's /status.
func tzOK(s string) bool {
	if s == "" || len(s) > 63 {
		return false
	}
	c := s[0]
	if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c == '<') {
		return false
	}
	quoted := false
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '<' || c == '>':
			if quoted != (c == '>') {
				return false
			}
			quoted = !quoted
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', strings.IndexByte("+-,./:", c) >= 0:
		default:
			return false
		}
	}
	return !quoted
}

func intIn(v *int, lo, hi int, what string) error {
	if v != nil && (*v < lo || *v > hi) {
		return fmt.Errorf("%s: an integer from %d to %d", what, lo, hi)
	}
	return nil
}

// Validate applies the node's checks. Cross-checks against the firmware defaults (a zone
// that is both secondary and forwarded) are the node's to make; it refuses such a config
// with the reason.
func (c *Config) Validate() error {
	if c.Format != 0 && c.Format != Format {
		return fmt.Errorf("format %d: nodes read format %d", c.Format, Format)
	}
	if len(c.Name) > 31 {
		return errors.New("name: at most 31 characters")
	}
	for _, r := range c.Name {
		if r < ' ' || r > '~' || r == '"' || r == '\\' {
			return errors.New("name: printable ASCII, without quotes or backslashes")
		}
	}
	if n := c.Network; n != nil {
		if err := n.Check(); err != nil {
			return err
		}
	}
	if w := c.Wifi; w != nil {
		if w.SSID != nil && (len(*w.SSID) < 1 || len(*w.SSID) > 32) {
			return errors.New("wifi.ssid: 1-32 characters")
		}
		if w.Password != nil {
			if w.SSID == nil {
				return errors.New("wifi.password: only with wifi.ssid")
			}
			if l := len(*w.Password); l > 63 || (l > 0 && l < 8) {
				return errors.New("wifi.password: 8-63 characters, or empty for an open network")
			}
		}
		if err := intIn(w.TxPowerDBm, 2, 20, "wifi.tx_power_dbm"); err != nil {
			return err
		}
	}
	if c.Forwarders != nil {
		if len(*c.Forwarders) > maxForwarders {
			return fmt.Errorf("forwarders: at most %d addresses", maxForwarders)
		}
		for _, f := range *c.Forwarders {
			if _, err := ipv4(f, "forwarders"); err != nil {
				return err
			}
		}
	}
	if err := intIn(c.UpstreamTimeoutMS, 100, 10000, "upstream_timeout_ms"); err != nil {
		return err
	}
	zones := map[string]string{}
	if s := c.Secondary; s != nil {
		if s.Primary != "" {
			p, err := ipv4(s.Primary, "secondary.primary")
			if err != nil {
				return err
			}
			if a, ok := c.StaticAddr(); ok && a == p {
				return errors.New("secondary.primary: the node's own address")
			}
		}
		if s.Zones != nil {
			if len(*s.Zones) > maxZones {
				return fmt.Errorf("secondary.zones: at most %d", maxZones)
			}
			for _, z := range *s.Zones {
				n, err := zoneName(z, "secondary.zones")
				if err != nil {
					return err
				}
				if zones[n] != "" {
					return fmt.Errorf("secondary.zones: %s twice", n)
				}
				zones[n] = "secondary"
			}
		}
		if err := intIn(s.SOAPollS, 10, 86400, "secondary.soa_poll_s"); err != nil {
			return err
		}
		if err := intIn(s.RetryS, 5, 3600, "secondary.retry_s"); err != nil {
			return err
		}
	}
	if c.ForwardZones != nil {
		if len(*c.ForwardZones) > maxZones {
			return fmt.Errorf("forward_zones: at most %d", maxZones)
		}
		for _, f := range *c.ForwardZones {
			n, err := zoneName(f.Zone, "forward_zones[].zone")
			if err != nil {
				return err
			}
			if zones[n] == "forward" {
				return fmt.Errorf("forward_zones: %s twice", n)
			} else if zones[n] != "" {
				return fmt.Errorf("%s: both a secondary zone and a forward zone", n)
			}
			zones[n] = "forward"
			if f.Forwarder == "" {
				return errors.New("forward_zones[].forwarder: required")
			}
			if _, err := ipv4(f.Forwarder, "forward_zones[].forwarder"); err != nil {
				return err
			}
		}
	}
	if t := c.Time; t != nil {
		if t.NTP != nil {
			if len(*t.NTP) > maxNTP {
				return fmt.Errorf("time.ntp: at most %d servers", maxNTP)
			}
			for _, h := range *t.NTP {
				if !hostOK(h) {
					return fmt.Errorf("time.ntp: host names or IPv4 addresses; not %q", h)
				}
			}
		}
		if t.TZ != "" && !tzOK(t.TZ) {
			return fmt.Errorf("time.tz: a POSIX TZ string, as EST5EDT,M3.2.0,M11.1.0; not %q", t.TZ)
		}
	}
	if b := c.Blocking; b != nil {
		if b.Answer != "" && b.Answer != "null" && b.Answer != "nxdomain" {
			return errors.New(`blocking.answer: "null" or "nxdomain"`)
		}
		if err := intIn(b.TTL, 0, 86400, "blocking.ttl"); err != nil {
			return err
		}
	}
	if q := c.QueryLog; q != nil && q.Client != "" && !slices.Contains(QueryLogClients, q.Client) {
		return errors.New(`querylog.client: "full", "subnet" or "hidden"`)
	}
	return nil
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().As4()
	host := uint32(1)<<(32-p.Bits()) - 1
	v := (uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])) | host
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}
