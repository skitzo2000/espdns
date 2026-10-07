// Package adoption builds a node's adoption, the fleet.Adopt that internal/fleet runs
// (docs/design.md, Adoption and addressing), from one request: the espdns CLI's adopt
// flags (make fleet-adopt) and the controller's Adopt page (Web) both make a Request and
// build it here, so for the same intent they adopt the node the same way: the same
// address, the same config with the same checks, the same zone primary edits, the same rule
// for a node already in service. After the node is confirmed, Run records the config it
// runs (internal/configs, Pushed) and, when asked, adds it to settings.json.
package adoption

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/configs"
	"github.com/skitzo2000/espdns/controller/internal/fleet"
	"github.com/skitzo2000/espdns/controller/internal/nodecfg"
	"github.com/skitzo2000/espdns/controller/internal/nodes"
	"github.com/skitzo2000/espdns/controller/internal/primary"
	"github.com/skitzo2000/espdns/controller/internal/release"
	"github.com/skitzo2000/espdns/controller/internal/rolling"
	"github.com/skitzo2000/espdns/controller/internal/settings"
)

// DefaultWait is how long the node is waited for on its new address (-wait).
const DefaultWait = fleet.TrialWindow + 30*time.Second

// Request is one adoption: what the CLI's adopt flags say, field for field.
type Request struct {
	Host          string        // -host: the node's address now
	Node          string        // -node: its ID (found over mDNS without -host, else checked)
	Address       string        // -address: a.b.c.d/nn, or dhcp; "": the config's, else the node's now
	Gateway       string        // -gateway
	Config        string        // -config: a bare name is the data directory's configs/<name>
	Name          string        // -name
	Reserved      bool          // -reserved
	Identify      time.Duration // -identify
	PrimaryKind   string        // -primary-kind ("": settings.json's "primary")
	PrimaryURL    string        // -primary-url ("": settings.json's)
	PrimaryDone   bool          // -primary-done: the allow lists were changed by hand
	AddToSettings bool          // -add-to-settings
	Wait          time.Duration // -wait
	Catalog       string        // -catalog: the board catalog, for the config's memory plan
	Checks        rolling.Checks

	// The rule, for a node already in service, and the peers for the clients' DNS list.
	DataDir      string        // -data
	Settings     string        // -settings ("": the data directory's settings.json)
	MDNS         time.Duration // -mdns
	Peers        []string      // -peer
	DNSPeers     []string      // -dns-peer
	DNSPeerZones []string      // -dns-peer-zone
	NoDNSPeers   bool          // -no-dns-peers
	AllowSingle  bool          // -allow-single
	Force        bool          // -force
	DryRun       bool          // -dry-run

	// ConfigText, if set, is the config's bytes, read once by the caller (the controller,
	// whose dry run fingerprints them); nil: read from Config.
	ConfigText []byte `json:"-"`
	// Report, if set, hears what step 4 changes on the zone primary, or would in a dry run
	// (the controller's progress).
	Report func(primary.Edit) `json:"-"`
}

// SettingsPath is the settings file the request reads.
func (r Request) SettingsPath() string {
	if r.Settings != "" {
		return r.Settings
	}
	return settings.Path(r.DataDir)
}

// ConfigPath is the config file the request names.
func (r Request) ConfigPath() string {
	if r.Config == "" {
		return ""
	}
	return configs.Resolve(r.DataDir, r.Config)
}

// Token gives the zone primary's API token: "" (and no error) when there is none, so the
// changes are named to make by hand.
type Token func() (string, error)

// ZonePrimary is the zone primary the request uses (internal/primary), with its kind and
// address: -primary-kind and -primary-url (the old -technitium is both), else settings.json's
// "primary" (or its old "technitium"), else none set up, treated as manual. There is no
// other default: a primary is never reached unless this deployment names it. The token is
// read only for a kind with an API, or when none is set up: a token with no primary to use
// it on, for a config with zones, is a setup left half done and refused, rather than the
// changes quietly left to be made by hand.
func (r Request) ZonePrimary(s settings.Settings, token Token, zones bool, o primary.Options) (primary.Primary, primary.Config, error) {
	set := s.ZonePrimary()
	kind, url := r.PrimaryKind, r.PrimaryURL
	switch {
	case kind == "" && url == "":
		kind, url = set.Kind, set.URL
	case kind == "":
		if d, _ := primary.Lookup(set.Kind); !d.API {
			return nil, primary.Config{}, errors.New("-primary-url: give -primary-kind too " +
				`(settings.json names no zone primary with an API: "primary": {"kind": ...})`)
		}
		kind = set.Kind
	case url == "" && kind == set.Kind:
		url = set.URL
	}
	unset := kind == ""
	if unset {
		kind = primary.KindManual
	}
	d, ok := primary.Lookup(kind)
	switch {
	case !ok:
		return nil, primary.Config{}, fmt.Errorf("-primary-kind: %q is not one of %s", kind, strings.Join(primary.Kinds(), ", "))
	case !d.API && url != "":
		return nil, primary.Config{}, fmt.Errorf("-primary-url: the %s kind has no API", kind)
	case url != "":
		// A plain http address from settings.json pauses the primary (Open); one given
		// now (-primary-url) is refused.
		if err := d.CheckAPI(url); err != nil && (r.PrimaryURL != "" || !errors.Is(err, primary.ErrPlainHTTP)) {
			return nil, primary.Config{}, fmt.Errorf("-primary-url: %w", err)
		}
	}
	tok := ""
	if token != nil && (d.API || unset) {
		var err error
		if tok, err = token(); err != nil {
			return nil, primary.Config{}, fmt.Errorf("the zone primary API token: %w", err)
		}
	}
	pc := primary.Config{Kind: kind, URL: url}
	if pc.SameTarget(set) {
		pc.CertSHA256 = set.CertSHA256 // the certificate pinned for this primary; none for another address
	}
	if unset {
		if tok != "" && zones {
			return nil, pc, fmt.Errorf(`a zone primary API token but no zone primary: add "primary": {"kind": <%s>, `+
				`"url": <its API>} to settings.json (or -primary-kind and -primary-url, the Makefile's `+
				`PRIMARY_KIND= and PRIMARY_URL=), or {"kind": "manual"} to change its lists by hand`, strings.Join(primary.APIKinds(), " or "))
		}
		return primary.ByHand(d, `no zone primary in settings.json ("primary"): any primary, its lists changed by hand`), pc, nil
	}
	p, err := primary.Open(pc, tok, o)
	return p, pc, err
}

// Built is a request made into what fleet.AdoptNode takes, and what Run does after.
type Built struct {
	Adopt fleet.Adopt
	// ConfigName is the config's file name, as the record of the config pushed has it.
	ConfigName string
	// PrimaryKind is the zone primary's kind (internal/primary); PrimaryAPI the API used
	// for step 4, "" when the changes are made by hand (PrimaryWhy says why).
	PrimaryKind string
	PrimaryAPI  string
	PrimaryWhy  string
	// Primary and Zones are the config's secondary zones and their primary.
	Primary string
	Zones   []string

	settings      string
	dataDir       string
	addToSettings bool
}

// HostOnly is an address without its port.
func HostOnly(a string) string {
	if ap, err := netip.ParseAddrPort(a); err == nil {
		return ap.Addr().String()
	}
	return a
}

// Build checks the request and makes the adoption: the config (with its network set from
// the address when it runs), the address, the zone primary's edits or the changes to make
// by hand, the peers and DNS peers for the rule, the checks. Nothing is changed here; the
// node is only found (mDNS, with -node and no -host) and the other nodes read.
func Build(ctx context.Context, c *fleet.Client, r Request, token Token, logf func(string, ...any)) (Built, error) {
	var b Built
	cfg := &nodecfg.Config{}
	if r.Config != "" {
		path := r.ConfigPath()
		text := r.ConfigText
		if text == nil {
			var err error
			if text, err = os.ReadFile(path); err != nil {
				return b, err
			}
		}
		var err error
		if cfg, err = nodecfg.Parse(text); err != nil {
			return b, fmt.Errorf("%s: %w", path, err)
		}
		b.ConfigName = filepath.Base(path)
	}
	if r.Name != "" {
		cfg.Name = r.Name
	}
	// The address: -address, else the config's, else (left zero) the one the node runs on.
	addr, gw := r.Address, r.Gateway
	if addr == "" && cfg.Network != nil {
		addr = cfg.Network.Address
	}
	if gw == "" && cfg.Network != nil {
		gw = cfg.Network.Gateway
	}
	var pfx netip.Prefix
	var gwAddr netip.Addr
	var err error
	dhcp := addr == "dhcp"
	if addr != "" && !dhcp {
		if pfx, err = netip.ParsePrefix(addr); err != nil {
			return b, fmt.Errorf("-address: %w", err)
		}
	}
	if gw != "" && !dhcp {
		if gwAddr, err = netip.ParseAddr(gw); err != nil {
			return b, fmt.Errorf("-gateway: %w", err)
		}
	}
	if dhcp && r.Gateway != "" {
		return b, errors.New("-gateway: only with a static address, not dhcp")
	}
	if r.Reserved && !dhcp {
		return b, errors.New("-reserved is for a config on DHCP (-address dhcp); a static address needs no reservation")
	}
	s, err := settings.Load(r.SettingsPath())
	if err != nil {
		return b, err
	}
	host := r.Host
	if host == "" {
		if r.Node == "" {
			return b, errors.New("need -host or -node")
		}
		if host, err = nodes.Find(ctx, r.Node, 5*time.Second); err != nil {
			return b, err
		}
	}
	if dhcp {
		if h, err := netip.ParseAddr(HostOnly(host)); err == nil {
			if n, ok := s.NoDHCPAt(h); ok {
				return b, fmt.Errorf("%s is on %s, which has no DHCP server (settings.json, no_dhcp): a node there gets a "+
					"static address (the config's, -address, or the one it runs on), never dhcp", host, n)
			}
		}
	}
	// A new address that another node or a DNS peer is known by: never moved onto it, even
	// while that one is off (adopt checks the address is free too, by asking it).
	if pfx.IsValid() && pfx.Addr().String() != HostOnly(host) {
		known := append(append(append([]string{}, s.Nodes...), s.DNSPeers...), r.Peers...)
		for _, o := range known {
			if HostOnly(o) == pfx.Addr().String() {
				return b, fmt.Errorf("%s is %s's address (settings.json, or -peer): a node is adopted only onto a free address",
					pfx.Addr(), o)
			}
		}
	}

	a := fleet.Adopt{Host: host, ID: r.Node, Address: pfx, Gateway: gwAddr, DHCP: dhcp, Config: cfg, Reserved: r.Reserved,
		Identify: r.Identify, DryRun: r.DryRun, ConfirmWait: r.Wait, AllowSingle: r.AllowSingle, Force: r.Force,
		ManualDone: r.PrimaryDone}
	if sec := cfg.Secondary; sec != nil && sec.Zones != nil {
		b.Primary, b.Zones = sec.Primary, slices.Clone(*sec.Zones)
	}

	// The zone primary: reached over its API, else the changes by hand.
	zp, pc, err := r.ZonePrimary(s, token, len(b.Zones) > 0, primary.Options{DryRun: r.DryRun, Logf: logf, Report: r.Report})
	if err != nil {
		return b, err
	}
	a.Primary, b.PrimaryKind, b.PrimaryAPI, b.PrimaryWhy = zp, pc.Kind, zp.API(), primary.Why(zp)
	if len(b.Zones) > 0 && b.PrimaryWhy != "" {
		logf("zone primary (%s): %s: the allow lists are to be changed by hand", pc.Kind, b.PrimaryWhy)
	}

	if a.Checks, err = r.Checks.Make(); err != nil {
		return b, err
	}
	rr := rolling.Request{DataDir: r.DataDir, Settings: r.Settings, MDNS: r.MDNS, Peers: r.Peers, DNSPeers: r.DNSPeers,
		DNSPeerZones: r.DNSPeerZones, NoDNSPeers: r.NoDNSPeers}
	if a.DNSPeers, err = rolling.DNSPeers(rr, logf); err != nil {
		return b, err
	}
	if ns, err := rolling.Known(ctx, c, rr, logf); err == nil {
		for _, n := range ns {
			if n.Addr != host && (fleet.Adopted(n) || slices.Contains(r.Peers, n.Addr)) {
				a.Peers = append(a.Peers, n.Addr)
			}
		}
	}
	name := b.ConfigName
	if name == "" {
		name = "config"
	}
	a.Check = func(cfg *nodecfg.Config, st release.NodeStatus) error {
		// -host may be a name: the address the node reports is checked too.
		if ip, err := netip.ParseAddr(st.IP); dhcp && err == nil {
			if n, ok := s.NoDHCPAt(ip); ok {
				return fmt.Errorf("%s is on %s, which has no DHCP server (settings.json, no_dhcp): a node there gets a "+
					"static address, never dhcp", st.IP, n)
			}
		}
		return CheckConfig(name, cfg, host, st, r.Catalog, r.DataDir)
	}
	a.Mask = func(b []byte) []byte { m, _ := configs.Mask(b); return m }
	b.Adopt = a
	b.settings, b.dataDir, b.addToSettings = r.SettingsPath(), r.DataDir, r.AddToSettings
	return b, nil
}

// CheckConfig runs the config checks (internal/configs: espdns config -check, the memory
// plan on the node, a config rollout's refusals) on cfg, as the node at host would get it.
func CheckConfig(name string, cfg *nodecfg.Config, host string, st release.NodeStatus, catalog, dataDir string) error {
	payload, err := cfg.Payload()
	if err != nil {
		return err
	}
	res := configs.Check{Name: name, Text: payload, Catalog: catalog, Host: host, Status: &st, DataDir: dataDir}.Run()
	if res.OK {
		return nil
	}
	switch {
	case res.Error != "":
		return errors.New(res.Error)
	case res.Node != nil && res.Node.Refusal != "":
		return errors.New(res.Node.Refusal)
	}
	for _, m := range res.Memory {
		if m.Error != "" {
			return fmt.Errorf("the memory plan on %s (%s): %s", m.Board, m.From, m.Error)
		}
	}
	return errors.New("the config doesn't pass its checks")
}

// Result is what Run did.
type Result struct {
	fleet.AdoptResult
	Recorded        bool // the config it runs is recorded (internal/configs, Pushed)
	AddedToSettings bool // its address was added to settings.json now
	InSettings      bool // its address is in settings.json
}

// Run adopts the node (fleet.AdoptNode), then, once it is confirmed: records the config it
// runs, by the config's file name and the seq the node took it at (by is "cli" or
// "controller"), and adds its address to settings.json if the request asked for that.
// Neither of those fails the adoption: the node is adopted by then, and what didn't
// happen is said (logf).
func Run(ctx context.Context, c *fleet.Client, b Built, by string, logf func(string, ...any)) (Result, error) {
	ar, err := c.AdoptNode(ctx, b.Adopt)
	res := Result{AdoptResult: ar}
	if err != nil || b.Adopt.DryRun {
		return res, err
	}
	if b.ConfigName == "" {
		logf("no -config: what %s runs isn't recorded as a config file", ar.Addr)
	} else if rerr := configs.RecordPushed(b.dataDir, configs.Pushed{NodeID: ar.NodeID, Host: ar.Addr, File: b.ConfigName,
		Seq: ar.Seq, Payload: ar.Payload, By: by}); rerr != nil {
		logf("%s: not recorded as running %s: %v", ar.Addr, b.ConfigName, rerr)
	} else {
		res.Recorded = true
		logf("recorded: %s runs %s (config seq %d)", ar.Addr, b.ConfigName, ar.Seq)
	}
	s, serr := settings.Load(b.settings)
	res.InSettings = serr == nil && slices.Contains(s.Nodes, ar.Addr)
	moved := b.Adopt.Host != ar.Addr && serr == nil && slices.Contains(s.Nodes, b.Adopt.Host)
	switch {
	case b.addToSettings && moved:
		// Listed by the address it moved from: its entry moves with it.
		if _, merr := settings.MoveNode(b.settings, b.Adopt.Host, ar.Addr); merr != nil {
			logf("settings.json: %s not changed to %s: %v: change it by hand", b.Adopt.Host, ar.Addr, merr)
			break
		}
		res.AddedToSettings, res.InSettings = true, true
		logf("settings.json: %s changed to %s, the address it moved to", b.Adopt.Host, ar.Addr)
	case res.InSettings:
		logf("%s is in settings.json already", ar.Addr)
	case b.addToSettings:
		added, aerr := settings.AddNode(b.settings, ar.Addr)
		if aerr != nil {
			logf("%s: not added to settings.json: %v: add it by hand", ar.Addr, aerr)
			break
		}
		res.AddedToSettings, res.InSettings = added, true
		logf("added %s to settings.json: it counts as a peer in rollouts, and the controller's actions take it", ar.Addr)
	default:
		logf("%s is not in settings.json: add it there (-add-to-settings, or the controller's Adopt page) so rollouts "+
			"count it and change it", ar.Addr)
	}
	if moved && !b.addToSettings {
		logf("settings.json still lists %s, the address it moved from: change it to %s", b.Adopt.Host, ar.Addr)
	}
	return res, nil
}

// ManualSteps are the changes to make by hand on the zone primary for addr, one per zone.
func (b Built) ManualSteps(addr string) []string {
	var out []string
	for _, z := range b.Zones {
		out = append(out, fleet.ManualSteps(b.Adopt.Primary, b.Primary, z, addr))
	}
	return out
}
