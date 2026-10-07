// Package rolling builds a rolling push, the plan and the change fleet.Rollout runs, from
// one request: the espdns CLI's rollout flags (make fleet-rollout KIND=...) and the
// controller's Push page (Web) both make a Request and build it here, so for the same
// intent they run the same plan with the same payloads (docs/rollout.md).
package rolling

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/blocklist"
	"github.com/skitzo2000/espdns/controller/internal/configs"
	"github.com/skitzo2000/espdns/controller/internal/fleet"
	"github.com/skitzo2000/espdns/controller/internal/release"
	"github.com/skitzo2000/espdns/controller/internal/settings"
	"github.com/skitzo2000/espdns/controller/internal/zonefiles"
	"github.com/skitzo2000/espdns/controller/internal/zones"
)

// DefaultSoak is how long each changed node runs, checked again, before the next starts
// (the CLI's -soak default; the Makefile and the Push page never go below it).
const DefaultSoak = time.Minute

// Request is one rolling push: what the CLI's rollout flags say, field for field.
type Request struct {
	Kind          release.Kind
	Hosts         []string      // -host: the nodes changed, in order after the canary
	All           bool          // -all: every node found (mDNS) or listed in settings.json
	Canary        string        // -canary
	Soak          time.Duration // -soak
	AllowDegraded []string      // -allow-degraded
	Images        []string      // -image: a chip image directory, or image=app.bin
	Board         string        // -board
	Reinstall     bool          // -reinstall
	Configs       []string      // -config: host=file
	Catalog       string        // -catalog
	Zones         []string      // -zone: <zone>.zone or origin=path
	EmptyZones    bool          // -empty
	File          string        // -file: a blocklist or overrides file
	Checks        Checks

	// The rule: who counts as another node.
	DataDir      string        // -data
	Settings     string        // -settings ("": the data directory's settings.json)
	MDNS         time.Duration // -mdns (every target that changes a node passes 0)
	Peers        []string      // -peer
	DNSPeers     []string      // -dns-peer ("" : settings.json's dns_peers)
	DNSPeerZones []string      // -dns-peer-zone
	NoDNSPeers   bool          // -no-dns-peers
	AllowSingle  bool          // -allow-single
	Force        bool          // -force
	DryRun       bool          // -dry-run

	// Files, if set, is where every file the request reads is read once (the settings
	// too), so its Fingerprint is over the bytes pushed; nil: read when needed.
	Files *Files `json:"-"`
}

// Checks are the DNS check flags.
type Checks struct {
	Local       []string // -check-local
	Forward     []string // -check-forward (default example.com)
	Blocked     []string // -check-blocked
	MustResolve string   // -must-resolve: a file of names
	Off         bool     // -no-dns-checks
}

// SettingsPath is the settings file the request reads.
func (r Request) SettingsPath() string {
	if r.Settings != "" {
		return r.Settings
	}
	return settings.Path(r.DataDir)
}

// Built is a request made into what fleet.Rollout takes. Specs are a config rollout's
// configs, to record as the ones the nodes run after it (RecordPushed).
type Built struct {
	Plan   fleet.Plan
	Change fleet.Change
	Specs  []configs.Spec
}

// Build makes the change (every file read and checked) and the plan (the nodes counted as
// the CLI counts them) for the request. logf gets what the CLI logs on the way.
func Build(ctx context.Context, c *fleet.Client, r Request, logf func(string, ...any)) (Built, error) {
	var b Built
	if r.Kind == release.Control {
		return b, errors.New("need -kind firmware, config, zones, blocklist or overrides")
	}
	hosts := slices.Clone(r.Hosts)
	if r.All {
		ns, err := Known(ctx, c, r, logf)
		if err != nil {
			return b, err
		}
		for _, n := range ns {
			hosts = append(hosts, n.Addr)
		}
	}
	if len(hosts) == 0 {
		return b, errors.New("need -host or -all")
	}
	ch, specs, err := LoadChange(r, hosts, logf)
	if err != nil {
		return b, err
	}
	b.Change, b.Specs = ch, specs
	p := fleet.Plan{Targets: hosts, AllowSingle: r.AllowSingle, Force: r.Force, DryRun: r.DryRun}
	if p.DNSPeers, err = DNSPeers(r, logf); err != nil {
		return b, err
	}
	ns, err := Known(ctx, c, r, logf)
	if err != nil {
		return b, err
	}
	c.Count(ctx, &p, ns, r.Peers)
	p.Canary, p.Soak, p.AllowDegraded = r.Canary, r.Soak, r.AllowDegraded
	if p.Canary == "" {
		if p.Canary = r.CanaryFor(hosts); p.Canary != "" {
			logf("canary: %s (settings.json)", p.Canary)
		}
	}
	if p.Checks, err = r.Checks.make(r.read); err != nil {
		return b, err
	}
	b.Plan = p
	return b, nil
}

// CanaryFor is the canary of a rollout of hosts: the request's (-canary), else
// settings.json's "canary" if it is one of hosts (it never adds a node), else "" (the
// first goes first), as firmware and list rollouts alike take it.
func (r Request) CanaryFor(hosts []string) string {
	if r.Canary != "" {
		return r.Canary
	}
	if s, err := r.loadSettings(); err == nil && s.Canary != "" && slices.Contains(hosts, s.Canary) {
		return s.Canary
	}
	return ""
}

// Order is the nodes as the request's rollout changes them (the canary first), for the
// request's own hosts (not -all's).
func (r Request) Order() []string {
	return (fleet.Plan{Targets: r.Hosts, Canary: r.CanaryFor(r.Hosts)}).Order()
}

// Make is the checks fleet.Rollout runs: example.com when no forwarded name is given, the
// must-resolve file's names.
func (ch Checks) Make() (fleet.Checks, error) { return ch.make(os.ReadFile) }

func (ch Checks) make(read func(string) ([]byte, error)) (fleet.Checks, error) {
	out := fleet.Checks{Local: ch.Local, Forwarded: ch.Forward, Blocked: ch.Blocked, Off: ch.Off}
	if len(out.Forwarded) == 0 {
		out.Forwarded = []string{"example.com"}
	}
	if ch.MustResolve != "" {
		b, err := read(ch.MustResolve)
		if err != nil {
			return out, err
		}
		n, err := blocklist.ParseNames(bytes.NewReader(b))
		if err != nil {
			return out, err
		}
		out.MustResolve = n
	}
	return out, nil
}

// DNSPeers are the request's DNS peers: its own, else the settings file's.
func DNSPeers(r Request, logf func(string, ...any)) ([]fleet.DNSPeer, error) {
	s, err := r.loadSettings()
	if err != nil {
		return nil, err
	}
	addrs, zs := r.DNSPeers, r.DNSPeerZones
	if len(addrs) == 0 && !r.NoDNSPeers {
		addrs = s.DNSPeers
	}
	if len(zs) == 0 {
		zs = s.DNSPeerZones
	}
	var out []fleet.DNSPeer
	for _, a := range addrs {
		out = append(out, fleet.DNSPeer{Addr: a, Zones: zs})
	}
	if len(out) > 0 {
		logf("DNS peers: %s", strings.Join(addrs, ", "))
	}
	return out, nil
}

// Known is every node the request can find: mDNS (a failed browse is only a warning) and
// the settings list, with the -peer nodes.
func Known(ctx context.Context, c *fleet.Client, r Request, logf func(string, ...any)) ([]fleet.Node, error) {
	s, err := r.loadSettings()
	if err != nil {
		return nil, err
	}
	l := append(slices.Clone(s.Nodes), r.Peers...)
	ns, err := c.Discover(ctx, r.MDNS, l)
	if err != nil && r.MDNS > 0 {
		logf("%v: going on with the listed nodes only", err)
		ns, err = c.Discover(ctx, 0, l)
	}
	return ns, err
}

// LoadChange reads what the request pushes to hosts, checked: the firmware's app
// descriptors, each node's config, the zones, the list's header.
func LoadChange(r Request, hosts []string, logf func(string, ...any)) (fleet.Change, []configs.Spec, error) {
	ch := fleet.Change{Kind: r.Kind, Reinstall: r.Reinstall}
	var specs []configs.Spec
	var err error
	switch r.Kind {
	case release.Firmware:
		ch.Firmware, err = loadFirmware(r.read, r.Images, r.Board, logf)
	case release.Config:
		ch.Payload, specs, err = configPayloads(r.read, r.Configs, hosts, r.Catalog, r.DataDir)
		if err == nil {
			ch.Payload, err = noDHCPCheck(r, specs, ch.Payload)
		}
	case release.Zones:
		ch.Payload, ch.Note, err = zonesPayloads(r.read, r.Zones, r.EmptyZones)
	case release.Blocklist, release.Overrides:
		if r.File == "" {
			return ch, nil, errors.New("need -file")
		}
		payload, rerr := r.read(r.File)
		if rerr != nil {
			return ch, nil, rerr
		}
		if err := CheckList(payload); err != nil {
			return ch, nil, fmt.Errorf("%s: %w", r.File, err)
		}
		ch.Payload = func(context.Context, string, release.NodeStatus) ([]byte, error) { return payload, nil }
		ch.Note = ListNote(r.Kind)
	default:
		err = errors.New("need -kind firmware, config, zones, blocklist or overrides")
	}
	return ch, specs, err
}

// CheckList refuses a file that isn't a blocklist (or overrides) file from espdns blocklist.
func CheckList(b []byte) error {
	if len(b) < 8 || string(b[:8]) != blocklist.FileMagic {
		return errors.New("not a blocklist file")
	}
	if _, err := blocklist.PlanNeed(b, int64(len(b))); err != nil {
		return err
	}
	return nil
}

// LoadFirmware reads the -image flags: chip image directories, or name=app.bin.
func LoadFirmware(specs []string, board string, logf func(string, ...any)) ([]fleet.Firmware, error) {
	return loadFirmware(os.ReadFile, specs, board, logf)
}

func loadFirmware(read func(string) ([]byte, error), specs []string, board string, logf func(string, ...any)) ([]fleet.Firmware, error) {
	if len(specs) == 0 {
		return nil, errors.New("need -image")
	}
	var out []fleet.Firmware
	for _, s := range specs {
		var f fleet.Firmware
		path := s
		if name, p, ok := strings.Cut(s, "="); ok {
			f.Image, path = name, p
		} else {
			var meta struct {
				Image string `json:"image"`
			}
			b, err := read(filepath.Join(s, "image.json"))
			if err != nil {
				return nil, fmt.Errorf("-image %s: want a chip image directory or name=app.bin: %w", s, err)
			}
			if err := json.Unmarshal(b, &meta); err != nil {
				return nil, fmt.Errorf("%s/image.json: %w", s, err)
			}
			f.Image, path = meta.Image, filepath.Join(s, "app.bin")
		}
		app, err := read(path)
		if err != nil {
			return nil, err
		}
		if f.Desc, err = release.ParseAppDesc(app); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		f.App, f.Board = app, board
		logf("%s: %s %s built %s, elf %s, for %s (%d bytes)", path, f.Desc.Project, f.Desc.Version,
			f.Desc.Built, f.Desc.ElfSHA256, f.Image, len(app))
		out = append(out, f)
	}
	return out, nil
}

// ConfigPayloads reads each node's config (host=file; a bare file with one host): a file
// name without a directory is the data directory's config of that name (internal/configs),
// else a path. The checks are internal/configs' (Payloads): a config that moves its node is
// refused (espdns config confirms a new address), and each node's is checked against its
// /status before any node is touched.
func ConfigPayloads(specs, hosts []string, catalog, dataDir string) (func(context.Context, string, release.NodeStatus) ([]byte, error), []configs.Spec, error) {
	return configPayloads(os.ReadFile, specs, hosts, catalog, dataDir)
}

func configPayloads(read func(string) ([]byte, error), specs, hosts []string, catalog, dataDir string) (func(context.Context, string, release.NodeStatus) ([]byte, error), []configs.Spec, error) {
	var out []configs.Spec
	for _, s := range specs {
		host, path, ok := strings.Cut(s, "=")
		if !ok {
			if len(hosts) != 1 {
				return nil, nil, errors.New("-config host=file for each node (a bare file only with one -host)")
			}
			host, path = hosts[0], s
		}
		path = configs.Resolve(dataDir, path)
		b, err := read(path)
		if err != nil {
			return nil, nil, err
		}
		sp, err := configs.ParseSpec(host, path, b)
		if err != nil {
			return nil, nil, err
		}
		out = append(out, sp)
	}
	f, err := configs.Payloads(out, hosts, catalog)
	return f, out, err
}

// noDHCPCheck adds to a config rollout's payloads the address check espdns config makes
// (internal/configs, AddressRefusal, from the settings: a move is refused by Payloads
// already): a config on DHCP for a node on a network in settings.json's no_dhcp is refused
// before any node is touched.
func noDHCPCheck(r Request, specs []configs.Spec, f func(context.Context, string, release.NodeStatus) ([]byte, error)) (
	func(context.Context, string, release.NodeStatus) ([]byte, error), error) {
	s, err := r.loadSettings()
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context, host string, st release.NodeStatus) ([]byte, error) {
		for _, sp := range specs {
			if sp.Host == host {
				if err := sp.AddressRefusal(configs.Addressing{Settings: s}, &st); err != nil {
					return nil, err
				}
			}
		}
		return f(ctx, host, st)
	}, nil
}

// ZonesPayloads reads the hosted zones; each node's bundle is checked against its limit and
// the secondary and forward zones its /status reports (zones.Set.Payload). The note says
// what each node stops serving (ZonesNote).
func ZonesPayloads(files []string, empty bool) (func(context.Context, string, release.NodeStatus) ([]byte, error),
	func(string, release.NodeStatus) string, error) {
	return zonesPayloads(os.ReadFile, files, empty)
}

func zonesPayloads(read func(string) ([]byte, error), files []string, empty bool) (
	func(context.Context, string, release.NodeStatus) ([]byte, error), func(string, release.NodeStatus) string, error) {
	if len(files) == 0 && !empty {
		return nil, nil, errors.New("need -zone (or -empty to remove every hosted zone)")
	}
	if len(files) > 0 && empty {
		return nil, nil, errors.New("-empty takes no -zone")
	}
	set := &zones.Set{}
	for _, f := range files {
		// zones.LoadFile, through read: <zone>.zone, or origin=path.
		origin, path, ok := strings.Cut(f, "=")
		if !ok {
			path, origin = f, strings.TrimSuffix(filepath.Base(f), ".zone")
		}
		b, err := read(path)
		if err != nil {
			return nil, nil, err
		}
		z, err := zones.ParseMaster(origin, bytes.NewReader(b), path)
		if err != nil {
			return nil, nil, err
		}
		set.Zones = append(set.Zones, z)
	}
	if err := set.Validate(); err != nil {
		return nil, nil, err
	}
	return func(_ context.Context, host string, st release.NodeStatus) ([]byte, error) {
		return set.Payload(host, st)
	}, ZonesNote(set), nil
}

// ZonesNote says, for a zones push of set, the hosted zones each node serves now that the
// set drops (zones.Set.Drops): the push replaces its whole set, so it stops serving them. The
// CLI's dry run logs it and the Push page shows it, per node (fleet.Change.Note).
func ZonesNote(set *zones.Set) func(string, release.NodeStatus) string {
	return func(_ string, st release.NodeStatus) string {
		d := set.Drops(st)
		if len(d) == 0 {
			return ""
		}
		return "it stops serving " + strings.Join(d, ", ")
	}
}

// ListNote says, for a blocklist or overrides push (k), a node the rollout couldn't send
// back if the list failed there (fleet.Rollout reverts every node that took it): one with
// no list of that kind in use now (nothing older would be left to go back to), or on
// firmware from before the revert command. The CLI's dry run logs it and the Push page
// shows it, per node (fleet.Change.Note).
func ListNote(k release.Kind) func(string, release.NodeStatus) string {
	return func(_ string, st release.NodeStatus) string {
		l := st.List(k)
		switch {
		case l == nil:
			return ""
		case l.Slot == nil:
			return fmt.Sprintf("its firmware is from before the revert command: if the %s fails there, it can't be sent back", k)
		case l.State != "on":
			return fmt.Sprintf("it has no %s in use now: if this one fails there, it can't be sent back (nothing older)", k)
		}
		return ""
	}
}

// Report logs how a rollout ended, as the CLI always has: done, already had it, where it
// stopped and (not a dry run) what it didn't touch; for a list, what was sent back.
func Report(logf func(string, ...any), p fleet.Plan, res fleet.Result) {
	report := func(what string, l []string) {
		if len(l) > 0 {
			logf("%s: %s", what, strings.Join(l, ", "))
		}
	}
	report("done", res.Done)
	report("already had it", res.Skipped)
	if res.Failed != "" {
		logf("stopped at %s", res.Failed)
	}
	report("reverted (back on the copy each had)", res.Reverted)
	for _, n := range res.NotReverted {
		logf("not reverted: %s: %s; the way on: %s", n.Host, n.Why, n.WayOn)
	}
	if !p.DryRun {
		report("not touched", res.Left)
	}
}

// RecordPushed keeps, for each node a config rollout changed, the config it runs now and
// its seq (internal/configs, Pushed), for the controller's editor; by is "cli" or
// "controller". Only reported (logf) if it fails.
func RecordPushed(ctx context.Context, c *fleet.Client, dataDir string, specs []configs.Spec, done []string, by string,
	logf func(string, ...any)) {
	for _, s := range specs {
		if !slices.Contains(done, s.Host) {
			continue
		}
		st, err := c.Status(ctx, s.Host)
		if err == nil && st.Config == nil {
			err = configs.ErrNoConfig
		}
		if err == nil {
			err = configs.RecordPushed(dataDir, configs.Pushed{NodeID: st.NodeID, Host: s.Host, File: filepath.Base(s.Path),
				Seq: st.Config.Seq, Payload: s.Payload, By: by})
		}
		if err != nil {
			logf("%s: not recorded as the config it runs: %v", s.Host, err)
		}
	}
}

// RecordZones keeps, for each node a zones rollout changed, the set it serves now: its
// hosted seq and the hash of each file pushed (internal/zonefiles, Pushed), for the
// controller's zone editor; by is "cli" or "controller". Only reported (logf) if it fails.
func RecordZones(ctx context.Context, c *fleet.Client, r Request, done []string, by string, logf func(string, ...any)) {
	files, err := zonefiles.PushedFiles(r.Zones, r.read)
	if err != nil {
		logf("zones: not recorded as pushed: %v", err)
		return
	}
	for _, h := range done {
		st, err := c.Status(ctx, h)
		if err == nil && st.Hosted == nil {
			err = errors.New("no hosted zones in its /status")
		}
		if err == nil {
			err = zonefiles.RecordPushed(r.DataDir, zonefiles.Pushed{NodeID: st.NodeID, Host: h, Seq: st.Hosted.Seq, Files: files, By: by})
		}
		if err != nil {
			logf("%s: not recorded as the zones it serves: %v", h, err)
		}
	}
}

// Inputs are the files the request reads, for a fingerprint of what a dry run checked.
func (r Request) Inputs() []string {
	var out []string
	for _, s := range r.Images {
		if _, p, ok := strings.Cut(s, "="); ok {
			out = append(out, p)
		} else {
			out = append(out, filepath.Join(s, "image.json"), filepath.Join(s, "app.bin"))
		}
	}
	for _, s := range r.Configs {
		_, p, ok := strings.Cut(s, "=")
		if !ok {
			p = s
		}
		out = append(out, configs.Resolve(r.DataDir, p))
	}
	for _, z := range r.Zones {
		_, p, ok := strings.Cut(z, "=")
		if !ok {
			p = z
		}
		out = append(out, p)
	}
	if r.File != "" {
		out = append(out, r.File)
	}
	if r.Checks.MustResolve != "" {
		out = append(out, r.Checks.MustResolve)
	}
	return append(out, r.SettingsPath())
}
