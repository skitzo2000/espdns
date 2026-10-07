package configs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"reflect"
	"slices"
	"strings"

	"github.com/skitzo2000/espdns/controller/internal/boards"
	"github.com/skitzo2000/espdns/controller/internal/memplan"
	"github.com/skitzo2000/espdns/controller/internal/nodecfg"
	"github.com/skitzo2000/espdns/controller/internal/release"
)

// The checks a config gets before it goes to a node, shared by the CLI (espdns config
// -check, espdns rollout -kind config) and the controller (its editor's check, its push
// job), so both refuse the same configs for the same reasons.

// CatalogBoard is the catalog's board called name.
func CatalogBoard(dir, name string) (boards.Board, error) {
	entries, err := boards.Load(dir, "")
	if err != nil {
		return boards.Board{}, err
	}
	e, ok := boards.Find(entries, name)
	if !ok {
		return boards.Board{}, fmt.Errorf("no board %s in the catalog (%s)", name, dir)
	}
	if len(e.Errors) > 0 {
		return boards.Board{}, fmt.Errorf("board %s: %s", name, strings.Join(e.Errors, "; "))
	}
	return e.Board, nil
}

// BoardPlan is the memory plan of the config's services on a catalog board, as a node on
// it makes it (espdns config -check -board). A board that doesn't say psram_mb is refused:
// a node on it plans with the PSRAM its chip finds, which only the node knows.
func BoardPlan(c *nodecfg.Config, name string, b boards.Board) (memplan.Plan, error) {
	if b.PSRAMMB == nil {
		return memplan.Plan{}, fmt.Errorf("board %s doesn't say psram_mb: a node on it plans with the PSRAM its chip finds, "+
			"which only the node knows", name)
	}
	return memplan.Make(memplan.Values(b.MemoryKeys(), b.Image, -1), c.Services())
}

// NodeMemory is the memory a node plans with: what its /status says (firmware with the
// memory plan), else its catalog board's values on its chip image, which the node takes
// once its firmware has the plan. false if neither is known.
func NodeMemory(st release.NodeStatus, catalog string) (memplan.Board, string, bool) {
	if st.Memory != nil {
		return st.Memory.Board, "as it reports", true
	}
	if st.Board == "" || catalog == "" {
		return memplan.Board{}, "", false
	}
	b, err := CatalogBoard(catalog, st.Board)
	if err != nil || b.PSRAMMB == nil { // without psram_mb, the node plans with what its chip finds
		return memplan.Board{}, "", false
	}
	image := st.Image
	if image == "" {
		image = b.Image
	}
	return memplan.Values(b.MemoryKeys(), image, -1), "catalog board " + st.Board, true
}

// Spec is one node's config for a push: the node's address, the file, the config and its
// payload.
type Spec struct {
	Host    string
	Path    string // as named (the file name in the data directory, or the CLI's path)
	Config  *nodecfg.Config
	Payload []byte
}

// LoadSpec reads and checks the config at path for the node at host.
func LoadSpec(host, path string) (Spec, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Spec{}, err
	}
	return ParseSpec(host, path, b)
}

// ParseSpec checks a config's text for the node at host; path names it in errors.
func ParseSpec(host, path string, b []byte) (Spec, error) {
	cfg, err := nodecfg.Parse(b)
	if err != nil {
		return Spec{}, fmt.Errorf("%s: %w", path, err)
	}
	p, err := cfg.Payload()
	if err != nil {
		return Spec{}, fmt.Errorf("%s: %w", path, err)
	}
	return Spec{Host: host, Path: path, Config: cfg, Payload: p}, nil
}

// Moves says whether the config gives the node another static address than host, and which.
func (s Spec) Moves() (netip.Addr, bool) {
	a, ok := s.Config.StaticAddr()
	return a, ok && a.String() != hostOnly(s.Host)
}

// hostOnly is host without a port.
func hostOnly(h string) string {
	if ap, err := netip.ParseAddrPort(h); err == nil {
		return ap.Addr().String()
	}
	return h
}

// Refusal is why the node, whose /status is st, can't take the config (nil if it can):
//   - a config without a network, for a node whose address comes from its pushed config
//     (/status address_from "config"): the node would drop to its board's or built-in
//     address, or none;
//   - services switched on or off, "cpu" or "querylog", for firmware from before them, which refuses
//     the config (and a node rolled back to such firmware couldn't boot on it);
//   - services that don't fit the node's memory plan (internal/memplan), which it refuses;
//   - a forward or secondary zone the node serves as a hosted zone (HostedClash).
func (s Spec) Refusal(st release.NodeStatus, catalog string) error {
	if s.Config.Network == nil && st.Config != nil && st.Config.AddressFrom == "config" {
		now, add := st.Config.IP, `"network": {"address": "dhcp"}`
		if st.Config.Address == "dhcp" {
			now = "dhcp"
		} else {
			if now == "" {
				now = s.Host
			}
			add = fmt.Sprintf(`"network": {"address": %q, "gateway": %q}`, now, st.Config.Gateway)
		}
		return fmt.Errorf("%s has no network, but the node's address (%s) comes from its pushed config: "+
			"this config would drop it off that address. Add it to the file: %s", s.Path, now, add)
	}
	if s.Config.SwitchesServices() && st.Services == nil {
		return fmt.Errorf("%s turns services on or off (hosted, blocking.enabled or \"forwarders\": []), "+
			"which %s's firmware doesn't take: update its firmware first", s.Path, s.Host)
	}
	if s.Config.SetsCPU() && st.CPU == nil {
		return fmt.Errorf("%s sets \"cpu\" (clock scaling), which %s's firmware doesn't take: "+
			"update its firmware first", s.Path, s.Host)
	}
	if s.Config.SetsQueryLog() && st.QueryLog == nil {
		return fmt.Errorf("%s sets \"querylog\" (the query log), which %s's firmware doesn't take: "+
			"update its firmware first", s.Path, s.Host)
	}
	if mb, from, ok := NodeMemory(st, catalog); ok {
		if _, err := memplan.Make(mb, s.Config.Services()); err != nil {
			return fmt.Errorf("%s: its services don't fit %s's memory (%s), so it would refuse it: %w",
				s.Path, s.Host, from, err)
		}
	}
	return s.HostedClash(st)
}

// HostedClash is an error if the config names as a forward zone (a conditional forwarder)
// or a secondary zone a zone the node, whose /status is st, serves as a hosted zone, while
// its hosted zones stay on: a zone has one source, and the node would not serve it as both
// (the same rule a zones rollout keeps from the other side, internal/zones, Payload).
func (s Spec) HostedClash(st release.NodeStatus) error {
	if st.Hosted == nil || len(st.Hosted.Zones) == 0 || !slices.Contains(s.Config.Services(), "hosted") {
		return nil
	}
	check := func(names []string, what string) error {
		for _, n := range names {
			for _, hz := range st.Hosted.Zones {
				if strings.EqualFold(strings.TrimSuffix(n, "."), strings.TrimSuffix(hz.Name, ".")) {
					return fmt.Errorf("%s makes %s a %s of %s, which serves it as a hosted zone: a zone has one source. "+
						"Push the hosted zones without it first (the Push page, or espdns rollout -kind zones), "+
						"or leave it out of the config", s.Path, strings.ToLower(strings.TrimSuffix(n, ".")), what, s.Host)
				}
			}
		}
		return nil
	}
	if fz := s.Config.ForwardZones; fz != nil {
		var names []string
		for _, f := range *fz {
			names = append(names, f.Zone)
		}
		if err := check(names, "forward zone"); err != nil {
			return err
		}
	}
	if sec := s.Config.Secondary; sec != nil && sec.Zones != nil {
		return check(*sec.Zones, "secondary zone")
	}
	return nil
}

// Payloads is a config rollout's payload for each node (fleet.Change.Payload): each
// node's spec, checked against the node's /status (Refusal) before any node is touched.
// A config that moves its node to another address is refused: it goes through espdns
// config (or the controller's push), which confirms the node on its new address.
func Payloads(specs []Spec, hosts []string, catalog string) (func(context.Context, string, release.NodeStatus) ([]byte, error), error) {
	byHost := map[string]Spec{}
	for _, s := range specs {
		if a, ok := s.Moves(); ok {
			return nil, fmt.Errorf("%s moves %s to %s: use espdns config, which confirms the new address", s.Path, s.Host, a)
		}
		byHost[s.Host] = s
	}
	for _, h := range hosts {
		if _, ok := byHost[h]; !ok {
			return nil, fmt.Errorf("no -config for %s", h)
		}
	}
	return func(_ context.Context, host string, st release.NodeStatus) ([]byte, error) {
		s, ok := byHost[host]
		if !ok {
			return nil, fmt.Errorf("no config for %s", host)
		}
		if err := s.Refusal(st, catalog); err != nil {
			return nil, err
		}
		return s.Payload, nil
	}, nil
}

// RunningNetwork is the network a node reports running on (/status config), for
// nodecfg.Compare; nil if it doesn't say.
func RunningNetwork(st release.NodeStatus) *nodecfg.Network {
	switch {
	case st.Config == nil:
		return nil
	case st.Config.Address == "dhcp":
		return &nodecfg.Network{Address: "dhcp"}
	case st.Config.Address == "static" && st.Config.IP != "" && strings.Contains(st.Config.IP, "/"):
		return &nodecfg.Network{Address: st.Config.IP, Gateway: st.Config.Gateway}
	}
	return nil
}

// ErrNoConfig: the node's firmware is from before node configs.
var ErrNoConfig = errors.New("the node's firmware is from before node configs (no config in /status)")

// Running is what a node runs, as far as the controller can tell, for nodecfg.Compare and
// the editor's "the node runs a different config than the file".
type Running struct {
	// State: "file" (the file as saved), "older" (this file, an earlier version), "other"
	// (another file), "defaults" (no pushed config: the board's and firmware's settings),
	// "unrecorded" (a pushed config this data directory has no record of), "unknown"
	// (firmware from before configs).
	State string `json:"state"`
	Text  string `json:"text"`
	Seq   uint64 `json:"seq"`
	// Config is what the node runs, if known: the base a change is compared with. When it
	// isn't (unrecorded), Assumed is the file as saved, said in Text.
	Config  *nodecfg.Config `json:"-"`
	Assumed bool            `json:"assumed,omitempty"`
}

// NodeRuns says what the node runs, against the file name (f may be nil: a new config).
func NodeRuns(dataDir, name string, f *File, st release.NodeStatus) Running {
	if st.Config == nil {
		return Running{State: "unknown", Text: ErrNoConfig.Error()}
	}
	r := Running{Seq: st.Config.Seq}
	if st.Config.Source != "node" {
		r.State, r.Config = "defaults", &nodecfg.Config{}
		r.Text = "no pushed config: the node runs on its board's and firmware's settings"
		return r
	}
	p, err := LoadPushed(dataDir, st.NodeID)
	if err == nil && p != nil && p.Seq == st.Config.Seq {
		if c, err := nodecfg.Parse(p.Payload); err == nil {
			r.Config = c
		}
		switch {
		case p.File != name:
			r.State, r.Text = "other", fmt.Sprintf("runs %s (config seq %d, pushed %s)", p.File, p.Seq, p.Time.Format("2006-01-02 15:04"))
		case f != nil && f.Config != nil && samePayload(f.Config, p.Payload):
			r.State, r.Text = "file", fmt.Sprintf("runs this file as saved (config seq %d, pushed %s)", p.Seq, p.Time.Format("2006-01-02 15:04"))
		default:
			r.State, r.Text = "older", fmt.Sprintf("runs an earlier version of this file (config seq %d, pushed %s): the file changed since",
				p.Seq, p.Time.Format("2006-01-02 15:04"))
		}
		return r
	}
	r.State = "unrecorded"
	r.Text = fmt.Sprintf("runs config seq %d (name %q), pushed without a record here (by an older controller before configs moved to the data directory, or another controller): whether it is this file can't be told",
		st.Config.Seq, st.Config.Name)
	if f != nil && f.Config != nil {
		r.Config, r.Assumed = f.Config, true
	}
	return r
}

// samePayload says whether c's payload is p.
func samePayload(c *nodecfg.Config, p []byte) bool {
	b, err := c.Payload()
	if err != nil {
		return false
	}
	var x, y any
	return json.Unmarshal(b, &x) == nil && json.Unmarshal(p, &y) == nil && reflect.DeepEqual(x, y)
}

// Matches says whether the node at host, whose /status is st, is the config's node: it
// reports the config's name; or, when one of the two has no name (a node not adopted, a
// config without one), it runs on the config's static address. A node that reports
// another name is not the config's node, even on its address (AtAddress: a config written
// for that address, which a push would rename).
func Matches(c *nodecfg.Config, host string, st release.NodeStatus) bool {
	if c == nil {
		return false
	}
	if c.Name != "" && st.Config != nil && st.Config.Name != "" {
		return st.Config.Name == c.Name
	}
	return AtAddress(c, host, st)
}

// AtAddress says whether the node at host, whose /status is st, runs on the config's
// static address.
func AtAddress(c *nodecfg.Config, host string, st release.NodeStatus) bool {
	if c == nil {
		return false
	}
	a, ok := c.StaticAddr()
	if !ok {
		return false
	}
	if hostOnly(host) == a.String() {
		return true
	}
	if st.Config != nil {
		if p, err := netip.ParsePrefix(st.Config.IP); err == nil && p.Addr() == a {
			return true
		}
	}
	return false
}

// OnTrial says whether the config comes up on trial on a new network at the node's next
// boot, so it must be confirmed there. Firmware from before JSON replies reboots by itself
// and says "on trial" in its plain-text reply. Later firmware replies in JSON
// (reboot_pending) and waits: its /status reboot reasons say whether the address or the
// network changes; without them (/status unread), a static address other than host does.
func OnTrial(reply release.Reply, pending bool, reasons []string, c *nodecfg.Config, host string) bool {
	if !reply.JSON {
		return strings.Contains(reply.Message, "on trial")
	}
	if !pending {
		return false
	}
	if slices.Contains(reasons, nodecfg.ReasonAddress) || slices.Contains(reasons, nodecfg.ReasonWifi) {
		return true
	}
	a, ok := c.StaticAddr()
	return reasons == nil && ok && a.String() != hostOnly(host)
}
