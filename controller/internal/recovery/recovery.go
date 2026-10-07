// Package recovery rebuilds what it can of a data directory from the nodes, without a
// backup (docs/design.md, Controller, Easy to rebuild): `espdns recover`.
//
// A node's /status says who it is (ID, board, chip image, firmware), which release key it
// trusts, its sequence numbers, the config it runs (its name, seq and address, not its
// contents), the hosted zones it serves (each zone's name, serial and record count, and the
// hash of the whole bundle, not the zones), its secondary zones by name, and its blocklist
// and overrides (seq, entries, not the lists). The firmware has no endpoint that returns a
// config, a zone or a list (only /status, /health, /ota, /release), so those can't come back
// from the nodes; what recovery does with what it can read:
//
//   - settings.json: the nodes in service that trust the release key imported here, written
//     when there is none (or added to one, when asked); never the DNS peers or the zone primary,
//     which the nodes don't know.
//   - recovered/<time>/: each node's /status as read, and the report, for what is left to
//     rebuild by hand. Nothing there is used by the controller.
//   - Each node's config and zones checked against the files here (a deployment's own seeds
//     that make data copies, SETTINGS_SEED and CONFIG_SEEDS, or files put back by hand): a config whose name or address is
//     the node's; the zone files whose bundle is byte for byte the one the node runs.
//
// Sequence numbers need nothing: a release's seq is the time in milliseconds (release.NextSeq),
// above any the node took from the controller before, so a new controller's releases are
// accepted. Each node listed that is in service and trusts the key is pinned to its address
// (internal/pins), as adopting it did: releases are signed only for a pinned node.
package recovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/configs"
	"github.com/skitzo2000/espdns/controller/internal/fleet"
	"github.com/skitzo2000/espdns/controller/internal/fleetlock"
	"github.com/skitzo2000/espdns/controller/internal/keys"
	"github.com/skitzo2000/espdns/controller/internal/pins"
	"github.com/skitzo2000/espdns/controller/internal/release"
	"github.com/skitzo2000/espdns/controller/internal/secfile"
	"github.com/skitzo2000/espdns/controller/internal/settings"
	"github.com/skitzo2000/espdns/controller/internal/zonefiles"
)

// Dir is where recovered files go in the data directory.
const Dir = "recovered"

// Options are what a recovery takes.
type Options struct {
	DataDir string
	// Hosts are addresses to read besides those found over mDNS and in settings.json.
	Hosts []string
	// MDNS is how long to browse for nodes (0: not at all, only Hosts and settings.json).
	MDNS time.Duration
	// AddToSettings adds the nodes found to a settings.json that is there already (one
	// that isn't is always written).
	AddToSettings bool
	// DryRun reads the nodes and says what it would write; it writes nothing.
	DryRun bool
	Key    keys.Source
	Now    func() time.Time
}

// Zone is one hosted zone a node serves.
type Zone struct {
	Name    string `json:"name"`
	Serial  uint32 `json:"serial"`
	Records int    `json:"records"`
	// File is what is here for it: "the node's bundle" (the files here are the bundle it
	// runs, byte for byte), "a file, not the one it serves", "a file, maybe it" (no hash
	// to tell; its serial and records match), or "no file".
	File string `json:"file"`
}

// Node is what recovery found of one node.
type Node struct {
	Addr    string            `json:"addr"`
	Source  string            `json:"source"`
	ID      string            `json:"node_id,omitempty"`
	Board   string            `json:"board,omitempty"`
	Image   string            `json:"image,omitempty"`
	Version string            `json:"version,omitempty"`
	Adopted bool              `json:"adopted"`
	Trusts  bool              `json:"trusts_key"` // its key slot 0 is the release key here
	Seq     map[string]uint64 `json:"seq,omitempty"`
	// Config is the config it runs: its name, seq and address (not its contents).
	Config *release.ConfigStatus `json:"config,omitempty"`
	// ConfigFiles are the files here that are its config (by name or address), if any.
	ConfigFiles []string `json:"config_files,omitempty"`
	Hosted      []Zone   `json:"hosted,omitempty"`
	Secondary   []string `json:"secondary,omitempty"`
	// Lists are its blocklist and overrides, as it reports them.
	Lists map[string]release.ListStatus `json:"lists,omitempty"`
	// Listed: in settings.json (as it was, or as written).
	Listed bool `json:"listed"`
	// Pinned: its ID is pinned to its address here (internal/pins), so releases are signed
	// for it: a node listed, in service, that trusts the key.
	Pinned bool   `json:"pinned"`
	Error  string `json:"error,omitempty"`
	// Notes say what it means for the rebuild.
	Notes []string `json:"notes,omitempty"`
	raw   any      // its /status, as written to recovered/
}

// Report is what a recovery found and did.
type Report struct {
	Time        time.Time `json:"time"`
	Fingerprint string    `json:"release_key"`
	Nodes       []Node    `json:"nodes"`
	// Settings says what was done with settings.json.
	Settings string `json:"settings"`
	// Dir is where the nodes' /status and this report were written ("" for a dry run).
	Dir string `json:"dir,omitempty"`
	// NotRecovered is what the nodes can't give back.
	NotRecovered []string `json:"not_recovered"`
}

// NotRecovered is what no node returns, whatever it runs.
var NotRecovered = []string{
	"node configs' contents (forwarders, zones' primaries, Wi-Fi, services, blocking settings): /status names the config and its seq; " +
		"copy your own back (into configs/ in the data directory), or write them again",
	"hosted zones' master files: /status names each zone with its serial and records, and the bundle's hash, which tells " +
		"whether files put back here are the ones a node serves",
	"blocklist and overrides files: build them again (espdns blocklist); /status gives each list's seq and entries",
	"the DNS peers and the zone primary (\"primary\": its kind and API) in settings.json, and the canary: add them by hand",
	"the login (espdns passwd), the zone primary token (espdns primary import), the action log, job records, " +
		"config and zone history, the pushed records (the next push writes them again)",
	"firmware builds and chip images: load them again with espdns release import",
}

// Run reads the nodes and writes what it can (Options.DryRun: nothing). The release key
// must be imported first: the nodes that trust it are the fleet.
func Run(ctx context.Context, c *fleet.Client, o Options) (Report, error) {
	now := time.Now
	if o.Now != nil {
		now = o.Now
	}
	r := Report{Time: now(), NotRecovered: NotRecovered}
	if o.Key == nil {
		o.Key = keys.FileSource{Path: keys.Path(o.DataDir)}
	}
	k, err := o.Key.Key()
	if err != nil {
		return r, fmt.Errorf("the release key: %w: recovery finds the nodes that trust it, so import it first (espdns key import: docs/getting-started.md, step 7)", err)
	}
	r.Fingerprint = keys.Fingerprint(k)
	spath := settings.Path(o.DataDir)
	_, statErr := os.Stat(spath)
	hadSettings := statErr == nil
	st, err := settings.Load(spath)
	if err != nil {
		return r, err
	}
	listed := slices.Clone(st.Nodes)
	for _, h := range o.Hosts {
		if !slices.Contains(listed, h) {
			listed = append(listed, h)
		}
	}
	found, err := c.Discover(ctx, o.MDNS, listed)
	if err != nil {
		return r, err
	}
	cfgs, _ := configs.List(o.DataDir)
	zfiles, _ := zonefiles.List(o.DataDir)
	// A node ID at more than one address: one of them isn't the node (anything on the
	// network can answer mDNS and copy a node's /status, key fingerprint and all, though it
	// can't sign). Neither is added: which is yours is for you to say (-host, or by hand).
	byID := map[string][]string{}
	for _, f := range found {
		if f.Status != nil && f.Status.NodeID != "" {
			id := strings.ToLower(f.Status.NodeID)
			byID[id] = append(byID[id], f.Addr)
		}
	}
	var add []string
	for _, f := range found {
		n := describe(f, r.Fingerprint, cfgs, zfiles)
		n.Listed = slices.Contains(st.Nodes, n.Addr)
		twice := false
		if as := byID[strings.ToLower(n.ID)]; n.ID != "" && len(as) > 1 {
			twice = true
			n.Notes = append(n.Notes, fmt.Sprintf("node ID %s answers at %s: one of them isn't this node; not added to settings.json "+
				"(add the one that is yours by hand)", n.ID, strings.Join(as, ", ")))
		}
		if n.Error == "" && n.Adopted && n.Trusts && !n.Listed && !twice {
			add = append(add, n.Addr)
		}
		r.Nodes = append(r.Nodes, n)
	}

	switch {
	case !hadSettings && len(add) > 0:
		r.Settings = fmt.Sprintf("%s written with the nodes in service that trust the key: %s", spath, strings.Join(add, ", "))
	case !hadSettings:
		r.Settings = "no settings.json written: no node in service that trusts the key was found"
	case len(add) == 0:
		r.Settings = spath + ": every node in service that trusts the key is in it already"
	case o.AddToSettings:
		r.Settings = fmt.Sprintf("added to %s: %s", spath, strings.Join(add, ", "))
	default:
		r.Settings = fmt.Sprintf("%s is there and doesn't list %s: -add-to-settings adds them (or the Adopt page's \"Add to settings.json\")",
			spath, strings.Join(add, ", "))
	}
	if o.DryRun {
		r.Settings = "dry run, nothing written: " + r.Settings
		return r, nil
	}

	lk, err := fleetlock.Acquire(fleetlock.Path(o.DataDir), fleetlock.Self("espdns recover", "writing settings.json and recovered/"))
	if err != nil {
		return r, err
	}
	defer lk.Release()
	if _, err := os.Stat(spath); !hadSettings && err == nil {
		return r, fmt.Errorf("%s was written while the nodes were read: run espdns recover again", spath)
	}
	if err := r.write(o.DataDir); err != nil {
		return r, err
	}
	written := false
	switch {
	case !hadSettings && len(add) > 0:
		err, written = settings.Save(spath, settings.Settings{Nodes: add}), true
	case hadSettings && o.AddToSettings:
		for _, a := range add {
			if _, err = settings.AddNode(spath, a); err != nil {
				break
			}
		}
		written = true
	}
	if err != nil {
		r.Settings = "settings.json not written: " + err.Error()
		r.writeReport()
		return r, err
	}
	for i := range r.Nodes {
		if written && slices.Contains(add, r.Nodes[i].Addr) {
			r.Nodes[i].Listed = true
		}
	}
	if err := pin(o.DataDir, r.Nodes, byID); err != nil {
		r.writeReport()
		return r, err
	}
	return r, r.writeReport()
}

// pin pins each node listed in settings.json that is in service and trusts the key to its
// address (internal/pins), as adoption would have: releases are signed only for a pinned
// node. An address already pinned to another node is left so, with a note (espdns pin
// changes it); a node ID at two addresses is pinned to neither.
func pin(dataDir string, nodes []Node, byID map[string][]string) error {
	l := pins.Open(dataDir)
	for i := range nodes {
		n := &nodes[i]
		if n.Error != "" || !n.Adopted || !n.Trusts || !n.Listed || n.ID == "" || len(byID[strings.ToLower(n.ID)]) > 1 {
			continue
		}
		cur, err := l.Pinned(n.Addr)
		switch {
		case errors.Is(err, pins.ErrNotPinned):
		case err != nil:
			return err
		case strings.EqualFold(cur, n.ID):
			n.Pinned = true
			continue
		default:
			n.Notes = append(n.Notes, fmt.Sprintf("node %s is pinned to %s here, not this one: releases for %s are signed "+
				"for node %s until it is pinned (espdns pin -host %s -node %s)", cur, n.Addr, n.Addr, cur, n.Addr, n.ID))
			continue
		}
		if _, err := l.Pin(n.ID, n.Addr); err != nil {
			return err
		}
		n.Pinned = true
	}
	return nil
}

// describe is one node as recovery reports it.
func describe(f fleet.Node, fp string, cfgs []configs.File, zfiles []zonefiles.File) Node {
	n := Node{Addr: f.Addr, Source: f.Source, Error: f.Error, Adopted: fleet.Adopted(f)}
	if f.Status == nil {
		if n.Error == "" {
			n.Error = "no /status"
		}
		return n
	}
	s := *f.Status
	n.raw = s
	n.ID, n.Board, n.Image, n.Version, n.Seq, n.Config = s.NodeID, s.Board, s.Image, s.Version, s.Seq, s.Config
	n.Trusts = len(s.Keys) > 0 && strings.EqualFold(s.Keys[0], fp)
	switch {
	case !n.Trusts:
		n.Notes = append(n.Notes, "it doesn't trust the release key imported here (key slot 0 is "+first(s.Keys)+
			"): this controller can't change it; not added to settings.json")
	case !n.Adopted:
		n.Notes = append(n.Notes, "not adopted (no pushed config): the Adopt page, or espdns adopt; not added to settings.json")
	}
	for _, z := range s.Zones {
		n.Secondary = append(n.Secondary, z.Name)
	}
	if b := s.Blocking; b != nil {
		n.Lists = map[string]release.ListStatus{"blocklist": b.List, "overrides": b.Overrides}
	}
	// Its config: a file here by its name or address; its contents never come back.
	if s.Config != nil && s.Config.Source == "node" {
		for _, c := range cfgs {
			if configs.Matches(c.Config, f.Addr, s) {
				n.ConfigFiles = append(n.ConfigFiles, c.Name)
			}
		}
		at := ""
		if s.Config.Seq > 0 {
			at = ", pushed " + time.UnixMilli(int64(s.Config.Seq)).Format("2006-01-02 15:04")
		}
		if len(n.ConfigFiles) == 0 {
			n.Notes = append(n.Notes, fmt.Sprintf("runs config %q (seq %d%s): no file here is it; write it again in configs/ (the node "+
				"doesn't return it)", s.Config.Name, s.Config.Seq, at))
		} else {
			n.Notes = append(n.Notes, fmt.Sprintf("runs config %q (seq %d%s): %s here by its name or address, but whether that is "+
				"the version it runs can't be told (there is no record, and the node doesn't return it): check it in Configs before a push",
				s.Config.Name, s.Config.Seq, at, strings.Join(n.ConfigFiles, ", ")))
		}
	}
	// Its hosted zones: the files here are its bundle, byte for byte, or not.
	if h := s.Hosted; h != nil && len(h.Zones) > 0 {
		m := zonefiles.SetMatch(zfiles, s)
		missing := 0
		for _, z := range h.Zones {
			zn := strings.ToLower(strings.TrimSuffix(z.Name, "."))
			hz := Zone{Name: zn, Serial: z.Serial, Records: z.Records, File: "no file"}
			i := slices.IndexFunc(zfiles, func(f zonefiles.File) bool { return f.Name == zn+".zone" })
			switch {
			case i < 0:
				missing++
			case m == zonefiles.MatchFiles:
				hz.File = "the node's bundle"
			case m == zonefiles.MatchNot:
				hz.File = "a file, not the one it serves"
			case zfiles[i].Parsed != nil && zfiles[i].Serial == z.Serial && zfiles[i].Records == z.Records:
				hz.File = "a file, maybe it (same serial and records)"
			default:
				hz.File = "a file, not the one it serves"
			}
			n.Hosted = append(n.Hosted, hz)
		}
		switch {
		case m == zonefiles.MatchFiles:
			n.Notes = append(n.Notes, "its hosted zones are the files here, byte for byte (the bundle's hash)")
		case missing > 0:
			n.Notes = append(n.Notes, fmt.Sprintf("%d hosted zone(s) with no file here: write them again in zones/ (the node doesn't "+
				"return them); a push of the zones without them would stop it serving them", missing))
		default:
			n.Notes = append(n.Notes, "its hosted zones have files here, but not the bundle it runs: check them in Zones before a push")
		}
	}
	if l := n.Lists["blocklist"]; l.State == "on" {
		n.Notes = append(n.Notes, fmt.Sprintf("blocks with a list of %d entries (seq %d): the file isn't returned; build it again to push one",
			l.Entries, l.Seq))
	}
	return n
}

func first(s []string) string {
	if len(s) == 0 {
		return "none"
	}
	return s[0]
}

// write puts each node's /status in recovered/<time>/, never over a file there.
func (r *Report) write(dataDir string) error {
	dir := filepath.Join(dataDir, Dir, r.Time.UTC().Format("20060102-150405"))
	if err := secfile.MkdirAll(filepath.Dir(dir)); err != nil {
		return err
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return fmt.Errorf("%s: %w (a recovery a second ago? run it again)", dir, err)
	}
	if err := os.Chmod(dir, secfile.DirMode); err != nil { // whatever the umask
		return err
	}
	r.Dir = dir
	for _, n := range r.Nodes {
		if n.raw == nil {
			continue
		}
		name := "status-" + strings.NewReplacer(":", "_", "/", "_", "[", "", "]", "").Replace(n.Addr) + ".json"
		if err := writeNew(filepath.Join(dir, name), n.raw); err != nil {
			return err
		}
	}
	return nil
}

func (r *Report) writeReport() error {
	if r.Dir == "" {
		return errors.New("no recovered directory")
	}
	return writeNew(filepath.Join(r.Dir, "report.json"), r)
}

func writeNew(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, secfile.FileMode)
	if err != nil {
		return err
	}
	if err := f.Chmod(secfile.FileMode); err != nil { // whatever the umask
		f.Close()
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
