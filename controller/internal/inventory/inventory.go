// Package inventory is every zone the fleet answers for, in one place, whatever its source
// (docs/plan.md, The GUI redesign: "Zones: every zone the fleet answers for, in one
// place"): the zones hosted here (the zone files), the zones the nodes copy from a primary
// (secondary zones, from the node configs and the nodes' /status) and the domains they
// forward (forward zones, the same). It also finds, for a zone name typed in, whether the
// fleet has it already and else which configured primary serves it (Find).
//
// All nodes serve the same zones, so a zone's state is the fleet's (docs/plan.md, The
// prototype): how many of the fleet's nodes serve it, never which. A node out of sync is
// that node's page's to show.
package inventory

import (
	"slices"
	"strconv"
	"strings"

	"github.com/skitzo2000/espdns/controller/internal/configs"
	"github.com/skitzo2000/espdns/controller/internal/release"
	"github.com/skitzo2000/espdns/controller/internal/zonefiles"
	"github.com/skitzo2000/espdns/controller/internal/zones"
)

// The kinds of zone, by where its records come from.
const (
	KindHosted    = "hosted"    // a zone file here: espDNS is its primary
	KindSecondary = "secondary" // copied from a primary (AXFR/IXFR)
	KindForward   = "forward"   // its queries sent to another server
)

// The fleet's state of a zone.
const (
	StateOK      = "ok"      // every node read serves it (a hosted zone: its file as saved)
	StatePartial = "partial" // some nodes serve it, not every one (or not the file as saved)
	StateWaiting = "waiting" // in a zone file or a config, on no node yet
	StateExpired = "expired" // a node's copy expired: it can't copy the zone from its primary
	StateError   = "error"   // the zone file doesn't pass its checks
	StateNoFile  = "no_file" // a hosted zone the nodes serve with no file here
	StateUnknown = "unknown" // no node's /status read yet
)

// Zone is one zone of the fleet. Name and Kind identify it: a name in two kinds (a zone
// file and a config's secondary zone, say) is two entries, a clash the page shows.
type Zone struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
	// Primary is the primary a secondary zone is copied from, as the configs name it.
	Primary string `json:"primary,omitempty"`
	// Forwarders are the servers a forward zone's queries go to (more than one: the configs
	// or nodes disagree).
	Forwarders []string `json:"forwarders,omitempty"`
	// A hosted zone's file, and its serial and records as saved; a secondary zone's serial
	// and records as the nodes copied it (the newest copy read).
	File    string `json:"file,omitempty"`
	Serial  uint32 `json:"serial,omitempty"`
	Records int    `json:"records,omitempty"`
	// Configs are the node config files that name a secondary or forward zone.
	Configs []string `json:"configs,omitempty"`
	// Serving is how many of the fleet's nodes serve it (a hosted zone: as saved); Nodes how
	// many nodes' /status was read.
	Serving int    `json:"serving"`
	Nodes   int    `json:"nodes"`
	State   string `json:"state"`
	Text    string `json:"text"` // the state in words
}

// Node is one of the fleet's nodes: its address and its last /status (nil: none read).
type Node struct {
	Host   string
	Status *release.NodeStatus
}

// Counts are the zones by kind, and the hosted zones' records.
type Counts struct {
	Hosted    int `json:"hosted"`
	Secondary int `json:"secondary"`
	Forward   int `json:"forward"`
	Records   int `json:"records"` // in the hosted zones' files and the secondary zones' newest copies
}

// Inventory is every zone, sorted by name, then kind.
type Inventory struct {
	Zones  []Zone `json:"zones"`
	Counts Counts `json:"counts"`
	// Primaries are the primaries the configs copy secondary zones from, sorted.
	Primaries []string `json:"primaries"`
	// Nodes is how many nodes' /status was read, of Fleet.
	Nodes int `json:"nodes"`
	Fleet int `json:"fleet"`
}

// Build makes the inventory from the zone files and node configs in dataDir and the
// fleet's nodes.
func Build(dataDir string, fleet []Node) (Inventory, error) {
	files, err := zonefiles.List(dataDir)
	if err != nil {
		return Inventory{}, err
	}
	cfgs, err := configs.List(dataDir)
	if err != nil {
		return Inventory{}, err
	}
	inv := Inventory{Zones: []Zone{}, Primaries: []string{}, Fleet: len(fleet)}
	var read []Node
	for _, n := range fleet {
		if n.Status != nil {
			read = append(read, n)
		}
	}
	inv.Nodes = len(read)

	// Hosted: each zone file, and each zone a node serves that has none.
	for _, f := range files {
		z := Zone{Name: f.Zone, Kind: KindHosted, File: f.Name, Serial: f.Serial, Records: f.Records, Nodes: len(read)}
		other := 0
		for _, n := range read {
			s, ok := zonefiles.Serves(dataDir, f, n.Host, *n.Status, zonefiles.SetMatch(files, *n.Status))
			switch {
			case !ok:
			case s.State == "file" || s.State == "unrecorded" && s.Serial == f.Serial && s.Records == f.Records:
				z.Serving++
			default:
				other++
			}
		}
		switch {
		case f.Error != "":
			z.State, z.Text = StateError, "the zone file doesn't pass its checks: "+f.Error
		case other > 0:
			z.State, z.Text = StatePartial, plural(other, "node serves", "nodes serve")+" another version"
			if z.Serving > 0 {
				_, on := served(z.Serving, len(read), ", as saved")
				z.Text = on + "; " + z.Text
			} else {
				z.Text += ", none the file as saved"
			}
		default:
			z.State, z.Text = served(z.Serving, len(read), ", as saved")
		}
		inv.Zones = append(inv.Zones, z)
		inv.Counts.Records += f.Records
	}
	unfiled := map[string]int{}
	for _, n := range read {
		if n.Status.Hosted == nil {
			continue
		}
		for _, hz := range n.Status.Hosted.Zones {
			name := canon(hz.Name)
			if !slices.ContainsFunc(files, func(f zonefiles.File) bool { return f.Zone == name }) {
				unfiled[name]++
			}
		}
	}
	for name, c := range unfiled {
		inv.Zones = append(inv.Zones, Zone{Name: name, Kind: KindHosted, Serving: c, Nodes: len(read), State: StateNoFile,
			Text: plural(c, "node serves", "nodes serve") + " it, with no zone file here"})
	}

	// Secondary and forward zones: the configs', then the nodes'.
	sec, fwd := map[string]*Zone{}, map[string]*Zone{}
	get := func(m map[string]*Zone, name, kind string) *Zone {
		z := m[name]
		if z == nil {
			z = &Zone{Name: name, Kind: kind, Nodes: len(read)}
			m[name] = z
		}
		return z
	}
	for _, f := range cfgs {
		c := f.Config
		if c == nil {
			continue
		}
		if s := c.Secondary; s != nil && s.Zones != nil {
			for _, name := range *s.Zones {
				z := get(sec, canon(name), KindSecondary)
				z.Configs = append(z.Configs, f.Name)
				if z.Primary == "" {
					z.Primary = s.Primary
				}
				if s.Primary != "" && !slices.Contains(inv.Primaries, s.Primary) {
					inv.Primaries = append(inv.Primaries, s.Primary)
				}
			}
		}
		if c.ForwardZones != nil {
			for _, fz := range *c.ForwardZones {
				z := get(fwd, canon(fz.Zone), KindForward)
				z.Configs = append(z.Configs, f.Name)
				z.Forwarders = addOnce(z.Forwarders, fz.Forwarder)
			}
		}
	}
	expired := map[string]int{}
	for _, n := range read {
		for _, x := range n.Status.Zones {
			name := canon(x.Name)
			z := get(sec, name, KindSecondary)
			z.Serving++
			if x.Records > 0 && (z.Records == 0 || zones.SerialAbove(x.Serial, z.Serial)) {
				z.Serial, z.Records = x.Serial, x.Records
			}
			if x.Expired {
				expired[name]++
			}
		}
		for _, x := range n.Status.ForwardZones {
			z := get(fwd, canon(x.Name), KindForward)
			z.Serving++
			z.Forwarders = addOnce(z.Forwarders, x.Forwarder)
		}
	}
	for name, z := range sec {
		switch e := expired[name]; {
		case e > 0:
			z.State, z.Text = StateExpired, plural(e, "node's copy", "nodes' copies")+" expired: it can't copy the zone from its primary"
		default:
			z.State, z.Text = served(z.Serving, len(read), "")
		}
		inv.Zones = append(inv.Zones, *z)
		inv.Counts.Records += z.Records
	}
	for _, z := range fwd {
		slices.Sort(z.Forwarders)
		z.State, z.Text = served(z.Serving, len(read), "")
		inv.Zones = append(inv.Zones, *z)
	}

	for _, z := range inv.Zones {
		switch z.Kind {
		case KindHosted:
			inv.Counts.Hosted++
		case KindSecondary:
			inv.Counts.Secondary++
		case KindForward:
			inv.Counts.Forward++
		}
	}
	slices.SortFunc(inv.Zones, func(a, b Zone) int {
		if c := strings.Compare(a.Name, b.Name); c != 0 {
			return c
		}
		return strings.Compare(a.Kind, b.Kind)
	})
	slices.Sort(inv.Primaries)
	return inv, nil
}

// served is the state of a zone on n of the read nodes; how follows "on every node".
func served(n, read int, how string) (string, string) {
	switch {
	case read == 0:
		return StateUnknown, "no node's status read yet"
	case n == 0:
		return StateWaiting, "on no node yet"
	case n >= read && read == 1:
		return StateOK, "on the node" + how
	case n >= read:
		return StateOK, "on every node" + how
	}
	return StatePartial, "on " + strconv.Itoa(n) + " of " + strconv.Itoa(read) + " nodes" + how
}

// Of is the inventory's zone of that name, of any kind: the first one by kind order.
func (inv Inventory) Of(name string) (Zone, bool) {
	i := slices.IndexFunc(inv.Zones, func(z Zone) bool { return z.Name == name })
	if i < 0 {
		return Zone{}, false
	}
	return inv.Zones[i], true
}

// canon is a zone name as the inventory keys it: lowercase, without the root's dot.
func canon(name string) string { return strings.ToLower(strings.TrimSuffix(name, ".")) }

func addOnce(l []string, s string) []string {
	if s == "" || slices.Contains(l, s) {
		return l
	}
	return append(l, s)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}
