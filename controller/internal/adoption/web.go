package adoption

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"regexp"

	"github.com/skitzo2000/espdns/controller/internal/configs"
	"github.com/skitzo2000/espdns/controller/internal/settings"
)

// Web is an adoption as the controller's Adopt page asks for it (the job kind "adopt"):
// a node it found, a config from the data directory, the address.
type Web struct {
	Node   string `json:"node"`    // the node's address now
	NodeID string `json:"node_id"` // its ID as the page showed it (checked at step 2)
	Config string `json:"config"`  // a file in configs/
	// Address: "" (the config's, else the one it runs on), a.b.c.d/nn, or "dhcp" (never on
	// a network in settings.json's no_dhcp); Gateway goes with a static one.
	Address  string `json:"address,omitempty"`
	Gateway  string `json:"gateway,omitempty"`
	Reserved bool   `json:"reserved,omitempty"`
	// PrimaryDone: the zone primary isn't changed from here (a manual kind, no address or
	// token), and the changes the dry run named were made by hand.
	PrimaryDone bool `json:"primary_done,omitempty"`
	// AddToSettings: once adopted, its address goes into settings.json.
	AddToSettings bool   `json:"add_to_settings,omitempty"`
	DryRun        bool   `json:"dry_run,omitempty"`
	After         string `json:"after,omitempty"` // the adoption: the dry run it follows
}

// ParseWeb reads an Adopt page request, unknown fields refused.
func ParseWeb(raw []byte) (Web, error) {
	var w Web
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&w); err != nil {
		return w, fmt.Errorf("params: %v", err)
	}
	return w, nil
}

var macRE = regexp.MustCompile(`^[0-9a-f]{2}(:[0-9a-f]{2}){5}$`)

// Request is the request the CLI's flags make for the same adoption, as make fleet-adopt
// runs it: -data, -mdns 0, -host and -node, -config in the data directory, the settings'
// zone primary and DNS peers, no flag that loosens the rule.
func (w Web) Request(dataDir, catalog string) (Request, error) {
	r := Request{DataDir: dataDir, Catalog: catalog, Wait: DefaultWait, DryRun: w.DryRun}
	if w.Node == "" {
		return r, errors.New(`"node": choose the node to adopt`)
	}
	if !macRE.MatchString(w.NodeID) {
		return r, errors.New(`"node_id": the node's ID as found (its MAC, aa:bb:cc:dd:ee:ff)`)
	}
	if err := configs.CheckName(w.Config); err != nil {
		return r, fmt.Errorf(`"config": %w`, err)
	}
	switch {
	case w.Address == "", w.Address == "dhcp":
	default:
		if p, err := netip.ParsePrefix(w.Address); err != nil || !p.Addr().Is4() {
			return r, fmt.Errorf(`"address": %q is not an IPv4 address with its prefix length (192.0.2.60/24)`, w.Address)
		}
	}
	if w.Gateway != "" {
		if w.Address == "dhcp" {
			return r, errors.New(`"gateway": only with a static address`)
		}
		if a, err := netip.ParseAddr(w.Gateway); err != nil || !a.Is4() {
			return r, fmt.Errorf(`"gateway": %q is not an IPv4 address`, w.Gateway)
		}
	}
	s, err := settings.Load(settings.Path(dataDir))
	if err != nil {
		return r, err
	}
	r.Host, r.Node, r.Address, r.Gateway, r.Reserved = w.Node, w.NodeID, w.Address, w.Gateway, w.Reserved
	r.Config = filepath.Join(configs.Path(dataDir), w.Config)
	zp := s.ZonePrimary()
	r.PrimaryKind, r.PrimaryURL, r.PrimaryDone, r.AddToSettings = zp.Kind, zp.URL, w.PrimaryDone, w.AddToSettings
	return r, nil
}

// Key is the request's identity for a dry run: what the adoption does, without the choices
// made only at the adoption itself (the dry run it follows, the changes made by hand, the
// settings).
func (w Web) Key() string {
	w.DryRun, w.After, w.PrimaryDone, w.AddToSettings = false, "", false, false
	b, _ := json.Marshal(w)
	return string(b)
}
