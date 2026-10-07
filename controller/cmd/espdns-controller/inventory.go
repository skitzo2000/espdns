package main

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/fleet"
	"github.com/skitzo2000/espdns/controller/internal/inventory"
	"github.com/skitzo2000/espdns/controller/internal/nodes"
	"github.com/skitzo2000/espdns/controller/internal/primary"
	"github.com/skitzo2000/espdns/controller/internal/settings"
)

// Every zone the fleet answers for, in one place (internal/inventory), for the Zones page:
//
//	GET /api/zone-inventory           every zone (hosted, secondary, forward), its source and the fleet's state; the zone primary
//	GET /api/zone-lookup?name=<zone>  where a typed zone lives: the fleet's already, a configured primary's (asked over DNS), or none
//
// Both need a login. The lookup sends each configured primary one SOA query, without
// recursion; nothing else leaves the controller.

// lookupTimeout bounds one lookup, every primary asked.
const lookupTimeout = 6 * time.Second

type inventoryServer struct {
	dataDir string
	nodes   func() []nodes.Node
	dns     inventory.Resolver // nil: UDP to port 53 of each primary
}

func (v inventoryServer) routes(mux *routes) {
	need := func(h http.HandlerFunc) http.HandlerFunc { return needLogin("the zone inventory needs", h) }
	mux.HandleFunc("GET /api/zone-inventory", need(v.list))
	mux.HandleFunc("GET /api/zone-lookup", need(v.lookup))
}

// build is the inventory of the fleet: the nodes in settings.json (any not seen yet
// counted as unread), or every node the controller knows when it lists none.
func (v inventoryServer) build() (inventory.Inventory, settings.Settings, error) {
	s, err := settings.Load(settings.Path(v.dataDir))
	if err != nil {
		return inventory.Inventory{}, s, err
	}
	known := v.nodes()
	var fl []inventory.Node
	node := func(n nodes.Node) inventory.Node {
		in := inventory.Node{Host: n.Addr}
		if st, ok := status(n); ok {
			in.Status = &st
		}
		return in
	}
	if len(s.Nodes) == 0 {
		for _, n := range known {
			fl = append(fl, node(n))
		}
	}
	for _, h := range s.Nodes {
		in := inventory.Node{Host: h}
		for _, n := range known {
			if n.Addr == h {
				in = node(n)
				break
			}
		}
		fl = append(fl, in)
	}
	inv, err := inventory.Build(v.dataDir, fl)
	return inv, s, err
}

// zonePrimary is settings.json's zone primary as the page shows it: its kind (manual when
// none is set), its driver's name, its API address and whether it has one, and "paused",
// why its calls are paused (a plain http address), if they are. Never its token.
func zonePrimary(s settings.Settings) map[string]any {
	zp := s.ZonePrimary()
	kind := zp.Kind
	if zp.IsZero() {
		kind = primary.KindManual
	}
	d, _ := primary.Lookup(kind)
	out := map[string]any{"kind": kind, "name": d.Name, "set": !zp.IsZero(), "url": zp.URL, "api": d.API}
	if zp.PlainHTTP() {
		out["paused"] = primary.ErrPlainHTTP.Error()
	}
	return out
}

func (v inventoryServer) list(w http.ResponseWriter, r *http.Request) {
	inv, s, err := v.build()
	if err != nil {
		httpErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, struct {
		inventory.Inventory
		Primary map[string]any `json:"primary"`
	}{inv, zonePrimary(s)})
}

// primaries are the primaries a lookup asks, in order: settings.json's zone primary (its
// API's host), then each the configs copy zones from.
func primaries(s settings.Settings, inv inventory.Inventory) []string {
	var out []string
	if u, err := url.Parse(s.ZonePrimary().URL); err == nil && u.Hostname() != "" {
		out = append(out, u.Hostname())
	}
	for _, p := range inv.Primaries {
		if p != "" && (len(out) == 0 || out[0] != p) {
			out = append(out, p)
		}
	}
	return out
}

func (v inventoryServer) lookup(w http.ResponseWriter, r *http.Request) {
	name, err := inventory.CheckName(r.URL.Query().Get("name"))
	if err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	inv, s, err := v.build()
	if err != nil {
		httpErr(w, http.StatusInternalServerError, err)
		return
	}
	res := v.dns
	if res == nil {
		res = fleet.UDP{}
	}
	ctx, cancel := context.WithTimeout(r.Context(), lookupTimeout)
	defer cancel()
	// The lookup asks each primary over DNS only (no token), so a paused zone primary is
	// still asked; the reply says it is paused.
	paused := ""
	if s.ZonePrimary().PlainHTTP() {
		paused = primary.ErrPlainHTTP.Error()
	}
	writeJSON(w, struct {
		inventory.Lookup
		PrimaryPaused string `json:"primary_paused,omitempty"`
	}{inventory.Find(ctx, res, inv, name, primaries(s, inv)), paused})
}
