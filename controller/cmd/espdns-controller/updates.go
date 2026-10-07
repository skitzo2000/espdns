package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/skitzo2000/espdns/controller/internal/auth"
	"github.com/skitzo2000/espdns/controller/internal/changes"
	"github.com/skitzo2000/espdns/controller/internal/nodes"
	"github.com/skitzo2000/espdns/controller/internal/settings"
	"github.com/skitzo2000/espdns/controller/internal/updates"
)

// Update availability (internal/updates), for the Nodes page's "update available" and its
// Update panel:
//
//	GET  /api/updates   each node's firmware against the newest build for it, as versions; the builds
//	POST /api/updates   {"nodes": [...], "builds": {host: build}}: the updates, as pending firmware changes (201)
//
// An update is never pushed from here: it waits in the pending changes until Apply. The
// read is open like /api/nodes (no file it reads holds a secret); the update needs a login.

type updatesServer struct {
	dataDir string
	catalog string
	store   *changes.Store
	nodes   func() []nodes.Node
}

func (u updatesServer) routes(mux *routes) {
	mux.HandleFunc("GET /api/updates", u.list)
	mux.HandleFunc("POST /api/updates", needLogin("an update needs", u.add))
}

// report is the fleet's update availability: the nodes in settings.json (any not seen yet
// unknown), or every node the controller knows when it lists none (none offered then).
func (u updatesServer) report() (updates.Report, error) {
	s, err := settings.Load(settings.Path(u.dataDir))
	if err != nil {
		return updates.Report{}, err
	}
	pending, err := u.store.List()
	if err != nil {
		return updates.Report{}, err
	}
	node := func(n nodes.Node, listed bool) updates.Node {
		un := updates.Node{Host: n.Addr, Listed: listed, Online: n.Online}
		if st, ok := status(n); ok {
			un.Status = &st
		}
		return un
	}
	known := u.nodes()
	var ns []updates.Node
	if len(s.Nodes) == 0 {
		for _, n := range known {
			ns = append(ns, node(n, false))
		}
	}
	for _, h := range s.Nodes {
		un := updates.Node{Host: h, Listed: true}
		for _, n := range known {
			if n.Addr == h {
				un = node(n, true)
				break
			}
		}
		ns = append(ns, un)
	}
	return updates.For(ns, updates.Builds(u.dataDir, u.catalog), pending), nil
}

func (u updatesServer) list(w http.ResponseWriter, r *http.Request) {
	rep, err := u.report()
	if err != nil {
		httpErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, rep)
}

// updateBody is POST /api/updates's body: the nodes (none: every one offered, "Update
// all"), and the build the page showed for each (optional: a newer one since is a 409).
type updateBody struct {
	Nodes  []string          `json:"nodes"`
	Builds map[string]string `json:"builds"`
}

func (u updatesServer) add(w http.ResponseWriter, r *http.Request) {
	var b updateBody
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	d.DisallowUnknownFields()
	if err := d.Decode(&b); err != nil {
		httpErr(w, http.StatusBadRequest, fmt.Errorf("body: %v", err))
		return
	}
	rep, err := u.report()
	if err != nil {
		httpErr(w, http.StatusInternalServerError, err)
		return
	}
	offers, err := rep.Plan(b.Nodes, b.Builds)
	if err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, updates.ErrMoved) {
			code = http.StatusConflict
		}
		httpErr(w, code, err)
		return
	}
	for _, o := range offers {
		if err := firmwareThere(u.dataDir, u.catalog, o.Source); err != nil {
			httpErr(w, http.StatusBadRequest, err)
			return
		}
	}
	// One change per build; all or none, in one save (an apply started meanwhile takes
	// either all of them or none).
	cs := changesServer{dataDir: u.dataDir}
	var es []changes.Edit
	for _, o := range offers {
		es = append(es, changes.Edit{Kind: changes.Firmware, Firmware: o.Source, Nodes: o.Nodes, Summary: o.Summary,
			Who: auth.User(r.Context())})
	}
	added, err := u.store.AddAll(es)
	if err != nil {
		httpErr(w, changeCode(err), err)
		return
	}
	for _, ch := range added {
		cs.log(r, "change add", ch, ch.Summary)
	}
	w.Header().Set("Location", "/api/changes")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{"changes": added})
}
