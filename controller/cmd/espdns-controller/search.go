package main

import (
	"net/http"

	"github.com/skitzo2000/espdns/controller/internal/changes"
	"github.com/skitzo2000/espdns/controller/internal/nodes"
	"github.com/skitzo2000/espdns/controller/internal/observe"
	"github.com/skitzo2000/espdns/controller/internal/search"
)

// The one search (internal/search), for the search box on every page:
//
//	GET /api/search?q=<text>   nodes, zones, records, devices, sites, rules, lists and pending changes that match
//
// It needs a login, as the query log does (it says who asked for what). It reads only what
// the controller holds (its files, the node list, the query log's buffer): nothing leaves
// the controller, and a search takes search.Budget at most.

type searchServer struct {
	dataDir string
	nodes   func() []nodes.Node
	changes *changes.Store
	log     *observe.Store
}

func (s searchServer) routes(mux *routes) {
	mux.HandleFunc("GET /api/search", needLogin("search needs", s.search))
}

func (s searchServer) search(w http.ResponseWriter, r *http.Request) {
	q, err := search.CheckQuery(r.URL.Query().Get("q"))
	if err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	// The zone inventory as the Zones page has it: the fleet in settings.json.
	inv, _, err := inventoryServer{dataDir: s.dataDir, nodes: s.nodes}.build()
	if err != nil {
		httpErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, search.Run(r.Context(), search.Input{DataDir: s.dataDir, Changes: s.changes, Log: s.log,
		Nodes: s.nodes(), Inventory: inv}, q))
}
