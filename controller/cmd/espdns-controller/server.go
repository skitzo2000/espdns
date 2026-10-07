package main

import (
	"errors"
	"net/http"
	"slices"
	"strconv"

	"github.com/skitzo2000/espdns/controller/internal/actionlog"
	"github.com/skitzo2000/espdns/controller/internal/auth"
	"github.com/skitzo2000/espdns/controller/internal/changes"
	"github.com/skitzo2000/espdns/controller/internal/fleet"
	"github.com/skitzo2000/espdns/controller/internal/fleetlock"
	"github.com/skitzo2000/espdns/controller/internal/inventory"
	"github.com/skitzo2000/espdns/controller/internal/jobs"
	"github.com/skitzo2000/espdns/controller/internal/keys"
	"github.com/skitzo2000/espdns/controller/internal/nodes"
	"github.com/skitzo2000/espdns/controller/internal/observe"
	"github.com/skitzo2000/espdns/controller/internal/settings"
	"github.com/skitzo2000/espdns/controller/internal/websec"
	"github.com/skitzo2000/espdns/controller/web"
)

// routes is the mux, recording every pattern added, so a test can walk them all.
type routes struct {
	mux      *http.ServeMux
	patterns []string
}

func (r *routes) HandleFunc(p string, h func(http.ResponseWriter, *http.Request)) {
	r.mux.HandleFunc(p, h)
	r.patterns = append(r.patterns, p)
}

func (r *routes) Handle(p string, h http.Handler) {
	r.mux.Handle(p, h)
	r.patterns = append(r.patterns, p)
}

// server is what the HTTP side serves.
type server struct {
	dataDir string
	nodes   func() []nodes.Node
	runner  *jobs.Runner
	auth    *auth.Auth
	key     keys.Source
	builder *builder
	catalog string // the shipped board catalog, for the configs' memory plans
	push    pushKind
	adopt   adoptKind
	observe *observe.Store     // the dashboard's and the query log's (nil: an empty one)
	zoneDNS inventory.Resolver // the zone lookup's DNS (nil: UDP to each primary)
	changes *changes.Store     // the pending changes (nil: the data directory's)
	listed  func([]string)     // settings.json's nodes after a save from the browser (nil: polled within 10 s)
	lookup  nodeLookup         // Add node's lookup at an address typed (nodes.Registry.Lookup)
	// saveSettings stands in for settings.SaveIf in the settings page's save (nil: SaveIf; a
	// test fails the write with it).
	saveSettings func(path, version string, s settings.Settings, before, after func() error) error
}

// handler is the whole controller over HTTP, outermost first: the security headers
// (websec.Headers: the CSP and the rest, on every response, a refusal too), LocalOnly (a
// localhost Host, no other site's Origin), the login (auth.Guard: a session, its cookie
// and the page's token), then the routes. It returns the patterns too.
func (s *server) handler() (http.Handler, []string) {
	mux := &routes{mux: http.NewServeMux()}
	s.auth.Routes(mux)
	mux.HandleFunc("GET /api/nodes", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, s.nodes())
	})
	s.runner.Who = func(r *http.Request) string { return auth.User(r.Context()) }
	s.runner.Routes(mux)
	// The release key: whether there is one to sign with, and its fingerprint (never the key).
	mux.HandleFunc("GET /api/key", func(w http.ResponseWriter, r *http.Request) {
		out := map[string]any{"source": s.key.String()}
		k, err := s.key.Key()
		switch {
		case err == nil:
			out["present"], out["fingerprint"] = true, keys.Fingerprint(k)
		default:
			out["present"], out["error"], out["missing"] = false, err.Error(), errors.Is(err, keys.ErrNoKey)
		}
		writeJSON(w, out)
	})
	// Who holds the fleet lock now (a CLI rollout, a job), if anyone.
	mux.HandleFunc("GET /api/lock", func(w http.ResponseWriter, r *http.Request) {
		h, held, err := fleetlock.Held(fleetlock.Path(s.dataDir))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		out := map[string]any{"held": held}
		if held {
			out["holder"], out["text"] = h, h.String()
		}
		writeJSON(w, out)
	})
	// The action log's newest entries (?n=, default 100), newest first.
	mux.HandleFunc("GET /api/actions", func(w http.ResponseWriter, r *http.Request) {
		n, err := strconv.Atoi(r.URL.Query().Get("n"))
		if err != nil || n <= 0 {
			n = 100
		}
		es, err := actionlog.Tail(s.dataDir, n)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		slices.Reverse(es)
		writeJSON(w, es)
	})
	s.builder.routes(mux)
	configsServer{dataDir: s.dataDir, catalog: s.catalog, nodes: s.nodes, auth: s.auth}.routes(mux)
	zonesServer{dataDir: s.dataDir, nodes: s.nodes}.routes(mux)
	inventoryServer{dataDir: s.dataDir, nodes: s.nodes, dns: s.zoneDNS}.routes(mux)
	blockingServer{dataDir: s.dataDir, nodes: s.nodes, runner: s.runner}.routes(mux)
	if s.changes == nil {
		s.changes = changes.New(s.dataDir)
	}
	changesServer{dataDir: s.dataDir, catalog: s.catalog, store: s.changes, nodes: s.nodes, runner: s.runner}.routes(mux)
	nodeSettingsServer{dataDir: s.dataDir, catalog: s.catalog, nodes: s.nodes, store: s.changes, known: s.push.known}.routes(mux)
	updatesServer{dataDir: s.dataDir, catalog: s.catalog, store: s.changes, nodes: s.nodes}.routes(mux)
	setupServer{dataDir: s.dataDir, auth: s.auth, key: s.key, listed: s.listed, saveIf: s.saveSettings}.routes(mux)
	primaryCertServer{dataDir: s.dataDir}.routes(mux)
	s.push.routes(mux)
	s.adopt.routes(mux)
	addNodeServer{adopt: s.adopt, lookup: s.lookup}.routes(mux)
	backupServer{dataDir: s.dataDir, auth: s.auth}.routes(mux)
	if s.observe == nil {
		s.observe = observe.New(&fleet.Client{})
	}
	observeServer{store: s.observe}.routes(mux)
	searchServer{dataDir: s.dataDir, nodes: s.nodes, changes: s.changes, log: s.observe}.routes(mux)
	mux.Handle("GET /", http.FileServerFS(web.Files))
	return websec.Headers(jobs.LocalOnly(s.auth.Guard(mux.mux))), mux.patterns
}
