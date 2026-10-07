// espdns-controller: the espDNS management dashboard. It finds nodes, shows their state,
// flashes new ones from the browser and runs fleet jobs, one at a time. All state lives in
// the data directory (in Docker, the /data volume mounted from the host), which the espdns
// CLI's fleet targets share. All of it is the controller's user's only: directories 0700,
// files 0600, whatever the umask (internal/secfile); at start, anything in it open to group
// or others (a data directory from before) is made so.
//
//	settings.json            deployment settings (internal/settings), read by the CLI too
//	fleet.lock               the fleet lock (internal/fleetlock): one fleet change at a time
//	log/actions.jsonl        the action log (internal/actionlog): every fleet change
//	log/jobs/<id>.json       each job's record and progress (internal/jobs)
//	firmware/images/<image>/ chip images from `make export-images` in firmware/
//	firmware/builds/<board>/ the production boards' builds, from make fleet-firmware (the rolling push)
//	lists/                   blocklist and overrides files (the rolling push; the Blocking page compiles them)
//	blocking/lists.json      the list definitions (internal/blocking): what each list is compiled from
//	blocking/sources/        local list sources, allow lists and the overrides, edited on the Blocking page
//	zones/<zone>.zone        hosted zones (internal/zonefiles): the zone editor's and the rolling push's
//	boards/                  your own board definitions (the shipped catalog is -catalog)
//	keys/release.pem         the release signing key, mode 0600 (internal/keys; espdns key import)
//	keys/primary.token       the zone primary's API token, mode 0600 (internal/keys; espdns primary import)
//	configs/<name>.json      node configs (internal/configs): the editor's and the CLI's config rollouts
//	changes/                 the pending changes (internal/changes): edits waiting for one apply
//	auth.json                the login: the user and an argon2id hash, mode 0600 (espdns passwd)
//
// The nodes don't depend on it: they keep answering DNS when it is off.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/auth"
	"github.com/skitzo2000/espdns/controller/internal/changes"
	"github.com/skitzo2000/espdns/controller/internal/fleet"
	"github.com/skitzo2000/espdns/controller/internal/jobs"
	"github.com/skitzo2000/espdns/controller/internal/keys"
	"github.com/skitzo2000/espdns/controller/internal/nodes"
	"github.com/skitzo2000/espdns/controller/internal/observe"
	"github.com/skitzo2000/espdns/controller/internal/primary"
	"github.com/skitzo2000/espdns/controller/internal/settings"
	"github.com/skitzo2000/espdns/controller/internal/version"
)

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("write json: %v", err)
	}
}

// loopbackListen says whether a listen address is on loopback only.
func loopbackListen(addr string) bool {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func main() {
	// Localhost: the dashboard is plain HTTP (its login cookie can't be Secure), and browsers
	// only allow USB flashing (Web Serial) on localhost or HTTPS.
	listen := flag.String("listen", "127.0.0.1:8480", "address to serve the dashboard on")
	dataDir := flag.String("data", "data", "data directory")
	catalog := flag.String("catalog", "../boards", "the shipped board catalog")
	browse := flag.Bool("browse-mdns", true, "browse mDNS for nodes besides settings.json's (false: only those are polled; the browser tests, which must reach no node)")
	mdns := flag.Duration("check-mdns", 3*time.Second, "how long a check job browses mDNS for nodes besides the settings' (0: don't)")
	health := flag.Bool("healthcheck", false, "only check that the controller on -listen answers (exit 0) or not (exit 1): the container's health check")
	flag.Parse()
	if *health {
		if err := healthcheck(*listen, 5*time.Second); err != nil {
			log.Printf("healthcheck: %v", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	if !loopbackListen(*listen) {
		log.Fatalf("-listen %s: the controller listens on localhost only (127.0.0.1, [::1] or localhost)", *listen)
	}

	log.Printf("espdns-controller %s", version.Version)
	if err := prepareData(*dataDir, log.Printf); err != nil {
		log.Fatalf("%v: the controller stores everything there, so it doesn't start (docker compose: the directory must exist and be owned by ESPDNS_UID:ESPDNS_GID, .env)", err)
	}
	st, err := loadSettings(*dataDir, log.Printf)
	if err != nil {
		log.Fatalf("settings: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	reg := nodes.New(st.Nodes)
	// The dashboard and the query log (internal/observe): after each poll of /status, each
	// node that answered has its /metrics and new query log entries read, in memory only. A
	// poll that comes while the last read still runs is skipped.
	obs := observe.New(&fleet.Client{})
	polled := make(chan []nodes.Node, 1)
	reg.OnPoll(func(list []nodes.Node) {
		select {
		case polled <- list:
		default:
		}
	})
	go obs.Run(ctx, polled)
	go reg.Run(ctx, *browse)
	// settings.json read again every 10 s: a node an adoption added (or one added by hand) is
	// polled without a restart. A file that doesn't parse leaves the list as it was.
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(10 * time.Second):
			}
			if s, err := settings.Load(settings.Path(*dataDir)); err == nil {
				reg.SetListed(s.Nodes)
			}
		}
	}()

	// The release key (internal/keys): a file in the data directory for now. Read again at
	// every action, so a key imported while the controller runs is used from then on.
	keySrc := keys.Source(keys.FileSource{Path: keys.Path(*dataDir)})
	if k, err := keySrc.Key(); err != nil {
		log.Printf("release key: %v: the controller only reads nodes until one is imported", err)
	} else {
		log.Printf("release key: %s, fingerprint %s", keySrc, keys.Fingerprint(k))
	}
	login := auth.New(auth.Path(*dataDir))
	if set, err := login.State(); !set {
		log.Printf("login: no password set (the first run in the browser, or espdns passwd): read-only until one is")
	} else if err != nil {
		log.Printf("login: %v: nobody can log in until it is fixed", err)
	}

	// The job kinds: check (read-only), and the node actions (actions.go).
	newClient := func() *fleet.Client { return &fleet.Client{} }
	act := actions{dataDir: *dataDir, key: keySrc, client: newClient, known: func() []string {
		var out []string
		for _, n := range reg.List() {
			out = append(out, n.Addr)
		}
		if s, err := settings.Load(settings.Path(*dataDir)); err == nil {
			out = append(out, s.Nodes...)
		}
		return out
	}}
	kinds := act.kinds()
	kinds["check"] = checker{dataDir: *dataDir, mdns: *mdns, client: newClient}.kind
	// Compiling a list (blocking.go): blocklist.Run, as espdns blocklist.
	kinds["blocklist"] = compileKind{dataDir: *dataDir}.kind
	// A config push (configs.go) names the dry run before it: the runner's job.
	var runner *jobs.Runner
	kinds["config-push"] = configPush{actions: act, catalog: *catalog, secret: newSecret(),
		job: func(id string) (jobs.Job, bool) { return runner.Get(id) }}.kind
	// The rolling push (push.go), which names its dry run too.
	push := pushKind{actions: act, catalog: *catalog, secret: newSecret(), nodes: reg.List, used: &usedRuns{},
		job: func(id string) (jobs.Job, bool) { return runner.Get(id) }}
	kinds["rollout"] = push.kind
	// Adoption and the zone primary's lists (adopt.go): the token is a file, as the key
	// (keys/primary.token).
	tokSrc := keys.TokenSource(keys.DataTokenSource{DataDir: *dataDir})
	switch zp := st.ZonePrimary(); {
	case zp.IsZero():
		log.Printf(`zone primary: none in settings.json ("primary"): manual, adoption names the changes to make on it by hand`)
	case !primaryHasAPI(zp.Kind):
		log.Printf("zone primary: %s: adoption names the changes to make on it by hand", zp.Kind)
	default:
		if _, err := tokSrc.Token(); err != nil {
			log.Printf("zone primary %s: token: %v: adoption names the changes to make there by hand", zp, err)
		}
	}
	adopt := adoptKind{actions: act, catalog: *catalog, secret: newSecret(), nodes: reg.List, used: &usedRuns{}, token: tokSrc,
		job: func(id string) (jobs.Job, bool) { return runner.Get(id) }}
	kinds["adopt"] = adopt.kind
	kinds["primary"] = adopt.primaryKind
	kinds["settings-add"] = adopt.settingsAdd
	// The pending changes and the apply (changes.go, apply.go): every change sent as one
	// rolling change.
	pending := changes.New(*dataDir)
	kinds["apply"] = applyKind{actions: act, catalog: *catalog, store: pending}.kind
	runner = jobs.New(*dataDir, kinds)
	jobsDone := make(chan struct{})
	go func() { runner.Run(ctx); close(jobsDone) }()

	srv := &server{dataDir: *dataDir, nodes: reg.List, runner: runner, auth: login, key: keySrc, catalog: *catalog, push: push, adopt: adopt, observe: obs, changes: pending, listed: reg.SetListed, lookup: reg.Lookup,
		builder: newBuilder(*catalog, filepath.Join(*dataDir, "boards"), filepath.Join(*dataDir, "firmware", "images"))}
	h, _ := srv.handler()

	hs := &http.Server{Addr: *listen, Handler: h, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		<-jobsDone // a running job is stopped and recorded first
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		hs.Shutdown(shutdown)
	}()
	log.Printf("dashboard on http://%s (data %s; settings %s: %d node(s), %d DNS peer(s))", *listen, *dataDir,
		settings.Path(*dataDir), len(st.Nodes), len(st.DNSPeers))
	if err := hs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

// primaryHasAPI: a kind of zone primary driven over an API (with a token), not by hand.
func primaryHasAPI(kind string) bool {
	d, _ := primary.Lookup(kind)
	return d.API
}

// loadSettings reads settings.json at startup. A zone primary at a plain http address
// doesn't stop the controller: it starts with that primary paused (never reached, the
// token never sent to it), says so once here, and the address is fixed from the GUI.
func loadSettings(dataDir string, logf func(format string, args ...any)) (settings.Settings, error) {
	st, err := settings.Load(settings.Path(dataDir))
	if err != nil {
		return st, err
	}
	if zp := st.ZonePrimary(); zp.PlainHTTP() {
		logf("warning: zone primary %s: %v: its calls (zone lists, adoption's step 4) are paused until then, the token never sent to it",
			zp.URL, primary.ErrPlainHTTP)
	}
	return st, nil
}
