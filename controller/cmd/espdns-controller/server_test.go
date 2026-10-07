package main

import (
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/skitzo2000/espdns/controller/internal/auth"
	"github.com/skitzo2000/espdns/controller/internal/fleet"
	"github.com/skitzo2000/espdns/controller/internal/jobs"
	"github.com/skitzo2000/espdns/controller/internal/keys"
	"github.com/skitzo2000/espdns/controller/internal/nodes"
	"github.com/skitzo2000/espdns/controller/web"
)

func init() { auth.DefaultParams = auth.Params{Time: 1, MemoryKiB: 64, Threads: 1} }

const testPassword = "a test password"

func testServer(t *testing.T, password bool, opts ...func(*server)) (http.Handler, []string) {
	dir := t.TempDir()
	if password {
		if err := auth.SetPassword(auth.Path(dir), "admin", testPassword); err != nil {
			t.Fatal(err)
		}
	}
	s := &server{dataDir: dir, nodes: func() []nodes.Node { return nil }, auth: auth.New(auth.Path(dir)),
		runner:  jobs.New(dir, map[string]jobs.Kind{}),
		key:     keys.FileSource{Path: keys.Path(dir)},
		builder: newBuilder(t.TempDir(), t.TempDir(), t.TempDir())}
	s.push = pushKind{actions: actions{dataDir: dir, key: s.key, known: func() []string { return nil },
		client: func() *fleet.Client { return &fleet.Client{} }}, secret: newSecret(), nodes: s.nodes,
		job: func(string) (jobs.Job, bool) { return jobs.Job{}, false }}
	s.adopt = adoptKind{actions: s.push.actions, secret: newSecret(), nodes: s.nodes, used: &usedRuns{},
		token: keys.TokenFileSource{Path: keys.TokenPath(dir)}, job: func(string) (jobs.Job, bool) { return jobs.Job{}, false }}
	for _, o := range opts {
		o(s)
	}
	return s.handler()
}

// request is a request for a route pattern ("POST /api/jobs/{id}/stop"), from the page.
func request(pattern string) *http.Request {
	method, path, _ := strings.Cut(pattern, " ")
	path = strings.ReplaceAll(strings.ReplaceAll(path, "{id}", "x"), "{name}", "x.json")
	r := httptest.NewRequest(method, "http://127.0.0.1:8480"+path, strings.NewReader("{}"))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "http://127.0.0.1:8480")
	return r
}

func serve(h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// refusedByLogin says whether the login answered the request instead of the route.
func refusedByLogin(w *httptest.ResponseRecorder) bool {
	return w.Code == http.StatusUnauthorized || w.Code == http.StatusSeeOther && strings.Contains(w.Header().Get("Location"), "login.html") ||
		w.Code == http.StatusForbidden && strings.Contains(w.Body.String(), "read-only")
}

// refusedForReauth says whether the request was refused for want of the password again.
func refusedForReauth(w *httptest.ResponseRecorder) bool {
	return w.Code == http.StatusForbidden && strings.Contains(w.Body.String(), `"reauth":true`)
}

// withSession puts a session on a request: its cookie, and the page's token unless "".
func withSession(r *http.Request, cookie, tok string) *http.Request {
	r.AddCookie(&http.Cookie{Name: auth.CookieName(r.Host), Value: cookie})
	if tok != "" {
		r.Header.Set(auth.TokenHeader, tok)
	}
	return r
}

// reauth asks for the password again in a session: the grant.
func reauth(t *testing.T, h http.Handler, cookie, tok string) string {
	t.Helper()
	r := withSession(request("POST /api/reauth"), cookie, tok)
	r.Body = io.NopCloser(strings.NewReader(`{"password":"` + testPassword + `"}`))
	w := serve(h, r)
	var g struct{ Reauth string }
	if json.Unmarshal(w.Body.Bytes(), &g); w.Code != http.StatusOK || g.Reauth == "" {
		t.Fatalf("reauth: %d %s", w.Code, w.Body)
	}
	return g.Reauth
}

func login(t *testing.T, h http.Handler) (cookie, tok string) {
	r := httptest.NewRequest("POST", "http://127.0.0.1:8480/api/login", strings.NewReader(`{"user":"admin","password":"`+testPassword+`"}`))
	r.Header.Set("Content-Type", "application/json")
	w := serve(h, r)
	if w.Code != http.StatusOK {
		t.Fatalf("login: %d %s", w.Code, w.Body)
	}
	var reply struct{ Token string }
	json.Unmarshal(w.Body.Bytes(), &reply)
	for _, c := range w.Result().Cookies() {
		if c.Name == auth.CookieName(r.Host) {
			return c.Value, reply.Token
		}
	}
	t.Fatal("no cookie")
	return "", ""
}

// needReauth are the routes that need the password again (internal/auth, Reauthed): a
// backup holds the release key and the Wi-Fi passwords.
var needReauth = map[string]bool{"POST /api/backup": true}

// Every route the controller has, walked: without a session each is refused but the
// login's own; with the cookie alone each is refused but the pages' (none is under /api/);
// with the cookie and the page's token each is let through, those in needReauth only with
// a grant. A route added later is in the walk without a change here.
func TestEveryRouteNeedsLogin(t *testing.T) {
	h, patterns := testServer(t, true)
	if len(patterns) < 15 {
		t.Fatalf("only %d routes recorded: %v", len(patterns), patterns)
	}
	// The first run's password is open too: once a password is set it refuses (409).
	public := map[string]bool{"GET /api/session": true, "POST /api/login": true, "POST /api/setup/password": true}
	cookie, tok := login(t, h)
	for _, p := range patterns {
		// No session.
		w := serve(h, request(p))
		if public[p] {
			if refusedByLogin(w) && p != "POST /api/login" { // the login's 401 is a wrong password
				t.Errorf("%s: public, refused: %d %s", p, w.Code, w.Body)
			}
			continue
		} else if !refusedByLogin(w) {
			t.Errorf("%s without a session: %d %s", p, w.Code, w.Body)
		}
		// The cookie alone: what another port of this host may have taken.
		cookieOnly := strings.HasPrefix(p, "GET ") && !strings.HasPrefix(p, "GET /api/") // the pages, /build/
		if w := serve(h, withSession(request(p), cookie, "")); !cookieOnly && w.Code != http.StatusUnauthorized {
			t.Errorf("%s with the cookie alone: %d %s", p, w.Code, w.Body)
		}
		// A session.
		if p == "POST /api/logout" {
			continue // would end the session the rest use
		}
		w = serve(h, withSession(request(p), cookie, tok))
		if refusedByLogin(w) {
			t.Errorf("%s with a session: %d %s", p, w.Code, w.Body)
		}
		if p != "POST /api/reauth" && refusedForReauth(w) != needReauth[p] { // its own: "{}" is a wrong password
			t.Errorf("%s with a session, no grant: %d %s", p, w.Code, w.Body)
		}
		if needReauth[p] {
			r := withSession(request(p), cookie, tok)
			r.Header.Set(auth.ReauthHeader, reauth(t, h, cookie, tok))
			if w := serve(h, r); refusedByLogin(w) || refusedForReauth(w) {
				t.Errorf("%s with a grant: %d %s", p, w.Code, w.Body)
			}
		}
	}

	// The pages: each needs a session but the login page; scripts and styles are open.
	files, _ := fs.ReadDir(web.Files, ".")
	for _, f := range files {
		name := f.Name()
		w := serve(h, request("GET /"+name))
		switch {
		case name == "login.html" || strings.HasSuffix(name, ".js") || strings.HasSuffix(name, ".css"):
			if w.Code != http.StatusOK {
				t.Errorf("%s logged out: %d", name, w.Code)
			}
		case strings.HasSuffix(name, ".html"):
			if w.Code != http.StatusSeeOther {
				t.Errorf("%s logged out: %d", name, w.Code)
			}
		}
	}
	// The builder's vendored flasher is a script like the others, served from here.
	if w := serve(h, request("GET /vendor/esp-web-tools/install-button.js")); w.Code != http.StatusOK ||
		!strings.Contains(w.Header().Get("Content-Type"), "javascript") {
		t.Errorf("the vendored esp-web-tools logged out: %d %q", w.Code, w.Header().Get("Content-Type"))
	}

	// LocalOnly is still in front: another Host, or another site's Origin, is refused even
	// with a session.
	r := request("GET /api/nodes")
	r.Host = "evil.example:8480"
	withSession(r, cookie, tok)
	if w := serve(h, r); w.Code != http.StatusForbidden {
		t.Errorf("rebound Host: %d", w.Code)
	}
	r = request("POST /api/jobs")
	r.Header.Set("Origin", "http://evil.example")
	withSession(r, cookie, tok)
	if w := serve(h, r); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "Origin") {
		t.Errorf("another site's Origin: %d %s", w.Code, w.Body)
	}
}

// Before a password is set: every GET open (read-only, as before the login) but the node
// configs' (they can hold a Wi-Fi password), the hosted zones', the zone inventory and its
// lookup (which queries the primaries), the list definitions' and
// source files' (a feed's URL can hold its key), the Push page's, the Adopt page's, the
// zone primary's lists (read with the token) and its certificate, the Backup page's, the query log's (who asked
// for what), the pending changes' (a config change holds the Wi-Fi password), a node's
// settings (from its config) and Add node's found nodes (as the Adopt page's), every change
// refused, saying how to set one.
func TestNoPasswordReadOnly(t *testing.T) {
	h, patterns := testServer(t, false)
	for _, p := range patterns {
		w := serve(h, request(p))
		switch {
		case strings.HasPrefix(p, "GET /api/configs"), strings.HasPrefix(p, "GET /api/zones"), strings.HasPrefix(p, "GET /api/zone-"), strings.HasPrefix(p, "GET /api/push/"), strings.HasPrefix(p, "GET /api/blocking/"), p == "GET /api/adopt",
			p == "GET /api/primary", p == "GET /api/primary/certificate", p == "GET /api/backup", strings.HasPrefix(p, "GET /api/querylog"), strings.HasPrefix(p, "GET /api/changes"),
			p == "GET /api/nodes/{id}/settings", p == "GET /api/search", p == "GET /api/nodes/found":
			if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "passwd") {
				t.Errorf("%s: %d %s", p, w.Code, w.Body)
			}
		case strings.HasPrefix(p, "GET "):
			if refusedByLogin(w) {
				t.Errorf("%s: %d %s", p, w.Code, w.Body)
			}
		case p == "POST /api/login":
			if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "passwd") {
				t.Errorf("%s: %d %s", p, w.Code, w.Body)
			}
		case p == "POST /api/setup/password": // the first run's (setup_test.go); request() comes from 192.0.2.1, not this machine
			if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "own machine") {
				t.Errorf("%s: %d %s", p, w.Code, w.Body)
			}
		default:
			if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "passwd") {
				t.Errorf("%s: %d %s", p, w.Code, w.Body)
			}
		}
	}
	var key map[string]any
	w := serve(h, request("GET /api/key"))
	json.Unmarshal(w.Body.Bytes(), &key)
	if key["present"] != false || key["missing"] != true {
		t.Errorf("/api/key without a key: %v", key)
	}
}

func TestLoopbackListen(t *testing.T) {
	for addr, ok := range map[string]bool{"127.0.0.1:8480": true, "[::1]:8480": true, "localhost:1": true,
		"0.0.0.0:8480": false, ":8480": false, "192.0.2.10:8480": false, "x": false} {
		if loopbackListen(addr) != ok {
			t.Errorf("%s: want %v", addr, ok)
		}
	}
}

// Odd spellings of the API's paths and of the pages, by every method, without a session:
// none reaches a route. Each is refused, not found, not allowed, or redirected to its clean
// path, which is refused in turn.
func TestOddPathsNeedLogin(t *testing.T) {
	h, _ := testServer(t, true)
	paths := []string{"/api/nodes/", "/api//nodes", "//api/nodes", "/./api/nodes", "/x/../api/nodes", "/api/nodes.js",
		"/api%2fnodes", "/api%2Fnodes.js", "/%2e/api/nodes", "/%2e/api/nodes.js", "/./api/nodes.js", "/x/..%2fapi%2fnodes.js",
		"/api/jobs/x.js", "/build/x.js", "/build/x/image.bin", "/build/x/manifest.json", "/x.js/../api/nodes",
		"/..%2fapi%2fnodes.js", "/index.html.js", "/./index.html", "/index.html/", "/login.html/../index.html",
		"/api/jobs/x/events", "/api/key", "/api/actions", "/.%2fapi/actions.css", "/api/../api/key.js", "//api/key.js",
		"/a/..//api/key.js", "/jobs.html", "/%61pi/key.js", "/api/key%00.js", "/api/key;.js", "/API/key", "/api/KEY"}
	for _, m := range []string{"GET", "HEAD", "OPTIONS", "POST", "PUT", "DELETE", "PATCH"} {
		for _, p := range paths {
			r := httptest.NewRequest(m, "http://127.0.0.1:8480"+p, strings.NewReader("{}"))
			r.Header.Set("Content-Type", "application/json")
			w := serve(h, r)
			for hops := 0; w.Code == http.StatusMovedPermanently || w.Code == http.StatusTemporaryRedirect ||
				w.Code == http.StatusPermanentRedirect; hops++ {
				if hops > 3 {
					t.Fatalf("%s %s: redirect loop", m, p)
				}
				loc := w.Header().Get("Location")
				r = httptest.NewRequest(m, "http://127.0.0.1:8480"+loc, strings.NewReader("{}"))
				r.Header.Set("Content-Type", "application/json")
				w = serve(h, r)
			}
			switch {
			case refusedByLogin(w), w.Code == http.StatusNotFound, w.Code == http.StatusMethodNotAllowed:
			default:
				t.Errorf("%s %s without a session: %d %.80q", m, p, w.Code, w.Body.String())
			}
		}
	}
}
