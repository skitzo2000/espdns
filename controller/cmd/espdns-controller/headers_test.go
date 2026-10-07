package main

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/skitzo2000/espdns/controller/internal/auth"
	"github.com/skitzo2000/espdns/controller/internal/websec"
	"github.com/skitzo2000/espdns/controller/web"
)

// hasSecurityHeaders checks the response to r for every header websec sets, once, with its
// value: the builder page's CSP on the builder page, websec.CSP everywhere else.
func hasSecurityHeaders(t *testing.T, what string, r *http.Request, w *httptest.ResponseRecorder) {
	t.Helper()
	csp := websec.CSP
	if r.URL.Path == "/builder.html" {
		csp = websec.BuilderCSP
	}
	for _, kv := range websec.Set {
		if kv[0] == "Content-Security-Policy" {
			kv[1] = csp
		}
		if got := w.Header().Values(kv[0]); len(got) != 1 || got[0] != kv[1] {
			t.Errorf("%s (%d): %s = %q", what, w.Code, kv[0], got)
		}
	}
}

// The security headers are on every response: every route and every page, logged out and
// logged in, with a password set and without one, and the answers that come from in front
// of the routes (the login's 401, 403, 429 and redirect, LocalOnly's 403, the mux's 404 and
// its redirect to a clean path).
func TestSecurityHeadersEverywhere(t *testing.T) {
	for _, password := range []bool{true, false} {
		h, patterns := testServer(t, password)
		var cookie, tok string
		if password {
			cookie, tok = login(t, h)
		}
		var pages []string
		files, _ := fs.ReadDir(web.Files, ".")
		for _, f := range files {
			if !f.IsDir() {
				pages = append(pages, "GET /"+f.Name())
			}
		}
		codes := map[int]bool{}
		builder := 0
		check := func(what string, r *http.Request) {
			w := serve(h, r)
			codes[w.Code] = true
			if r.URL.Path == "/builder.html" {
				builder++
			}
			hasSecurityHeaders(t, what, r, w)
		}
		for _, p := range append(append([]string{}, patterns...), pages...) {
			what := p
			if !password {
				what += " (no password)"
			}
			// Logged out.
			check(what+" logged out", request(p))
			if !password || p == "POST /api/logout" {
				continue // no session to have (or one the rest still use)
			}
			// Logged in, without the session token, then with it.
			r := request(p)
			r.AddCookie(&http.Cookie{Name: auth.CookieName(r.Host), Value: cookie})
			check(what+" logged in, no session token", r)
			r = request(p)
			r.AddCookie(&http.Cookie{Name: auth.CookieName(r.Host), Value: cookie})
			r.Header.Set(auth.TokenHeader, tok)
			check(what+" logged in", r)
		}
		// Answered in front of the routes.
		odd := map[string]*http.Request{
			"not found":     httptest.NewRequest("GET", "http://127.0.0.1:8480/no-such-page.html", nil),
			"a clean path":  httptest.NewRequest("GET", "http://127.0.0.1:8480/./index.html", nil),
			"not allowed":   httptest.NewRequest("DELETE", "http://127.0.0.1:8480/api/nodes", nil),
			"another Host":  httptest.NewRequest("GET", "http://evil.example:8480/api/nodes", nil),
			"a bad session": httptest.NewRequest("GET", "http://127.0.0.1:8480/index.html", nil),
		}
		odd["a bad session"].AddCookie(&http.Cookie{Name: auth.CookieName(odd["a bad session"].Host), Value: "not-a-session"})
		other := request("POST /api/jobs")
		other.Header.Set("Origin", "http://evil.example")
		odd["another site's Origin"] = other
		wrong := httptest.NewRequest("POST", "http://127.0.0.1:8480/api/login", strings.NewReader(`{"user":"admin","password":"wrong"}`))
		wrong.Header.Set("Content-Type", "application/json")
		odd["a wrong password"] = wrong
		for what, r := range odd {
			check(what, r)
		}
		// The walk met the builder page, logged out (and logged in).
		if builder == 0 {
			t.Errorf("password %v: the walk never asked for /builder.html", password)
		}
		// The walk met the answers it is about.
		want := []int{http.StatusOK, http.StatusForbidden, http.StatusNotFound, http.StatusTemporaryRedirect}
		if password {
			want = []int{http.StatusOK, http.StatusForbidden, http.StatusNotFound, http.StatusMovedPermanently,
				http.StatusUnauthorized, http.StatusSeeOther, http.StatusTooManyRequests}
		}
		for _, c := range want {
			if !codes[c] {
				t.Errorf("password %v: no %d answered in the walk (%v)", password, c, codes)
			}
		}
	}
}
