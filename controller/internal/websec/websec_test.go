package websec

import (
	"crypto/sha256"
	"encoding/base64"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"path"
	"regexp"
	"slices"
	"testing"

	"github.com/skitzo2000/espdns/controller/web"
)

// Exactly these headers, with exactly these values (docs/plan.md, issue #54).
var want = map[string]string{
	"Content-Security-Policy":      "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
	"X-Frame-Options":              "DENY",
	"X-Content-Type-Options":       "nosniff",
	"Referrer-Policy":              "no-referrer",
	"Cross-Origin-Opener-Policy":   "same-origin",
	"Cross-Origin-Resource-Policy": "same-origin",
	"Permissions-Policy":           "serial=(self), usb=(), camera=(), microphone=(), geolocation=()",
}

// The builder page's: the same, and style attributes with exactly the vendored esp-web-tools'
// two values.
const wantBuilderCSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; " +
	"style-src-attr 'unsafe-hashes' 'sha256-w68cv7ZL7DW/1c2v0g4i6aPlMi0iRw663JuMxEmNmU4=' 'sha256-2PZQPqAcY6IE7H879XiZ2Hm3cBUNVB41T1m3kjNvN6E='"

func TestSet(t *testing.T) {
	if len(Set) != len(want) {
		t.Fatalf("%d headers, want %d", len(Set), len(want))
	}
	for _, kv := range Set {
		if want[kv[0]] != kv[1] {
			t.Errorf("%s: %q, want %q", kv[0], kv[1], want[kv[0]])
		}
	}
}

// Every response gets them: a page, an error, a redirect, a not-found, one that wrote nothing.
func TestHeaders(t *testing.T) {
	handlers := map[string]http.HandlerFunc{
		"ok":       func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("<!doctype html>")) },
		"error":    func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no", http.StatusUnauthorized) },
		"redirect": func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/login.html", http.StatusSeeOther) },
		"notfound": http.NotFound,
		"nothing":  func(w http.ResponseWriter, r *http.Request) {},
	}
	paths := map[string]string{
		"/":                 want["Content-Security-Policy"],
		"/index.html":       want["Content-Security-Policy"],
		"/login.html":       want["Content-Security-Policy"],
		"/builder.html":     wantBuilderCSP,
		"/builder.html?x=1": wantBuilderCSP,
		"/builder.js":       want["Content-Security-Policy"],
		"/builder.html/":    want["Content-Security-Policy"],
		"/vendor/esp-web-tools/install-button.js": want["Content-Security-Policy"],
		"/api/build": want["Content-Security-Policy"],
	}
	for name, h := range handlers {
		for p, csp := range paths {
			w := httptest.NewRecorder()
			Headers(h).ServeHTTP(w, httptest.NewRequest("GET", "http://127.0.0.1:8480"+p, nil))
			for k, v := range want {
				if k == "Content-Security-Policy" {
					v = csp
				}
				if got := w.Header().Values(k); len(got) != 1 || got[0] != v {
					t.Errorf("%s %s: %s = %q", name, p, k, got)
				}
			}
		}
	}
}

func TestCSPFor(t *testing.T) {
	if got := CSPFor("/builder.html"); got != wantBuilderCSP {
		t.Errorf("builder: %q", got)
	}
	for _, p := range []string{"/", "/index.html", "/Builder.html", "/builder", "/x/builder.html"} {
		if got := CSPFor(p); got != want["Content-Security-Policy"] {
			t.Errorf("%s: %q", p, got)
		}
	}
}

// BuilderStyleHashes are the hashes of exactly the static style attributes the embedded
// esp-web-tools has, recomputed from its files: an update that changes, adds or drops one
// fails here, and BuilderStyleHashes (and the README) are updated with it.
func TestBuilderStyleHashes(t *testing.T) {
	attr := regexp.MustCompile(`\bstyle="([^"]*)"`)
	const dir = "vendor/esp-web-tools"
	files, err := fs.ReadDir(web.Files, dir)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range files {
		b, err := fs.ReadFile(web.Files, path.Join(dir, f.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range attr.FindAllSubmatch(b, -1) {
			sum := sha256.Sum256(m[1])
			h := "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
			t.Logf("%s: style=%q: %s", f.Name(), m[1], h)
			if !slices.Contains(got, h) {
				got = append(got, h)
			}
		}
	}
	want := slices.Clone(BuilderStyleHashes)
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("the vendored esp-web-tools' style attributes hash to %q, BuilderStyleHashes is %q", got, want)
	}
	if len(want) != 2 {
		t.Errorf("%d hashes, want the dialog's 2", len(want))
	}
}
