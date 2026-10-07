// Package websec is the security headers every response of the controller carries: a
// Content-Security-Policy that lets a page run only the controller's own scripts and styles
// (no inline code, no other origin; the vendored esp-web-tools is the controller's own) and
// connect only to the controller, and headers that keep other sites from framing a page,
// reading a response or learning where a page was.
package websec

import (
	"net/http"
	"strings"
)

// CSP is the Content-Security-Policy. img-src allows data: for the pages' favicons.
const CSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
	"connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

// BuilderPage is the one page whose CSP is BuilderCSP.
const BuilderPage = "/builder.html"

// BuilderStyleHashes are the SHA-256 hashes (base64) of the only inline style attributes the
// vendored esp-web-tools has, both in its "no port picked" dialog (shown when the port
// picker is cancelled): style="width: 28px; vertical-align: middle;" on an icon's svg and
// style="fill:currentColor;" on its path. The vendored files stay as the registry ships them
// (SHA256SUMS); websec_test.go recomputes these from the embedded copy, so an update of
// esp-web-tools that changes them fails there.
var BuilderStyleHashes = []string{
	"sha256-w68cv7ZL7DW/1c2v0g4i6aPlMi0iRw663JuMxEmNmU4=", // width: 28px; vertical-align: middle;
	"sha256-2PZQPqAcY6IE7H879XiZ2Hm3cBUNVB41T1m3kjNvN6E=", // fill:currentColor;
}

// BuilderCSP is CSP plus, for style attributes only, exactly those two values: no other
// inline style, no inline script, on the builder page and nowhere else.
var BuilderCSP = CSP + "; style-src-attr 'unsafe-hashes' '" + strings.Join(BuilderStyleHashes, "' '") + "'"

// CSPFor is the Content-Security-Policy of a response to a request for path:
// BuilderCSP for BuilderPage, CSP for everything else.
func CSPFor(path string) string {
	if path == BuilderPage {
		return BuilderCSP
	}
	return CSP
}

// Set is every header Headers sets, with its value, in the order set; the
// Content-Security-Policy is CSPFor's for the request's path.
var Set = [][2]string{
	{"Content-Security-Policy", CSP},
	{"X-Frame-Options", "DENY"},
	{"X-Content-Type-Options", "nosniff"},
	{"Referrer-Policy", "no-referrer"},
	{"Cross-Origin-Opener-Policy", "same-origin"},
	{"Cross-Origin-Resource-Policy", "same-origin"},
	// Web Serial for the builder's flasher and Improv, from this origin only; nothing else.
	{"Permissions-Policy", "serial=(self), usb=(), camera=(), microphone=(), geolocation=()"},
}

// Headers sets the headers on every response, before next runs: outermost, so a refusal,
// a redirect or a not-found from anything inside it carries them too.
func Headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		for _, kv := range Set {
			h.Set(kv[0], kv[1])
		}
		h.Set("Content-Security-Policy", CSPFor(r.URL.Path))
		next.ServeHTTP(w, r)
	})
}
