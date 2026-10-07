package web

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"path"
	"regexp"
	"strings"
	"testing"
)

const ewt = "vendor/esp-web-tools"

// SHA256SUMS lists every embedded file of the vendored esp-web-tools, and each one's bytes
// are the ones it lists: nothing was edited, added or left out since `make vendor-ewt`.
func TestVendorSums(t *testing.T) {
	sums, err := fs.ReadFile(Files, ewt+"/SHA256SUMS")
	if err != nil {
		t.Fatal(err)
	}
	listed := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(sums)), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			t.Fatalf("SHA256SUMS line %q", line)
		}
		want, name := f[0], f[1]
		listed[name] = true
		b, err := fs.ReadFile(Files, ewt+"/"+name)
		if err != nil {
			t.Errorf("%s: listed, not embedded: %v", name, err)
			continue
		}
		if got := sha256.Sum256(b); hex.EncodeToString(got[:]) != want {
			t.Errorf("%s: sha256 %x, SHA256SUMS says %s", name, got, want)
		}
	}
	entries, err := fs.ReadDir(Files, ewt)
	if err != nil {
		t.Fatal(err)
	}
	scripts := 0
	for _, e := range entries {
		switch name := e.Name(); {
		case e.IsDir():
			t.Errorf("%s: a directory in %s", name, ewt)
		case name == "SHA256SUMS":
		case !listed[name]:
			t.Errorf("%s: embedded, not in SHA256SUMS", name)
		case strings.HasSuffix(name, ".js"):
			scripts++
		}
	}
	for _, name := range []string{"install-button.js", "LICENSE", "THIRD_PARTY.md", "VERSION"} {
		if !listed[name] {
			t.Errorf("%s: missing", name)
		}
	}
	if scripts < 2 {
		t.Errorf("%d scripts", scripts)
	}
}

// The module specifiers in a script: import ... from "x", import "x", import("x"), export
// ... from "x". Minified (from"x") or not.
var importSpec = regexp.MustCompile(`(?:\bfrom|\bimport)\s*\(?\s*["'` + "`" + `]([^"'` + "`" + `]+)["'` + "`" + `]`)

// Every import in the vendored chunks is relative and names an embedded file: the whole
// chunk graph (the install dialog, the chips' and stub flashers' chunks, loaded on demand)
// is served from here, with nothing from another origin.
func TestVendorImports(t *testing.T) {
	entries, err := fs.ReadDir(Files, ewt)
	if err != nil {
		t.Fatal(err)
	}
	imports := 0
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".js") {
			continue
		}
		b, err := fs.ReadFile(Files, ewt+"/"+e.Name())
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range importSpec.FindAllStringSubmatch(string(b), -1) {
			spec := m[1]
			imports++
			if !strings.HasPrefix(spec, "./") && !strings.HasPrefix(spec, "../") {
				t.Errorf("%s imports %q: not relative", e.Name(), spec)
				continue
			}
			if _, err := fs.Stat(Files, path.Join(ewt, spec)); err != nil {
				t.Errorf("%s imports %q: not embedded", e.Name(), spec)
			}
		}
	}
	if imports == 0 {
		t.Error("no imports found: the pattern no longer matches the bundle")
	}
}

// A URL that names another origin: absolute (scheme://) or protocol-relative ("//host",
// after a quote, "(", "=", "," or a space). Any of them in a first-party page, script or style
// fails the test, whatever loads it (src, srcset, href, action, import, fetch, a Worker, a
// WebSocket, an EventSource, a meta refresh, CSS url() or @import...): listing the ways to
// load is never complete, so the URL itself is what is refused. Comments are skipped (a
// whole-line // comment, /* */ and <!-- -->), and so are XML namespace names, which are
// identifiers, never fetched.
var (
	otherOrigin    = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://[^\s"'` + "`" + `)]*|["'` + "`" + `(=,\s]//[a-z0-9\[$][^\s"'` + "`" + `)]*`)
	blockComment   = regexp.MustCompile(`(?s)/\*.*?\*/|<!--.*?-->`)
	lineComment    = regexp.MustCompile(`^\s*//`)
	xmlNamespaceOK = regexp.MustCompile(`^http://www\.w3\.org/`)
)

// otherOrigins returns the lines of src (1-based) that name another origin.
func otherOrigins(src string) map[int]string {
	// Blank out the block comments, keeping their newlines so line numbers stay right
	src = blockComment.ReplaceAllStringFunc(src, func(c string) string {
		return strings.Repeat("\n", strings.Count(c, "\n"))
	})
	found := map[int]string{}
	for i, line := range strings.Split(src, "\n") {
		if lineComment.MatchString(line) {
			continue
		}
		for _, m := range otherOrigin.FindAllString(line, -1) {
			if !xmlNamespaceOK.MatchString(m) {
				found[i+1] = strings.TrimSpace(line)
			}
		}
	}
	return found
}

func TestOtherOriginPattern(t *testing.T) {
	for _, s := range []string{
		`<script type="module" src="https://unpkg.com/esp-web-tools@10/dist/web/install-button.js?module"></script>`,
		`<link rel="stylesheet" href="//cdn.example.com/x.css">`,
		`<img src=http://example.com/a.png>`,
		`<img srcset="a.png 1x, https://example.com/b.png 2x">`,
		`<img srcset="a.png 1x,//example.com/b.png 2x">`,
		`<form action="https://example.com/">`,
		`<meta http-equiv="refresh" content="0; url=https://example.com/">`,
		`import {x} from "https://example.com/m.js";`,
		`import"https://example.com/m.js"`,
		`await import('https://example.com/m.js')`,
		"fetch(`https://example.com/api`)",
		"fetch(`//${host}/api`)",
		`new WebSocket("wss://example.com/ws")`,
		`new Worker("https://example.com/w.js")`,
		`new EventSource("//example.com/events")`,
		`@import url("https://fonts.example.com/css");`,
		`@import "https://example.com/a.css";`,
		`background: url(//example.com/bg.png)`,
		`x(); // a trailing comment is code's line: https://example.com/`,
		"/* a comment */ fetch(\"https://example.com/\")",
		`const NS = "http://www.w3.org/2000/svg", API = "https://example.com/";`,
	} {
		if len(otherOrigins(s)) == 0 {
			t.Errorf("not caught: %s", s)
		}
	}
	for _, s := range []string{
		`<script type="module" src="vendor/esp-web-tools/install-button.js"></script>`,
		`<link rel="icon" href="data:,">`,
		`import { api } from "./common.js";`,
		`fetch("/api/nodes")`,
		`const p = s.split("//");`,
		`const SVG = "http://www.w3.org/2000/svg";`,
		`// Improv Wi-Fi over Web Serial (https://www.improv-wifi.com/serial/)`,
		"/* see\n * https://example.com/\n */",
		"<!-- https://example.com/ -->",
	} {
		if got := otherOrigins(s); len(got) != 0 {
			t.Errorf("caught: %s (%v)", s, got)
		}
	}
}

// No first-party page, script or style names another origin, so none loads anything from
// one: what the controller's pages run is what it serves.
func TestNoOtherOrigin(t *testing.T) {
	entries, err := fs.ReadDir(Files, ".")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, e := range entries {
		if e.IsDir() {
			continue // vendor/: third-party, checked by TestVendorImports
		}
		b, err := fs.ReadFile(Files, e.Name())
		if err != nil {
			t.Fatal(err)
		}
		checked++
		for n, line := range otherOrigins(string(b)) {
			t.Errorf("%s:%d names another origin: %s", e.Name(), n, line)
		}
	}
	if checked == 0 {
		t.Error("no files checked")
	}
}
