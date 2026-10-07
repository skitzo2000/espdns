package web

import (
	"io/fs"
	"path"
	"regexp"
	"strings"
	"testing"
)

// What the Content-Security-Policy (script-src 'self', style-src 'self', no 'unsafe-inline')
// would refuse, in a page or in markup a script writes: an inline <script> or <style>, an
// on*= handler, a style= attribute, a javascript: URL. Styles a script sets through the
// CSSOM (el.style.width = ...) and handlers it adds as functions (addEventListener, .onclick
// = ...) are allowed, and not matched.
var inlineChecks = []struct {
	what string
	re   *regexp.Regexp
	in   []string // the file extensions it applies to
}{
	{"an inline <script>", regexp.MustCompile(`(?i)<script\b[^>]*>`), []string{".html", ".js"}},
	{"a <style> element", regexp.MustCompile(`(?i)<style\b`), []string{".html", ".js"}},
	{"an on*= handler attribute", regexp.MustCompile(`(?i)<[a-z][^>]*\son[a-z]+\s*=`), []string{".html"}},
	{"an on*= handler in markup", regexp.MustCompile(`(?i)\bon[a-z]+\s*=\s*\\?["']`), []string{".js"}},
	{"an on*= handler set as an attribute", regexp.MustCompile(`(?i)setAttribute(NS)?\(\s*(null\s*,\s*)?["'\x60]on`), []string{".js"}},
	{"a style= attribute", regexp.MustCompile(`(?i)<[a-z][^>]*\sstyle\s*=`), []string{".html"}},
	{"a style= attribute in markup", regexp.MustCompile(`(?i)\bstyle\s*=\s*\\?["']`), []string{".js"}},
	{"a style attribute set as one", regexp.MustCompile(`(?i)setAttribute(NS)?\(\s*(null\s*,\s*)?["'\x60]style["'\x60]|\.style\.cssText\b`), []string{".js"}},
	{"a javascript: URL", regexp.MustCompile(`(?i)javascript\s*:`), []string{".html", ".js", ".css"}},
}

// srcScript is a <script> that loads a file, the one kind a page may have.
var srcScript = regexp.MustCompile(`(?i)<script\b[^>]*\ssrc\s*=\s*"[^"]+"[^>]*>\s*</script>`)

// inlineProblems lists what the CSP would refuse in one first-party file.
func inlineProblems(name, text string) []string {
	ext := path.Ext(name)
	if ext == ".html" {
		text = srcScript.ReplaceAllString(text, "")
	}
	var out []string
	for _, c := range inlineChecks {
		for _, e := range c.in {
			if e != ext {
				continue
			}
			for _, m := range c.re.FindAllString(text, -1) {
				out = append(out, c.what+": "+strings.TrimSpace(m))
			}
		}
	}
	return out
}

// No first-party page, script or style has code or styles inline: the CSP's script-src
// 'self' and style-src 'self' would refuse them (internal/websec). Third-party code under
// vendor/ is not ours to change, and is checked by its own tests.
func TestNoInlineCode(t *testing.T) {
	checked := 0
	err := fs.WalkDir(Files, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name == "vendor" {
				return fs.SkipDir
			}
			return nil
		}
		switch path.Ext(name) {
		case ".html", ".js", ".css":
		default:
			return nil
		}
		b, err := fs.ReadFile(Files, name)
		if err != nil {
			return err
		}
		checked++
		for _, p := range inlineProblems(name, string(b)) {
			t.Errorf("%s: %s", name, p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked < 20 {
		t.Fatalf("only %d files checked", checked)
	}
}

// The checks catch what they are for, and pass what is allowed.
func TestInlineChecks(t *testing.T) {
	bad := map[string]string{
		"a.html": `<script>alert(1)</script>`,
		"b.html": `<script type="module">import "./x.js";</script>`,
		"c.html": `<button onclick="go()">Go</button>`,
		"d.html": "<body\n  onload='x()'>",
		"e.html": `<div style="color:red">`,
		"f.html": `<a href="javascript:void(0)">x</a>`,
		"g.html": `<style>p{}</style>`,
		"h.html": `<script src="x.js">alert(1)</script>`,
		"a.js":   `box.innerHTML = '<img src=x onerror="go()">';`,
		"b.js":   "box.innerHTML = `<div style=\"color:red\">`;",
		"c.js":   `el.setAttribute("onclick", "go()");`,
		"d.js":   `el.setAttribute('style', 'color:red');`,
		"e.js":   `el.style.cssText = "color:red";`,
		"f.js":   `a.href = "javascript:go()";`,
		"g.js":   `box.innerHTML = "<script>go()</script>";`,
		"a.css":  `p { background: url("javascript:go()"); }`,
	}
	for name, text := range bad {
		if len(inlineProblems(name, text)) == 0 {
			t.Errorf("%s: %q passed", name, text)
		}
	}
	good := map[string]string{
		"a.html": `<script type="module" src="builder.js"></script><link rel="icon" href="data:,">`,
		"b.html": `<label data-for="emac w5500" class="check"><input name="eth_optional" type="checkbox"> An add-on</label>`,
		"a.js":   `tr.style.cursor = "pointer"; tr.onclick = () => showJob(j); b.addEventListener("click", go);`,
		"b.js":   `f.style.width = ` + "`${pct}%`" + `; el.setAttribute("aria-label", "x"); const online = 1; const stylesheet = 2;`,
		"a.css":  `.on { color: red; }`,
	}
	for name, text := range good {
		if p := inlineProblems(name, text); len(p) != 0 {
			t.Errorf("%s: %q: %v", name, text, p)
		}
	}
}
