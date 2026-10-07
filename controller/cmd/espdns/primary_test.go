package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skitzo2000/espdns/controller/internal/keys"
	"github.com/skitzo2000/espdns/controller/internal/primary"
	"github.com/skitzo2000/espdns/controller/internal/settings"
)

// withStdin runs f with s on standard input, piped.
func withStdin(t *testing.T, s string, f func() error) error {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = old })
	go func() { w.WriteString(s); w.Close() }()
	defer r.Close()
	return f()
}

// espdns primary import: the token from standard input (as a password manager gives it, with a
// line break) into the data directory, 0600; the same again changes nothing, another only
// with -replace; status reads it back. No error says the token.
func TestPrimaryImport(t *testing.T) {
	data := t.TempDir()
	if err := withStdin(t, techToken+"\n", func() error { return cmdPrimary("primary", []string{"import", "-data", data}) }); err != nil {
		t.Fatal(err)
	}
	if got, err := (keys.TokenFileSource{Path: keys.TokenPath(data)}).Token(); got != techToken || err != nil {
		t.Fatal(got, err)
	}
	if err := cmdPrimary("primary", []string{"status", "-data", data}); err != nil {
		t.Fatal(err)
	}
	if err := withStdin(t, techToken, func() error { return cmdPrimary("primary", []string{"import", "-data", data}) }); err != nil {
		t.Fatal(err)
	}
	const other = "another-token-0123456789"
	err := withStdin(t, other, func() error { return cmdPrimary("primary", []string{"import", "-data", data}) })
	if err == nil || strings.Contains(err.Error(), other) || strings.Contains(err.Error(), techToken) {
		t.Fatal(err)
	}
	if err := withStdin(t, other, func() error { return cmdPrimary("primary", []string{"import", "-data", data, "-replace"}) }); err != nil {
		t.Fatal(err)
	}
	err = withStdin(t, "two words here", func() error { return cmdPrimary("primary", []string{"import", "-data", data}) })
	if err == nil || strings.Contains(err.Error(), "two words") {
		t.Fatal(err)
	}
	if err := cmdPrimary("primary", []string{"status", "-data", t.TempDir()}); err == nil || !strings.Contains(err.Error(), "espdns primary import") {
		t.Fatal(err)
	}
}

// A keys/technitium.token (the token's name before the zone primary was generic) is not
// read: status says to import one; import writes keys/primary.token.
func TestOldTokenFileNotRead(t *testing.T) {
	data := t.TempDir()
	if _, err := keys.ImportToken(filepath.Join(data, keys.Dir, "technitium.token"), techToken, false); err != nil {
		t.Fatal(err)
	}
	if err := cmdPrimary("primary", []string{"status", "-data", data}); err == nil || !strings.Contains(err.Error(), "espdns primary import") {
		t.Fatal(err)
	}
	if err := withStdin(t, "another-token-0123456789", func() error {
		return cmdPrimary("primary", []string{"import", "-data", data})
	}); err != nil {
		t.Fatal(err)
	}
	if got, err := (keys.DataTokenSource{DataDir: data}).Token(); got != "another-token-0123456789" || err != nil {
		t.Fatal(got, err)
	}
}

// espdns primary cert, pin and unpin against a primary over https with its own
// certificate: cert shows its fingerprint and how to pin it; a fingerprint it doesn't
// present isn't pinned; the one shown is; cert then says so; unpin takes it away. No
// primary over an API in settings.json: said so.
func TestPrimaryCertPin(t *testing.T) {
	data := t.TempDir()
	var buf strings.Builder
	if err := cmdPrimaryCert("primary", "cert", []string{"-data", data}, &buf); err == nil || !strings.Contains(err.Error(), "no zone primary") {
		t.Fatal("no primary:", err)
	}
	ts := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(ts.Close)
	fp := primary.Fingerprint(ts.Certificate())
	if err := settings.Save(settings.Path(data), settings.Settings{Primary: &primary.Config{Kind: primary.KindTechnitium, URL: ts.URL}}); err != nil {
		t.Fatal(err)
	}
	if err := cmdPrimaryCert("primary", "cert", []string{"-data", data}, &buf); err != nil ||
		!strings.Contains(buf.String(), "SHA-256   "+fp) || !strings.Contains(buf.String(), "not trusted") ||
		!strings.Contains(buf.String(), "pin -data "+data+" -sha256 "+fp) {
		t.Fatalf("cert: %v\n%s", err, buf.String())
	}
	if err := cmdPrimaryCert("primary", "pin", []string{"-data", data, "-sha256", strings.Repeat("1", 64)}, &buf); err == nil ||
		!strings.Contains(err.Error(), "now presents SHA-256 "+fp) {
		t.Fatal("another fingerprint:", err)
	}
	if err := cmdPrimaryCert("primary", "pin", []string{"-data", data, "-sha256", "x"}, &buf); err == nil {
		t.Fatal("a garbled fingerprint taken")
	}
	if s, _ := settings.Load(settings.Path(data)); s.ZonePrimary().CertSHA256 != "" {
		t.Fatal("pinned on a refusal")
	}
	if err := cmdPrimaryCert("primary", "pin", []string{"-data", data, "-sha256", strings.ToUpper(fp)}, &buf); err != nil {
		t.Fatal(err)
	}
	if s, _ := settings.Load(settings.Path(data)); s.ZonePrimary().CertSHA256 != fp {
		t.Fatal("not pinned:", s.ZonePrimary())
	}
	buf.Reset()
	if err := cmdPrimaryCert("primary", "cert", []string{"-data", data}, &buf); err != nil || !strings.Contains(buf.String(), "pinned: this certificate") {
		t.Fatalf("pinned: %v\n%s", err, buf.String())
	}
	if err := cmdPrimaryCert("primary", "unpin", []string{"-data", data}, &buf); err != nil {
		t.Fatal(err)
	}
	if s, _ := settings.Load(settings.Path(data)); s.ZonePrimary().CertSHA256 != "" {
		t.Fatal("still pinned")
	}
}

// status, with the zone primary at a plain http address in settings.json: paused, the one
// reason said.
func TestPrimaryStatusPlainHTTP(t *testing.T) {
	data := t.TempDir()
	if err := os.WriteFile(settings.Path(data), []byte(`{"primary": {"kind": "technitium", "url": "http://192.0.2.254:5380"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	primaryStatus(data, &b)
	if !strings.Contains(b.String(), "http://192.0.2.254:5380") || !strings.Contains(b.String(), "paused: "+primary.ErrPlainHTTP.Error()) {
		t.Fatal(b.String())
	}
}
