package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/configs"
	"github.com/skitzo2000/espdns/controller/internal/faketech"
	"github.com/skitzo2000/espdns/controller/internal/keys"
	"github.com/skitzo2000/espdns/controller/internal/primary"
	"github.com/skitzo2000/espdns/controller/internal/settings"
)

// The confirm step for a primary with its own certificate, against a fake Technitium over
// https on loopback: not trusted, nothing is sent to it (the Zone primary view says why and
// gives the fingerprint); the certificate shown; a wrong or garbled fingerprint not pinned;
// the one shown pinned (in any of the forms people copy it in), and the primary reached; a
// settings save can keep the pin or drop it, never set one or carry it to another address;
// a certificate changed on the primary refused, nothing sent; the pin taken away.
func TestPrimaryCertificatePin(t *testing.T) {
	e := newSetupEnv(t)
	e.firstPassword()
	if code, out := e.do("GET /api/primary/certificate", ""); code != http.StatusConflict || !strings.Contains(out["error"].(string), "no zone primary") {
		t.Fatalf("no primary: %d %v", code, out)
	}
	fake := faketech.New(setupToken, "home.example")
	ts := httptest.NewTLSServer(fake)
	t.Cleanup(ts.Close)
	fp := primary.Fingerprint(ts.Certificate())
	if err := os.MkdirAll(configs.Path(e.dir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configs.Path(e.dir), "n1.json"),
		[]byte(`{"name": "dns1", "secondary": {"primary": "192.0.2.254", "zones": ["home.example"]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out := e.do("POST /api/settings", `{"settings": {"primary": {"kind": "technitium", "url": "`+ts.URL+`"}},
		"version": "", "primary_token": "`+setupToken+`"}`)
	if code != http.StatusOK {
		t.Fatal(code, out)
	}
	version := out["version"].(string)

	// Not trusted, not pinned: the view says so, with the fingerprint; nothing sent
	_, out = e.do("GET /api/primary", "")
	if z := zoneErr(out); !strings.Contains(z, "doesn't trust") || !strings.Contains(z, fp) {
		t.Fatalf("unpinned: %v", out)
	}
	if len(fake.Calls()) != 0 {
		t.Fatal("sent to an unverified primary:", fake.Calls())
	}
	code, out = e.do("GET /api/primary/certificate", "")
	pres, _ := out["presented"].(map[string]any)
	if code != http.StatusOK || pres["sha256"] != fp || pres["trusted"] != false || out["pinned"] != "" || out["matches"] != false {
		t.Fatalf("certificate: %d %v", code, out)
	}

	// A wrong or garbled fingerprint: nothing pinned
	if code, out := e.do("POST /api/primary/certificate", `{"sha256": "`+strings.Repeat("0", 64)+`"}`); code != http.StatusConflict ||
		!strings.Contains(out["error"].(string), "now presents") {
		t.Fatalf("wrong: %d %v", code, out)
	}
	if code, out := e.do("POST /api/primary/certificate", `{"sha256": "abc"}`); code != http.StatusBadRequest || out["field"] != "sha256" {
		t.Fatalf("garbled: %d %v", code, out)
	}
	if s, _ := settings.Load(settings.Path(e.dir)); s.ZonePrimary().CertSHA256 != "" {
		t.Fatal("pinned on a refusal")
	}

	// The fingerprint shown, as copied with colons in capitals: pinned, and the primary reached
	var colons []string
	for i := 0; i < len(fp); i += 2 {
		colons = append(colons, strings.ToUpper(fp[i:i+2]))
	}
	if code, out := e.do("POST /api/primary/certificate", `{"sha256": "`+strings.Join(colons, ":")+`"}`); code != http.StatusOK ||
		out["pinned"] != fp || out["matches"] != true {
		t.Fatalf("pin: %d %v", code, out)
	}
	if s, _ := settings.Load(settings.Path(e.dir)); s.ZonePrimary().CertSHA256 != fp {
		t.Fatal("not pinned:", s.ZonePrimary())
	}
	_, out = e.do("GET /api/primary", "")
	if z := zoneErr(out); z != "" || out["api"] != ts.URL {
		t.Fatalf("pinned: %v", out)
	}
	if len(fake.Calls()) == 0 {
		t.Fatal("the pinned primary not asked")
	}
	_, out = e.do("GET /api/settings", "")
	version = out["version"].(string)
	if st := out["primary_state"].(map[string]any); st["cert_sha256"] != fp || st["by_hand"] != false {
		t.Fatalf("state: %v", st)
	}

	// A settings save: a pin set there, or carried to another address, is refused; kept, it
	// stays (no token asked again)
	for body, want := range map[string]string{
		`{"kind": "technitium", "url": "` + ts.URL + `", "cert_sha256": "` + strings.Repeat("ab", 32) + `"}`: "set by confirming",
		`{"kind": "technitium", "url": "https://192.0.2.254:53443", "cert_sha256": "` + fp + `"}`:            "leave it out",
	} {
		if code, out := e.do("POST /api/settings", `{"settings": {"primary": `+body+`}, "version": "`+version+`"}`); code != http.StatusBadRequest ||
			out["field"] != "primary" || !strings.Contains(out["error"].(string), want) {
			t.Fatalf("%s: %d %v", body, code, out)
		}
		// Nor with a token given or removed in the same save: the token stays as it was
		for _, tok := range []string{`"primary_token": "` + setupToken + `"`, `"remove_primary_token": true`} {
			if code, out := e.do("POST /api/settings", `{"settings": {"primary": `+body+`}, "version": "`+version+`", `+tok+`}`); code != http.StatusBadRequest ||
				out["field"] != "primary" || !strings.Contains(out["error"].(string), want) {
				t.Fatalf("%s with %s: %d %v", body, tok, code, out)
			}
			if s, _ := settings.Load(settings.Path(e.dir)); s.ZonePrimary().CertSHA256 != fp || s.ZonePrimary().URL != ts.URL {
				t.Fatalf("%s with %s: saved %v", body, tok, s.ZonePrimary())
			}
			if _, err := (keys.DataTokenSource{DataDir: e.dir}).Token(); err != nil {
				t.Fatalf("%s with %s: the token: %v", body, tok, err)
			}
		}
	}
	code, out = e.do("POST /api/settings", `{"settings": {"nodes": ["192.0.2.53"], "primary": {"kind": "technitium", "url": "`+ts.URL+
		`", "cert_sha256": "`+fp+`"}}, "version": "`+version+`"}`)
	if code != http.StatusOK || out["primary_token"].(map[string]any)["set"] != true {
		t.Fatalf("kept: %d %v", code, out)
	}

	// The primary's certificate changes: refused, nothing sent
	n := len(fake.Calls())
	ts.TLS.Certificates = []tls.Certificate{otherCert(t)}
	ts.CloseClientConnections()
	_, out = e.do("GET /api/primary", "")
	if z := zoneErr(out); !strings.Contains(z, "other than the one pinned") {
		t.Fatalf("changed: %v", out)
	}
	if len(fake.Calls()) != n {
		t.Fatal("sent to a changed certificate:", fake.Calls()[n:])
	}

	// Unpinned
	if code, out := e.do("DELETE /api/primary/certificate", ""); code != http.StatusOK || out["pinned"] != "" {
		t.Fatalf("unpin: %d %v", code, out)
	}
	if s, _ := settings.Load(settings.Path(e.dir)); s.ZonePrimary().CertSHA256 != "" || s.ZonePrimary().URL != ts.URL {
		t.Fatal("still pinned:", s.ZonePrimary())
	}
}

// otherCert is a self-signed certificate for 127.0.0.1, another key than httptest's.
func otherCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "primary"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// zoneErr is the first zone's error in a GET /api/primary reply, or its error ("" none).
func zoneErr(out map[string]any) string {
	if s, ok := out["error"].(string); ok {
		return s
	}
	zs, _ := out["zones"].([]any)
	for _, z := range zs {
		if s, ok := z.(map[string]any)["error"].(string); ok {
			return s
		}
	}
	return ""
}

// A settings.json saved with the zone primary at a plain http address (before https was
// required): the controller still starts, saying once why the primary is paused; the
// primary is never reached and the token never sent (a fake primary over plain http gets
// nothing, from the settings form, the Zone primary view, the inventory, the lookup or the
// confirm step); each says the one reason; a save that keeps the http address is refused
// (400, "primary"), one with its https address taken.
func TestPrimaryPlainHTTPPaused(t *testing.T) {
	fake := faketech.New(setupToken, "home.example")
	var sent []string
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sent = append(sent, r.URL.String())
		fake.ServeHTTP(w, r)
	}))
	t.Cleanup(plain.Close)
	e := newSetupEnv(t, func(s *server) { s.zoneDNS = &fakeZonePrimary{at: "192.0.2.254", zones: map[string]uint32{}} })
	e.firstPassword()
	if _, err := keys.ImportDataToken(e.dir, setupToken, false); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(configs.Path(e.dir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configs.Path(e.dir), "n1.json"),
		[]byte(`{"name": "dns1", "secondary": {"primary": "192.0.2.254", "zones": ["home.example"]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settings.Path(e.dir), []byte(`{"nodes": ["192.0.2.53"], "primary": {"kind": "technitium", "url": "`+plain.URL+`"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	reason := primary.ErrPlainHTTP.Error()

	// Starts: settings.json loads, the warning said once
	var logs []string
	st, err := loadSettings(e.dir, func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) })
	if err != nil || st.ZonePrimary().URL != plain.URL || len(logs) != 1 || !strings.Contains(logs[0], reason) ||
		!strings.Contains(logs[0], plain.URL) || strings.Contains(logs[0], setupToken) {
		t.Fatalf("start: %v %v", err, logs)
	}

	// Each place the primary is shown says why it is paused
	code, out := e.do("GET /api/settings", "")
	if ps := out["primary_state"].(map[string]any); code != http.StatusOK || ps["why"] != reason || ps["by_hand"] != true {
		t.Fatalf("settings: %d %v", code, out)
	}
	version := out["version"].(string)
	if _, out := e.do("GET /api/primary", ""); out["by_hand"] != reason {
		t.Fatalf("primary view: %v", out)
	}
	if _, out := e.do("GET /api/zone-inventory", ""); out["primary"].(map[string]any)["paused"] != reason {
		t.Fatalf("inventory: %v", out)
	}
	if _, out := e.do("GET /api/zone-lookup?name=new.example", ""); out["primary_paused"] != reason {
		t.Fatalf("lookup: %v", out)
	}
	if code, out := e.do("GET /api/primary/certificate", ""); code != http.StatusConflict || !strings.Contains(out["error"].(string), reason) {
		t.Fatalf("certificate: %d %v", code, out)
	}

	// A save keeping the plain http address, with or without the token: refused, nothing written
	for _, extra := range []string{"", `, "primary_token": "` + setupToken + `"`} {
		code, out := e.do("POST /api/settings", `{"settings": {"nodes": ["192.0.2.53", "192.0.2.54"], "primary": {"kind": "technitium", "url": "`+
			plain.URL+`"}}, "version": "`+version+`"`+extra+`}`)
		if code != http.StatusBadRequest || out["field"] != "primary" || !strings.Contains(out["error"].(string), "plain http") {
			t.Fatalf("save%s: %d %v", extra, code, out)
		}
	}
	if s, _ := settings.Load(settings.Path(e.dir)); len(s.Nodes) != 1 {
		t.Fatal("saved:", s)
	}
	if len(sent) != 0 || len(fake.Calls()) != 0 {
		t.Fatal("sent to a plain http primary:", sent)
	}

	// Its https address saved (the token given again): no longer paused
	code, out = e.do("POST /api/settings", `{"settings": {"nodes": ["192.0.2.53"], "primary": {"kind": "technitium", "url": "https://192.0.2.254:53443"}},
		"version": "`+version+`", "primary_token": "`+setupToken+`"}`)
	if ps, _ := out["primary_state"].(map[string]any); code != http.StatusOK || ps["why"] != nil || ps["by_hand"] != false {
		t.Fatalf("fixed: %d %v", code, out)
	}
}
