package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testKeyPEM(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return k, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// The key comes from $ESPDNS_RELEASE_KEY (base64 of the PEM, or the
// PEM) only while -key is the default; an explicit file and -recovery read the file.
func TestLoadReleaseKey(t *testing.T) {
	k, p := testKeyPEM(t)
	t.Setenv(envReleaseKey, base64.StdEncoding.EncodeToString(p))
	if got, err := loadReleaseKey(defaultKey, false); err != nil || !got.Equal(k) {
		t.Fatalf("base64 env key: %v", err)
	}
	t.Setenv(envReleaseKey, string(p))
	if got, err := loadReleaseKey(defaultKey, false); err != nil || !got.Equal(k) {
		t.Fatalf("PEM env key: %v", err)
	}

	k2, p2 := testKeyPEM(t)
	file := filepath.Join(t.TempDir(), "other.pem")
	if err := os.WriteFile(file, p2, 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := loadReleaseKey(file, false); err != nil || !got.Equal(k2) {
		t.Fatalf("explicit -key: %v", err)
	}
	if got, err := loadReleaseKey(file, true); err != nil || !got.Equal(k2) {
		t.Fatalf("-recovery with -key: %v", err)
	}
	if _, err := loadReleaseKey(defaultKey, true); err == nil {
		t.Error("-recovery took the release key from the environment")
	}

	t.Setenv(envReleaseKey, "not base64!")
	if _, err := loadReleaseKey(defaultKey, false); err == nil {
		t.Error("garbage env key accepted")
	}

	// Unset (or blank): the default file, as before.
	t.Setenv(envReleaseKey, " \n")
	if _, err := loadReleaseKey(defaultKey, false); err == nil || !strings.Contains(err.Error(), defaultKey) {
		t.Errorf("no env key: want the default file's error, got %v", err)
	}
}

// A bad key in the environment is reported by name, never by its bytes.
func TestLoadReleaseKeyErrorsHideTheValue(t *testing.T) {
	_, p := testKeyPEM(t)
	body := strings.Join(strings.Split(string(p), "\n")[1:3], "")
	broken := strings.Replace(string(p), body[:20], strings.Repeat("A", 20), 1) // a PEM whose DER doesn't parse
	for name, v := range map[string]string{
		"not base64":          "secret-ish value",
		"base64, not PEM":     base64.StdEncoding.EncodeToString([]byte("secret-ish value")),
		"PEM, bad DER":        broken,
		"base64 of a bad PEM": base64.StdEncoding.EncodeToString([]byte(broken)),
	} {
		t.Setenv(envReleaseKey, v)
		_, err := loadReleaseKey(defaultKey, false)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		msg := err.Error()
		if !strings.Contains(msg, "$"+envReleaseKey) {
			t.Errorf("%s: error doesn't name the variable: %v", name, err)
		}
		for _, leak := range []string{"secret-ish", body[20:40], v[:min(len(v), 24)]} {
			if strings.Contains(msg, leak) {
				t.Errorf("%s: error shows the value: %v", name, err)
			}
		}
	}
}

// -key - reads the key from standard input (the fleet-* Docker runs pipe it from the
// environment): base64 of the PEM with printenv's newline, or the PEM; errors hide the value.
func TestReadKeyStdin(t *testing.T) {
	k, p := testKeyPEM(t)
	name := "-key - (standard input)"
	for what, in := range map[string]string{
		"base64": base64.StdEncoding.EncodeToString(p) + "\n",
		"PEM":    string(p),
	} {
		if got, err := readKey(name, strings.NewReader(in)); err != nil || !got.Equal(k) {
			t.Errorf("%s: %v", what, err)
		}
	}
	for what, in := range map[string]string{"empty": "\n", "garbage": "secret-ish value\n"} {
		_, err := readKey(name, strings.NewReader(in))
		if err == nil || !strings.Contains(err.Error(), name) || strings.Contains(err.Error(), "secret-ish") {
			t.Errorf("%s: %v", what, err)
		}
	}
}

// The zone primary token: the file first, then $ESPDNS_PRIMARY_TOKEN, then the variable
// -primary-token-env names; the old names ($ESPDNS_TECHNITIUM_TOKEN, $TECHNITIUM_API_TOKEN)
// only when -primary-token-env names one.
func TestPrimaryToken(t *testing.T) {
	for _, e := range []string{envPrimaryToken, "ESPDNS_TECHNITIUM_TOKEN", "TECHNITIUM_API_TOKEN", "TOKEN_NAMED"} {
		t.Setenv(e, "")
	}
	if tok, err := primaryToken("", "TOKEN_NAMED"); tok != "" || err != nil {
		t.Errorf("no token: %q %v", tok, err)
	}
	t.Setenv("TECHNITIUM_API_TOKEN", " token \n")
	t.Setenv("ESPDNS_TECHNITIUM_TOKEN", "espdns")
	if tok, _ := primaryToken("", ""); tok != "" {
		t.Errorf("an old name read: %q", tok)
	}
	if tok, _ := primaryToken("", "TECHNITIUM_API_TOKEN"); tok != "token" {
		t.Errorf("-primary-token-env TECHNITIUM_API_TOKEN: %q", tok)
	}
	t.Setenv("TOKEN_NAMED", "named")
	if tok, _ := primaryToken("", "TOKEN_NAMED"); tok != "named" {
		t.Errorf("-primary-token-env's first: %q", tok)
	}
	t.Setenv(envPrimaryToken, "primary")
	if tok, _ := primaryToken("", "TOKEN_NAMED"); tok != "primary" {
		t.Errorf("$ESPDNS_PRIMARY_TOKEN first: %q", tok)
	}
	file := filepath.Join(t.TempDir(), "token")
	os.WriteFile(file, []byte("file\n"), 0o600)
	if tok, _ := primaryToken(file, ""); tok != "file" {
		t.Errorf("file first: %q", tok)
	}
	if _, err := primaryToken(file+".missing", ""); err == nil {
		t.Error("missing file accepted")
	}
}
