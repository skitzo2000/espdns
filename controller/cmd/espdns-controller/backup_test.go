package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/skitzo2000/espdns/controller/internal/auth"
	"github.com/skitzo2000/espdns/controller/internal/backup"
	"github.com/skitzo2000/espdns/controller/internal/fleetlock"
)

func init() { backup.WorkFactor = 10 }

// logOutput sends the log to w until the test ends.
func logOutput(t *testing.T, w io.Writer) {
	old := log.Writer()
	log.SetOutput(w)
	t.Cleanup(func() { log.SetOutput(old) })
}

// backupPost is the Backup page's POST, logged in.
func backupPost(t *testing.T, h http.Handler, cookie, tok, body string) *httptest.ResponseRecorder {
	return backupPostGrant(h, cookie, tok, reauth(t, h, cookie, tok), body)
}

// backupPostGrant is the page's POST with a re-authentication grant ("": none).
func backupPostGrant(h http.Handler, cookie, tok, grant, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "http://127.0.0.1:8480/api/backup", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "http://127.0.0.1:8480")
	withSession(r, cookie, tok)
	if grant != "" {
		r.Header.Set(auth.ReauthHeader, grant)
	}
	return serve(h, r)
}

// The page's backup: a file that restores to the data directory; the passphrase in no reply
// or log; refused while the fleet lock is held; a short passphrase refused.
func TestBackupDownload(t *testing.T) {
	dir := t.TempDir()
	if err := auth.SetPassword(auth.Path(dir), "admin", testPassword); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "settings.json"), []byte(`{"nodes": ["203.0.113.51"]}`))
	writeFile(t, filepath.Join(dir, "configs/dns2.json"), []byte(`{"name": "dns2"}`))
	writeFile(t, filepath.Join(dir, "firmware/builds/p4-ip101/dns2.bin"), []byte("app"))
	srv := &server{dataDir: dir, auth: auth.New(auth.Path(dir))}
	mux := &routes{mux: http.NewServeMux()}
	srv.auth.Routes(mux)
	backupServer{dataDir: dir, auth: srv.auth}.routes(mux)
	h := srv.auth.Guard(mux.mux)
	cookie, tok := login(t, h)

	const pass = "the backup's passphrase"
	var logs bytes.Buffer
	logOutput(t, &logs)
	w := backupPost(t, h, cookie, tok, `{"passphrase": "`+pass+`"}`)
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "application/octet-stream" ||
		!strings.Contains(w.Header().Get("Content-Disposition"), `filename="espdns-backup-`) {
		t.Fatalf("%d %v %.200s", w.Code, w.Header(), w.Body)
	}
	if strings.Contains(logs.String(), pass) || !strings.Contains(logs.String(), "admin downloaded") {
		t.Errorf("log: %s", logs.String())
	}
	// Written in the data directory's .tmp (0700), not the system's /tmp, and gone once sent
	tmp := filepath.Join(dir, TmpDir)
	if fi, err := os.Stat(tmp); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("%s: %v %v", tmp, fi, err)
	}
	if ents, _ := os.ReadDir(tmp); len(ents) != 0 {
		t.Errorf("left behind: %v", ents)
	}
	_, id, _ := backup.Passphrase(pass)
	dst := filepath.Join(t.TempDir(), "d")
	c, err := backup.Restore(bytes.NewReader(w.Body.Bytes()), []age.Identity{id}, dst, backup.RestoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "configs/dns2.json")); string(b) != `{"name": "dns2"}` || c.Manifest.Firmware {
		t.Errorf("restored %q, firmware %v", b, c.Manifest.Firmware)
	}
	if _, err := os.Stat(filepath.Join(dst, "firmware")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("firmware without asking: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dst, TmpDir)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the backup holds its own temporary directory: %v", err)
	}
	if _, err := auth.Load(auth.Path(dst)); err != nil {
		t.Errorf("the login: %v", err)
	}

	// What it holds.
	r := withSession(httptest.NewRequest("GET", "http://127.0.0.1:8480/api/backup", nil), cookie, tok)
	var info struct {
		Parts []part `json:"parts"`
	}
	if w := serve(h, r); w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &info) != nil || len(info.Parts) < 4 {
		t.Fatalf("info %d %s", w.Code, w.Body)
	}
	for _, p := range info.Parts {
		if (p.Name == "firmware" || p.Name == "fleet.lock") == p.Included || p.Name == TmpDir {
			t.Errorf("%+v", p)
		}
	}

	for body, want := range map[string]string{
		`{"passphrase": "short"}`:                          "at least 12",
		`{"passphrase": ""}`:                               "at least 12",
		`{"recipient": "age1nope"}`:                        "age key",
		`{"passphrase": "` + pass + `", "recipient": "x"}`: "not both",
	} {
		if w := backupPost(t, h, cookie, tok, body); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), want) ||
			strings.Contains(w.Body.String(), pass) {
			t.Errorf("%s: %d %s", body, w.Code, w.Body)
		}
	}
	// An age key, and the firmware too.
	idk, _ := age.GenerateX25519Identity()
	w = backupPost(t, h, cookie, tok, `{"recipient": "`+idk.Recipient().String()+`", "firmware": true}`)
	if w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if c, err := backup.Restore(bytes.NewReader(w.Body.Bytes()), []age.Identity{idk}, "", backup.RestoreOptions{DryRun: true}); err != nil ||
		!c.Manifest.Firmware {
		t.Errorf("age key: %v %+v", err, c.Manifest)
	}

	// The fleet lock held (a job, a CLI rollout): refused at once, naming who.
	lk, err := fleetlock.Acquire(fleetlock.Path(dir), fleetlock.Self("espdns rollout", "-kind firmware"))
	if err != nil {
		t.Fatal(err)
	}
	defer lk.Release()
	if w := backupPost(t, h, cookie, tok, `{"passphrase": "`+pass+`"}`); w.Code != http.StatusConflict ||
		!strings.Contains(w.Body.String(), "espdns rollout") {
		t.Errorf("locked: %d %s", w.Code, w.Body)
	}
}

// A backup holds the release key and the Wi-Fi passwords: a session isn't enough, the
// password is asked again (a grant from POST /api/reauth), good for one download; a wrong
// password gives none, and the password goes into no log.
func TestBackupNeedsPassword(t *testing.T) {
	h, _ := testServer(t, true)
	cookie, tok := login(t, h)
	var logs bytes.Buffer
	logOutput(t, &logs)
	body := `{"passphrase": "the backup's passphrase"}`
	if w := backupPostGrant(h, cookie, tok, "", body); !refusedForReauth(w) {
		t.Fatalf("no grant: %d %s", w.Code, w.Body)
	}
	if w := backupPostGrant(h, cookie, tok, "made-up", body); !refusedForReauth(w) {
		t.Fatalf("a made-up grant: %d %s", w.Code, w.Body)
	}
	r := withSession(request("POST /api/reauth"), cookie, tok)
	r.Body = io.NopCloser(strings.NewReader(`{"password":"not the password"}`))
	if w := serve(h, r); w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), `"reauth":"`) {
		t.Fatalf("a wrong password: %d %s", w.Code, w.Body)
	}
	g := reauth(t, h, cookie, tok)
	if w := backupPostGrant(h, cookie, "", g, body); w.Code != http.StatusUnauthorized {
		t.Fatalf("a grant with the cookie alone: %d %s", w.Code, w.Body)
	}
	other, otherTok := login(t, h)
	if w := backupPostGrant(h, other, otherTok, g, body); !refusedForReauth(w) {
		t.Fatalf("one session's grant in another: %d %s", w.Code, w.Body)
	}
	if w := backupPostGrant(h, cookie, tok, g, body); w.Code != http.StatusOK {
		t.Fatalf("with the grant: %d %s", w.Code, w.Body)
	}
	if w := backupPostGrant(h, cookie, tok, g, body); !refusedForReauth(w) {
		t.Fatalf("the grant twice: %d %s", w.Code, w.Body)
	}
	if strings.Contains(logs.String(), testPassword) || strings.Contains(logs.String(), "not the password") ||
		!strings.Contains(logs.String(), "reauth: admin") {
		t.Errorf("log: %s", logs.String())
	}
}
