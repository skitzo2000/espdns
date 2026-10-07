package main

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHealthcheck(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
		}
	}))
	defer ok.Close()
	if err := healthcheck(ok.Listener.Addr().String(), time.Second); err != nil {
		t.Errorf("a controller answering: %v", err)
	}

	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no", http.StatusInternalServerError)
	}))
	defer bad.Close()
	if err := healthcheck(bad.Listener.Addr().String(), time.Second); err == nil {
		t.Error("a 500 is healthy")
	}

	// Nothing listening: a port taken and given back
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	if err := healthcheck(addr, time.Second); err == nil {
		t.Error("nothing listening is healthy")
	}
	if err := healthcheck("nonsense", time.Second); err == nil {
		t.Error("a bad -listen is healthy")
	}
}

func TestWritable(t *testing.T) {
	dir := t.TempDir()
	if err := writable(dir); err != nil {
		t.Fatalf("a temp dir: %v", err)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "*")); len(left) != 0 {
		t.Errorf("left behind: %v", left)
	}
	if os.Getuid() == 0 {
		t.Skip("root writes anywhere")
	}
	ro := filepath.Join(dir, "ro")
	if err := os.Mkdir(ro, 0o555); err != nil {
		t.Fatal(err)
	}
	if err := writable(ro); err == nil {
		t.Error("a read-only directory is writable")
	}
	if err := writable(filepath.Join(dir, "missing")); err == nil {
		t.Error("a missing directory is writable")
	}
}

// A data directory from before (0755, files 0644) is made the controller user's only at
// start, and said; a missing one is made 0700.
func TestPrepareData(t *testing.T) {
	var logged []string
	logf := func(format string, args ...any) { logged = append(logged, fmt.Sprintf(format, args...)) }
	dir := filepath.Join(t.TempDir(), "data")
	if err := prepareData(dir, logf); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("made: %v %v", fi, err)
	}
	if len(logged) != 0 {
		t.Errorf("a new one: %q", logged)
	}

	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "log"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"settings.json", "fleet.lock", "log/actions.jsonl"} {
		p := filepath.Join(dir, f)
		if err := os.WriteFile(p, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := prepareData(dir, logf); err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]os.FileMode{"": 0o700, "log": 0o700, "settings.json": 0o600, "fleet.lock": 0o600, "log/actions.jsonl": 0o600} {
		if fi, err := os.Stat(filepath.Join(dir, p)); err != nil || fi.Mode().Perm() != want {
			t.Errorf("%q: %v %v, want %04o", p, fi.Mode().Perm(), err, want)
		}
	}
	if len(logged) != 1 || !strings.Contains(logged[0], "5 open to group or others") {
		t.Errorf("logged: %q", logged)
	}
}

// A backup the Backup page left in .tmp (the controller stopped while it was sent) is
// removed at start; anything else there is left.
func TestPrepareDataClearsLeftBackups(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	tmp := filepath.Join(dir, TmpDir)
	if err := os.MkdirAll(filepath.Join(tmp, "espdns-backup-dir.age"), 0o700); err != nil {
		t.Fatal(err)
	}
	left := filepath.Join(tmp, "espdns-backup-123.age")
	other := filepath.Join(tmp, "other")
	for _, p := range []string{left, other} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var logged []string
	if err := prepareData(dir, func(f string, a ...any) { logged = append(logged, fmt.Sprintf(f, a...)) }); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(left); !os.IsNotExist(err) {
		t.Errorf("a left backup: %v, want removed", err)
	}
	for _, p := range []string{other, filepath.Join(tmp, "espdns-backup-dir.age")} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s: %v, want left", p, err)
		}
	}
	if len(logged) != 1 || !strings.Contains(logged[0], "espdns-backup-123.age") {
		t.Errorf("logged %q", logged)
	}
	// None there, no .tmp: nothing said
	logged = nil
	if err := os.RemoveAll(tmp); err != nil {
		t.Fatal(err)
	}
	if err := prepareData(dir, func(f string, a ...any) { logged = append(logged, fmt.Sprintf(f, a...)) }); err != nil || len(logged) != 0 {
		t.Errorf("no .tmp: %v %q", err, logged)
	}
}
