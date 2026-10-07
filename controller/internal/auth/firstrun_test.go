package auth

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// firstRun is POST /api/setup/password from remote (a loopback client unless said).
func firstRun(h http.Handler, body, remote string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", host+"/api/setup/password", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = remote
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// CreatePassword: only while there is no auth.json; checked as SetPassword checks.
func TestCreatePassword(t *testing.T) {
	path := filepath.Join(t.TempDir(), File)
	if err := CreatePassword(path, "admin", "short"); err == nil || !strings.Contains(err.Error(), "password: too short") {
		t.Fatalf("short: %v", err)
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("a refused password made the file")
	}
	if err := CreatePassword(path, "admin", pw); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	if err := CreatePassword(path, "admin", "another password"); !errors.Is(err, ErrPasswordSet) {
		t.Fatalf("second: %v", err)
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Fatal("the second changed auth.json")
	}
	if c, err := Load(path); err != nil || c.User != "admin" {
		t.Fatal(c, err)
	}
}

// The first run's password from the browser: set while none is, by a loopback client, and
// the reply is a login (cookie and token) that works at once; then refused (409), whoever
// asks, and the password stays.
func TestFirstPasswordHTTP(t *testing.T) {
	path := filepath.Join(t.TempDir(), File)
	a := New(path)
	h := guarded(a)

	// Not from this machine: refused, nothing set.
	if w := firstRun(h, `{"password":"`+pw+`"}`, "192.0.2.10:4000"); w.Code != http.StatusForbidden {
		t.Fatalf("from another machine: %d %s", w.Code, w.Body)
	}
	// Not JSON.
	r := httptest.NewRequest("POST", host+"/api/setup/password", strings.NewReader(`{"password":"`+pw+`"}`))
	r.RemoteAddr = "127.0.0.1:4000"
	if w := httptest.NewRecorder(); func() bool { h.ServeHTTP(w, r); return w.Code != http.StatusForbidden }() {
		t.Fatalf("form post: %d", w.Code)
	}
	// Refused fields, with the field named.
	for body, field := range map[string]string{`{"password":"short"}`: "password", `{"user":"a b","password":"` + pw + `"}`: "user"} {
		w := firstRun(h, body, "127.0.0.1:4000")
		var out struct{ Error, Field string }
		json.Unmarshal(w.Body.Bytes(), &out)
		if w.Code != http.StatusBadRequest || out.Field != field {
			t.Errorf("%s: %d %s", body, w.Code, w.Body)
		}
	}
	if set, _ := a.State(); set {
		t.Fatal("a refused request set a password")
	}

	w := firstRun(h, `{"password":"`+pw+`"}`, "[::1]:4000")
	if w.Code != http.StatusOK {
		t.Fatalf("first run: %d %s", w.Code, w.Body)
	}
	var reply struct{ User, Token, Device string }
	json.Unmarshal(w.Body.Bytes(), &reply)
	var cookie string
	for _, c := range w.Result().Cookies() {
		if c.Name == cookieName {
			cookie = c.Value
		}
	}
	if reply.User != DefaultUser || reply.Token == "" || reply.Device == "" || cookie == "" {
		t.Fatalf("reply %s, cookies %v", w.Body, w.Result().Cookies())
	}
	if strings.Contains(w.Body.String(), pw) {
		t.Fatal("the password in the reply")
	}
	// The session works at once; the guard is no longer read-only.
	if w := do(h, req{method: "POST", path: "/api/x", cookies: []string{cookie}, token: reply.Token}); w.Body.String() != "ok admin" {
		t.Fatalf("with the new session: %d %s", w.Code, w.Body)
	}
	if w := do(h, req{method: "GET", path: "/api/x"}); w.Code != http.StatusUnauthorized {
		t.Fatalf("logged out after the first run: %d", w.Code)
	}
	// Once set: refused, with a session too, and the password stays.
	for _, q := range []req{{}, {cookies: []string{cookie}, token: reply.Token}} {
		q.method, q.path, q.body = "POST", "/api/setup/password", `{"password":"another password"}`
		if w := do(h, q); w.Code != http.StatusConflict {
			t.Errorf("again: %d %s", w.Code, w.Body)
		}
	}
	if _, _, err := a.Login("admin", pw, "c"); err != nil {
		t.Fatal("the first password no longer logs in:", err)
	}
}

// Two first runs at once: one sets its password, the other is refused and the password is
// the winner's.
func TestFirstPasswordRace(t *testing.T) {
	a := New(filepath.Join(t.TempDir(), File))
	h := guarded(a)
	pws := []string{"first password one", "first password two", "first password six", "first password ten"}
	codes := make([]int, len(pws))
	var wg sync.WaitGroup
	for i, p := range pws {
		wg.Add(1)
		go func() { defer wg.Done(); codes[i] = firstRun(h, `{"password":"`+p+`"}`, "127.0.0.1:4000").Code }()
	}
	wg.Wait()
	won := -1
	for i, c := range codes {
		switch {
		case c == http.StatusOK && won < 0:
			won = i
		case c != http.StatusConflict:
			t.Errorf("%d: %d", i, c)
		}
	}
	if won < 0 {
		t.Fatal("none set")
	}
	for i, p := range pws {
		if _, _, err := a.Login("admin", p, "c"+p); (err == nil) != (i == won) {
			t.Errorf("%s: %v (winner %d)", p, err, won)
		}
	}
}
