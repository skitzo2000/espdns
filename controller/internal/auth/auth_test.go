package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/secfile"
	"github.com/skitzo2000/espdns/controller/internal/version"
)

// Cheap costs for tests: the format and checks are the same.
func init() { DefaultParams = Params{Time: 1, MemoryKiB: 64, Threads: 1} }

const pw = "correct horse battery"

func TestHashVerify(t *testing.T) {
	h := Hash(pw, DefaultParams)
	if !strings.HasPrefix(h, "$argon2id$v=19$m=64,t=1,p=1$") {
		t.Fatalf("hash %q", h)
	}
	if ok, err := Verify(h, pw); !ok || err != nil {
		t.Fatalf("right password: %v %v", ok, err)
	}
	if ok, err := Verify(h, pw+"!"); ok || err != nil {
		t.Fatalf("wrong password: %v %v", ok, err)
	}
	if Hash(pw, DefaultParams) == h {
		t.Error("two hashes of one password are the same: no salt")
	}
	for _, bad := range []string{"", "$2a$10$abc", "$argon2id$v=19$m=999999999,t=1,p=1$AAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAA",
		"$argon2id$v=19$m=64,t=1,p=1$!!$AAAA", "$argon2i$v=19$m=64,t=1,p=1$AAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAA"} {
		if ok, err := Verify(bad, pw); ok || err == nil {
			t.Errorf("Verify(%q) = %v, %v", bad, ok, err)
		}
	}
}

func TestCheckPassword(t *testing.T) {
	for p, ok := range map[string]bool{pw: true, "short": false, " leading space ok?": false,
		strings.Repeat("x", MaxPassword+1): false, "\xff\xfe invalid utf8": false, "twelve chars": true} {
		if err := CheckPassword(p); (err == nil) != ok {
			t.Errorf("CheckPassword(%q): %v", p, err)
		}
	}
}

func TestSetPasswordFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), File)
	if _, err := Load(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("no file: %v", err)
	}
	if err := SetPassword(path, "admin", "short"); err == nil {
		t.Fatal("short password set")
	}
	if err := SetPassword(path, "ad min", pw); err == nil {
		t.Fatal("user with a space set")
	}
	if err := SetPassword(path, "admin", pw); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	b, _ := os.ReadFile(path)
	if strings.Contains(string(b), pw) {
		t.Fatal("the password is in the file")
	}
	c, err := Load(path)
	if err != nil || c.User != "admin" {
		t.Fatalf("load: %+v %v", c, err)
	}
	os.Chmod(path, 0o640)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("group-readable auth.json used: %v", err)
	}
}

// clock is a settable now.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newAuth(t *testing.T) (*Auth, *clock, string) {
	path := filepath.Join(t.TempDir(), File)
	if err := SetPassword(path, "admin", pw); err != nil {
		t.Fatal(err)
	}
	a := New(path)
	c := &clock{t: time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)}
	a.now = c.now
	return a, c, path
}

func TestLoginAndSession(t *testing.T) {
	a, _, _ := newAuth(t)
	if _, _, err := a.Login("admin", "wrong password!", "c"); !errors.Is(err, ErrBadLogin) {
		t.Fatalf("wrong password: %v", err)
	}
	if _, _, err := a.Login("root", pw, "c"); !errors.Is(err, ErrBadLogin) {
		t.Fatalf("wrong user: %v", err)
	}
	tok, s, err := a.Login("admin", pw, "c")
	if err != nil || s.User != "admin" || s.Token == "" || tok == "" || tok == s.Token {
		t.Fatalf("login: %q %+v %v", tok, s, err)
	}
	if got, ok := a.Session(tok); !ok || got.User != "admin" {
		t.Fatal("session not found")
	}
	if _, ok := a.Session(tok + "x"); ok {
		t.Fatal("a wrong token is a session")
	}
	a.Logout(tok)
	if _, ok := a.Session(tok); ok {
		t.Fatal("session after logout")
	}
}

func TestSessionExpiry(t *testing.T) {
	a, c, _ := newAuth(t)
	tok, s, err := a.Login("admin", pw, "c")
	if err != nil {
		t.Fatal(err)
	}
	// Used every hour (by the page, with its token): alive until Max after its login.
	for elapsed := time.Duration(0); elapsed+time.Hour < a.Max; elapsed += time.Hour {
		c.add(time.Hour)
		if _, ok := a.SessionWith(tok, s.Token); !ok {
			t.Fatalf("session ended after %v of use", elapsed+time.Hour)
		}
	}
	c.add(time.Hour)
	if _, ok := a.Session(tok); ok {
		t.Fatal("session past Max")
	}
	// Idle past Idle: ended.
	tok, s, _ = a.Login("admin", pw, "c")
	c.add(a.Idle - time.Second)
	if _, ok := a.SessionWith(tok, s.Token); !ok {
		t.Fatal("ended before Idle")
	}
	c.add(a.Idle)
	if _, ok := a.Session(tok); ok {
		t.Fatal("session idle past Idle")
	}
}

// A new password (espdns passwd while the controller runs) ends every session of the old.
func TestNewPasswordEndsSessions(t *testing.T) {
	a, _, path := newAuth(t)
	tok, _, _ := a.Login("admin", pw, "c")
	time.Sleep(10 * time.Millisecond) // a new mtime
	if err := SetPassword(path, "admin", "another long password"); err != nil {
		t.Fatal(err)
	}
	if _, ok := a.Session(tok); ok {
		t.Fatal("old session alive after a new password")
	}
	if _, _, err := a.Login("admin", pw, "c"); !errors.Is(err, ErrBadLogin) {
		t.Fatalf("old password: %v", err)
	}
	if _, _, err := a.Login("admin", "another long password", "c"); err != nil {
		t.Fatal(err)
	}
}

// A new user name, even with the same password, ends every session (each write is a new
// salted hash); the old name logs in no more, the new one does.
func TestNewUserEndsSessions(t *testing.T) {
	a, _, path := newAuth(t)
	tok, _, _ := a.Login("admin", pw, "c")
	time.Sleep(10 * time.Millisecond) // a new mtime
	if err := SetPassword(path, "alice", pw); err != nil {
		t.Fatal(err)
	}
	if _, ok := a.Session(tok); ok {
		t.Fatal("old session alive after a new user name")
	}
	if _, _, err := a.Login("admin", pw, "c"); !errors.Is(err, ErrBadLogin) {
		t.Fatalf("old name: %v", err)
	}
	if _, s, err := a.Login("alice", pw, "c"); err != nil || s.User != "alice" {
		t.Fatalf("new name: %v %v", s.User, err)
	}
}

// A user name an older passwd set that CheckUser no longer takes still logs in.
func TestOldUserLogsIn(t *testing.T) {
	a, _, path := newAuth(t)
	old := `it's\a "b"`
	b, _ := json.Marshal(Config{User: old, Hash: Hash(pw, DefaultParams)})
	time.Sleep(10 * time.Millisecond) // a new mtime
	if err := secfile.Write(path, b); err != nil {
		t.Fatal(err)
	}
	if _, s, err := a.Login(old, pw, "c"); err != nil || s.User != old {
		t.Fatalf("%v %v", s.User, err)
	}
}

// The user names passwd takes: printable, no white space, no quotes or backslashes.
func TestCheckUser(t *testing.T) {
	for _, ok := range []string{"admin", "alice", "a.user@home", "ops-1_x", "zoë", strings.Repeat("a", MaxUser)} {
		if err := CheckUser(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "a b", "a\tb", "a\nb", "a b", "x\x01", "x\x7f", "it's", `a"b`, "a`b", `a\b`,
		"\xff", strings.Repeat("a", MaxUser+1)} {
		if err := CheckUser(bad); err == nil {
			t.Errorf("%q taken", bad)
		}
	}
}

func TestBackoff(t *testing.T) {
	a, c, _ := newAuth(t)
	for i := range freeFails {
		if _, _, err := a.Login("admin", "nope nope nope", "c"); !errors.Is(err, ErrBadLogin) {
			t.Fatalf("failure %d: %v", i+1, err)
		}
	}
	// Past the free ones: locked, even for the right password.
	var be BackoffError
	if _, _, err := a.Login("admin", pw, "c"); !errors.As(err, &be) || be.Wait != backoffBase {
		t.Fatalf("after %d failures: %v", freeFails, err)
	}
	c.add(backoffBase)
	a.Login("admin", "nope nope nope", "c") // the 4th: 2 s
	if _, _, err := a.Login("admin", pw, "c"); !errors.As(err, &be) || be.Wait != 2*backoffBase {
		t.Fatalf("after %d failures: %v", freeFails+1, err)
	}
	// Doubling, up to the cap.
	for range 12 {
		c.add(backoffMax)
		a.Login("admin", "nope nope nope", "c")
	}
	if _, _, err := a.Login("admin", pw, "c"); !errors.As(err, &be) || be.Wait != backoffMax {
		t.Fatalf("capped: %v", err)
	}
	c.add(backoffMax)
	if _, _, err := a.Login("admin", pw, "c"); err != nil {
		t.Fatalf("after the wait: %v", err)
	}
	// A login that works starts the count over.
	if _, _, err := a.Login("admin", "nope nope nope", "c"); !errors.Is(err, ErrBadLogin) {
		t.Fatalf("after a good login: %v", err)
	}
	if _, _, err := a.Login("admin", pw, "c"); err != nil {
		t.Fatalf("one failure locked: %v", err)
	}
}

func TestNoPassword(t *testing.T) {
	a := New(filepath.Join(t.TempDir(), File))
	if set, err := a.State(); set || err != nil {
		t.Fatalf("State: %v %v", set, err)
	}
	if _, _, err := a.Login("admin", pw, "c"); !errors.Is(err, ErrNoPassword) {
		t.Fatalf("login without a password: %v", err)
	}
}

// guarded is the login's routes and a catch-all that says who it saw, behind Guard; the
// requests come by 127.0.0.1:8480.
func guarded(a *Auth, extra ...func(*http.ServeMux)) http.Handler {
	mux := http.NewServeMux()
	a.Routes(mux)
	for _, e := range extra {
		e(mux)
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok " + User(r.Context()))) })
	return a.Guard(mux)
}

const host = "http://127.0.0.1:8480"

var cookieName = CookieName("127.0.0.1:8480")

type req struct {
	method, path, body string
	cookies            []string // values of cookieName, in order
	token, reauth      string
	device             string
}

func do(h http.Handler, q req) *httptest.ResponseRecorder {
	r := httptest.NewRequest(q.method, host+q.path, strings.NewReader(q.body))
	r.Header.Set("Content-Type", "application/json")
	for _, c := range q.cookies {
		r.AddCookie(&http.Cookie{Name: cookieName, Value: c})
	}
	if q.token != "" {
		r.Header.Set(TokenHeader, q.token)
	}
	if q.reauth != "" {
		r.Header.Set(ReauthHeader, q.reauth)
	}
	if q.device != "" {
		r.Header.Set(DeviceHeader, q.device)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

type loginReply struct {
	User, Token, Device string
	cookie              *http.Cookie
}

func httpLogin(t *testing.T, h http.Handler, q req) loginReply {
	t.Helper()
	q.method, q.path = "POST", "/api/login"
	if q.body == "" {
		q.body = `{"user":"admin","password":"` + pw + `"}`
	}
	w := do(h, q)
	if w.Code != http.StatusOK {
		t.Fatalf("login: %d %s", w.Code, w.Body)
	}
	var out loginReply
	json.Unmarshal(w.Body.Bytes(), &out)
	for _, x := range w.Result().Cookies() {
		if x.Name == cookieName {
			out.cookie = x
		}
	}
	if out.cookie == nil || out.Token == "" || out.Device == "" {
		t.Fatalf("login reply %s, cookies %v", w.Body, w.Result().Cookies())
	}
	return out
}

// The guard over a mux: what each kind of request gets, with and without a session.
func TestGuard(t *testing.T) {
	a, _, _ := newAuth(t)
	h := guarded(a)
	// Logged out.
	if w := do(h, req{method: "GET", path: "/index.html"}); w.Code != http.StatusSeeOther || !strings.HasPrefix(w.Header().Get("Location"), "/login.html?next=") {
		t.Errorf("page logged out: %d %v", w.Code, w.Header())
	}
	for _, p := range []string{"/api/nodes", "/build/x/image.bin"} {
		if w := do(h, req{method: "GET", path: p}); w.Code != http.StatusUnauthorized {
			t.Errorf("GET %s logged out: %d", p, w.Code)
		}
	}
	if w := do(h, req{method: "POST", path: "/api/jobs", body: "{}"}); w.Code != http.StatusUnauthorized {
		t.Errorf("POST logged out: %d", w.Code)
	}
	for _, p := range []string{"/login.html", "/style.css", "/nodes.js", "/api/session"} {
		if w := do(h, req{method: "GET", path: p}); w.Code != http.StatusOK {
			t.Errorf("public %s: %d", p, w.Code)
		}
	}

	// Log in through the API.
	if w := do(h, req{method: "POST", path: "/api/login", body: `{"user":"admin","password":"wrong!!!!!!!!"}`}); w.Code != http.StatusUnauthorized {
		t.Fatalf("bad login: %d", w.Code)
	}
	l := httpLogin(t, h, req{})
	c := l.cookie
	if c.Name != CookiePrefix+"8480" || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" {
		t.Fatalf("cookie %+v", c)
	}
	if l.User != "admin" || l.Token == c.Value {
		t.Fatalf("reply %+v", l)
	}
	ck := []string{c.Value}

	// The cookie alone: the pages and /build/, nothing under /api/ and no change.
	if w := do(h, req{method: "GET", path: "/index.html", cookies: ck}); w.Code != http.StatusOK || w.Body.String() != "ok admin" {
		t.Errorf("page with the cookie: %d %q", w.Code, w.Body)
	}
	if w := do(h, req{method: "GET", path: "/build/x/image.bin", cookies: ck}); w.Code != http.StatusOK {
		t.Errorf("build with the cookie: %d %q", w.Code, w.Body)
	}
	for _, q := range []req{
		{method: "GET", path: "/api/nodes"}, {method: "GET", path: "/api/configs/x.json"},
		{method: "POST", path: "/api/jobs", body: "{}"}, {method: "POST", path: "/index.html"},
		{method: "GET", path: "/api/nodes", token: "wrong"}, {method: "POST", path: "/api/jobs", body: "{}", token: "wrong"},
	} {
		q.cookies = ck
		if w := do(h, q); w.Code != http.StatusUnauthorized {
			t.Errorf("%s %s with the cookie, token %q: %d %s", q.method, q.path, q.token, w.Code, w.Body)
		}
	}
	var st map[string]any
	json.Unmarshal(do(h, req{method: "GET", path: "/api/session", cookies: ck}).Body.Bytes(), &st)
	if st["logged_in"] != false || st["user"] != nil || st["token"] != nil || st["csrf"] != nil {
		t.Errorf("session with the cookie alone: %v", st)
	}
	// The token alone: nothing.
	if w := do(h, req{method: "GET", path: "/api/nodes", token: l.Token}); w.Code != http.StatusUnauthorized {
		t.Errorf("the token alone: %d", w.Code)
	}
	// Both.
	for _, q := range []req{{method: "GET", path: "/api/nodes"}, {method: "POST", path: "/api/jobs", body: "{}"}} {
		q.cookies, q.token = ck, l.Token
		if w := do(h, q); w.Code != http.StatusOK || w.Body.String() != "ok admin" {
			t.Errorf("%s %s with both: %d %q", q.method, q.path, w.Code, w.Body)
		}
	}
	st = nil
	json.Unmarshal(do(h, req{method: "GET", path: "/api/session", cookies: ck, token: l.Token}).Body.Bytes(), &st)
	if st["logged_in"] != true || st["user"] != "admin" || st["token"] != nil || st["version"] != version.Version {
		t.Errorf("session %v", st)
	}
	// Log out: the cookie no longer works.
	if w := do(h, req{method: "POST", path: "/api/logout", cookies: ck, token: l.Token}); w.Code != http.StatusOK {
		t.Fatalf("logout: %d", w.Code)
	}
	if w := do(h, req{method: "GET", path: "/api/nodes", cookies: ck, token: l.Token}); w.Code != http.StatusUnauthorized {
		t.Errorf("after logout: %d", w.Code)
	}
}

// The cookie is named for the port the page came by, so two controllers (or anything else)
// on two ports of one host don't overwrite each other's; a cookie of the name planted by
// another port (before the real one, as a narrower Path puts it) doesn't hide the real one.
func TestCookiePerPort(t *testing.T) {
	for host, want := range map[string]string{"127.0.0.1:8480": "espdns_session_8480", "localhost:1": "espdns_session_1",
		"[::1]:65535": "espdns_session_65535", "127.0.0.1": "espdns_session_80", "localhost:x;y": "espdns_session_80",
		"localhost:99999": "espdns_session_80"} {
		if got := CookieName(host); got != want {
			t.Errorf("CookieName(%q) = %q, want %q", host, got, want)
		}
	}
	a, _, _ := newAuth(t)
	h := guarded(a)
	l := httpLogin(t, h, req{})
	// Another port's cookie: not this one.
	r := httptest.NewRequest("GET", host+"/api/nodes", nil)
	r.AddCookie(&http.Cookie{Name: CookieName("127.0.0.1:9000"), Value: l.cookie.Value})
	r.Header.Set(TokenHeader, l.Token)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("another port's cookie: %d", w.Code)
	}
	// Planted ones first.
	if w := do(h, req{method: "GET", path: "/api/nodes", cookies: []string{"planted", "", l.cookie.Value}, token: l.Token}); w.Code != http.StatusOK {
		t.Errorf("with planted cookies first: %d %s", w.Code, w.Body)
	}
	// Another session's cookie with this session's token: no.
	l2 := httpLogin(t, h, req{})
	if w := do(h, req{method: "GET", path: "/api/nodes", cookies: []string{l2.cookie.Value}, token: l.Token}); w.Code != http.StatusUnauthorized {
		t.Errorf("one session's token with another's cookie: %d", w.Code)
	}
}

// A request with the cookie alone doesn't keep a session alive.
func TestCookieAloneNotSeen(t *testing.T) {
	a, c, _ := newAuth(t)
	tok, s, _ := a.Login("admin", pw, "c")
	c.add(a.Idle - time.Minute)
	if _, ok := a.SessionWith(tok, "wrong"); ok {
		t.Fatal("a wrong page token")
	}
	if _, ok := a.Session(tok); !ok { // a page, by the cookie alone: open, but not seen
		t.Fatal("the cookie alone refused for a page")
	}
	c.add(2 * time.Minute)
	if _, ok := a.SessionWith(tok, s.Token); ok {
		t.Fatal("a wrong page token or the cookie alone kept the session alive")
	}
}

// Without a password set, the controller is read-only: GETs open, every change refused.
func TestGuardNoPassword(t *testing.T) {
	a := New(filepath.Join(t.TempDir(), File))
	mux := http.NewServeMux()
	a.Routes(mux)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	h := a.Guard(mux)
	for _, tc := range []struct {
		method, path string
		code         int
	}{
		{"GET", "/index.html", 200}, {"GET", "/api/nodes", 200}, {"POST", "/api/jobs", 403},
		{"POST", "/api/boards", 403}, {"POST", "/api/login", 403},
		{"POST", "/api/setup/password", 403}, // httptest.NewRequest comes from 192.0.2.1, not this machine
	} {
		r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(`{"user":"admin","password":"`+pw+`"}`))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.code {
			t.Errorf("%s %s: %d, want %d (%s)", tc.method, tc.path, w.Code, tc.code, w.Body)
		}
	}
}

// auth.json opened up to others while the controller runs: refused from the next request
// on (a chmod changes neither its contents nor its mtime); fixed again, used again.
func TestModeChangeSeen(t *testing.T) {
	a, _, path := newAuth(t)
	tok, _, err := a.Login("admin", pw, "c")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := a.Session(tok); ok {
		t.Fatal("a session of an auth.json open to others")
	}
	if _, _, err := a.Login("admin", pw, "c"); err == nil || errors.Is(err, ErrBadLogin) {
		t.Fatalf("a login with an auth.json open to others: %v", err)
	}
	os.Chmod(path, 0o600)
	if _, _, err := a.Login("admin", pw, "c"); err != nil {
		t.Fatalf("fixed: %v", err)
	}
}

// A login ends the session the browser had before; the new token is a new one.
func TestLoginEndsOldSession(t *testing.T) {
	a, _, _ := newAuth(t)
	h := guarded(a)
	first := httpLogin(t, h, req{}).cookie.Value
	second := httpLogin(t, h, req{cookies: []string{"planted", first}}).cookie.Value
	if first == second {
		t.Fatal("the same token twice")
	}
	if _, ok := a.Session(first); ok {
		t.Error("the session before a login lives on")
	}
	if _, ok := a.Session(second); !ok {
		t.Error("the new session isn't one")
	}
}

// Public is only for clean paths: one with dot segments or double slashes is not public
// (the mux redirects it to the clean path, which is checked again).
func TestPublicClean(t *testing.T) {
	for p, want := range map[string]bool{"/common.js": true, "/login.html": true, "/x/style.css": true,
		"/./api/nodes.js": false, "//api/key.js": false, "/a/../api/key.js": false, "/api/key.js": false,
		"/build/x.js": false, "/index.html": false, "/api/session": true, "/api/session/": false} {
		if Public(p) != want {
			t.Errorf("Public(%q) = %v", p, !want)
		}
	}
}

// One client's failed logins lock out that client, not another.
func TestBackoffPerClient(t *testing.T) {
	a, _, _ := newAuth(t)
	for range freeFails + 3 {
		a.Login("admin", "nope nope nope", "attacker")
	}
	var be BackoffError
	if _, _, err := a.Login("admin", pw, "attacker"); !errors.As(err, &be) {
		t.Fatalf("the attacker isn't backed off: %v", err)
	}
	if _, _, err := a.Login("admin", pw, "admin's browser"); err != nil {
		t.Fatalf("another client locked out: %v", err)
	}
	// The attacker is still backed off: another's login doesn't reset it.
	if _, _, err := a.Login("admin", pw, "attacker"); !errors.As(err, &be) {
		t.Fatalf("the attacker's count reset by another's login: %v", err)
	}
}

// Past maxClients the rest are counted together: a client can't get a fresh count by
// coming as many; old counts past failForget are dropped to make room.
func TestBackoffClientsBounded(t *testing.T) {
	a, c, _ := newAuth(t)
	for i := range maxClients {
		a.Login("admin", "nope", fmt.Sprint("client ", i))
	}
	if n := len(a.clients); n != maxClients {
		t.Fatalf("%d clients counted", n)
	}
	var be BackoffError
	for i := range freeFails {
		if _, _, err := a.Login("admin", "nope", fmt.Sprint("new ", i)); !errors.Is(err, ErrBadLogin) {
			t.Fatalf("new %d: %v", i, err)
		}
	}
	if _, _, err := a.Login("admin", pw, "yet another"); !errors.As(err, &be) {
		t.Fatalf("the overflow isn't counted together: %v", err)
	}
	if len(a.clients) != maxClients+1 {
		t.Fatalf("%d clients counted, want %d", len(a.clients), maxClients+1)
	}
	// One counted apart before still has its own.
	if _, _, err := a.Login("admin", pw, "client 7"); err != nil {
		t.Fatalf("a client counted apart: %v", err)
	}
	// Past failForget, the old ones make room.
	c.add(failForget + backoffMax)
	if _, _, err := a.Login("admin", "nope", "fresh"); !errors.Is(err, ErrBadLogin) {
		t.Fatal(err)
	}
	if _, ok := a.clients["fresh"]; !ok {
		t.Fatalf("no room made: %d counted", len(a.clients))
	}
}

// Device tokens: only this run's are taken; a new Auth (a restart) takes none of the old.
func TestDeviceTokens(t *testing.T) {
	a, _, _ := newAuth(t)
	d := a.DeviceToken("")
	if a.Device(d) == "" || a.DeviceToken(d) != d {
		t.Fatalf("own token %q not taken", d)
	}
	id, _, _ := strings.Cut(d, ".")
	for _, bad := range []string{"", "x", id, id + ".", id + ".AAAA", "." + d, New(a.path).DeviceToken("")} {
		if a.Device(bad) != "" {
			t.Errorf("%q taken", bad)
		}
		if a.DeviceToken(bad) == bad {
			t.Errorf("%q kept", bad)
		}
	}
	if a.DeviceToken("") == d {
		t.Error("two new tokens the same")
	}
}

// Over HTTP: failures from the address back that address off; a browser with its device
// token (from a login that worked before) has its own count and still logs in.
func TestLoginBackoffHTTP(t *testing.T) {
	a, _, _ := newAuth(t)
	h := guarded(a)
	mine := httpLogin(t, h, req{}).Device
	var last *httptest.ResponseRecorder
	for range freeFails + 1 {
		last = do(h, req{method: "POST", path: "/api/login", body: `{"user":"admin","password":"nope nope nope"}`})
	}
	if last.Code != http.StatusTooManyRequests || last.Header().Get("Retry-After") != "1" {
		t.Fatalf("after %d failures: %d %v", freeFails+1, last.Code, last.Header())
	}
	// A made-up device token is the address.
	if w := do(h, req{method: "POST", path: "/api/login", device: "made.up", body: `{"user":"admin","password":"` + pw + `"}`}); w.Code != http.StatusTooManyRequests {
		t.Fatalf("a made-up device: %d", w.Code)
	}
	// The browser's own: logs in, and keeps its token.
	if l := httpLogin(t, h, req{device: mine}); l.Device != mine {
		t.Fatalf("device token changed: %q, was %q", l.Device, mine)
	}
	r := httptest.NewRequest("POST", host+"/api/login", strings.NewReader(`{"user":"admin","password":"x"}`))
	r.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("login not as JSON: %d", w.Code)
	}
}

// Addresses as the backoff counts them: all of loopback one client (a local process can
// send from any 127.x address, which counted apart would be maxClients counts for it), an
// IPv6 address by its /64.
func TestAddressKey(t *testing.T) {
	for _, c := range []struct{ remote, want string }{
		{"127.0.0.1:5000", "address loopback"},
		{"127.0.0.2:5000", "address loopback"},
		{"127.255.3.9:1", "address loopback"},
		{"[::1]:5000", "address loopback"},
		{"[::ffff:127.0.0.7]:5000", "address loopback"},
		{"192.0.2.7:5000", "address 192.0.2.7"},
		{"[::ffff:192.0.2.7]:5000", "address 192.0.2.7"},
		{"[2001:db8::1]:5000", "address 2001:db8::/64"},
		{"[2001:db8::ffff:1]:5000", "address 2001:db8::/64"},
		{"[2001:db8:0:1::1]:5000", "address 2001:db8:0:1::/64"},
		{"pipe", "address pipe"},
	} {
		if got := addressKey(c.remote); got != c.want {
			t.Errorf("%s: %q, want %q", c.remote, got, c.want)
		}
	}
	// Over HTTP: failures from 127.0.0.2..5 back off 127.0.0.1 too.
	a, _, _ := newAuth(t)
	h := guarded(a)
	for i := range freeFails + 1 {
		r := httptest.NewRequest("POST", host+"/api/login", strings.NewReader(`{"user":"admin","password":"nope nope nope"}`))
		r.Header.Set("Content-Type", "application/json")
		r.RemoteAddr = fmt.Sprintf("127.0.0.%d:4000", i+2)
		h.ServeHTTP(httptest.NewRecorder(), r)
	}
	r := httptest.NewRequest("POST", host+"/api/login", strings.NewReader(`{"user":"admin","password":"`+pw+`"}`))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = "127.0.0.1:4000"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("loopback counted apart by address: %d", w.Code)
	}
	if n := len(a.clients); n != 1 {
		t.Fatalf("%d clients counted, want 1", n)
	}
}

// Re-authentication: the password gives a grant, good once and for ReauthTTL; wrong ones
// give none, and reauthTries in a row end the session.
func TestReauth(t *testing.T) {
	a, c, _ := newAuth(t)
	tok, _, _ := a.Login("admin", pw, "c")
	if a.UseReauth(tok, "") || a.UseReauth(tok, "anything") {
		t.Fatal("a grant before any")
	}
	g, until, err := a.Reauth(tok, pw)
	if err != nil || g == "" || !until.Equal(c.now().Add(ReauthTTL)) {
		t.Fatalf("reauth: %q %v %v", g, until, err)
	}
	if a.UseReauth("other", g) || a.UseReauth(tok, g+"x") {
		t.Fatal("a wrong grant or session")
	}
	if !a.UseReauth(tok, g) {
		t.Fatal("the grant refused")
	}
	if a.UseReauth(tok, g) {
		t.Fatal("a grant used twice")
	}
	// Past its time.
	g, _, _ = a.Reauth(tok, pw)
	c.add(ReauthTTL)
	if a.UseReauth(tok, g) {
		t.Fatal("a grant past ReauthTTL")
	}
	// A wrong password closes an open grant and counts; a good one resets the count.
	g, _, _ = a.Reauth(tok, pw)
	if _, _, err := a.Reauth(tok, "nope nope nope"); !errors.Is(err, ErrBadPassword) {
		t.Fatal(err)
	}
	if a.UseReauth(tok, g) {
		t.Fatal("a grant open after a wrong password")
	}
	for range reauthTries - 2 {
		a.Reauth(tok, "nope nope nope")
	}
	if _, _, err := a.Reauth(tok, pw); err != nil { // reauthTries-1 wrong, then a good one
		t.Fatal(err)
	}
	for i := range reauthTries {
		_, _, err := a.Reauth(tok, "nope nope nope")
		if want := ErrBadPassword; i == reauthTries-1 {
			if !errors.Is(err, ErrReauthEnded) {
				t.Fatalf("wrong %d: %v", i+1, err)
			}
		} else if !errors.Is(err, want) {
			t.Fatalf("wrong %d: %v", i+1, err)
		}
	}
	if _, ok := a.Session(tok); ok {
		t.Fatal("the session lives after reauthTries wrong passwords")
	}
	if _, _, err := a.Reauth(tok, pw); !errors.Is(err, ErrReauthEnded) {
		t.Fatalf("reauth of an ended session: %v", err)
	}
}

// Over HTTP: POST /api/reauth needs the session (both halves), and Reauthed lets a request
// through only with a grant.
func TestReauthHTTP(t *testing.T) {
	a, _, _ := newAuth(t)
	h := guarded(a, func(m *http.ServeMux) {
		m.HandleFunc("POST /api/secret", a.Reauthed(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("secret")) }))
	})
	l := httpLogin(t, h, req{})
	ck := []string{l.cookie.Value}
	body := `{"password":"` + pw + `"}`
	if w := do(h, req{method: "POST", path: "/api/reauth", body: body, cookies: ck}); w.Code != http.StatusUnauthorized {
		t.Fatalf("reauth with the cookie alone: %d", w.Code)
	}
	if w := do(h, req{method: "POST", path: "/api/secret", cookies: ck, token: l.Token}); w.Code != http.StatusForbidden ||
		!strings.Contains(w.Body.String(), `"reauth":true`) {
		t.Fatalf("without a grant: %d %s", w.Code, w.Body)
	}
	w := do(h, req{method: "POST", path: "/api/reauth", body: `{"password":"nope nope nope"}`, cookies: ck, token: l.Token})
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), `"reauth":true`) {
		t.Fatalf("a wrong password: %d %s", w.Code, w.Body)
	}
	w = do(h, req{method: "POST", path: "/api/reauth", body: body, cookies: ck, token: l.Token})
	var g struct{ Reauth string }
	json.Unmarshal(w.Body.Bytes(), &g)
	if w.Code != http.StatusOK || g.Reauth == "" {
		t.Fatalf("reauth: %d %s", w.Code, w.Body)
	}
	if w := do(h, req{method: "POST", path: "/api/secret", cookies: ck, token: l.Token, reauth: g.Reauth}); w.Code != http.StatusOK || w.Body.String() != "secret" {
		t.Fatalf("with the grant: %d %s", w.Code, w.Body)
	}
	if w := do(h, req{method: "POST", path: "/api/secret", cookies: ck, token: l.Token, reauth: g.Reauth}); w.Code != http.StatusForbidden {
		t.Fatalf("the grant again: %d %s", w.Code, w.Body)
	}
	// Wrong passwords end the session; its cookie is cleared.
	for range reauthTries {
		w = do(h, req{method: "POST", path: "/api/reauth", body: `{"password":"nope nope nope"}`, cookies: ck, token: l.Token})
	}
	if w.Code != http.StatusUnauthorized || len(w.Result().Cookies()) != 1 || w.Result().Cookies()[0].MaxAge >= 0 {
		t.Fatalf("after %d wrong: %d %v", reauthTries, w.Code, w.Result().Cookies())
	}
	if w := do(h, req{method: "GET", path: "/api/nodes", cookies: ck, token: l.Token}); w.Code != http.StatusUnauthorized {
		t.Fatalf("the session after: %d", w.Code)
	}
}
