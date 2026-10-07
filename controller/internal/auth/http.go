package auth

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/version"
)

// The API:
//
//	GET  /api/session   {"password_set", "logged_in", "user", "expires", "error", "version"}:
//	                    public; "version", the controller's (internal/version)
//	POST /api/login     {"user", "password"} (JSON): sets the session cookie, and answers
//	                    {"user", "token", "device", "expires"}; public
//	POST /api/logout    ends the session
//	POST /api/reauth    {"password"} (JSON): the password again, for what needs it (a
//	                    backup, a config's Wi-Fi password shown): {"reauth", "expires"},
//	                    a grant sent once in X-Reauth
//	POST /api/setup/password
//	                    {"user", "password"} (JSON; "user" "": admin): the first run's
//	                    password, set from the browser only while none is set and only by a
//	                    client on this machine; logs in as /api/login does; public
//
// A session has two halves. The cookie is HttpOnly (no script reads it), SameSite=Strict
// (no other site's page sends it) and named for the port the page came by
// (espdns_session_8480), not Secure: the controller is plain HTTP on localhost. But a
// browser keeps cookies by host, not port: whatever else listens on another localhost port
// gets this cookie when the browser goes there, and can set one of this name. So the
// cookie alone opens only the pages and /build/ (no data). The other half, the session's
// token, the login gives to the page, which keeps it in its origin's localStorage (the
// origin has the port: another port can't read it) and sends it in X-Session-Token with
// every request under /api/ and every one that changes something. A page elsewhere can't
// send that header either (a custom header needs CORS, which the controller never answers);
// LocalOnly (internal/jobs) also checks Host and Origin in front of this. A cookie planted
// by another port under this name is passed over: every cookie of the name is tried.
//
// Failed logins back off per client: a browser by the device token the login page keeps
// (one this run of the controller made, sent in X-Login-Device), else by its address, all
// of loopback as one (addressKey).

// CookiePrefix is the session cookie's name before the port.
const CookiePrefix = "espdns_session_"

// CookieName is the session cookie's name for the Host a request came by: the prefix and
// the port (80 when none is given).
func CookieName(host string) string {
	port := "80"
	if _, p, err := net.SplitHostPort(host); err == nil && p != "" {
		if _, err := strconv.ParseUint(p, 10, 16); err == nil {
			port = p
		}
	}
	return CookiePrefix + port
}

// TokenHeader carries the session's token on every API request and every change.
const TokenHeader = "X-Session-Token"

// DeviceHeader carries the login page's device token with a login.
const DeviceHeader = "X-Login-Device"

// ReauthHeader carries a re-authentication grant (POST /api/reauth) to what needs one.
const ReauthHeader = "X-Reauth"

type ctxKey struct{}

// ctxSession is a request's session and its cookie's token.
type ctxSession struct {
	cookie string
	s      Session
}

// User is the logged-in user of a request through Guard, or "".
func User(ctx context.Context) string {
	c, _ := ctx.Value(ctxKey{}).(ctxSession)
	return c.s.User
}

func withSession(r *http.Request, cookie string, s Session) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), ctxKey{}, ctxSession{cookie, s}))
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("write json: %v", err)
	}
}

func httpError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// fromRequest is the request's session: by any cookie of the name for its port (one planted
// by another port doesn't hide the real one), with the page's token when withToken.
func (a *Auth) fromRequest(r *http.Request, withToken bool) (string, Session, bool) {
	name, tok := CookieName(r.Host), r.Header.Get(TokenHeader)
	for _, c := range r.Cookies() {
		if c.Name != name {
			continue
		}
		var s Session
		var ok bool
		if withToken {
			s, ok = a.SessionWith(c.Value, tok)
		} else {
			s, ok = a.Session(c.Value)
		}
		if ok {
			return c.Value, s, true
		}
	}
	return "", Session{}, false
}

// needsToken: the API, and anything that changes something, needs the page's token besides
// the cookie.
func needsToken(r *http.Request) bool {
	return strings.HasPrefix(r.URL.Path, "/api/") || !safe(r.Method)
}

func safe(method string) bool { return method == http.MethodGet || method == http.MethodHead }

// Public paths need no session: the login page and what it loads, and the login API.
var publicPaths = map[string]bool{
	"/login.html": true, "/style.css": true, "/common.js": true,
	"/api/session": true, "/api/login": true, "/api/setup/password": true,
}

// Public says whether path is open without a session: the login page and its assets, the
// login API (the first run's password too: it refuses once one is set), and the static
// scripts and styles (code from the repo, no data).
func Public(p string) bool {
	if path.Clean(p) != p { // "/./api/x.js": the mux sends it to the clean path, checked again
		return false
	}
	return publicPaths[p] || !strings.HasPrefix(p, "/api/") && !strings.HasPrefix(p, "/build/") &&
		(strings.HasSuffix(p, ".js") || strings.HasSuffix(p, ".css"))
}

// Guard puts the login in front of next:
//   - Public paths: open.
//   - A session: the cookie, and the page's token for the API and anything not GET or HEAD.
//   - No password set yet: read-only. GET and HEAD open (as before the login), anything
//     else refused (403) saying how to set one.
//   - Else: the API (/api/, /build/) and anything not GET answer 401; a page redirects to
//     the login page.
func (a *Auth) Guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if Public(r.URL.Path) {
			if c, s, ok := a.fromRequest(r, needsToken(r)); ok {
				r = withSession(r, c, s)
			}
			next.ServeHTTP(w, r)
			return
		}
		if c, s, ok := a.fromRequest(r, needsToken(r)); ok {
			next.ServeHTTP(w, withSession(r, c, s))
			return
		}
		set, _ := a.State()
		if !set {
			if safe(r.Method) {
				next.ServeHTTP(w, r)
				return
			}
			httpError(w, http.StatusForbidden, "read-only: "+ErrNoPassword.Error())
			return
		}
		p := r.URL.Path
		if strings.HasPrefix(p, "/api/") || strings.HasPrefix(p, "/build/") || !safe(r.Method) {
			httpError(w, http.StatusUnauthorized, "log in first (a session's cookie and its "+TokenHeader+")")
			return
		}
		http.Redirect(w, r, "/login.html?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
	})
}

// Reauthed puts the password asked again in front of h: the request carries a grant from
// POST /api/reauth in X-Reauth, used once. Without one it answers 403 {"reauth": true},
// which the page answers by asking for the password. Behind Guard (a session).
func (a *Auth) Reauthed(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if a.TakeReauth(w, r) {
			h(w, r)
		}
	}
}

// TakeReauth is Reauthed inside a handler, for a request that needs the password again
// only sometimes (a config shown with its Wi-Fi password): it uses the request's grant and
// says true, or answers 403 {"reauth": true} and says false.
func (a *Auth) TakeReauth(w http.ResponseWriter, r *http.Request) bool {
	c, _ := r.Context().Value(ctxKey{}).(ctxSession)
	if !a.UseReauth(c.cookie, r.Header.Get(ReauthHeader)) {
		writeJSON(w, http.StatusForbidden, map[string]any{"reauth": true,
			"error": "this needs your password again (POST /api/reauth, then its grant in " + ReauthHeader + ")"})
		return false
	}
	log.Printf("reauth: %s used a grant for %s %s", c.s.User, r.Method, r.URL.Path)
	return true
}

// Routes adds the login API to mux.
func (a *Auth) Routes(mux interface {
	HandleFunc(string, func(http.ResponseWriter, *http.Request))
}) {
	mux.HandleFunc("GET /api/session", a.handleSession)
	mux.HandleFunc("POST /api/login", a.handleLogin)
	mux.HandleFunc("POST /api/logout", a.handleLogout)
	mux.HandleFunc("POST /api/reauth", a.handleReauth)
	mux.HandleFunc("POST /api/setup/password", a.handleFirstPassword)
}

func (a *Auth) handleSession(w http.ResponseWriter, r *http.Request) {
	set, err := a.State()
	out := map[string]any{"password_set": set, "logged_in": false, "version": version.Version}
	if err != nil {
		out["error"] = err.Error()
	}
	if _, s, ok := a.fromRequest(r, true); ok {
		out["logged_in"], out["user"], out["expires"] = true, s.User, s.Expires(a)
	}
	writeJSON(w, http.StatusOK, out)
}

// clientKey is who a login's failures count against: the browser, by a device token this
// run made, else the address it came from (addressKey).
func (a *Auth) clientKey(r *http.Request) string {
	if id := a.Device(r.Header.Get(DeviceHeader)); id != "" {
		return "device " + id
	}
	return addressKey(r.RemoteAddr)
}

// addressKey is a client's address as the backoff counts it: loopback is one client (any
// local process can send from any of 127.0.0.0/8, so counting those apart would give it
// maxClients counts and the overflow), an IPv6 address by its /64 (one host has them all),
// any other by itself.
func addressKey(remote string) string {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return "address " + host
	}
	ip = ip.Unmap()
	switch {
	case ip.IsLoopback():
		return "address loopback"
	case ip.Is6():
		p, _ := ip.Prefix(64)
		return "address " + p.String()
	}
	return "address " + ip.String()
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt != "application/json" {
		httpError(w, http.StatusForbidden, "send JSON (Content-Type: application/json)")
		return false
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(v); err != nil {
		httpError(w, http.StatusBadRequest, "bad request")
		return false
	}
	return true
}

func (a *Auth) cookie(r *http.Request, value string, maxAge int) *http.Cookie {
	return &http.Cookie{Name: CookieName(r.Host), Value: value, Path: "/", HttpOnly: true,
		SameSite: http.SameSiteStrictMode, MaxAge: maxAge}
}

func (a *Auth) handleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		User     string `json:"user"`
		Password string `json:"password"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	t, s, err := a.Login(body.User, body.Password, a.clientKey(r))
	var be BackoffError
	switch {
	case errors.As(err, &be):
		w.Header().Set("Retry-After", strconv.Itoa(int((be.Wait+time.Second-1)/time.Second)))
		httpError(w, http.StatusTooManyRequests, err.Error())
		return
	case errors.Is(err, ErrBadLogin):
		log.Printf("login: failed from %s", r.RemoteAddr) // not the user given: it may be a password typed in the wrong box
		httpError(w, http.StatusUnauthorized, err.Error())
		return
	case err != nil:
		httpError(w, http.StatusForbidden, err.Error())
		return
	}
	log.Printf("login: %s from %s", s.User, r.RemoteAddr)
	a.startSession(w, r, t, s)
}

// startSession answers a login: the session's cookie, and the page's half of it.
func (a *Auth) startSession(w http.ResponseWriter, r *http.Request, t string, s Session) {
	name := CookieName(r.Host)
	for _, old := range r.Cookies() {
		if old.Name == name {
			a.Logout(old.Value) // a session the browser had before ends: one cookie, one session
		}
	}
	http.SetCookie(w, a.cookie(r, t, int(a.Max/time.Second)))
	writeJSON(w, http.StatusOK, map[string]any{"user": s.User, "token": s.Token,
		"device": a.DeviceToken(r.Header.Get(DeviceHeader)), "expires": s.Expires(a)})
}

// handleFirstPassword sets the first password from the browser, the first run's first
// step: while none is set only (409 after, whatever the request), from a client on this
// machine only (a loopback address: the controller listens on loopback, so this holds
// unless something on the machine relays to it), besides LocalOnly's localhost Host and no
// other site's Origin in front, and JSON. Of two at once only one is set (CreatePassword);
// the other is refused as any request once a password is set. Then it logs in, as
// /api/login does. A password set by `espdns passwd` meanwhile wins the same way.
func (a *Auth) handleFirstPassword(w http.ResponseWriter, r *http.Request) {
	if set, _ := a.State(); set {
		httpError(w, http.StatusConflict, ErrPasswordSet.Error())
		return
	}
	if !loopbackClient(r.RemoteAddr) {
		httpError(w, http.StatusForbidden, "the first password is set from the controller's own machine only")
		return
	}
	var body struct {
		User     string `json:"user"`
		Password string `json:"password"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if body.User == "" {
		body.User = DefaultUser
	}
	if err := CheckUser(body.User); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "user: " + err.Error(), "field": "user"})
		return
	}
	if err := CheckPassword(body.Password); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "password: " + err.Error(), "field": "password"})
		return
	}
	a.verify.Lock() // one password hash at a time, as the logins
	err := CreatePassword(a.path, body.User, body.Password)
	a.verify.Unlock()
	switch {
	case errors.Is(err, ErrPasswordSet):
		httpError(w, http.StatusConflict, err.Error())
		return
	case err != nil:
		log.Printf("first run: password not set: %v", err)
		httpError(w, http.StatusInternalServerError, "the password could not be saved: "+err.Error())
		return
	}
	log.Printf("first run: password set for %s from %s", body.User, r.RemoteAddr)
	t, s, err := a.Login(body.User, body.Password, a.clientKey(r))
	if err != nil {
		httpError(w, http.StatusInternalServerError, "the password is set, but the login failed: "+err.Error())
		return
	}
	a.startSession(w, r, t, s)
}

// loopbackClient: a request from a loopback address.
func loopbackClient(remote string) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.Unmap().IsLoopback()
}

func (a *Auth) handleLogout(w http.ResponseWriter, r *http.Request) {
	if t, s, ok := a.fromRequest(r, true); ok {
		a.Logout(t)
		log.Printf("logout: %s", s.User)
	}
	http.SetCookie(w, a.cookie(r, "", -1))
	writeJSON(w, http.StatusOK, map[string]any{"logged_in": false})
}

func (a *Auth) handleReauth(w http.ResponseWriter, r *http.Request) {
	c, _ := r.Context().Value(ctxKey{}).(ctxSession)
	if c.cookie == "" {
		httpError(w, http.StatusUnauthorized, "log in first")
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	g, until, err := a.Reauth(c.cookie, body.Password)
	switch {
	case errors.Is(err, ErrBadPassword):
		log.Printf("reauth: %s: wrong password from %s", c.s.User, r.RemoteAddr)
		writeJSON(w, http.StatusForbidden, map[string]any{"reauth": true, "error": err.Error()})
		return
	case errors.Is(err, ErrReauthEnded):
		log.Printf("reauth: %s: session ended after wrong passwords, from %s", c.s.User, r.RemoteAddr)
		http.SetCookie(w, a.cookie(r, "", -1))
		httpError(w, http.StatusUnauthorized, err.Error())
		return
	case err != nil:
		httpError(w, http.StatusForbidden, err.Error())
		return
	}
	log.Printf("reauth: %s from %s", c.s.User, r.RemoteAddr)
	writeJSON(w, http.StatusOK, map[string]any{"reauth": g, "expires": until})
}
