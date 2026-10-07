package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"sync"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/secfile"
)

// Session lifetimes: a session ends after Idle without a request, and Max after its login
// whatever happens. Sessions are in memory only: a restarted controller asks again.
const (
	DefaultIdle = 2 * time.Hour
	DefaultMax  = 12 * time.Hour
	maxSessions = 32 // the oldest goes past this
)

// Backoff after failed logins, per client (clientKey in http.go: a browser by its device
// token, else the address): the first freeFails in a row cost nothing; each one after locks
// that client's logins for backoffBase, doubling up to backoffMax. A login that works, or
// failForget with no failure, starts its count over. One client's failures never lock
// another out; at most maxClients are counted apart, the rest together.
const (
	freeFails   = 3
	backoffBase = time.Second
	backoffMax  = time.Minute
	failForget  = 15 * time.Minute
	maxClients  = 256
	overflow    = "\x00overflow" // the clients past maxClients, counted together
)

// Re-authentication: what needs the password again (a backup: it holds the release key and
// the Wi-Fi passwords) takes a grant from Reauth, used once, within ReauthTTL. reauthTries
// wrong passwords in a row end the session, so a taken session can't guess the password.
const (
	ReauthTTL   = 2 * time.Minute
	reauthTries = 3
)

var (
	// ErrNoPassword: no password is set; nobody can log in (the first run in the browser,
	// or espdns passwd, sets one).
	ErrNoPassword = errors.New("no password is set: set one in the browser (the first run) or with espdns passwd (docs/getting-started.md, step 6)")
	// ErrBadLogin: the user or the password is wrong (which, isn't said).
	ErrBadLogin = errors.New("wrong user or password")
	// ErrBadPassword: a re-authentication's password is wrong.
	ErrBadPassword = errors.New("wrong password")
	// ErrReauthEnded: too many wrong passwords in a row for one session, now ended.
	ErrReauthEnded = errors.New("wrong password too many times: the session is ended, log in again")
)

// BackoffError: logins are refused for Wait after failed ones.
type BackoffError struct{ Wait time.Duration }

func (e BackoffError) Error() string {
	return fmt.Sprintf("too many failed logins: try again in %d s", int((e.Wait+time.Second-1)/time.Second))
}

// Session is a logged-in user. It has two halves: the cookie's token (HttpOnly, kept by
// the browser for the host, so every port of it gets it) and Token, which only the page
// holds (in its origin's storage, which another port can't read) and sends in TokenHeader
// with every API request. The cookie alone gets no data and changes nothing.
type Session struct {
	User    string
	Token   string
	Created time.Time
	Seen    time.Time
	hash    string // the password hash it logged in with: a new password ends it

	reauth      string // the SHA-256 of its re-authentication grant, if one is open
	reauthUntil time.Time
	reauthFails int
}

// Expires is when the session ends without another request.
func (s Session) Expires(a *Auth) time.Time {
	return minTime(s.Seen.Add(a.Idle), s.Created.Add(a.Max))
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// fails is one client's run of failed logins.
type fails struct {
	n        int
	lastFail time.Time
	until    time.Time // no login before this
}

// Auth is the login: the user and password hash from auth.json (read again whenever the
// file changes, so `espdns passwd` works while the controller runs), and the sessions.
type Auth struct {
	path      string
	Idle, Max time.Duration
	now       func() time.Time
	secret    []byte // this run's: signs the device tokens, which die with it

	mu       sync.Mutex
	cfg      Config
	cfgErr   error // fs.ErrNotExist: no password set
	cfgStamp secfile.Stamp
	cfgRead  bool
	sessions map[string]*Session // by the SHA-256 of the cookie's token
	clients  map[string]*fails   // by client (clientKey)
	verify   sync.Mutex          // one password hash at a time
}

// New is the login kept in path (auth.json).
func New(path string) *Auth {
	secret := make([]byte, 32)
	rand.Read(secret)
	return &Auth{path: path, Idle: DefaultIdle, Max: DefaultMax, now: time.Now, secret: secret,
		sessions: map[string]*Session{}, clients: map[string]*fails{}}
}

// config is auth.json as it is now, read again if it changed: written, replaced, or its
// mode or owner changed (a file opened up to others is refused from then on). Called with
// a.mu held.
func (a *Auth) config() (Config, error) {
	if st := secfile.StampOf(a.path); !a.cfgRead || st != a.cfgStamp {
		a.cfgStamp, a.cfgRead = st, true
		a.cfg, a.cfgErr = Load(a.path)
	}
	return a.cfg, a.cfgErr
}

// State says whether a password is set (auth.json is there, usable or not) and, if it
// can't be used, why.
func (a *Auth) State() (set bool, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	_, err = a.config()
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return true, err
}

func token() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func tokenKey(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

// A device token names a browser that logged in during this run: "<id>.<HMAC of id>", kept
// by the login page in its origin's storage and sent with each login, so that browser's
// failed logins are counted apart from everyone else's. Only this controller makes one
// (one is handed out at each login), so a client can't make up as many as it likes.
func (a *Auth) deviceMAC(id string) string {
	m := hmac.New(sha256.New, a.secret)
	m.Write([]byte(id))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// Device is the id of a device token this run made, or "".
func (a *Auth) Device(t string) string {
	id, mac, ok := strings.Cut(t, ".")
	if !ok || id == "" || !hmac.Equal([]byte(mac), []byte(a.deviceMAC(id))) {
		return ""
	}
	return id
}

// DeviceToken is t if it is a device token of this run, else a new one.
func (a *Auth) DeviceToken(t string) string {
	if a.Device(t) != "" {
		return t
	}
	id := token()[:22]
	return id + "." + a.deviceMAC(id)
}

// Login checks the user and password for a client (clientKey), and starts a session: its
// cookie token and the session. Failed logins back off, the client's own (BackoffError);
// one password is checked at a time.
func (a *Auth) Login(user, password, client string) (string, Session, error) {
	if err := a.backoff(client); err != nil {
		return "", Session{}, err
	}
	a.verify.Lock()
	defer a.verify.Unlock()
	if err := a.backoff(client); err != nil { // a login that failed while this one waited
		return "", Session{}, err
	}
	a.mu.Lock()
	cfg, err := a.config()
	a.mu.Unlock()
	if errors.Is(err, fs.ErrNotExist) {
		return "", Session{}, ErrNoPassword
	}
	if err != nil {
		return "", Session{}, fmt.Errorf("the login can't be used: %v", err)
	}
	ok, err := Verify(cfg.Hash, password)
	if err != nil {
		return "", Session{}, fmt.Errorf("the login can't be used: %s: %v", a.path, err)
	}
	userOK := subtle.ConstantTimeCompare([]byte(user), []byte(cfg.User)) == 1
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	if !ok || !userOK {
		f := a.failsLocked(client, true)
		if now.Sub(f.lastFail) > failForget {
			f.n = 0
		}
		f.n++
		f.lastFail = now
		if f.n >= freeFails {
			f.until = now.Add(min(backoffBase<<min(f.n-freeFails, 10), backoffMax))
		}
		return "", Session{}, ErrBadLogin
	}
	if f := a.failsLocked(client, false); f != nil {
		*f = fails{}
	}
	t := token()
	s := &Session{User: cfg.User, Token: token(), Created: now, Seen: now, hash: cfg.Hash}
	a.expireLocked(now)
	for len(a.sessions) >= maxSessions {
		var oldest string
		for k, v := range a.sessions {
			if oldest == "" || v.Seen.Before(a.sessions[oldest].Seen) {
				oldest = k
			}
		}
		delete(a.sessions, oldest)
	}
	a.sessions[tokenKey(t)] = s
	return t, *s, nil
}

// failsLocked is the count of client's failed logins: its own, or the overflow's once
// maxClients others are counted (those past failForget and their wait are dropped first).
// With add, one is made if there is none.
func (a *Auth) failsLocked(client string, add bool) *fails {
	if f := a.clients[client]; f != nil {
		return f
	}
	now := a.now()
	if add && a.countedLocked() >= maxClients {
		for k, f := range a.clients {
			if k != overflow && now.Sub(f.lastFail) > failForget && !now.Before(f.until) {
				delete(a.clients, k)
			}
		}
	}
	if a.countedLocked() >= maxClients {
		client = overflow
		if f := a.clients[overflow]; f != nil {
			return f
		}
	}
	if !add {
		return nil
	}
	f := &fails{}
	a.clients[client] = f
	return f
}

// countedLocked is how many clients are counted apart.
func (a *Auth) countedLocked() int {
	if _, ok := a.clients[overflow]; ok {
		return len(a.clients) - 1
	}
	return len(a.clients)
}

// backoff is the BackoffError while client's logins are refused.
func (a *Auth) backoff(client string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if f := a.failsLocked(client, false); f != nil {
		if w := f.until.Sub(a.now()); w > 0 {
			return BackoffError{w}
		}
	}
	return nil
}

// expireLocked drops the sessions past their time.
func (a *Auth) expireLocked(now time.Time) {
	for k, s := range a.sessions {
		if !now.Before(s.Expires(a)) {
			delete(a.sessions, k)
		}
	}
}

// Session is the session of a cookie's token, if it is one, not past its time, and of
// the password set now. The cookie alone: for the pages and /build/, which hold no data
// (SessionWith for the API). It doesn't count as a request (Seen): whatever else on the
// host took the cookie can't keep the session from going idle.
func (a *Auth) Session(t string) (Session, bool) {
	return a.lookup(t, nil)
}

// SessionWith is Session for a cookie's token and the page's token both; it counts as a
// request (Seen).
func (a *Auth) SessionWith(t, pageToken string) (Session, bool) {
	return a.lookup(t, &pageToken)
}

func (a *Auth) lookup(t string, pageToken *string) (Session, bool) {
	if t == "" {
		return Session{}, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	s, ok := a.liveLocked(t)
	if !ok || pageToken != nil && subtle.ConstantTimeCompare([]byte(*pageToken), []byte(s.Token)) != 1 {
		return Session{}, false
	}
	if pageToken != nil { // the cookie alone (another port may have it) keeps no session alive
		s.Seen = a.now()
	}
	return *s, true
}

// liveLocked is the session of a cookie's token if it is still good (dropped if not).
func (a *Auth) liveLocked(t string) (*Session, bool) {
	k := tokenKey(t)
	s := a.sessions[k]
	if s == nil {
		return nil, false
	}
	cfg, err := a.config()
	if err != nil || cfg.Hash != s.hash || !a.now().Before(s.Expires(a)) {
		delete(a.sessions, k)
		return nil, false
	}
	return s, true
}

// Reauth checks the password again for the session of a cookie's token, and opens a
// grant for one request that needs it (UseReauth) within ReauthTTL: the grant and when it
// ends. A wrong password is ErrBadPassword; the reauthTries-th in a row ends the session
// (ErrReauthEnded).
func (a *Auth) Reauth(t, password string) (string, time.Time, error) {
	a.verify.Lock()
	defer a.verify.Unlock()
	a.mu.Lock()
	s, ok := a.liveLocked(t)
	hash := ""
	if ok {
		hash = s.hash
	}
	a.mu.Unlock()
	if !ok {
		return "", time.Time{}, ErrReauthEnded
	}
	good, err := Verify(hash, password)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("the login can't be used: %s: %v", a.path, err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if s, ok = a.liveLocked(t); !ok {
		return "", time.Time{}, ErrReauthEnded
	}
	now := a.now()
	if !good {
		s.reauth = ""
		if s.reauthFails++; s.reauthFails >= reauthTries {
			delete(a.sessions, tokenKey(t))
			return "", time.Time{}, ErrReauthEnded
		}
		return "", time.Time{}, ErrBadPassword
	}
	g := token()
	s.reauthFails, s.reauth, s.reauthUntil, s.Seen = 0, tokenKey(g), now.Add(ReauthTTL), now
	return g, s.reauthUntil, nil
}

// UseReauth says whether grant is the open re-authentication of the session of a cookie's
// token; a grant is good once.
func (a *Auth) UseReauth(t, grant string) bool {
	if t == "" || grant == "" {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	s, ok := a.liveLocked(t)
	if !ok || s.reauth == "" || !a.now().Before(s.reauthUntil) ||
		subtle.ConstantTimeCompare([]byte(tokenKey(grant)), []byte(s.reauth)) != 1 {
		return false
	}
	s.reauth = ""
	return true
}

// Logout ends a session.
func (a *Auth) Logout(t string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.sessions, tokenKey(t))
}
