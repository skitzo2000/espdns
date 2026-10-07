// Package auth is the controller's login (docs/design.md, Controller): one admin user,
// whose password `espdns passwd` sets once, kept as an argon2id hash in <data>/auth.json
// (mode 0600); sessions in memory, by an HttpOnly, SameSite=Strict cookie named for the
// port and a token only the page holds (http.go); failed logins back off per client; the
// password asked again for what gives away secrets (a backup).
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"

	"github.com/skitzo2000/espdns/controller/internal/secfile"
)

// File is the login's file in the data directory.
const File = "auth.json"

// Path is the login's file in dataDir.
func Path(dataDir string) string { return filepath.Join(dataDir, File) }

// DefaultUser is the one user's name until `espdns passwd` is given another (asked on a
// terminal, or -user): the deployment's choice.
const DefaultUser = "admin"

// MaxUser is the longest user name, in bytes.
const MaxUser = 64

// CheckUser says whether a user name is one the controller takes: 1 to MaxUser bytes of
// valid UTF-8, printable, no white space, and no quote or backslash (a name easy to type,
// quote and show anywhere). Login compares the name byte for byte, and takes a name set
// before by an older passwd that this no longer would.
func CheckUser(user string) error {
	switch {
	case user == "":
		return errors.New("empty")
	case len(user) > MaxUser:
		return fmt.Errorf("too long: at most %d bytes", MaxUser)
	case !utf8.ValidString(user):
		return errors.New("not valid UTF-8")
	}
	for _, r := range user {
		switch {
		case unicode.IsSpace(r):
			return errors.New("no spaces or other white space")
		case !unicode.IsPrint(r):
			return errors.New("printable characters only")
		case strings.ContainsRune("'\"`\\", r):
			return errors.New("no quotes or backslashes")
		}
	}
	return nil
}

// Password lengths, in characters.
const (
	MinPassword = 12
	MaxPassword = 256
)

// Params are argon2id's costs. Hash records them, so they can grow without breaking the
// hashes already kept.
type Params struct {
	Time      uint32
	MemoryKiB uint32
	Threads   uint8
}

// DefaultParams: 64 MiB and 3 passes, about 0.1 s here: one login at a time (Login), so
// the controller never holds more than one of these at once.
var DefaultParams = Params{Time: 3, MemoryKiB: 64 << 10, Threads: 2}

const keyLen = 32

// Hash is password's argon2id hash with a random salt, in the PHC string format:
// $argon2id$v=19$m=65536,t=3,p=2$<salt>$<hash> (base64, no padding).
func Hash(password string, p Params) string {
	salt := make([]byte, 16)
	rand.Read(salt)
	h := argon2.IDKey([]byte(password), salt, p.Time, p.MemoryKiB, p.Threads, keyLen)
	b := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, p.MemoryKiB, p.Time, p.Threads,
		b.EncodeToString(salt), b.EncodeToString(h))
}

// Verify says whether password is the one encoded hashes.
func Verify(encoded, password string) (bool, error) {
	f := strings.Split(encoded, "$")
	if len(f) != 6 || f[0] != "" || f[1] != "argon2id" {
		return false, errors.New("not an argon2id hash")
	}
	var v int
	var p Params
	if _, err := fmt.Sscanf(f[2], "v=%d", &v); err != nil || v != argon2.Version {
		return false, fmt.Errorf("argon2 version %q", f[2])
	}
	if _, err := fmt.Sscanf(f[3], "m=%d,t=%d,p=%d", &p.MemoryKiB, &p.Time, &p.Threads); err != nil {
		return false, fmt.Errorf("argon2 parameters %q", f[3])
	}
	// Bounds, so a hash edited by hand can't make every login take the controller's memory.
	if p.Time < 1 || p.Time > 20 || p.MemoryKiB < 8 || p.MemoryKiB > 1<<20 || p.Threads < 1 {
		return false, fmt.Errorf("argon2 parameters out of range %q", f[3])
	}
	salt, err := base64.RawStdEncoding.DecodeString(f[4])
	if err != nil || len(salt) < 8 {
		return false, errors.New("bad salt")
	}
	want, err := base64.RawStdEncoding.DecodeString(f[5])
	if err != nil || len(want) < 16 {
		return false, errors.New("bad hash")
	}
	got := argon2.IDKey([]byte(password), salt, p.Time, p.MemoryKiB, p.Threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// CheckPassword says whether a new password is one the controller takes.
func CheckPassword(pw string) error {
	n := utf8.RuneCountInString(pw)
	switch {
	case !utf8.ValidString(pw):
		return errors.New("not valid UTF-8")
	case n < MinPassword:
		return fmt.Errorf("too short: at least %d characters", MinPassword)
	case n > MaxPassword:
		return fmt.Errorf("too long: at most %d characters", MaxPassword)
	case strings.TrimSpace(pw) != pw:
		return errors.New("starts or ends with a space")
	}
	return nil
}

// Config is auth.json.
type Config struct {
	User string    `json:"user"`
	Hash string    `json:"hash"`
	Set  time.Time `json:"set"`
}

// Load reads auth.json, checked as secfile checks it. fs.ErrNotExist (errors.Is): no
// password set.
func Load(path string) (Config, error) {
	b, err := secfile.Read(path)
	if err != nil {
		return Config{}, err
	}
	return Parse(path, b)
}

// Parse reads auth.json's contents (name, for errors: never the hash).
func Parse(name string, b []byte) (Config, error) {
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return c, fmt.Errorf("%s: %w", name, err)
	}
	if c.User == "" || !strings.HasPrefix(c.Hash, "$argon2id$") {
		return c, fmt.Errorf("%s: no user or no argon2id hash", name)
	}
	return c, nil
}

// SetPassword sets the one user and their password in auth.json (mode 0600), replacing
// the one before: every session of the old password ends at its next request.
func SetPassword(path, user, password string) error {
	b, err := encode(user, password)
	if err != nil {
		return err
	}
	return secfile.Write(path, b)
}

// ErrPasswordSet: a password is set already, so the first run's is refused.
var ErrPasswordSet = errors.New("a password is set already: log in (change it with espdns passwd)")

// CreatePassword is SetPassword for the first run: only while there is no auth.json, made
// so that of two at once only one is set (secfile.Create). ErrPasswordSet otherwise, the
// file as it was.
func CreatePassword(path, user, password string) error {
	b, err := encode(user, password)
	if err != nil {
		return err
	}
	if err := secfile.Create(path, b); errors.Is(err, fs.ErrExist) {
		return ErrPasswordSet
	} else if err != nil {
		return err
	}
	return nil
}

// encode is auth.json for user and password, both checked.
func encode(user, password string) ([]byte, error) {
	if err := CheckUser(user); err != nil {
		return nil, fmt.Errorf("user: %w", err)
	}
	if err := CheckPassword(password); err != nil {
		return nil, fmt.Errorf("password: %w", err)
	}
	b, _ := json.MarshalIndent(Config{User: user, Hash: Hash(password, DefaultParams), Set: time.Now().UTC()}, "", "  ")
	return append(b, '\n'), nil
}
