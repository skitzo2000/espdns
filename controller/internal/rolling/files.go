package rolling

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sync"

	"github.com/skitzo2000/espdns/controller/internal/settings"
)

// Files reads each file once and keeps what it read: a request with Files (Request.Files)
// reads every file through it, the settings too, so the bytes a fingerprint covers
// (Fingerprint) are the bytes the rollout checks and pushes, even if a file is replaced
// in between.
type Files struct {
	mu sync.Mutex
	m  map[string]fileRead
}

type fileRead struct {
	b   []byte
	err error
}

// NewFiles is an empty set of reads.
func NewFiles() *Files { return &Files{m: map[string]fileRead{}} }

// Read is the file at path as first read (a nil Files reads it every time).
func (f *Files) Read(path string) ([]byte, error) {
	if f == nil {
		return os.ReadFile(path)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if r, ok := f.m[path]; ok {
		return r.b, r.err
	}
	b, err := os.ReadFile(path)
	f.m[path] = fileRead{b, err}
	return b, err
}

// read reads a file the request reads.
func (r Request) read(path string) ([]byte, error) { return r.Files.Read(path) }

// loadSettings is settings.Load through the request's Files: no file is no settings.
func (r Request) loadSettings() (settings.Settings, error) {
	path := r.SettingsPath()
	b, err := r.read(path)
	if errors.Is(err, fs.ErrNotExist) {
		return settings.Settings{}, nil
	}
	if err != nil {
		return settings.Settings{}, err
	}
	s, err := settings.Parse(b)
	if err != nil {
		return settings.Settings{}, fmt.Errorf("%s: %w", path, err)
	}
	return s, nil
}

// Fingerprint keys the request (its files resolved, DryRun aside) and the bytes of every
// file it reads (Inputs), read through its Files: two requests match only for the same
// push with the same bytes. secret keys it to one run of the controller.
func (r Request) Fingerprint(secret []byte) string {
	files := r.Files
	r.DryRun, r.Files = false, nil
	m := hmac.New(sha256.New, secret)
	b, _ := json.Marshal(r)
	m.Write(b)
	for _, path := range r.Inputs() {
		m.Write([]byte("\x00" + path + "\x00"))
		if c, err := files.Read(path); err == nil {
			s := sha256.Sum256(c)
			m.Write(s[:])
		} else {
			m.Write([]byte("missing"))
		}
	}
	return hex.EncodeToString(m.Sum(nil))
}
