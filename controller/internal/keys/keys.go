// Package keys is where the controller's release signing key comes from (docs/design.md,
// Controller): today a file in the data directory, <data>/keys/release.pem, mode 0600,
// owned by the user the controller runs as. Callers ask a Source, so another source can
// take the file's place without them changing.
//
// The key gets there by `espdns key import` (from standard input, never an argument, the
// environment or a log), which checks that the nodes trust it first (Trust). The recovery
// key (key slot 1) is never imported: it stays offline.
package keys

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/skitzo2000/espdns/controller/internal/release"
	"github.com/skitzo2000/espdns/controller/internal/secfile"
)

// Dir and File are the key's place in the data directory.
const (
	Dir  = "keys"
	File = "release.pem"
)

// Path is the release key file in dataDir.
func Path(dataDir string) string { return filepath.Join(dataDir, Dir, File) }

// ErrNoKey: no release key is set up. The controller then only reads: every action that
// signs a release is refused.
var ErrNoKey = errors.New("no release key")

// Source gives the release key: the one interface the controller signs through.
type Source interface {
	// Key is the release key (key slot 0), read now: ErrNoKey (errors.Is) if none is set
	// up, another error if one is but can't be used.
	Key() (*ecdsa.PrivateKey, error)
	// String says where it comes from, for messages; never the key.
	String() string
}

// FileSource is the key in a file, checked as secfile checks it at every read: a key
// imported while the controller runs is used from the next action on, and one whose mode
// was opened up is refused from then on.
type FileSource struct{ Path string }

func (f FileSource) String() string { return f.Path }

func (f FileSource) Key() (*ecdsa.PrivateKey, error) {
	b, err := secfile.Read(f.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s doesn't exist (import one with espdns key import: docs/getting-started.md, step 7)", ErrNoKey, f.Path)
	}
	if err != nil {
		return nil, err
	}
	return release.ParseKey(f.Path, b)
}

// Parse reads a key as base64 of the PEM file or as the PEM itself. Errors name the key
// by name, never by its value.
func Parse(name string, b []byte) (*ecdsa.PrivateKey, error) {
	v := bytes.TrimSpace(b)
	if len(v) == 0 {
		return nil, errors.New(name + ": empty (no key given)")
	}
	if !bytes.HasPrefix(v, []byte("-----BEGIN")) {
		d, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(string(v)), ""))
		if err != nil {
			return nil, errors.New(name + ": neither a PEM key nor base64 of one")
		}
		v = d
	}
	return release.ParseKey(name, v)
}

// Encode is the key as a PKCS#8 PEM file, as `make keys` writes it.
func Encode(k *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// Fingerprint is the key's public half as /status "keys" names it.
func Fingerprint(k *ecdsa.PrivateKey) string { return release.Fingerprint(release.PublicRaw(k)) }

// ErrExists: Import was given a different key than the one already there.
var ErrExists = errors.New("a different release key is already imported")

// Import writes k to path (mode 0600, its directory 0700). The same key again changes
// nothing (and says so); a different one is refused unless replace.
func Import(path string, k *ecdsa.PrivateKey, replace bool) (same bool, err error) {
	old, err := (FileSource{path}).Key()
	switch {
	case err == nil && old.Equal(k):
		return true, nil
	case err == nil && !replace:
		return false, fmt.Errorf("%w (%s, fingerprint %s): -replace to replace it", ErrExists, path, Fingerprint(old))
	case err != nil && !errors.Is(err, ErrNoKey) && !replace:
		return false, fmt.Errorf("%s is there but can't be read (%v): -replace to replace it", path, err)
	}
	b, err := Encode(k)
	if err != nil {
		return false, err
	}
	return false, secfile.Write(path, b)
}
