package keys

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/skitzo2000/espdns/controller/internal/secfile"
)

// The zone primary's API token (internal/primary: Technitium's, today): the controller
// edits the primary's zone transfer and NOTIFY lists with it when it adopts a node, and
// reads them for its Zone primary view. As the release key, a file in the data directory
// for now, <data>/keys/primary.token, mode 0600, owned by the user the controller runs as
// (secfile), read through one interface (TokenSource) so another source can take the
// file's place later. It gets there by `espdns primary import` (make primary-import), from
// standard input (the Makefile's PRIMARY_TOKEN_ENV or PRIMARY_TOKEN_FILE), never an argument, the environment or a log. A primary of the
// manual kind needs none.

// TokenFile is the token's file name in Dir.
const TokenFile = "primary.token"

// TokenPath is the token file in dataDir.
func TokenPath(dataDir string) string { return filepath.Join(dataDir, Dir, TokenFile) }

// ErrNoToken: no zone primary token is set up. Adoption then says what to change on the
// primary by hand, and the Zone primary view can't read the lists.
var ErrNoToken = errors.New("no zone primary API token")

// TokenSource gives the zone primary's API token.
type TokenSource interface {
	// Token is the token, read now: ErrNoToken (errors.Is) if none is set up, another error
	// if one is but can't be used.
	Token() (string, error)
	// String says where it comes from, for messages; never the token.
	String() string
}

// TokenFileSource is the token in a file, checked as secfile checks it at every read.
type TokenFileSource struct{ Path string }

func (f TokenFileSource) String() string { return f.Path }

func (f TokenFileSource) Token() (string, error) {
	b, err := secfile.Read(f.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", fmt.Errorf("%w: %s doesn't exist (import it with espdns primary import: docs/reference/cli.md#primary)", ErrNoToken, f.Path)
	}
	if err != nil {
		return "", err
	}
	return ParseToken(f.Path, b)
}

// DataTokenSource is the token in a data directory: keys/primary.token.
type DataTokenSource struct{ DataDir string }

// Path is the file the token is read from.
func (d DataTokenSource) Path() string { return TokenPath(d.DataDir) }

func (d DataTokenSource) String() string { return d.Path() }

func (d DataTokenSource) Token() (string, error) {
	return TokenFileSource{d.Path()}.Token()
}

// ParseToken checks a token as it is kept (surrounding white space dropped): 8 to
// 512 printable ASCII characters, none of them a space. Errors name it by name, never by
// its value.
func ParseToken(name string, b []byte) (string, error) {
	t := bytes.TrimSpace(b)
	switch {
	case len(t) == 0:
		return "", errors.New(name + ": empty (no token given)")
	case len(t) < 8 || len(t) > 512:
		return "", fmt.Errorf("%s: %d characters: not an API token (8 to 512)", name, len(t))
	}
	for _, c := range t {
		if c <= ' ' || c > '~' {
			return "", errors.New(name + ": not an API token (printable characters only, no spaces or line breaks)")
		}
	}
	return string(t), nil
}

// ImportToken writes tok to path (mode 0600, its directory 0700). The same token again
// changes nothing (and says so); a different one is refused unless replace.
func ImportToken(path, tok string, replace bool) (same bool, err error) {
	old, err := (TokenFileSource{path}).Token()
	switch {
	case err == nil && old == tok:
		return true, nil
	case err == nil && !replace:
		return false, fmt.Errorf("a different zone primary token is already imported (%s): -replace to replace it", path)
	case err != nil && !errors.Is(err, ErrNoToken) && !replace:
		return false, fmt.Errorf("%s is there but can't be read (%v): -replace to replace it", path, err)
	}
	return false, secfile.Write(path, []byte(tok+"\n"))
}

// ImportDataToken imports tok into dataDir as keys/primary.token, as ImportToken does.
// same: it already held it.
func ImportDataToken(dataDir, tok string, replace bool) (same bool, err error) {
	return ImportToken(TokenPath(dataDir), tok, replace)
}

// RemoveToken deletes the token file at path (the zone primary is then changed by hand);
// none there is no error.
func RemoveToken(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}
