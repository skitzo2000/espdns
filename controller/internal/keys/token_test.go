package keys

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The token file as the release key's: imported once (0600, its directory 0700), the same
// one again changes nothing, a different one only with replace; a file opened up, or a
// link, is refused; errors never hold the token.
func TestToken(t *testing.T) {
	dir := t.TempDir()
	path := TokenPath(dir)
	src := TokenFileSource{path}
	if _, err := src.Token(); !errors.Is(err, ErrNoToken) {
		t.Fatal(err)
	}
	const tok = "0123456789abcdef0123456789abcdef"
	if same, err := ImportToken(path, tok, false); same || err != nil {
		t.Fatal(same, err)
	}
	fi, _ := os.Stat(path)
	di, _ := os.Stat(filepath.Dir(path))
	if fi.Mode().Perm() != 0o600 || di.Mode().Perm() != 0o700 {
		t.Fatal(fi.Mode(), di.Mode())
	}
	if got, err := src.Token(); got != tok || err != nil {
		t.Fatal(got, err)
	}
	if same, err := ImportToken(path, tok, false); !same || err != nil {
		t.Fatal(same, err)
	}
	const other = "fedcba9876543210fedcba9876543210"
	if _, err := ImportToken(path, other, false); err == nil || strings.Contains(err.Error(), other) || strings.Contains(err.Error(), tok) {
		t.Fatal(err)
	}
	if _, err := ImportToken(path, other, true); err != nil {
		t.Fatal(err)
	}
	os.Chmod(path, 0o640)
	if _, err := src.Token(); err == nil || !strings.Contains(err.Error(), "mode 0640") || strings.Contains(err.Error(), other) {
		t.Fatal(err)
	}
	os.Chmod(path, 0o600)
	link := filepath.Join(dir, "link.token")
	os.Symlink(path, link)
	if _, err := (TokenFileSource{link}).Token(); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "short", "has a space in it", "line\nbreak-token", strings.Repeat("x", 513), "tok\x00en-with-nul"} {
		if _, err := ParseToken("t", []byte(bad)); err == nil || (bad != "" && strings.Contains(err.Error(), bad)) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	if got, err := ParseToken("t", []byte("  "+tok+"\n")); got != tok || err != nil {
		t.Fatal(got, err)
	}
}

// The token in a data directory is keys/primary.token: import writes it, the same token
// again changes nothing, a different one needs replace. A keys/technitium.token (its name
// before the zone primary was generic) is not read.
func TestDataToken(t *testing.T) {
	dir := t.TempDir()
	src := DataTokenSource{dir}
	const tok, other = "0123456789abcdef-first", "fedcba9876543210-new"
	if _, err := ImportToken(filepath.Join(dir, Dir, "technitium.token"), tok, false); err != nil {
		t.Fatal(err)
	}
	if _, err := src.Token(); !errors.Is(err, ErrNoToken) || src.Path() != TokenPath(dir) {
		t.Fatal(err, src.Path())
	}
	if same, err := ImportDataToken(dir, tok, false); same || err != nil {
		t.Fatal(same, err)
	}
	if got, err := src.Token(); got != tok || err != nil {
		t.Fatal(got, err)
	}
	if same, err := ImportDataToken(dir, tok, false); !same || err != nil {
		t.Fatal(same, err)
	}
	if _, err := ImportDataToken(dir, other, false); err == nil || strings.Contains(err.Error(), other) || strings.Contains(err.Error(), tok) {
		t.Fatal(err)
	}
	if _, err := ImportDataToken(dir, other, true); err != nil {
		t.Fatal(err)
	}
	if got, _ := src.Token(); got != other {
		t.Fatal(got)
	}
}

// RemoveToken: the file gone, the source then says no token; none there is fine.
func TestRemoveToken(t *testing.T) {
	path := TokenPath(t.TempDir())
	if err := RemoveToken(path); err != nil {
		t.Fatal(err)
	}
	if _, err := ImportToken(path, "0123456789abcdef", false); err != nil {
		t.Fatal(err)
	}
	if err := RemoveToken(path); err != nil {
		t.Fatal(err)
	}
	if _, err := (TokenFileSource{path}).Token(); !errors.Is(err, ErrNoToken) {
		t.Fatal(err)
	}
}
