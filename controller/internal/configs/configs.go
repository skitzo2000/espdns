// Package configs is the node configs as files in the data directory (docs/design.md,
// Controller: configs are files), the one place the controller's editor and the espdns
// CLI's config rollouts read them:
//
//	configs/<name>.json             a node config (format: internal/nodecfg), by file name, as
//	                                CONFIGS="192.0.2.53=node1.json" names it
//	configs/.history/<name>.<time>  the versions a save replaced, the newest HistoryKeep of each
//	configs/.pushed/<node-id>.json  the config last pushed to each node (by the CLI or a job),
//	                                with the seq it got: what the node runs while its /status
//	                                config seq is that one
//
// Keyed by file name, not node ID: a config exists before its node is adopted (make
// fleet-adopt CONFIG=), outlives a board swap (a new chip, a new node ID), and keeps the
// name the Makefile and the docs use. Which node runs which config is from the nodes
// themselves: a node whose /status config name is the config's "name", or whose address is
// its network address.
//
// The repo's configs/ holds examples only, never read. A deployment's own seeds (make data,
// CONFIG_SEEDS=, outside the repo) are copied into an empty slot here
// once, never over a file that is here; make data says when a seed differs from the one in use.
//
// Files are written whole or not at all (a temporary file renamed over the old one), mode
// 0600: a config can hold a Wi-Fi password.
package configs

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/filestore"
	"github.com/skitzo2000/espdns/controller/internal/nodecfg"
)

const (
	Dir        = "configs"            // in the data directory
	HistoryDir = filestore.HistoryDir // in Dir
	PushedDir  = ".pushed"            // in Dir
	// HistoryKeep is how many earlier versions of each config are kept.
	HistoryKeep = 20
	// MaxFile is the most a config file may hold (a node takes at most 16 KB of payload).
	MaxFile = 64 << 10
)

// Path is the configs directory in dataDir.
func Path(dataDir string) string { return filepath.Join(dataDir, Dir) }

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// FileName refuses a file name in the data directory that isn't a plain <name><ext>
// (ext: ".json", ".bin", ...; "" for a directory's name): lowercase letters, digits, '.',
// '_' and '-', no directories, no "..". what names the file in the error.
func FileName(name, ext, what string) error {
	base, ok := strings.CutSuffix(name, ext)
	if !ok || base == "" || !nameRE.MatchString(name) || strings.Contains(name, "..") {
		return fmt.Errorf("%q: %s is <name>%s, with lowercase letters, digits, '.', '_' and '-' only", name, what, ext)
	}
	return nil
}

// CheckName refuses a file name that isn't a plain <name>.json: lowercase letters, digits,
// '.', '_' and '-', no directories. fleet.json, the settings' old name, isn't a node config.
func CheckName(name string) error {
	if err := FileName(name, ".json", "a config"); err != nil {
		return err
	}
	if name == "fleet.json" || name == "settings.json" {
		return fmt.Errorf("%s is the deployment's settings, not a node config", name)
	}
	return nil
}

// File is one config in the directory.
type File struct {
	Name     string    `json:"name"`     // the file name: dns2.json
	Modified time.Time `json:"modified"` // the file's time
	Size     int64     `json:"size"`
	Hash     string    `json:"hash"` // sha256 of the file, hex: a save names it, so a file changed since isn't overwritten
	// The config parsed, if it parses; else Error says why.
	Config *nodecfg.Config `json:"-"`
	Error  string          `json:"error,omitempty"`
	Text   []byte          `json:"-"`
}

// Hash is a file's hash as File.Hash has it.
func Hash(b []byte) string { return filestore.Hash(b) }

// Read reads one config by file name.
func Read(dataDir, name string) (File, error) {
	if err := CheckName(name); err != nil {
		return File{}, err
	}
	p := filepath.Join(Path(dataDir), name)
	fi, err := os.Stat(p)
	if err != nil {
		return File{}, err
	}
	if !fi.Mode().IsRegular() {
		return File{}, fmt.Errorf("%s: not a regular file", p)
	}
	if fi.Size() > MaxFile {
		return File{}, fmt.Errorf("%s: over %d bytes", p, MaxFile)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return File{}, err
	}
	f := File{Name: name, Modified: fi.ModTime(), Size: int64(len(b)), Hash: Hash(b), Text: b}
	if f.Config, err = nodecfg.Parse(b); err != nil {
		f.Error = err.Error()
	}
	return f, nil
}

// List reads every config in the directory, by name; none if there is no directory.
func List(dataDir string) ([]File, error) {
	ents, err := os.ReadDir(Path(dataDir))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []File
	for _, e := range ents {
		if CheckName(e.Name()) != nil {
			continue
		}
		f, err := Read(dataDir, e.Name())
		if err != nil {
			out = append(out, File{Name: e.Name(), Error: err.Error()})
			continue
		}
		out = append(out, f)
	}
	return out, nil
}

// ErrChanged: the file isn't the version the save was made from.
var ErrChanged = filestore.ErrChanged

// Store is the configs directory as a filestore: the name rule, the node's checks, the
// history (the pending changes write through it).
func Store(dataDir string) filestore.Store { return store(dataDir) }

// store is the configs directory as a filestore: the name rule, the node's checks, the
// history.
func store(dataDir string) filestore.Store {
	return filestore.Store{Dir: Path(dataDir), Name: CheckName, Max: MaxFile, Keep: HistoryKeep,
		Check: func(_ string, text []byte) error { _, err := nodecfg.Parse(text); return err }}
}

// Save writes a config: checked as the node checks it (a config the node would refuse is
// never saved), whole or not at all, mode 0600. expect is the hash of the version the edit
// started from ("" for a new file, which must not exist); the version replaced goes to the
// history first. It returns the new file.
func Save(dataDir, name string, text []byte, expect string) (File, error) {
	if err := store(dataDir).Save(name, text, expect); err != nil {
		return File{}, err
	}
	return Read(dataDir, name)
}

// writeFile writes b to path whole or not at all, mode 0600, synced before the rename.
func writeFile(path string, b []byte) error { return filestore.WriteFile(path, b) }

// Version is one kept earlier version of a config.
type Version = filestore.Version

// History is the kept versions of name, newest first.
func History(dataDir, name string) ([]Version, error) { return store(dataDir).History(name) }

// Resolve is where a config named on the command line is: a bare file name (no directory)
// is the data directory's config of that name if there is one; anything else is a path.
func Resolve(dataDir, arg string) string {
	if dataDir != "" && !strings.ContainsRune(arg, '/') && CheckName(arg) == nil {
		p := filepath.Join(Path(dataDir), arg)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return arg
}
