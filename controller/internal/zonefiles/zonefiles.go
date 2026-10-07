// Package zonefiles is the hosted zones as files in the data directory, the one place the
// controller's zone editor and the rolling push (the Push page, make fleet-rollout
// KIND=zones) read them:
//
//	zones/<zone>.zone            a hosted zone, an RFC 1035 master file (internal/zones),
//	                             named after its zone: home.example.zone holds home.example
//	zones/.history/<name>.<time> the versions a save replaced or a delete removed, the newest HistoryKeep
//	zones/.pushed/<node-id>.json the zones last pushed to each node (by the CLI or a job), with
//	                             the hosted seq it got and each file's hash: what the node
//	                             serves while its /status hosted seq is that one
//
// Files are written whole or not at all, mode 0600, through internal/filestore, as the
// node configs are. A zone the node would refuse is never saved.
package zonefiles

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/configs"
	"github.com/skitzo2000/espdns/controller/internal/filestore"
	"github.com/skitzo2000/espdns/controller/internal/secfile"
	"github.com/skitzo2000/espdns/controller/internal/zones"
)

const (
	Dir        = "zones"              // in the data directory
	HistoryDir = filestore.HistoryDir // in Dir
	PushedDir  = ".pushed"            // in Dir
	// HistoryKeep is how many earlier versions of each zone are kept.
	HistoryKeep = 20
	// MaxFile is the most a zone file may hold (a P4 holds 1 MB of zones in memory).
	MaxFile = 4 << 20
)

// Path is the zones directory in dataDir.
func Path(dataDir string) string { return filepath.Join(dataDir, Dir) }

var labelRE = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$`)

// CheckName refuses a file name that isn't <zone>.zone for a zone name: the data
// directory's file name rule (lowercase letters, digits, '.', '_' and '-', no directories,
// no "..", as the Push page takes it), and each label of the zone 1 to 63 characters, not
// starting or ending with '-'.
func CheckName(name string) error {
	if err := configs.FileName(name, ".zone", "a zone file"); err != nil {
		return err
	}
	zone := strings.TrimSuffix(name, ".zone")
	for _, l := range strings.Split(zone, ".") {
		if !labelRE.MatchString(l) {
			return fmt.Errorf("%q: %q is not a zone name (labels of 1 to 63 letters, digits, '_' and '-', not starting or ending with '-')",
				name, zone)
		}
	}
	return nil
}

// ZoneOf is the zone a file name holds: home.example.zone holds home.example.
func ZoneOf(name string) string { return strings.TrimSuffix(name, ".zone") }

// Parse reads a zone's text as the node will (espdns zones -check without the limit): the
// master file parsed, and the zone checked alone.
func Parse(name string, text []byte) (*zones.Zone, error) {
	z, err := zones.ParseMaster(ZoneOf(name), bytes.NewReader(text), name)
	if err != nil {
		return nil, err
	}
	if err := (&zones.Set{Zones: []*zones.Zone{z}}).Validate(); err != nil {
		return nil, err
	}
	return z, nil
}

// Store is the zones directory as a filestore: the name rule, the node's checks, the
// history (the pending changes write through it).
func Store(dataDir string) filestore.Store { return store(dataDir) }

func store(dataDir string) filestore.Store {
	return filestore.Store{Dir: Path(dataDir), Name: CheckName, Max: MaxFile, Keep: HistoryKeep,
		Check: func(name string, text []byte) error { _, err := Parse(name, text); return err }}
}

// File is one zone file.
type File struct {
	Name     string    `json:"name"` // home.example.zone
	Zone     string    `json:"zone"` // home.example
	Modified time.Time `json:"modified"`
	Size     int64     `json:"size"`
	Hash     string    `json:"hash"`
	// What it holds, if it passes the node's checks; else Error says why.
	Serial  uint32      `json:"serial"`
	Records int         `json:"records"`
	Mem     int         `json:"mem"` // what it takes in a node's memory
	Error   string      `json:"error,omitempty"`
	Text    []byte      `json:"-"`
	Parsed  *zones.Zone `json:"-"`
}

func fileOf(f filestore.File) File {
	out := File{Name: f.Name, Zone: ZoneOf(f.Name), Modified: f.Modified, Size: int64(len(f.Text)), Hash: f.Hash, Text: f.Text}
	z, err := Parse(f.Name, f.Text)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	out.Parsed, out.Serial, out.Records = z, z.Serial(), len(z.Records)
	out.Mem = (&zones.Set{Zones: []*zones.Zone{z}}).Mem()
	return out
}

// Read reads one zone file by name.
func Read(dataDir, name string) (File, error) {
	f, err := store(dataDir).Read(name)
	if err != nil {
		return File{}, err
	}
	return fileOf(f), nil
}

// List reads every zone file, by name; none if there is no directory.
func List(dataDir string) ([]File, error) {
	names, err := store(dataDir).Names()
	if err != nil {
		return nil, err
	}
	var out []File
	for _, n := range names {
		f, err := Read(dataDir, n)
		if err != nil {
			out = append(out, File{Name: n, Zone: ZoneOf(n), Error: err.Error()})
			continue
		}
		out = append(out, f)
	}
	return out, nil
}

// Hash is a file's hash as File.Hash has it.
func Hash(b []byte) string { return filestore.Hash(b) }

// ErrChanged: the file isn't the version the save was made from.
var ErrChanged = filestore.ErrChanged

// Save writes a zone file: checked as the node checks the zone (one it would refuse is never
// saved), whole or not at all, mode 0600. expect is the hash of the version the edit
// started from ("" for a new file, which must not exist); the version replaced goes to the
// history first.
func Save(dataDir, name string, text []byte, expect string) (File, error) {
	if err := store(dataDir).Save(name, text, expect); err != nil {
		return File{}, err
	}
	return Read(dataDir, name)
}

// Delete removes a zone file (the version expect names), kept in the history. The nodes
// serve it until a push of a set without it.
func Delete(dataDir, name, expect string) error { return store(dataDir).Delete(name, expect) }

// Version is one kept earlier version of a zone file.
type Version = filestore.Version

// History is the kept versions of name, newest first.
func History(dataDir, name string) ([]Version, error) { return store(dataDir).History(name) }

// Deleted are the zone files deleted (none now, versions kept), each with its newest version.
func Deleted(dataDir string) (map[string]Version, error) { return store(dataDir).Kept() }

// ReadVersion is a kept version of name, by its file name in the history.
func ReadVersion(dataDir, name, file string) ([]byte, error) {
	return store(dataDir).ReadVersion(name, file)
}

// ---- the zones pushed -----------------------------------------------------------------

// Pushed is the set of zones last pushed to a node, kept so the editor can say whether the
// node serves a file as saved. It holds while the node's /status hosted seq is Seq.
type Pushed struct {
	NodeID string            `json:"node_id"`
	Host   string            `json:"host"`
	Seq    uint64            `json:"seq"`
	Files  map[string]string `json:"files"` // file name: the hash of the bytes pushed
	Time   time.Time         `json:"time"`
	By     string            `json:"by"` // "cli" or "controller"
}

var nodeIDRE = regexp.MustCompile(`^[0-9a-f]{2}(:[0-9a-f]{2}){5}$`)

func pushedPath(dataDir, nodeID string) (string, error) {
	id := strings.ToLower(nodeID)
	if !nodeIDRE.MatchString(id) {
		return "", fmt.Errorf("node ID %q: not a MAC address", nodeID)
	}
	return filepath.Join(Path(dataDir), PushedDir, strings.ReplaceAll(id, ":", "")+".json"), nil
}

// PushedFiles is Pushed.Files for the -zone arguments of a push (<zone>.zone or
// origin=path, read through read): each by the file name the zone has here, <zone>.zone,
// wherever it was read from, with the hash of the bytes pushed.
func PushedFiles(specs []string, read func(string) ([]byte, error)) (map[string]string, error) {
	out := map[string]string{}
	for _, s := range specs {
		origin, path, ok := strings.Cut(s, "=")
		if !ok {
			path, origin = s, strings.TrimSuffix(filepath.Base(s), ".zone")
		}
		b, err := read(path)
		if err != nil {
			return nil, err
		}
		out[strings.ToLower(strings.TrimSuffix(origin, "."))+".zone"] = Hash(b)
	}
	return out, nil
}

// RecordPushed keeps p as the zones node p.NodeID serves.
func RecordPushed(dataDir string, p Pushed) error {
	path, err := pushedPath(dataDir, p.NodeID)
	if err != nil {
		return err
	}
	if err := secfile.MkdirAll(filepath.Dir(path)); err != nil {
		return err
	}
	if p.Time.IsZero() {
		p.Time = time.Now()
	}
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return filestore.WriteFile(path, append(b, '\n'))
}

// LoadPushed is the zones last pushed to the node, if recorded.
func LoadPushed(dataDir, nodeID string) (*Pushed, error) {
	path, err := pushedPath(dataDir, nodeID)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var p Pushed
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &p, nil
}
