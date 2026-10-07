package configs

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/secfile"
)

// Pushed is the config last pushed to a node, kept so the editor can say whether the node
// runs the file as saved, and what a change would do (live or with a reboot) from what the
// node runs. It holds while the node's /status config seq is Seq; a config pushed some
// other way (an older CLI, another controller) leaves a seq this record doesn't have.
type Pushed struct {
	NodeID  string          `json:"node_id"`
	Host    string          `json:"host"`
	File    string          `json:"file"` // the config's file name (or the path the CLI was given)
	Seq     uint64          `json:"seq"`
	Payload json.RawMessage `json:"payload"`
	Time    time.Time       `json:"time"`
	By      string          `json:"by"` // "cli" or "controller"
}

var nodeIDRE = regexp.MustCompile(`^[0-9a-f]{2}(:[0-9a-f]{2}){5}$`)

func pushedPath(dataDir, nodeID string) (string, error) {
	id := strings.ToLower(nodeID)
	if !nodeIDRE.MatchString(id) {
		return "", fmt.Errorf("node ID %q: not a MAC address", nodeID)
	}
	return filepath.Join(Path(dataDir), PushedDir, strings.ReplaceAll(id, ":", "")+".json"), nil
}

// RecordPushed keeps p as the config node p.NodeID runs (mode 0600: it holds the payload).
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
	return writeFile(path, append(b, '\n'))
}

// AllPushed is every record of a config pushed, one per node (those that can't be read
// are left out).
func AllPushed(dataDir string) []Pushed {
	ents, _ := os.ReadDir(filepath.Join(Path(dataDir), PushedDir))
	var out []Pushed
	for _, e := range ents {
		id, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok || len(id) != 12 {
			continue
		}
		var mac []string
		for i := 0; i < 12; i += 2 {
			mac = append(mac, id[i:i+2])
		}
		if p, err := LoadPushed(dataDir, strings.Join(mac, ":")); err == nil && p != nil {
			out = append(out, *p)
		}
	}
	return out
}

// LoadPushed is the config last pushed to the node, if one was recorded.
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
