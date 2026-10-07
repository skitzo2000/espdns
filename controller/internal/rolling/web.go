package rolling

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/blocklist"
	"github.com/skitzo2000/espdns/controller/internal/configs"
	"github.com/skitzo2000/espdns/controller/internal/release"
)

// What a rolling push from the controller pushes is files in the data directory, put
// there by make (the controller compiles nothing and takes no uploads):
//
//	firmware/builds/<board>/dns2.bin  make fleet-firmware: the image each production node runs
//	                                  (its board's chip image from boards/<board>.json)
//	firmware/images/<image>/          make export-images in firmware/, then make -C controller firmware
//	lists/<name>.bin                  espdns blocklist ... -out data/lists/<name>.bin (blocklist or overrides)
//	lists/must-resolve*.txt           names that must resolve after each node (MUST_RESOLVE)
//	zones/<zone>.zone                 the hosted zones' master files, named after their zone
//	configs/<name>.json               the node configs (internal/configs)
const (
	BuildsDir  = "firmware/builds"
	ImagesDir  = "firmware/images"
	ListsDir   = "lists"
	ZonesDir   = "zones"
	BuildFile  = "dns2.bin"
	MaxSoak    = time.Hour
	mustPrefix = "must-resolve"
)

// Web is a rolling push as the Push page asks for it (the job kind "rollout"). Every name
// is a file in the data directory, by the rules above; the nodes are settings.json's.
type Web struct {
	Kind   string   `json:"kind"`
	Nodes  []string `json:"nodes"`            // in order after the canary (NODES)
	Canary string   `json:"canary,omitempty"` // one of Nodes (CANARY); "": settings.json's if one of them, else the first
	SoakS  int      `json:"soak_s,omitempty"` // 0: DefaultSoak; never less
	// Firmware: "builds/<board>" or "images/<image>", one per chip image (FLEET_BOARDS).
	Firmware []string `json:"firmware,omitempty"`
	// Configs: node: file in configs/, one for each node (CONFIGS).
	Configs      map[string]string `json:"configs,omitempty"`
	File         string            `json:"file,omitempty"`  // in lists/ (FILE)
	Zones        []string          `json:"zones,omitempty"` // in zones/ (ZONES)
	CheckBlocked []string          `json:"check_blocked,omitempty"`
	MustResolve  string            `json:"must_resolve,omitempty"` // in lists/ (MUST_RESOLVE)
	DryRun       bool              `json:"dry_run,omitempty"`
	After        string            `json:"after,omitempty"` // the push: the dry run it follows
	// EmptyZones (zones, no Zones): the nodes serve no hosted zone (the CLI's -empty). Never
	// from the Push page's JSON: an apply sets it when its changes delete every zone file.
	EmptyZones bool `json:"-"`
}

// ParseWeb reads a Push page request, unknown fields refused.
func ParseWeb(raw []byte) (Web, error) {
	var w Web
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&w); err != nil {
		return w, fmt.Errorf("params: %v", err)
	}
	return w, nil
}

// Request is the request the CLI's flags make for the same push, as make fleet-rollout
// runs it: -data, -mdns 0, the settings' DNS peers, no flag that loosens the rule. Every
// name is checked here (a file of the data directory, by its rule); the files are read
// when the request is built, each once (Files, from the settings read here on), so the
// push is checked, fingerprinted and pushed from the same bytes.
func (w Web) Request(dataDir, catalog string) (Request, error) {
	r := Request{DataDir: dataDir, Catalog: catalog, Soak: DefaultSoak, DryRun: w.DryRun, Files: NewFiles()}
	kind, err := release.ParseKind(w.Kind)
	if err != nil || kind == release.Control {
		return r, errors.New(`"kind": firmware, config, blocklist, overrides or zones`)
	}
	r.Kind = kind
	s, err := r.loadSettings()
	if err != nil {
		return r, err
	}
	if len(w.Nodes) == 0 {
		return r, errors.New(`"nodes": choose the nodes to change`)
	}
	for i, n := range w.Nodes {
		switch {
		case !slices.Contains(s.Nodes, n):
			return r, fmt.Errorf("%s is not in settings.json: a rolling push changes only the nodes listed there", n)
		case slices.Contains(w.Nodes[:i], n):
			return r, fmt.Errorf("%s twice in \"nodes\"", n)
		}
	}
	r.Hosts = slices.Clone(w.Nodes)
	if w.Canary != "" {
		if !slices.Contains(w.Nodes, w.Canary) {
			return r, fmt.Errorf("the canary %s is not one of the nodes changed (it never adds a node)", w.Canary)
		}
		r.Canary = w.Canary
	}
	if w.SoakS != 0 {
		// Checked in seconds first: a huge count of seconds would overflow a Duration.
		if w.SoakS < int(DefaultSoak/time.Second) || w.SoakS > int(MaxSoak/time.Second) {
			return r, fmt.Errorf("soak: %v to %v, not %d s", DefaultSoak, MaxSoak, w.SoakS)
		}
		r.Soak = time.Duration(w.SoakS) * time.Second
	}
	for _, n := range w.CheckBlocked {
		c, ok := blocklist.Canon(n)
		if !ok || c != n {
			return r, fmt.Errorf("check_blocked: %q is not a name (lowercase, no trailing dot)", n)
		}
		if !slices.Contains(r.Checks.Blocked, c) {
			r.Checks.Blocked = append(r.Checks.Blocked, c)
		}
	}
	if w.MustResolve != "" {
		if err := MustResolveName(w.MustResolve); err != nil {
			return r, err
		}
		r.Checks.MustResolve = filepath.Join(dataDir, ListsDir, w.MustResolve)
	}
	only := func(field string, set bool, kinds ...release.Kind) error {
		if set && !slices.Contains(kinds, kind) {
			return fmt.Errorf("%q is not for a %s push", field, kind)
		}
		return nil
	}
	if err := errors.Join(only("firmware", len(w.Firmware) > 0, release.Firmware),
		only("configs", len(w.Configs) > 0, release.Config),
		only("file", w.File != "", release.Blocklist, release.Overrides),
		only("zones", len(w.Zones) > 0, release.Zones)); err != nil {
		return r, err
	}
	switch kind {
	case release.Firmware:
		if len(w.Firmware) == 0 {
			return r, errors.New(`"firmware": choose the firmware, one per chip image`)
		}
		seen := map[string]string{}
		for _, f := range w.Firmware {
			img, spec, err := FirmwareSource(dataDir, catalog, f)
			if err != nil {
				return r, err
			}
			if o, ok := seen[img]; ok {
				return r, fmt.Errorf("%s and %s are both chip image %s: the rollout picks a node's firmware by its chip image, so one each", o, f, img)
			}
			seen[img] = f
			r.Images = append(r.Images, spec)
		}
	case release.Config:
		for _, n := range w.Nodes {
			name, ok := w.Configs[n]
			if !ok {
				return r, fmt.Errorf("configs: no config for %s", n)
			}
			if err := configs.CheckName(name); err != nil {
				return r, err
			}
			r.Configs = append(r.Configs, n+"="+filepath.Join(configs.Path(dataDir), name))
		}
		for n := range w.Configs {
			if !slices.Contains(w.Nodes, n) {
				return r, fmt.Errorf("configs: %s is not one of the nodes changed", n)
			}
		}
	case release.Blocklist, release.Overrides:
		if w.File == "" {
			return r, fmt.Errorf(`"file": choose the %s file`, kind)
		}
		if err := configs.FileName(w.File, ".bin", "a list file"); err != nil {
			return r, err
		}
		r.File = filepath.Join(dataDir, ListsDir, w.File)
	case release.Zones:
		if len(w.Zones) == 0 && !w.EmptyZones {
			return r, errors.New(`"zones": choose the hosted zones: the set replaces each node's, so every zone it should serve`)
		}
		if len(w.Zones) > 0 && w.EmptyZones {
			return r, errors.New("zones: no zones, or the zones, not both")
		}
		r.EmptyZones = w.EmptyZones
		for i, z := range w.Zones {
			if err := configs.FileName(z, ".zone", "a zone file"); err != nil {
				return r, err
			}
			if slices.Contains(w.Zones[:i], z) {
				return r, fmt.Errorf("%s twice in \"zones\"", z)
			}
			r.Zones = append(r.Zones, filepath.Join(dataDir, ZonesDir, z))
		}
	}
	return r, nil
}

// MustResolveName refuses a must-resolve file name but lists/must-resolve*.txt.
func MustResolveName(name string) error {
	if err := configs.FileName(name, ".txt", "a must-resolve file"); err != nil {
		return err
	}
	if !strings.HasPrefix(name, mustPrefix) {
		return fmt.Errorf("%q: a must-resolve file is lists/%s*.txt", name, mustPrefix)
	}
	return nil
}

// FirmwareSource is a Push page's firmware ("builds/<board>" or "images/<image>"): its chip
// image and the CLI's -image for it, as the Makefile passes it (image=dns2.bin for a
// board's build; the directory for an exported chip image).
func FirmwareSource(dataDir, catalog, src string) (image, spec string, err error) {
	dir, name, ok := strings.Cut(src, "/")
	if !ok {
		return "", "", fmt.Errorf("firmware %q: builds/<board> or images/<image>", src)
	}
	if err := configs.FileName(name, "", "a board or chip image"); err != nil {
		return "", "", fmt.Errorf("firmware %q: %w", src, err)
	}
	switch dir {
	case "builds":
		img, err := BoardImage(dataDir, catalog, name)
		if err != nil {
			return "", "", err
		}
		return img, img + "=" + filepath.Join(dataDir, BuildsDir, name, BuildFile), nil
	case "images":
		return name, filepath.Join(dataDir, ImagesDir, name), nil
	}
	return "", "", fmt.Errorf("firmware %q: builds/<board> or images/<image>", src)
}

// BoardImage is the chip image a board's firmware is built as: its boards/<board>.json
// "image" (the catalog's, else the data directory's boards/), as the Makefile reads it.
func BoardImage(dataDir, catalog, board string) (string, error) {
	for _, dir := range []string{catalog, filepath.Join(dataDir, "boards")} {
		b, err := os.ReadFile(filepath.Join(dir, board+".json"))
		if err != nil {
			continue
		}
		var def struct {
			Image string `json:"image"`
		}
		if err := json.Unmarshal(b, &def); err != nil || def.Image == "" {
			return "", fmt.Errorf("board %s: no \"image\" in its definition", board)
		}
		return def.Image, nil
	}
	return "", fmt.Errorf("board %s: no boards/%s.json", board, board)
}
