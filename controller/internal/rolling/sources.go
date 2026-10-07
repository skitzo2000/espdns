package rolling

import (
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/skitzo2000/espdns/controller/internal/blocklist"
	"github.com/skitzo2000/espdns/controller/internal/configs"
	"github.com/skitzo2000/espdns/controller/internal/image"
	"github.com/skitzo2000/espdns/controller/internal/release"
	"github.com/skitzo2000/espdns/controller/internal/zones"
)

// What the Push page can push, from the data directory: each file read and checked as the
// rollout would, a file that fails shown with why.

// FirmwareInfo is one firmware the page offers.
type FirmwareInfo struct {
	Source  string `json:"source"`          // builds/<board> or images/<image>
	Image   string `json:"image,omitempty"` // the chip image: the nodes it fits run it
	Board   string `json:"board,omitempty"` // a build's board
	Chip    string `json:"chip,omitempty"`
	Project string `json:"project,omitempty"`
	Version string `json:"version,omitempty"`
	Built   string `json:"built,omitempty"`
	Elf     string `json:"elf,omitempty"`
	Bytes   int64  `json:"bytes"`
	Path    string `json:"path"`
	Error   string `json:"error,omitempty"`
}

// ListInfo is one list file (blocklist or overrides).
type ListInfo struct {
	Name     string `json:"name"`
	Bytes    int64  `json:"bytes"`
	Version  int    `json:"version,omitempty"`
	HashBits int    `json:"hash_bits,omitempty"`
	XorBits  int    `json:"xor_bits"`
	Entries  uint32 `json:"entries,omitempty"`
	Modified string `json:"modified"`
	Error    string `json:"error,omitempty"`
}

// ZoneInfo is one hosted zone file.
type ZoneInfo struct {
	Name    string `json:"name"`
	Zone    string `json:"zone,omitempty"`
	Serial  uint32 `json:"serial,omitempty"`
	Records int    `json:"records,omitempty"`
	Error   string `json:"error,omitempty"`
}

// NamesInfo is one must-resolve file.
type NamesInfo struct {
	Name  string `json:"name"`
	Names int    `json:"names"`
	Error string `json:"error,omitempty"`
}

// Sources is everything the page offers.
type Sources struct {
	Firmware    []FirmwareInfo    `json:"firmware"`
	Lists       []ListInfo        `json:"lists"`
	Zones       []ZoneInfo        `json:"zones"`
	MustResolve []NamesInfo       `json:"must_resolve"`
	Configs     []string          `json:"configs"`
	Dirs        map[string]string `json:"dirs"`
}

// listFiles is the names in dir with ext that pass the name rule.
func listFiles(dir, ext string) []string {
	ents, _ := os.ReadDir(dir)
	var out []string
	for _, e := range ents {
		if e.Type().IsRegular() && configs.FileName(e.Name(), ext, "") == nil {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}

// ReadSources reads what is in the data directory to push.
func ReadSources(dataDir, catalog string) Sources {
	s := Sources{Firmware: []FirmwareInfo{}, Lists: []ListInfo{}, Zones: []ZoneInfo{}, MustResolve: []NamesInfo{},
		Configs: []string{}, Dirs: map[string]string{"builds": filepath.Join(dataDir, BuildsDir),
			"images": filepath.Join(dataDir, ImagesDir), "lists": filepath.Join(dataDir, ListsDir),
			"zones": filepath.Join(dataDir, ZonesDir), "configs": configs.Path(dataDir)}}
	s.Firmware = ReadFirmware(dataDir, catalog)
	s.Lists = ReadLists(dataDir)
	for _, n := range listFiles(filepath.Join(dataDir, ListsDir), ".txt") {
		if MustResolveName(n) != nil {
			continue
		}
		ni := NamesInfo{Name: n}
		if names, err := blocklist.ReadNames(filepath.Join(dataDir, ListsDir, n)); err != nil {
			ni.Error = err.Error()
		} else {
			ni.Names = len(names)
		}
		s.MustResolve = append(s.MustResolve, ni)
	}
	for _, n := range listFiles(filepath.Join(dataDir, ZonesDir), ".zone") {
		zi := ZoneInfo{Name: n}
		if z, err := zones.LoadFile(filepath.Join(dataDir, ZonesDir, n)); err != nil {
			zi.Error = err.Error()
		} else {
			set := &zones.Set{Zones: []*zones.Zone{z}}
			if err := set.Validate(); err != nil {
				zi.Error = err.Error()
			}
			zi.Zone, zi.Serial, zi.Records = z.Name(), z.Serial(), len(z.Records)
		}
		s.Zones = append(s.Zones, zi)
	}
	if fs, err := configs.List(dataDir); err == nil {
		for _, f := range fs {
			s.Configs = append(s.Configs, f.Name)
		}
	}
	return s
}

// ReadFirmware reads the firmware in the data directory (the boards' builds, then the
// exported chip images), each read and checked as the rollout reads it, one that fails
// with why.
func ReadFirmware(dataDir, catalog string) []FirmwareInfo {
	out := []FirmwareInfo{}
	// The builds: firmware/builds/<board>/dns2.bin.
	ents, _ := os.ReadDir(filepath.Join(dataDir, BuildsDir))
	for _, e := range ents {
		if !e.IsDir() || configs.FileName(e.Name(), "", "") != nil {
			continue
		}
		f := FirmwareInfo{Source: "builds/" + e.Name(), Board: e.Name(), Path: filepath.Join(dataDir, BuildsDir, e.Name(), BuildFile)}
		img, err := BoardImage(dataDir, catalog, e.Name())
		if err != nil {
			f.Error = err.Error()
		}
		f.Image = img
		appInfo(&f, f.Path)
		out = append(out, f)
	}
	// The exported chip images: firmware/images/<image>/.
	ents, _ = os.ReadDir(filepath.Join(dataDir, ImagesDir))
	for _, e := range ents {
		if !e.IsDir() || configs.FileName(e.Name(), "", "") != nil {
			continue
		}
		dir := filepath.Join(dataDir, ImagesDir, e.Name())
		f := FirmwareInfo{Source: "images/" + e.Name(), Image: e.Name(), Path: filepath.Join(dir, "app.bin")}
		c, err := image.Open(dir)
		switch {
		case err != nil:
			f.Error = err.Error()
		case c.Image != e.Name():
			f.Error = "its image.json says chip image " + c.Image + ", not " + e.Name()
		default:
			f.Chip = c.Chip
		}
		appInfo(&f, f.Path)
		out = append(out, f)
	}
	return out
}

// ReadLists reads the list files in lists/ (blocklist or overrides) as a push checks them.
func ReadLists(dataDir string) []ListInfo {
	out := []ListInfo{}
	for _, n := range listFiles(filepath.Join(dataDir, ListsDir), ".bin") {
		out = append(out, listInfo(filepath.Join(dataDir, ListsDir, n)))
	}
	return out
}

// appInfo reads an app image's descriptor (as the rollout does) into f.
func appInfo(f *FirmwareInfo, path string) {
	b, err := os.ReadFile(path)
	if err != nil {
		if f.Error == "" {
			f.Error = err.Error()
		}
		return
	}
	f.Bytes = int64(len(b))
	d, err := release.ParseAppDesc(b)
	if err != nil {
		if f.Error == "" {
			f.Error = path + ": " + err.Error()
		}
		return
	}
	f.Project, f.Version, f.Built, f.Elf = d.Project, d.Version, strings.TrimSpace(d.Built), d.ElfSHA256
}

// listInfo reads a list file's header, checked as the rollout checks it.
func listInfo(path string) ListInfo {
	li := ListInfo{Name: filepath.Base(path)}
	fi, err := os.Stat(path)
	if err != nil {
		li.Error = err.Error()
		return li
	}
	li.Bytes, li.Modified = fi.Size(), fi.ModTime().UTC().Format("2006-01-02T15:04:05Z")
	f, err := os.Open(path)
	if err != nil {
		li.Error = err.Error()
		return li
	}
	defer f.Close()
	hdr := make([]byte, blocklist.FileHeader)
	if _, err := io.ReadFull(f, hdr); err != nil || string(hdr[:8]) != blocklist.FileMagic {
		li.Error = "not a blocklist file (espdns blocklist ... -out)"
		return li
	}
	need, err := blocklist.PlanNeed(hdr, fi.Size())
	if err != nil {
		li.Error = err.Error()
		return li
	}
	li.Version, li.HashBits, li.XorBits, li.Entries = int(hdr[8]), int(hdr[9]), int(hdr[10]), need.Entries
	return li
}
