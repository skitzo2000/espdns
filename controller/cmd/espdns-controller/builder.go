package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/skitzo2000/espdns/controller/internal/boards"
	"github.com/skitzo2000/espdns/controller/internal/image"
	"github.com/skitzo2000/espdns/controller/internal/jobs"
	"github.com/skitzo2000/espdns/controller/internal/nodecfg"
)

// builder serves the board catalog and builds a board's image for flashing from the browser.
type builder struct {
	catalogDir string // shipped boards
	customDir  string // data/boards
	imagesDir  string // data/firmware/images

	mu     sync.Mutex
	builds map[string]*build
}

// build is one image prepared for flashing: a board (from the catalog, possibly changed for
// this node, or a custom one) on its chip image.
type build struct {
	ID    string       `json:"id"`
	Board boards.Board `json:"board"`
	Chip  image.Chip   `json:"chip"`
	bin   []byte
}

func newBuilder(catalogDir, customDir, imagesDir string) *builder {
	return &builder{catalogDir: catalogDir, customDir: customDir, imagesDir: imagesDir, builds: map[string]*build{}}
}

func (b *builder) routes(mux jobs.Mux) {
	mux.HandleFunc("GET /api/boards", b.listBoards)
	mux.HandleFunc("POST /api/boards/check", b.checkBoard)
	mux.HandleFunc("POST /api/boards", b.saveBoard)
	mux.HandleFunc("GET /api/images", b.listImages)
	mux.HandleFunc("POST /api/build", b.prepare)
	mux.HandleFunc("GET /build/{id}/manifest.json", b.manifest)
	mux.HandleFunc("GET /build/{id}/image.bin", b.image)
}

type boardView struct {
	boards.Entry
	ImageReady bool `json:"image_ready"` // its chip image has been imported
}

func (b *builder) listBoards(w http.ResponseWriter, r *http.Request) {
	entries, err := boards.Load(b.catalogDir, b.customDir)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	imgs, _ := image.List(b.imagesDir)
	ready := map[string]bool{}
	for _, c := range imgs {
		ready[c.Image] = true
	}
	out := make([]boardView, 0, len(entries))
	for _, e := range entries {
		out = append(out, boardView{e, ready[e.Board.Image]})
	}
	writeJSON(w, out)
}

func (b *builder) listImages(w http.ResponseWriter, r *http.Request) {
	imgs, err := image.List(b.imagesDir)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"images": imgs, "known": boards.Images})
}

func readBoard(w http.ResponseWriter, r *http.Request) (boards.Board, error) {
	var raw json.RawMessage
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&raw); err != nil {
		return boards.Board{}, err
	}
	return boards.Parse(raw)
}

func (b *builder) checkBoard(w http.ResponseWriter, r *http.Request) {
	bd, err := readBoard(w, r)
	if err != nil {
		writeJSON(w, map[string]any{"errors": []string{err.Error()}, "warnings": []string{}})
		return
	}
	errs, warns := boards.Check(bd)
	writeJSON(w, map[string]any{"errors": nonNil(errs), "warnings": nonNil(warns)})
}

func (b *builder) saveBoard(w http.ResponseWriter, r *http.Request) {
	bd, err := readBoard(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	entries, err := boards.Load(b.catalogDir, b.customDir)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := boards.Save(b.customDir, bd, entries); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, bd)
}

// prepare builds the image for a board: {"name": "<catalog board>"} as it is, or
// {"board": {...}} for a changed or custom one, with the node's address in "network"
// ({"address": "192.0.2.52/24", "gateway": "192.0.2.1"}, or {"address": "dhcp"} on
// a network with a DHCP server), which goes into its board partition. It answers with the
// build's id; the browser then flashes /build/<id>/manifest.json with ESP Web Tools.
func (b *builder) prepare(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name    string           `json:"name"`
		Board   json.RawMessage  `json:"board"`
		Network *nodecfg.Network `json:"network"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	entries, err := boards.Load(b.catalogDir, b.customDir)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var e boards.Entry
	switch {
	case len(req.Board) > 0:
		bd, err := boards.Parse(req.Board)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		e = boards.Entry{Source: "custom"}.WithChanges(bd)
	case req.Name != "":
		var ok bool
		if e, ok = boards.Find(entries, req.Name); !ok {
			http.Error(w, "no board "+req.Name, http.StatusNotFound)
			return
		}
	default:
		http.Error(w, "name or board required", http.StatusBadRequest)
		return
	}
	if req.Network != nil {
		bd := e.Board
		bd.Network = req.Network
		e = e.WithChanges(bd)
	}
	bl, err := b.make(e)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	writeJSON(w, bl)
}

func (b *builder) make(e boards.Entry) (*build, error) {
	if len(e.Errors) > 0 {
		return nil, errors.New(strings.Join(e.Errors, "; "))
	}
	if e.Board.Network == nil {
		return nil, errors.New("network: the node's address, with its prefix length and gateway (or dhcp on a network " +
			"with a DHCP server): a node never asks DHCP for one on its own")
	}
	chip, err := image.Open(b.imagesDir + "/" + e.Board.Image)
	if err != nil {
		return nil, fmt.Errorf("chip image %s isn't imported: build it and load it with espdns release import (docs/getting-started.md, steps 4 and 8)", e.Board.Image)
	}
	part, err := e.Pack()
	if err != nil {
		return nil, err
	}
	flash := e.Board.FlashMB
	if flash == 0 {
		flash = 4
	}
	bin, err := chip.Assemble(flash, part)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(bin)
	bl := &build{ID: hex.EncodeToString(sum[:8]), Board: e.Board, Chip: chip, bin: bin}
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.builds) > 32 { // a handful of recent builds is plenty; they are cheap to make again
		b.builds = map[string]*build{}
	}
	b.builds[bl.ID] = bl
	return bl, nil
}

func (b *builder) get(w http.ResponseWriter, r *http.Request) *build {
	b.mu.Lock()
	bl := b.builds[r.PathValue("id")]
	b.mu.Unlock()
	if bl == nil {
		http.Error(w, "no such build: prepare it again", http.StatusNotFound)
	}
	return bl
}

func (b *builder) manifest(w http.ResponseWriter, r *http.Request) {
	bl := b.get(w, r)
	if bl == nil {
		return
	}
	writeJSON(w, bl.Chip.Manifest(bl.Board.Name, "image.bin"))
}

func (b *builder) image(w http.ResponseWriter, r *http.Request) {
	bl := b.get(w, r)
	if bl == nil {
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=espdns-%s.bin", bl.Board.Name))
	w.Write(bl.bin)
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
