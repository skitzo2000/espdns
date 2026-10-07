package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"filippo.io/age"

	"github.com/skitzo2000/espdns/controller/internal/auth"
	"github.com/skitzo2000/espdns/controller/internal/backup"
	"github.com/skitzo2000/espdns/controller/internal/fleetlock"
	"github.com/skitzo2000/espdns/controller/internal/secfile"
)

// minPassphrase is the shortest passphrase the page takes, as espdns backup.
const minPassphrase = 12

// TmpDir, in the data directory, holds a backup while it is written and sent (mode 0700,
// the file in it 0600, removed once sent), not the system's temporary directory: a backup is
// as big as the lists, and the container's /tmp is a small tmpfs, in memory, under a
// read-only root (compose.yaml). A backup leaves it out, as every hidden top-level entry
// (internal/backup).
const TmpDir = ".tmp"

// tmpBackup is a backup's name in TmpDir (os.CreateTemp's pattern, and filepath.Match's):
// one left there by a controller stopped while it was sent is removed at start (clearTmp).
const tmpBackup = "espdns-backup-*.age"

// backupServer is the Backup page's API: what a backup holds, and a backup downloaded.
// Restore is the CLI's only (espdns restore, into a stopped controller's data directory):
// the controller keeps the login's sessions, the jobs and their dry runs in memory, and a
// restore replaces the login and the release key, which a page shouldn't be able to do.
// A download needs the password again (auth.Reauthed): a backup is the release key and the
// Wi-Fi passwords to whoever has its passphrase, which the request names, so a session
// taken over must not be enough.
type backupServer struct {
	dataDir string
	auth    *auth.Auth
}

func (b backupServer) routes(mux *routes) {
	mux.HandleFunc("GET /api/backup", needLogin("a backup needs", b.info))
	mux.HandleFunc("POST /api/backup", needLogin("a backup needs", b.auth.Reauthed(b.download)))
}

// part is one top-level entry of the data directory, its size and whether a backup has it.
type part struct {
	Name     string `json:"name"`
	Bytes    int64  `json:"bytes"`
	Files    int    `json:"files"`
	Included bool   `json:"included"` // in every backup ("firmware" only when asked)
	Note     string `json:"note,omitempty"`
}

// info is what a backup would hold, by top-level entry, and who holds the fleet lock.
func (b backupServer) info(w http.ResponseWriter, r *http.Request) {
	ents, err := os.ReadDir(b.dataDir)
	if err != nil {
		httpErr(w, http.StatusInternalServerError, err)
		return
	}
	var parts []part
	for _, e := range ents {
		if e.Name() == TmpDir {
			continue // the controller's own, empty but while a backup is sent
		}
		p := part{Name: e.Name(), Included: true}
		switch {
		case e.Name() == fleetlock.File:
			p.Included, p.Note = false, "the fleet lock's note"
		case strings.HasPrefix(e.Name(), "."):
			p.Included, p.Note = false, "hidden: a restore's own, or a temporary file"
		case e.Name() == backup.FirmwareDir:
			p.Included, p.Note = false, "only when asked: load the chip images again with espdns release import (docs/operations.md)"
		}
		filepath.WalkDir(filepath.Join(b.dataDir, e.Name()), func(_ string, d fs.DirEntry, err error) error {
			if err == nil && d.Type().IsRegular() {
				if fi, err := d.Info(); err == nil {
					p.Bytes += fi.Size()
					p.Files++
				}
			}
			return nil
		})
		parts = append(parts, p)
	}
	sort.Slice(parts, func(i, j int) bool { return parts[i].Name < parts[j].Name })
	out := map[string]any{"data_dir": b.dataDir, "parts": parts, "format": backup.Format, "min_passphrase": minPassphrase}
	if h, held, err := fleetlock.Held(fleetlock.Path(b.dataDir)); err == nil && held {
		out["lock"] = h.String()
	}
	writeJSON(w, out)
}

// download writes a backup and sends it. The passphrase comes in the request's body (the
// page's POST, on localhost) and goes only into age's scrypt: never into a reply, a log or
// a file. The backup is written whole to a temporary file (encrypted) under the fleet lock,
// which is let go before it is sent: a lock held by a job or the CLI refuses it at once
// (409, naming who holds it) rather than keeping the page waiting.
func (b backupServer) download(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Passphrase string `json:"passphrase"`
		Recipient  string `json:"recipient"`
		Firmware   bool   `json:"firmware"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&body); err != nil {
		httpErr(w, http.StatusBadRequest, errors.New("bad request"))
		return
	}
	var rs []age.Recipient
	how := "a passphrase"
	switch {
	case body.Recipient != "" && body.Passphrase != "":
		httpErr(w, http.StatusBadRequest, errors.New("a passphrase or an age key, not both"))
		return
	case body.Recipient != "":
		parsed, err := age.ParseRecipients(strings.NewReader(body.Recipient))
		if err != nil {
			httpErr(w, http.StatusBadRequest, fmt.Errorf("the age key: %v", err))
			return
		}
		rs, how = parsed, fmt.Sprintf("%d age key(s)", len(parsed))
	case len([]rune(body.Passphrase)) < minPassphrase:
		httpErr(w, http.StatusBadRequest, fmt.Errorf("the passphrase: at least %d characters", minPassphrase))
		return
	default:
		rec, _, err := backup.Passphrase(body.Passphrase)
		if err != nil {
			httpErr(w, http.StatusBadRequest, errors.New("the passphrase can't be used"))
			return
		}
		rs = []age.Recipient{rec}
	}
	body.Passphrase = ""
	who := auth.User(r.Context())

	tmp := filepath.Join(b.dataDir, TmpDir)
	if err := secfile.MkdirAll(tmp); err != nil {
		httpErr(w, http.StatusInternalServerError, err)
		return
	}
	f, err := os.CreateTemp(tmp, tmpBackup)
	if err != nil {
		httpErr(w, http.StatusInternalServerError, err)
		return
	}
	defer os.Remove(f.Name())
	defer f.Close()
	s, err := func() (backup.Summary, error) {
		lk, err := backup.Lock(r.Context(), b.dataDir, "espdns-controller backup by "+who, 0, nil)
		if err != nil {
			return backup.Summary{}, err
		}
		defer lk.Release()
		return backup.Write(b.dataDir, f, rs, backup.Options{Firmware: body.Firmware, Context: r.Context()})
	}()
	switch {
	case errors.Is(err, fleetlock.ErrLocked):
		httpErr(w, http.StatusConflict, fmt.Errorf("%v (the page's backup doesn't wait for it; espdns backup -wait does)", err))
		return
	case err != nil:
		httpErr(w, http.StatusInternalServerError, err)
		return
	}
	size, err := f.Seek(0, io.SeekCurrent)
	if err == nil {
		_, err = f.Seek(0, io.SeekStart)
	}
	if err != nil {
		httpErr(w, http.StatusInternalServerError, err)
		return
	}
	name := "espdns-backup-" + time.Now().Format("20060102-150405") + ".age"
	h := w.Header()
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Content-Disposition", `attachment; filename="`+name+`"`)
	h.Set("Content-Length", strconv.FormatInt(size, 10))
	h.Set("Cache-Control", "no-store")
	h.Set("X-Backup-Summary", fmt.Sprintf("%d files, %d directories, %d bytes", s.Files, s.Dirs, s.Bytes))
	log.Printf("backup: %s downloaded %s (%d files, %d directories, %d bytes before encryption, to %s; firmware %v)",
		who, name, s.Files, s.Dirs, s.Bytes, how, body.Firmware)
	if _, err := io.Copy(w, f); err != nil && !errors.Is(err, context.Canceled) {
		log.Printf("backup: sending %s: %v", name, err)
	}
}
