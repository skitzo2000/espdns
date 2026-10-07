// Package backup writes the controller's data directory to one encrypted file and restores
// it into an empty one (docs/design.md, Controller, Easy to rebuild): `espdns backup`, the
// Backup page, `espdns restore`.
//
// The file is an age file (filippo.io/age, the age-encryption.org/v1 format, binary): to a
// passphrase (age's scrypt recipient, work factor 2^18) or to age public keys. Its plaintext
// is a tar stream (PAX):
//
//	espdns-backup.json      the manifest: the format (1), when and where it was made, what it leaves out
//	data/<path>             every directory and regular file of the data directory, by its path
//	                        there, with its mode and modification time; directories before what is in them
//	espdns-backup.end.json  every file's size and sha256, and what was skipped: the end
//
// age authenticates the stream in 64 KiB chunks, the last one marked as the last, so a
// wrong passphrase, a byte changed anywhere and a file cut short anywhere are each refused,
// and a restore checks everything (the paths, the sizes, the sums, the settings, the keys and
// the login) before it puts anything in place. Being age, a backup can also be opened with
// the age tool (`age -d backup.age | tar -t`).
//
// Left out: the fleet lock (only a note of its last holder), temporary files (a name starting
// with "."; the .history and .pushed directories are kept), a top-level entry starting with
// "." (a restore's own), and firmware/ unless asked (Options.Firmware: the boards' builds
// and the chip images, made again from the repository by make fleet-firmware and make
// firmware, and the largest part by far). A symbolic link, device, socket or pipe is not
// backed up: it is listed in the end as skipped.
package backup

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"
)

// The format.
const (
	Format       = 1 // this package writes; a restore refuses a newer one
	Kind         = "espdns-backup"
	ManifestName = "espdns-backup.json"
	EndName      = "espdns-backup.end.json"
	DataPrefix   = "data/"
)

// Limits a restore holds a backup to.
const (
	MaxFile    = 4 << 30  // one file
	MaxTotal   = 32 << 30 // every file
	MaxEntries = 500_000
	MaxDepth   = 16
	maxMeta    = 64 << 20 // the manifest and the end
)

// WorkFactor is the scrypt work factor (log2 N) a passphrase is stretched with: age's
// default, about a second and 256 MiB. Tests lower it.
var WorkFactor = 18

// FirmwareDir is left out unless Options.Firmware.
const FirmwareDir = "firmware"

// Manifest is the backup's first entry.
type Manifest struct {
	Kind     string    `json:"kind"`
	Format   int       `json:"format"`
	Created  time.Time `json:"created"`
	Host     string    `json:"host,omitempty"`
	DataDir  string    `json:"data_dir"`
	Firmware bool      `json:"firmware"` // firmware/ is in it
	// Excluded says what a backup leaves out by rule, for the listing.
	Excluded []string `json:"excluded"`
}

// FileSum is one file's size and sha256 (hex).
type FileSum struct {
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// End is the backup's last entry.
type End struct {
	Files   map[string]FileSum `json:"files"` // by path in the data directory
	Dirs    int                `json:"dirs"`
	Bytes   int64              `json:"bytes"`
	Skipped []string           `json:"skipped,omitempty"` // "path: why"
}

// Options are what a backup takes.
type Options struct {
	Firmware bool             // firmware/ too
	Now      func() time.Time // nil: time.Now
	// Context stops the backup when done (the page's request gone, the CLI's Ctrl-C), so
	// the fleet lock isn't held for a backup nobody will get. nil: never.
	Context context.Context
}

// Summary is what a backup wrote.
type Summary struct {
	Files, Dirs int
	Bytes       int64
	Skipped     []string
	Excluded    []string
}

func (o Options) ctx() context.Context {
	if o.Context != nil {
		return o.Context
	}
	return context.Background()
}

func (o Options) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

// excluded says what the backup leaves out by rule, for the manifest.
func (o Options) excluded() []string {
	ex := []string{"fleet.lock (the lock's note)", "temporary files (names starting with \".\")"}
	if !o.Firmware {
		ex = append(ex, "firmware/ (the boards' builds and the chip images: load them again with espdns release import)")
	}
	return ex
}

// skip says whether rel (a path in the data directory, slashes) is left out by rule.
func (o Options) skip(rel string, dir bool) bool {
	base := path.Base(rel)
	switch {
	case rel == "fleet.lock":
		return true
	case !strings.Contains(rel, "/") && strings.HasPrefix(rel, "."):
		return true // a restore's own (.restore-*, .before-restore-*), or anything hidden at the top
	case !dir && strings.HasPrefix(base, "."):
		return true // a temporary file a write renames into place
	case rel == FirmwareDir && !o.Firmware:
		return true
	}
	return false
}

// Passphrase is the age recipient and identity of a passphrase.
func Passphrase(p string) (age.Recipient, age.Identity, error) {
	if p == "" {
		return nil, nil, errors.New("an empty passphrase")
	}
	r, err := age.NewScryptRecipient(p)
	if err != nil {
		return nil, nil, err
	}
	r.SetWorkFactor(WorkFactor)
	id, err := age.NewScryptIdentity(p)
	if err != nil {
		return nil, nil, err
	}
	return r, id, nil
}

// Write writes a backup of dataDir to w, encrypted to recipients. The caller holds the
// fleet lock (Lock), so no job or CLI change writes while it reads; a file that changes as
// it is read (an editor's save is a new file renamed into place, so one open reads a whole
// version) fails the backup.
func Write(dataDir string, w io.Writer, recipients []age.Recipient, o Options) (Summary, error) {
	var sum Summary
	if len(recipients) == 0 {
		return sum, errors.New("no passphrase or recipient to encrypt to")
	}
	root, err := filepath.EvalSymlinks(dataDir)
	if err != nil {
		return sum, err
	}
	if fi, err := os.Stat(root); err != nil || !fi.IsDir() {
		return sum, fmt.Errorf("%s: not a directory", dataDir)
	}
	aw, err := age.Encrypt(w, recipients...)
	if err != nil {
		return sum, err
	}
	tw := tar.NewWriter(aw)
	host, _ := os.Hostname()
	now := o.now()
	sum.Excluded = o.excluded()
	m := Manifest{Kind: Kind, Format: Format, Created: now.UTC(), Host: host, DataDir: dataDir, Firmware: o.Firmware,
		Excluded: sum.Excluded}
	if err := writeJSON(tw, ManifestName, m, now); err != nil {
		return sum, err
	}
	end := End{Files: map[string]FileSum{}}
	ctx := o.ctx()
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("the backup stopped: %w", err)
		}
		if p == root {
			return nil
		}
		r, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		rel := filepath.ToSlash(r)
		t := d.Type()
		if o.skip(rel, t.IsDir()) {
			if t.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		switch {
		case t.IsDir():
			fi, err := d.Info()
			if err != nil {
				return err
			}
			end.Dirs++
			return tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: DataPrefix + rel + "/", Mode: int64(fi.Mode().Perm()),
				ModTime: fi.ModTime(), Format: tar.FormatPAX})
		case t.IsRegular():
			s, err := addFile(ctx, tw, p, rel)
			if err != nil {
				return err
			}
			end.Files[rel] = s
			end.Bytes += s.Size
			return nil
		default:
			end.Skipped = append(end.Skipped, rel+": "+kindOf(t)+", not backed up")
			return nil
		}
	})
	if err != nil {
		return sum, err
	}
	if err := writeJSON(tw, EndName, end, now); err != nil {
		return sum, err
	}
	if err := tw.Close(); err != nil {
		return sum, err
	}
	if err := aw.Close(); err != nil {
		return sum, err
	}
	sum.Files, sum.Dirs, sum.Bytes, sum.Skipped = len(end.Files), end.Dirs, end.Bytes, end.Skipped
	return sum, nil
}

func kindOf(t fs.FileMode) string {
	switch {
	case t&fs.ModeSymlink != 0:
		return "a symbolic link"
	case t&fs.ModeDevice != 0:
		return "a device"
	case t&fs.ModeNamedPipe != 0:
		return "a pipe"
	case t&fs.ModeSocket != 0:
		return "a socket"
	}
	return "not a regular file (" + t.String() + ")"
}

// addFile writes one file: opened without following a link, read to the size it had when
// opened, and refused if it grew or shrank meanwhile.
func addFile(ctx context.Context, tw *tar.Writer, p, rel string) (FileSum, error) {
	f, err := os.OpenFile(p, os.O_RDONLY|noFollow, 0)
	if err != nil {
		return FileSum{}, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return FileSum{}, err
	}
	if !fi.Mode().IsRegular() {
		return FileSum{}, fmt.Errorf("%s: no longer a regular file", rel)
	}
	if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: DataPrefix + rel, Mode: int64(fi.Mode().Perm()),
		Size: fi.Size(), ModTime: fi.ModTime(), Format: tar.FormatPAX}); err != nil {
		return FileSum{}, err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tw, h), ctxReader{ctx, io.LimitReader(f, fi.Size())})
	if err != nil {
		return FileSum{}, fmt.Errorf("%s: %w", rel, err)
	}
	var one [1]byte
	if k, _ := f.Read(one[:]); n != fi.Size() || k != 0 {
		return FileSum{}, fmt.Errorf("%s changed while it was read (a writer outside the fleet lock): run the backup again", rel)
	}
	return FileSum{Size: n, SHA256: hex.EncodeToString(h.Sum(nil))}, nil
}

// ctxReader fails its reads once ctx is done: a large file stops at the next read.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c ctxReader) Read(b []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, fmt.Errorf("the backup stopped: %w", err)
	}
	return c.r.Read(b)
}

func writeJSON(tw *tar.Writer, name string, v any, now time.Time) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: name, Mode: 0o600, Size: int64(len(b)), ModTime: now,
		Format: tar.FormatPAX}); err != nil {
		return err
	}
	_, err = tw.Write(b)
	return err
}
