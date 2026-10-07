package backup

import (
	"archive/tar"
	"bytes"
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
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"filippo.io/age"

	"github.com/skitzo2000/espdns/controller/internal/auth"
	"github.com/skitzo2000/espdns/controller/internal/fleetlock"
	"github.com/skitzo2000/espdns/controller/internal/keys"
	"github.com/skitzo2000/espdns/controller/internal/secfile"
	"github.com/skitzo2000/espdns/controller/internal/settings"
)

// Errors a restore is refused with (errors.Is).
var (
	ErrWrongKey = errors.New("wrong passphrase (or a backup made for another age key)")
	ErrNotEmpty = errors.New("the data directory is not empty")
	ErrNewer    = errors.New("a newer backup format")
	ErrDamaged  = errors.New("the backup is damaged, cut short or was changed")
	ErrRefused  = errors.New("the backup holds an entry a restore refuses")
)

// RestoreOptions are what a restore takes.
type RestoreOptions struct {
	// DryRun reads and checks the whole backup and writes nothing.
	DryRun bool
	// Force restores into a data directory that isn't empty: what is there is moved into
	// <dir>/.before-restore-<time>/ first, nothing deleted.
	Force bool
	Now   func() time.Time
}

// Entry is one directory or file in a backup.
type Entry struct {
	Path    string      `json:"path"`
	Dir     bool        `json:"dir,omitempty"`
	Size    int64       `json:"size"`
	Mode    fs.FileMode `json:"mode"` // as restored
	ModTime time.Time   `json:"mod_time"`
}

// Contents is what a restore read (and, but for a dry run, put in place).
type Contents struct {
	Manifest Manifest
	Entries  []Entry
	End      End
	// Checked says what was checked beyond the sums: the settings, the keys, the login.
	Checked []string
	// MovedAside is where a forced restore moved what the directory held ("" if nothing).
	MovedAside string
}

// checked are the files a restore checks as the controller reads them.
var checked = []string{settings.File, auth.File, keys.Dir + "/" + keys.File, keys.Dir + "/" + keys.TokenFile}

// mode is the mode a restored entry gets, whatever the backup says: the controller user's
// only, as the controller makes everything in the data directory (internal/secfile), a
// directory 0700 and a file 0600 (no set-id bits, no execute).
func mode(dir bool) fs.FileMode {
	if dir {
		return secfile.DirMode
	}
	return secfile.FileMode
}

// entryPath checks a tar entry's name and returns its path in the data directory: under
// data/, relative, clean, no "..", no hidden top-level entry, no fleet lock, at most MaxDepth
// deep, printable UTF-8.
func entryPath(name string, dir bool) (string, error) {
	rel, ok := strings.CutPrefix(name, DataPrefix)
	if dir {
		rel = strings.TrimSuffix(rel, "/")
	}
	bad := func(why string) (string, error) {
		return "", fmt.Errorf("%w: %q: %s", ErrRefused, name, why)
	}
	switch {
	case !ok:
		return bad("not under " + DataPrefix)
	case rel == "" || !utf8.ValidString(rel):
		return bad("no name, or not UTF-8")
	case strings.ContainsFunc(rel, func(r rune) bool { return r == '\\' || r != ' ' && !unicode.IsPrint(r) }):
		// (not printable: C0 and C1 controls, which a terminal listing it could act on, and
		// format characters such as the bidirectional overrides, which make it read as another)
		return bad("a control or format character, or a backslash")
	case path.Clean(rel) != rel || !filepath.IsLocal(filepath.FromSlash(rel)) || strings.HasPrefix(rel, "/"):
		return bad("not a clean relative path in the data directory")
	}
	parts := strings.Split(rel, "/")
	if len(parts) > MaxDepth {
		return bad(fmt.Sprintf("more than %d deep", MaxDepth))
	}
	for _, p := range parts {
		if p == "." || p == ".." || len(p) > 255 {
			return bad("a . or .. part, or a name over 255 bytes")
		}
	}
	if rel == "fleet.lock" || strings.HasPrefix(parts[0], ".") {
		return bad("never in a backup (the fleet lock, or a hidden top-level entry)")
	}
	return rel, nil
}

// Empty says whether dir has nothing a restore would replace: it doesn't exist, or holds
// nothing but a fleet lock (a controller or a CLI run there made it, and it holds only a note).
func Empty(dir string) (bool, error) {
	ents, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	for _, e := range ents {
		if e.Name() != fleetlock.File {
			return false, nil
		}
	}
	return true, nil
}

// Restore reads a backup from src (decrypted with ids), checks all of it, and, unless a dry
// run, puts it in dataDir: an empty directory (made if missing), or with o.Force one whose
// contents are moved aside first. Nothing is in place until every check has passed: the
// files go into <dataDir>/.restore-<time>/ and are moved into place at the end. It holds
// dataDir's fleet lock while it writes. The controller must not be running on dataDir
// (it keeps the login's sessions, job records and dry runs in memory).
func Restore(src io.Reader, ids []age.Identity, dataDir string, o RestoreOptions) (c Contents, err error) {
	now := time.Now
	if o.Now != nil {
		now = o.Now
	}
	stamp := now().UTC().Format("20060102-150405")
	var stage string
	keepStage := false
	if !o.DryRun {
		var lk *fleetlock.Lock
		if lk, stage, err = prepare(dataDir, stamp, o.Force); err != nil {
			return c, err
		}
		defer lk.Release()
		defer func() {
			if err != nil && !keepStage { // (the named result: whatever refused the restore)
				os.RemoveAll(stage)
			}
		}()
	}
	small, err := read(src, ids, stage, &c)
	if err != nil {
		return c, err
	}
	if c.Checked, err = validate(small); err != nil {
		return c, err
	}
	if o.DryRun {
		return c, nil
	}
	if err := finish(stage, c.Entries); err != nil {
		return c, err
	}
	if c.MovedAside, err = moveAside(dataDir, stage, stamp); err != nil {
		if c.MovedAside != "" {
			return c, fmt.Errorf("%w: nothing restored; part of what %s held was moved into %s: move it back", err, dataDir, c.MovedAside)
		}
		return c, err
	}
	if err = moveIn(dataDir, stage); err != nil {
		// Some of the backup's files may be in place already: keep the rest where they are.
		keepStage = true
		where := ""
		if c.MovedAside != "" {
			where = "; what was there is in " + c.MovedAside
		}
		return c, fmt.Errorf("%w: the restore stopped part way: the backup's files not yet moved are in %s%s", err, stage, where)
	}
	os.Remove(stage)
	// As the controller reads them, from where they are now: the modes and the owner too.
	if err := validatePlaced(dataDir); err != nil {
		return c, fmt.Errorf("restored, but: %w", err)
	}
	return c, nil
}

// prepare checks the data directory is empty (or o.Force), makes it if missing, takes its
// fleet lock and makes the stage in it.
func prepare(dataDir, stamp string, force bool) (*fleetlock.Lock, string, error) {
	if fi, err := os.Lstat(dataDir); err == nil && !fi.IsDir() {
		return nil, "", fmt.Errorf("%s: not a directory", dataDir)
	}
	empty, err := Empty(dataDir)
	if err != nil {
		return nil, "", err
	}
	if !empty && !force {
		return nil, "", fmt.Errorf("%w: %s (restore into an empty one, or -force to move what is there into %s/.before-restore-<time>/ first)",
			ErrNotEmpty, dataDir, dataDir)
	}
	if err := secfile.MkdirAll(dataDir); err != nil {
		return nil, "", err
	}
	lk, err := fleetlock.Acquire(fleetlock.Path(dataDir), fleetlock.Self("espdns restore", "into "+dataDir))
	if err != nil {
		return nil, "", err
	}
	stage := filepath.Join(dataDir, ".restore-"+stamp)
	if err := os.Mkdir(stage, 0o700); err != nil {
		lk.Release()
		return nil, "", err
	}
	return lk, stage, nil
}

// read decrypts and reads the whole backup, writing its files into stage ("" for a dry run),
// and returns the small files validate checks.
func read(src io.Reader, ids []age.Identity, stage string, c *Contents) (map[string][]byte, error) {
	dec, err := age.Decrypt(src, ids...)
	if err != nil {
		var nm *age.NoIdentityMatchError
		if errors.As(err, &nm) {
			return nil, ErrWrongKey
		}
		return nil, fmt.Errorf("not an espdns backup (an age file), or its header is damaged: %v", err)
	}
	damaged := func(err error) error {
		if errors.Is(err, ErrRefused) || errors.Is(err, ErrNewer) {
			return err
		}
		return fmt.Errorf("%w: %v: nothing restored", ErrDamaged, err)
	}
	tr := tar.NewReader(dec)
	// The manifest.
	h, err := tr.Next()
	if err != nil {
		return nil, damaged(err)
	}
	if h.Name != ManifestName || h.Typeflag != tar.TypeReg || h.Size > maxMeta {
		return nil, fmt.Errorf("not an espdns backup: it starts with %q, not %s", h.Name, ManifestName)
	}
	if err := readJSON(tr, h.Size, &c.Manifest); err != nil {
		return nil, damaged(err)
	}
	switch m := c.Manifest; {
	case m.Kind != Kind:
		return nil, fmt.Errorf("not an espdns backup (kind %q)", m.Kind)
	case m.Format > Format:
		return nil, fmt.Errorf("%w %d (this espdns reads %d and older): restore it with the espdns that made it, or a newer one",
			ErrNewer, m.Format, Format)
	case m.Format < 1:
		return nil, fmt.Errorf("not an espdns backup (format %d)", m.Format)
	}
	small := map[string][]byte{}
	dirs, seen := map[string]bool{}, map[string]bool{}
	files := map[string]FileSum{}
	var total int64
	ended := false
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, damaged(err)
		}
		if ended {
			return nil, fmt.Errorf("%w: %q after the end", ErrRefused, h.Name)
		}
		if h.Name == EndName && h.Typeflag == tar.TypeReg {
			if h.Size > maxMeta {
				return nil, fmt.Errorf("%w: the end is over %d bytes", ErrRefused, maxMeta)
			}
			if err := readJSON(tr, h.Size, &c.End); err != nil {
				return nil, damaged(err)
			}
			ended = true
			continue
		}
		if len(c.Entries) >= MaxEntries {
			return nil, fmt.Errorf("%w: over %d entries", ErrRefused, MaxEntries)
		}
		var dir bool
		switch h.Typeflag {
		case tar.TypeDir:
			dir = true
		case tar.TypeReg: // (the reader reports an old writer's TypeRegA as this)
		default:
			return nil, fmt.Errorf("%w: %q is %s, not a file or directory", ErrRefused, h.Name, typeName(h.Typeflag))
		}
		rel, err := entryPath(h.Name, dir)
		if err != nil {
			return nil, err
		}
		for k := range h.PAXRecords {
			// A PAX sparse file reads back larger than it is stored (its holes as zeros): a
			// backup never writes one.
			if strings.HasPrefix(k, "GNU.sparse.") {
				return nil, fmt.Errorf("%w: %q is a sparse file", ErrRefused, h.Name)
			}
		}
		if seen[rel] {
			return nil, fmt.Errorf("%w: %q twice", ErrRefused, rel)
		}
		seen[rel] = true
		if parent := path.Dir(rel); parent != "." && !dirs[parent] {
			return nil, fmt.Errorf("%w: %q before its directory", ErrRefused, rel)
		}
		e := Entry{Path: rel, Dir: dir, Mode: mode(dir), ModTime: h.ModTime}
		if dir {
			e.Mode |= fs.ModeDir
			dirs[rel] = true
			c.Entries = append(c.Entries, e)
			if stage != "" {
				if err := os.Mkdir(filepath.Join(stage, filepath.FromSlash(rel)), 0o700); err != nil {
					return nil, err
				}
			}
			continue
		}
		if h.Size < 0 || h.Size > MaxFile {
			return nil, fmt.Errorf("%w: %q: %d bytes (at most %d)", ErrRefused, rel, h.Size, int64(MaxFile))
		}
		if total += h.Size; total > MaxTotal {
			return nil, fmt.Errorf("%w: over %d bytes in all", ErrRefused, int64(MaxTotal))
		}
		e.Size = h.Size
		var keep *bytes.Buffer
		if slices.Contains(checked, rel) && h.Size <= 1<<20 {
			keep = &bytes.Buffer{}
			small[rel] = nil
		}
		s, err := extract(tr, h.Size, stage, rel, keep)
		if err != nil {
			return nil, damaged(err)
		}
		if keep != nil {
			small[rel] = keep.Bytes()
		}
		files[rel] = s
		c.Entries = append(c.Entries, e)
	}
	if !ended {
		return nil, fmt.Errorf("%w: no %s: nothing restored", ErrDamaged, EndName)
	}
	// age checks the last chunk is marked as the last only once it is read to its end.
	if _, err := io.Copy(io.Discard, dec); err != nil {
		return nil, damaged(err)
	}
	// Every file the end lists, of its size and sum, and no other.
	if len(c.End.Files) != len(files) {
		return nil, fmt.Errorf("%w: %d files, the end lists %d: nothing restored", ErrDamaged, len(files), len(c.End.Files))
	}
	for rel, s := range files {
		if c.End.Files[rel] != s {
			return nil, fmt.Errorf("%w: %s doesn't match its sum: nothing restored", ErrDamaged, rel)
		}
	}
	return small, nil
}

func typeName(t byte) string {
	switch t {
	case tar.TypeSymlink:
		return "a symbolic link"
	case tar.TypeLink:
		return "a hard link"
	case tar.TypeChar, tar.TypeBlock:
		return "a device"
	case tar.TypeFifo:
		return "a pipe"
	}
	return fmt.Sprintf("an entry of type %q", t)
}

func readJSON(r io.Reader, size int64, v any) error {
	b, err := io.ReadAll(io.LimitReader(r, size))
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// extract reads one file of size bytes into stage/rel (a new file, never through a link;
// nowhere for a dry run), and into keep if given.
func extract(r io.Reader, size int64, stage, rel string, keep *bytes.Buffer) (FileSum, error) {
	h := sha256.New()
	w := io.Writer(h)
	if keep != nil {
		w = io.MultiWriter(h, keep)
	}
	var f *os.File
	if stage != "" {
		var err error
		f, err = os.OpenFile(filepath.Join(stage, filepath.FromSlash(rel)), os.O_WRONLY|os.O_CREATE|os.O_EXCL|noFollow, 0o600)
		if err != nil {
			return FileSum{}, err
		}
		defer f.Close()
		w = io.MultiWriter(w, f)
	}
	n, err := io.Copy(w, io.LimitReader(r, size))
	if err == nil && n != size {
		err = io.ErrUnexpectedEOF
	}
	if err != nil {
		return FileSum{}, fmt.Errorf("%s: %w", rel, err)
	}
	if f != nil {
		if err := f.Close(); err != nil {
			return FileSum{}, err
		}
	}
	return FileSum{Size: n, SHA256: hex.EncodeToString(h.Sum(nil))}, nil
}

// validate checks the files the controller can't run without, as it reads them: the
// settings parse, the release key is a key, the token a token, the login a user and an
// argon2id hash. A file a backup doesn't have is said so, not refused.
func validate(small map[string][]byte) ([]string, error) {
	var out []string
	for _, rel := range checked {
		b, ok := small[rel]
		if !ok {
			out = append(out, rel+": not in the backup")
			continue
		}
		if b == nil {
			return out, fmt.Errorf("%w: %s: over 1 MiB", ErrRefused, rel)
		}
		var err error
		switch rel {
		case settings.File:
			_, err = settings.Parse(b)
		case auth.File:
			var a auth.Config
			if a, err = auth.Parse(rel, b); err == nil {
				out = append(out, rel+": the login of "+a.User)
				continue
			}
		case keys.Dir + "/" + keys.File:
			k, kerr := keys.Parse(rel, b)
			if err = kerr; err == nil {
				out = append(out, rel+": a release key, fingerprint "+keys.Fingerprint(k))
				continue
			}
		case keys.Dir + "/" + keys.TokenFile:
			_, err = keys.ParseToken(rel, b)
		}
		if err != nil {
			return out, fmt.Errorf("the backup's %s can't be used: %w: nothing restored", rel, err)
		}
		out = append(out, rel+": good")
	}
	return out, nil
}

// validatePlaced reads the restored files as the controller reads them (secfile: mode
// 0600, this user's, no link).
func validatePlaced(dataDir string) error {
	if _, err := settings.Load(settings.Path(dataDir)); err != nil {
		return err
	}
	if _, err := auth.Load(auth.Path(dataDir)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if _, err := (keys.FileSource{Path: keys.Path(dataDir)}).Key(); err != nil && !errors.Is(err, keys.ErrNoKey) {
		return err
	}
	if _, err := (keys.DataTokenSource{DataDir: dataDir}).Token(); err != nil && !errors.Is(err, keys.ErrNoToken) {
		return err
	}
	return nil
}

// finish sets every entry's mode and time in stage, the deepest first, so a directory's
// time is set after what is in it is written.
func finish(stage string, entries []Entry) error {
	for i := len(entries) - 1; i >= 0; i-- {
		e := entries[i]
		p := filepath.Join(stage, filepath.FromSlash(e.Path))
		if err := os.Chmod(p, e.Mode); err != nil {
			return err
		}
		if !e.ModTime.IsZero() {
			if err := os.Chtimes(p, e.ModTime, e.ModTime); err != nil {
				return err
			}
		}
	}
	return nil
}

// moveAside moves what dataDir holds (but the stage and the fleet lock) into
// .before-restore-<stamp>/, if there is anything.
func moveAside(dataDir, stage, stamp string) (string, error) {
	ents, err := os.ReadDir(dataDir)
	if err != nil {
		return "", err
	}
	aside := filepath.Join(dataDir, ".before-restore-"+stamp)
	made := false
	for _, e := range ents {
		p := filepath.Join(dataDir, e.Name())
		if p == stage || e.Name() == fleetlock.File {
			continue
		}
		if !made {
			if err := os.Mkdir(aside, secfile.DirMode); err != nil {
				return "", err
			}
			if err := os.Chmod(aside, secfile.DirMode); err != nil { // whatever the umask
				return "", err
			}
			made = true
		}
		if err := os.Rename(p, filepath.Join(aside, e.Name())); err != nil {
			return aside, err
		}
	}
	if !made {
		return "", nil
	}
	return aside, nil
}

// moveIn moves the stage's top-level entries into dataDir.
func moveIn(dataDir, stage string) error {
	ents, err := os.ReadDir(stage)
	if err != nil {
		return err
	}
	for _, e := range ents {
		if err := os.Rename(filepath.Join(stage, e.Name()), filepath.Join(dataDir, e.Name())); err != nil {
			return err
		}
	}
	return nil
}
