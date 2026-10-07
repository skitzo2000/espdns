// Package dist makes, signs, checks and imports a release's files (docs/releasing.md): every
// chip image as the controller's builder imports it, one factory image per catalog board
// with its ESP Web Tools manifest, and SHA256SUMS over them all, which the release key signs.
//
// The signature is the one nodes already check on every release (internal/release, Sign):
// ECDSA P-256 over the SHA-256 of the file, r || s, 64 bytes, in SHA256SUMS.sig. It is
// checked with the public key the firmware has built in (firmware/keys/release.pub, 65 raw
// bytes), so a release is trusted by the same key as the nodes trust. A signed SHA256SUMS
// can't be taken for a node release, nor the other way round: a release manifest is 128
// bytes that start "ESPDNS1\0", and SHA256SUMS is text lines, refused with any NUL in it.
//
// CI makes the files and SHA256SUMS (Build) and never sees the key; a person signs SHA256SUMS
// afterwards, with the key on standard input (Sign).
package dist

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/boards"
	"github.com/skitzo2000/espdns/controller/internal/image"
	"github.com/skitzo2000/espdns/controller/internal/nodecfg"
	"github.com/skitzo2000/espdns/controller/internal/release"
	"github.com/skitzo2000/espdns/controller/internal/secfile"
)

const (
	// SumsFile lists every other file of the release with its SHA-256, as sha256sum writes
	// it ("<hex>  <name>"), so `sha256sum -c SHA256SUMS` checks them too.
	SumsFile = "SHA256SUMS"
	// SigFile is the release key's signature over SumsFile.
	SigFile = SumsFile + ".sig"
	// FactoryNetwork is the address a factory image starts on: a release can't know a node's,
	// so its board definition asks DHCP for one (as the builder's "dhcp"), and adoption then
	// gives the node its own. On a network with no DHCP server, flash from the controller's
	// builder instead, which writes a static address.
	FactoryNetwork = "dhcp"
	// maxFile is the most one file in a chip image may be (the largest flash is 16 MB).
	maxFile = 32 << 20
	// maxTarball is the most a chip image's tarball may be: its six files (chipFiles), at most maxFile each.
	maxTarball = 6 * maxFile
)

// ChipFile is a chip image's tarball: its exported directory, <image>/<file>.
func ChipFile(version, img string) string { return "espdns-" + version + "-image-" + img + ".tar.gz" }

// FactoryFile is a board's factory image, written at offset 0 of a new node's flash.
func FactoryFile(version, board string) string {
	return "espdns-" + version + "-factory-" + board + ".bin"
}

// ManifestFile is the ESP Web Tools manifest beside FactoryFile.
func ManifestFile(version, board string) string {
	return "espdns-" + version + "-factory-" + board + ".manifest.json"
}

// The files of an exported chip image (firmware/tools/export_image.py), the only ones a
// chip image's tarball may hold.
var chipFiles = []string{"app.bin", "bootloader.bin", "image.json", "ota_data_initial.bin", "partitions-4mb.bin", "partitions-8mb.bin"}

// Options are what Build makes a release from.
type Options struct {
	Version string   // the repository's VERSION: every chip image must be built at it
	Images  string   // the exported chip images, <Images>/<image>/image.json
	Catalog string   // the board catalog (boards/), one factory image per board
	Out     string   // where the release's files go: missing or empty
	Include []string // more files the release carries (and SHA256SUMS lists), by their base name
}

// Build writes a release into o.Out: each chip image's tarball, each catalog board's
// factory image and manifest, the included files, then SHA256SUMS over all of them. It
// returns the files written, SHA256SUMS last. A chip image of another version, a catalog
// board with errors or with no chip image here, and an Out with anything in it are refused.
func Build(o Options) ([]string, error) {
	if !version.MatchString(o.Version) {
		return nil, fmt.Errorf("version %q: not MAJOR.MINOR.PATCH", o.Version)
	}
	chips, err := image.List(o.Images)
	if err != nil {
		return nil, err
	}
	if len(chips) == 0 {
		return nil, fmt.Errorf("%s: no chip images (<image>/image.json)", o.Images)
	}
	byName := map[string]image.Chip{}
	for _, c := range chips {
		if c.Version != o.Version {
			return nil, fmt.Errorf("chip image %s is version %q, not %s", c.Image, c.Version, o.Version)
		}
		if filepath.Base(c.Dir()) != c.Image {
			return nil, fmt.Errorf("%s: image.json names %s", c.Dir(), c.Image)
		}
		if err := generic(c, o.Version); err != nil {
			return nil, err
		}
		byName[c.Image] = c
	}
	entries, err := boards.Load(o.Catalog, "")
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("%s: no boards", o.Catalog)
	}
	if err := emptyDir(o.Out); err != nil {
		return nil, err
	}

	var files []string
	write := func(name string, b []byte) error {
		if !fileName.MatchString(name) {
			return fmt.Errorf("%q: not a release file name", name)
		}
		if slices.Contains(files, name) {
			return fmt.Errorf("%s: written twice", name)
		}
		files = append(files, name)
		return os.WriteFile(filepath.Join(o.Out, name), b, 0o644)
	}
	for _, c := range chips {
		b, err := packChip(c)
		if err != nil {
			return nil, err
		}
		if err := write(ChipFile(o.Version, c.Image), b); err != nil {
			return nil, err
		}
	}
	for _, e := range entries {
		c, ok := byName[e.Board.Image]
		if !ok {
			return nil, fmt.Errorf("board %s runs chip image %s, which isn't in %s", e.Board.Name, e.Board.Image, o.Images)
		}
		bin, err := Factory(c, e)
		if err != nil {
			return nil, fmt.Errorf("board %s: %w", e.Board.Name, err)
		}
		m, err := json.MarshalIndent(c.Manifest(e.Board.Name, FactoryFile(o.Version, e.Board.Name)), "", "  ")
		if err != nil {
			return nil, err
		}
		if err := write(FactoryFile(o.Version, e.Board.Name), bin); err != nil {
			return nil, err
		}
		if err := write(ManifestFile(o.Version, e.Board.Name), append(m, '\n')); err != nil {
			return nil, err
		}
	}
	for _, f := range o.Include {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		if err := write(filepath.Base(f), b); err != nil {
			return nil, err
		}
	}
	sums, err := Sums(o.Out, files)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(o.Out, SumsFile), sums, 0o644); err != nil {
		return nil, err
	}
	return append(files, SumsFile), nil
}

// generic checks a chip image's app is a release's: its descriptor says the version, and
// it has no address built in (a transitional image's, firmware/Makefile STATIC_IP), only
// the firmware's mark saying it has none.
func generic(c image.Chip, version string) error {
	app, err := os.ReadFile(filepath.Join(c.Dir(), "app.bin"))
	if err != nil {
		return fmt.Errorf("chip image %s: %w", c.Image, err)
	}
	d, err := release.ParseAppDesc(app)
	if err != nil {
		return fmt.Errorf("chip image %s: app.bin: %w", c.Image, err)
	}
	if d.Version != version {
		return fmt.Errorf("chip image %s: its app is version %q, not %s", c.Image, d.Version, version)
	}
	switch addr, known := release.BuiltinAddress(app); {
	case !known:
		return fmt.Errorf("chip image %s: its app has no built-in address mark: not this firmware's build", c.Image)
	case addr != "":
		return fmt.Errorf("chip image %s: its app has the address %s built in: a release's images carry none", c.Image, addr)
	}
	return nil
}

// Factory is a catalog board's factory image: its chip image with its board definition, as
// the controller's builder assembles one, the address FactoryNetwork.
func Factory(c image.Chip, e boards.Entry) ([]byte, error) {
	if len(e.Errors) > 0 {
		return nil, errors.New(strings.Join(e.Errors, "; "))
	}
	if e.Board.Network != nil {
		return nil, errors.New("a catalog board names no address: it is per node")
	}
	bd := e.Board
	bd.Network = &nodecfg.Network{Address: FactoryNetwork}
	e = e.WithChanges(bd)
	if len(e.Errors) > 0 {
		return nil, errors.New(strings.Join(e.Errors, "; "))
	}
	part, err := e.Pack()
	if err != nil {
		return nil, err
	}
	flash := e.Board.FlashMB
	if flash == 0 {
		flash = 4 // as the builder takes a board that doesn't say
	}
	return c.Assemble(flash, part)
}

// tarTime is every tarball entry's time: a release's bytes depend only on what is in it.
var tarTime = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

// packChip is a chip image's directory as a gzipped tar, <image>/<file>, the same bytes for
// the same files.
func packChip(c image.Chip) ([]byte, error) {
	var buf bytes.Buffer
	gz, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	tw := tar.NewWriter(gz)
	hdr := func(name string, mode int64, typ byte, size int64) *tar.Header {
		return &tar.Header{Name: name, Mode: mode, Typeflag: typ, Size: size, ModTime: tarTime, Format: tar.FormatUSTAR}
	}
	if err := tw.WriteHeader(hdr(c.Image+"/", 0o755, tar.TypeDir, 0)); err != nil {
		return nil, err
	}
	for _, f := range chipFiles {
		b, err := os.ReadFile(filepath.Join(c.Dir(), f))
		if err != nil {
			return nil, fmt.Errorf("chip image %s: %w", c.Image, err)
		}
		if err := tw.WriteHeader(hdr(c.Image+"/"+f, 0o644, tar.TypeReg, int64(len(b)))); err != nil {
			return nil, err
		}
		if _, err := tw.Write(b); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// emptyDir makes dir if it is missing, and refuses one with anything in it: SHA256SUMS
// must list what this release made, not what was left there.
func emptyDir(dir string) error {
	ents, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return os.MkdirAll(dir, 0o755)
	}
	if err != nil {
		return err
	}
	if len(ents) > 0 {
		return fmt.Errorf("%s isn't empty: a release is written into an empty directory", dir)
	}
	return nil
}

var (
	version  = regexp.MustCompile(`^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$`)
	fileName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,199}$`)
	sumLine  = regexp.MustCompile(`^([0-9a-f]{64})  ([^/]+)$`)
)

// Sums is SHA256SUMS for these files of dir, sorted by name.
func Sums(dir string, files []string) ([]byte, error) {
	names := slices.Clone(files)
	sort.Strings(names)
	var b bytes.Buffer
	for _, n := range names {
		sum, err := fileSum(filepath.Join(dir, n))
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(&b, "%s  %s\n", sum, n)
	}
	if _, err := ParseSums(b.Bytes()); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func fileSum(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Sum is one line of SHA256SUMS.
type Sum struct {
	Name   string
	SHA256 string
}

// ParseSums reads SHA256SUMS strictly: one "<64 hex>  <name>" a line, each ending in a
// newline, names plain file names (no directory, so a check never reads outside the
// release), none twice, at least one; nothing else, and no NUL anywhere.
func ParseSums(b []byte) ([]Sum, error) {
	if len(b) == 0 || b[len(b)-1] != '\n' {
		return nil, errors.New(SumsFile + ": empty, or not ending in a newline")
	}
	if bytes.IndexByte(b, 0) >= 0 {
		return nil, errors.New(SumsFile + ": a NUL byte: not a list of sums")
	}
	var out []Sum
	seen := map[string]bool{}
	for i, l := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
		m := sumLine.FindStringSubmatch(l)
		if m == nil || !fileName.MatchString(m[2]) {
			return nil, fmt.Errorf("%s line %d: not \"<sha256>  <file name>\"", SumsFile, i+1)
		}
		if m[2] == SumsFile || m[2] == SigFile || seen[m[2]] {
			return nil, fmt.Errorf("%s line %d: %s listed again", SumsFile, i+1, m[2])
		}
		seen[m[2]] = true
		out = append(out, Sum{Name: m[2], SHA256: m[1]})
	}
	return out, nil
}

// Sign writes SHA256SUMS.sig in dir: k's signature over its SHA256SUMS, which must be one.
func Sign(dir string, k *ecdsa.PrivateKey) error {
	sums, err := os.ReadFile(filepath.Join(dir, SumsFile))
	if err != nil {
		return err
	}
	if _, err := ParseSums(sums); err != nil {
		return err
	}
	sig, err := release.Sign(k, sums)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, SigFile), sig, 0o644)
}

// Checked is what Verify found: the files SHA256SUMS lists, all as signed, and the files in
// the directory it doesn't list (not part of the release: nothing vouches for them).
type Checked struct {
	Files    []string
	Unlisted []string
	sums     map[string]string // each listed file's SHA-256, as signed
}

// ErrSignature: SHA256SUMS.sig is not the key's signature over SHA256SUMS.
var ErrSignature = errors.New(SigFile + " is not this key's signature over " + SumsFile)

// Verify checks a release in dir: SHA256SUMS.sig is pub's signature over SHA256SUMS (pub as
// the firmware has it built in, 65 bytes), then every file SHA256SUMS lists is there with
// its SHA-256. Any of them missing or different is an error naming each.
func Verify(dir string, pub []byte) (Checked, error) {
	var c Checked
	if len(pub) != 65 || pub[0] != 4 {
		return c, fmt.Errorf("the public key is %d bytes: not a raw P-256 key (65, as firmware/keys/release.pub)", len(pub))
	}
	sums, err := os.ReadFile(filepath.Join(dir, SumsFile))
	if err != nil {
		return c, err
	}
	sig, err := os.ReadFile(filepath.Join(dir, SigFile))
	if errors.Is(err, fs.ErrNotExist) {
		return c, fmt.Errorf("no %s: the release isn't signed (yet)", SigFile)
	}
	if err != nil {
		return c, err
	}
	if !release.VerifySig(pub, sums, sig) {
		return c, ErrSignature
	}
	list, err := ParseSums(sums)
	if err != nil {
		return c, err
	}
	var bad []string
	listed := map[string]bool{SumsFile: true, SigFile: true}
	c.sums = map[string]string{}
	for _, s := range list {
		listed[s.Name] = true
		c.sums[s.Name] = s.SHA256
		got, err := fileSum(filepath.Join(dir, s.Name))
		switch {
		case errors.Is(err, fs.ErrNotExist):
			bad = append(bad, s.Name+": missing")
		case err != nil:
			bad = append(bad, s.Name+": "+err.Error())
		case got != s.SHA256:
			bad = append(bad, s.Name+": not the file signed (SHA-256 "+got+")")
		default:
			c.Files = append(c.Files, s.Name)
		}
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return c, err
	}
	for _, e := range ents {
		if !listed[e.Name()] {
			c.Unlisted = append(c.Unlisted, e.Name())
		}
	}
	if len(bad) > 0 {
		return c, errors.New(strings.Join(bad, "; "))
	}
	return c, nil
}

// Import checks the release in dir (Verify) and puts each of its chip images in images
// (the data directory's firmware/images, where the builder and the Nodes page's updates
// find them), replacing one of the same name; every directory 0700 and file 0600 as the
// data directory's are. Nothing is imported unless the whole release checks. It returns
// the chip images imported.
func Import(dir string, pub []byte, images string) ([]string, error) {
	c, err := Verify(dir, pub)
	if err != nil {
		return nil, err
	}
	return importChecked(dir, c, images)
}

// importChecked imports the chip images of the release in dir that Verify checked (c).
func importChecked(dir string, c Checked, images string) ([]string, error) {
	type chip struct {
		name  string
		files map[string][]byte
	}
	var chips []chip
	for _, f := range c.Files {
		v, img, ok := chipOf(f)
		if !ok {
			continue
		}
		// Read once, and the bytes read checked against SHA256SUMS: a file changed after
		// Verify hashed it is never what is unpacked
		tgz, err := readMax(filepath.Join(dir, f), maxTarball)
		if err != nil {
			return nil, err
		}
		if sum := sha256.Sum256(tgz); hex.EncodeToString(sum[:]) != c.sums[f] {
			return nil, fmt.Errorf("%s: changed since it was checked", f)
		}
		files, err := unpackChip(tgz, img)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		var info image.Chip
		if err := json.Unmarshal(files["image.json"], &info); err != nil {
			return nil, fmt.Errorf("%s: image.json: %w", f, err)
		}
		if info.Image != img || info.Version != v {
			return nil, fmt.Errorf("%s: image.json says %s %s", f, info.Image, info.Version)
		}
		chips = append(chips, chip{img, files})
	}
	if len(chips) == 0 {
		return nil, errors.New("the release has no chip images")
	}
	if err := secfile.MkdirAll(images); err != nil {
		return nil, err
	}
	var done []string
	for _, ch := range chips {
		tmp := filepath.Join(images, "."+ch.name+".import")
		if err := os.RemoveAll(tmp); err != nil {
			return done, err
		}
		if err := secfile.MkdirAll(tmp); err != nil {
			return done, err
		}
		for name, b := range ch.files {
			if err := secfile.WriteFile(filepath.Join(tmp, name), b); err != nil {
				return done, err
			}
		}
		// The one there before is moved aside, not removed first: the builder, reading
		// without the fleet lock, finds the old image or the new one, never none
		final := filepath.Join(images, ch.name)
		old := filepath.Join(images, "."+ch.name+".old")
		if err := os.RemoveAll(old); err != nil {
			return done, err
		}
		if err := os.Rename(final, old); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return done, err
		}
		if err := os.Rename(tmp, final); err != nil {
			os.Rename(old, final)
			return done, err
		}
		if err := os.RemoveAll(old); err != nil {
			return done, err
		}
		done = append(done, ch.name)
	}
	return done, nil
}

// readMax reads a file of at most max bytes.
func readMax(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%s: more than %d bytes", path, max)
	}
	return b, nil
}

// chipOf reads a chip image tarball's name: its version and image.
func chipOf(name string) (v, img string, ok bool) {
	m := regexp.MustCompile(`^espdns-([0-9.]+)-image-([a-z0-9][a-z0-9_-]*)\.tar\.gz$`).FindStringSubmatch(name)
	if m == nil {
		return "", "", false
	}
	return m[1], m[2], true
}

// unpackChip reads a chip image's tarball: <img>/ and its files, each one of chipFiles once
// and all of them, regular files of at most maxFile; anything else is refused.
func unpackChip(tgz []byte, img string) (map[string][]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(tgz))
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(gz)
	files := map[string][]byte{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if h.Typeflag == tar.TypeDir && h.Name == img+"/" {
			continue
		}
		name, ok := strings.CutPrefix(h.Name, img+"/")
		if h.Typeflag != tar.TypeReg || !ok || !slices.Contains(chipFiles, name) || files[name] != nil {
			return nil, fmt.Errorf("%s: not a file of chip image %s", h.Name, img)
		}
		if h.Size > maxFile {
			return nil, fmt.Errorf("%s: %d bytes", h.Name, h.Size)
		}
		b, err := io.ReadAll(io.LimitReader(tr, maxFile+1))
		if err != nil {
			return nil, err
		}
		files[name] = b
	}
	for _, n := range chipFiles {
		if files[n] == nil {
			return nil, fmt.Errorf("no %s/%s", img, n)
		}
	}
	return files, nil
}
