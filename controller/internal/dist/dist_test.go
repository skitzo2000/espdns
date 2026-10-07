package dist

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/skitzo2000/espdns/controller/internal/boards"
	"github.com/skitzo2000/espdns/controller/internal/image"
	"github.com/skitzo2000/espdns/controller/internal/release"
)

const catalog = "../../../boards"

// fakeChips writes exported chip images (export_image.py's files) for the catalog's images,
// with a bootloader that is an ESP image header and parts that say which image they are.
func fakeChips(t *testing.T, version string, images ...string) string {
	t.Helper()
	dir := t.TempDir()
	for _, img := range images {
		d := filepath.Join(dir, img)
		os.MkdirAll(d, 0o755)
		boot := make([]byte, 64)
		boot[0], boot[2], boot[3] = 0xE9, 2, 0x2F // magic, DIO, 4 MB / 80 MHz
		files := map[string][]byte{
			"bootloader.bin": boot, "partitions-8mb.bin": []byte("table 8 " + img),
			"partitions-4mb.bin": []byte("table 4 " + img), "ota_data_initial.bin": bytes.Repeat([]byte{0xFF}, 8192),
			"app.bin": appImage(version, "", "the app of "+img),
		}
		for n, b := range files {
			if err := os.WriteFile(filepath.Join(d, n), b, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		chip := map[string]string{"esp32p4-rev1": "esp32p4", "esp32p4": "esp32p4", "esp32s3-octal": "esp32s3",
			"esp32s3-quad": "esp32s3", "esp32": "esp32", "esp32c3": "esp32c3", "esp32c6": "esp32c6"}[img]
		info := map[string]any{"image": img, "chip": chip, "chip_family": strings.ToUpper(strings.Replace(chip, "esp32", "ESP32-", 1)),
			"offsets": map[string]int{"bootloader.bin": 0, "partitions-8mb.bin": 0x8000, "partitions-4mb.bin": 0x8000,
				"ota_data_initial.bin": 0xf000, "app.bin": 0x20000, "board": 0x12000},
			"flash_mode": "dio", "flash_freq": "80m", "version": version, "built": "2026-10-07T00:00:00Z", "elf_sha256": "00"}
		b, _ := json.Marshal(info)
		if err := os.WriteFile(filepath.Join(d, "image.json"), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// appImage is an ESP app image as far as the release reads one: its header, the app
// descriptor with the version, the firmware's built-in address mark (addr "": none), and text.
func appImage(version, addr, text string) []byte {
	b := make([]byte, 32+256)
	b[0] = 0xE9
	binary.LittleEndian.PutUint32(b[32:], 0xABCD5432)
	copy(b[32+16:], version)
	copy(b[32+48:], "dns2")
	b = append(b, "espdns:builtin-address="+addr+"\x00"...)
	return append(b, text...)
}

// The catalog's chip images, and one more no board runs (it is released all the same)
var catalogImages = []string{"esp32p4-rev1", "esp32s3-octal", "esp32c6"}

func catalogBoards(t *testing.T) []boards.Entry {
	t.Helper()
	entries, err := boards.Load(catalog, "")
	if err != nil || len(entries) == 0 {
		t.Fatal("the catalog:", entries, err)
	}
	return entries
}

func build(t *testing.T, version string, include ...string) (string, []string) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "dist")
	files, err := Build(Options{Version: version, Images: fakeChips(t, version, catalogImages...), Catalog: catalog, Out: out, Include: include})
	if err != nil {
		t.Fatal(err)
	}
	return out, files
}

func testKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// A release: every chip image's tarball, every catalog board's factory image and manifest,
// the included files, and SHA256SUMS listing exactly those, in sha256sum's format.
func TestBuild(t *testing.T) {
	ref := filepath.Join(t.TempDir(), "espdns-0.0.4-controller-image.txt")
	os.WriteFile(ref, []byte("registry.example.com/owner/espdns-controller:0.0.4@sha256:"+strings.Repeat("ab", 32)+"\n"), 0o644)
	out, files := build(t, "0.0.4", ref)

	var want []string
	for _, img := range catalogImages {
		want = append(want, ChipFile("0.0.4", img))
	}
	for _, e := range catalogBoards(t) {
		want = append(want, FactoryFile("0.0.4", e.Board.Name), ManifestFile("0.0.4", e.Board.Name))
	}
	want = append(want, "espdns-0.0.4-controller-image.txt")
	if got := files[:len(files)-1]; !slices.Equal(slices.Sorted(slices.Values(got)), slices.Sorted(slices.Values(want))) || files[len(files)-1] != SumsFile {
		t.Fatalf("files %v, want %v and SHA256SUMS", files, want)
	}
	if !slices.Contains(want, "espdns-0.0.4-image-esp32s3-octal.tar.gz") || !slices.Contains(want, "espdns-0.0.4-factory-ws-s3-eth.bin") {
		t.Fatalf("names: %v", want)
	}
	sums, err := os.ReadFile(filepath.Join(out, SumsFile))
	if err != nil {
		t.Fatal(err)
	}
	list, err := ParseSums(sums)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, s := range list {
		names = append(names, s.Name)
		b, _ := os.ReadFile(filepath.Join(out, s.Name))
		if h := sha256.Sum256(b); hex.EncodeToString(h[:]) != s.SHA256 {
			t.Errorf("%s: sum %s is not the file's", s.Name, s.SHA256)
		}
	}
	if !slices.IsSorted(names) || !slices.Equal(names, slices.Sorted(slices.Values(want))) {
		t.Errorf("SHA256SUMS lists %v", names)
	}
	if ents, _ := os.ReadDir(out); len(ents) != len(want)+1 {
		t.Errorf("%d files in the release directory, want %d", len(ents), len(want)+1)
	}

	// The same inputs make the same bytes (tarballs included): a rebuild can be checked
	out2, _ := build(t, "0.0.4", ref)
	if b, _ := os.ReadFile(filepath.Join(out2, SumsFile)); !bytes.Equal(b, sums) {
		t.Errorf("a second build differs:\n%s\n%s", sums, b)
	}
}

// Each factory image is the builder's assembly of its board with the address "dhcp", and its
// manifest installs it, erasing first, as the builder's does.
func TestBuildFactory(t *testing.T) {
	out, _ := build(t, "0.0.4")
	for _, e := range catalogBoards(t) {
		name := e.Board.Name
		bin, err := os.ReadFile(filepath.Join(out, FactoryFile("0.0.4", name)))
		if err != nil {
			t.Fatal(err)
		}
		// The board partition at 0x12000: "EDBD", v1, the JSON with its CRC
		part := bin[0x12000 : 0x12000+4096]
		n := binary.LittleEndian.Uint32(part[8:])
		if string(part[:4]) != "EDBD" || n > 4080 {
			t.Fatalf("%s: no board partition at 0x12000: %x", name, part[:16])
		}
		var bd boards.Board
		if err := json.Unmarshal(part[16:16+n], &bd); err != nil {
			t.Fatalf("%s: board partition: %v", name, err)
		}
		if bd.Name != name || bd.Image != e.Board.Image || bd.Network == nil || bd.Network.Address != "dhcp" || bd.Network.Gateway != "" {
			t.Errorf("%s: board partition says %+v %+v", name, bd, bd.Network)
		}
		if errs, _ := boards.Check(bd); len(errs) > 0 {
			t.Errorf("%s: its board definition: %v", name, errs)
		}
		// The bootloader's flash size is the board's (16 MB: 4, 8 MB: 3, high nibble of byte 3)
		if code := map[int]byte{8: 3, 16: 4}[e.Board.FlashMB]; bin[3]>>4 != code {
			t.Errorf("%s: bootloader flash size code %d, want %d", name, bin[3]>>4, code)
		}
		if !bytes.Contains(bin[0x20000:], []byte("the app of "+e.Board.Image)) {
			t.Errorf("%s: not its chip image's app", name)
		}
		var m struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Erase   bool   `json:"new_install_prompt_erase"`
			Builds  []struct {
				ChipFamily string `json:"chipFamily"`
				Parts      []struct {
					Path   string `json:"path"`
					Offset int    `json:"offset"`
				} `json:"parts"`
			} `json:"builds"`
		}
		b, _ := os.ReadFile(filepath.Join(out, ManifestFile("0.0.4", name)))
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		if m.Name != "espDNS "+name || m.Version != "0.0.4" || !m.Erase || len(m.Builds) != 1 ||
			!strings.HasPrefix(m.Builds[0].ChipFamily, "ESP32") || len(m.Builds[0].Parts) != 1 ||
			m.Builds[0].Parts[0].Path != FactoryFile("0.0.4", name) || m.Builds[0].Parts[0].Offset != 0 {
			t.Errorf("%s: manifest %s", name, b)
		}
	}
}

// withApp is the catalog's chip images with esp32s3-octal's app replaced
func withApp(t *testing.T, app []byte) string {
	t.Helper()
	dir := fakeChips(t, "0.0.4", catalogImages...)
	if err := os.WriteFile(filepath.Join(dir, "esp32s3-octal", "app.bin"), app, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestBuildRefused(t *testing.T) {
	good := fakeChips(t, "0.0.4", catalogImages...)
	full := t.TempDir()
	os.WriteFile(filepath.Join(full, "left-over.bin"), []byte("x"), 0o644)
	for _, c := range []struct {
		o   Options
		why string
	}{
		{Options{Version: "0.0.5", Images: good, Catalog: catalog}, `is version "0.0.4", not 0.0.5`},
		{Options{Version: "v0.0.4", Images: good, Catalog: catalog}, "not MAJOR.MINOR.PATCH"},
		{Options{Version: "0.0.4", Images: fakeChips(t, "0.0.4", "esp32s3-octal"), Catalog: catalog}, "runs chip image esp32p4-rev1, which isn't in"},
		{Options{Version: "0.0.4", Images: t.TempDir(), Catalog: catalog}, "no chip images"},
		{Options{Version: "0.0.4", Images: good, Catalog: t.TempDir()}, "no boards"},
		{Options{Version: "0.0.4", Images: good, Catalog: catalog, Out: full}, "isn't empty"},
		{Options{Version: "0.0.4", Images: withApp(t, appImage("0.0.4", "192.0.2.53", "x")), Catalog: catalog}, "address 192.0.2.53 built in"},
		{Options{Version: "0.0.4", Images: withApp(t, appImage("0.0.3", "", "x")), Catalog: catalog}, `its app is version "0.0.3"`},
		{Options{Version: "0.0.4", Images: withApp(t, appImage("0.0.4", "", "x")[:300]), Catalog: catalog}, "no built-in address mark"},
		{Options{Version: "0.0.4", Images: withApp(t, []byte("not an image")), Catalog: catalog}, "not an ESP app image"},
		{Options{Version: "0.0.4", Images: good, Catalog: catalog, Include: []string{filepath.Join(full, "left-over.bin"), filepath.Join(full, "left-over.bin")}}, "written twice"},
	} {
		if c.o.Out == "" {
			c.o.Out = filepath.Join(t.TempDir(), "dist")
		}
		if _, err := Build(c.o); err == nil || !strings.Contains(err.Error(), c.why) {
			t.Errorf("%+v: %v, want %q", c.o, err, c.why)
		}
	}
}

// Signed with the release key, a release verifies with its public key, file by file; a
// file changed or gone, SHA256SUMS changed, another key, or no signature at all does not.
func TestSignVerify(t *testing.T) {
	out, files := build(t, "0.0.4")
	k := testKey(t)
	pub := release.PublicRaw(k)
	if _, err := Verify(out, pub); err == nil || !strings.Contains(err.Error(), "isn't signed") {
		t.Fatalf("unsigned: %v", err)
	}
	if err := Sign(out, k); err != nil {
		t.Fatal(err)
	}
	sig, _ := os.ReadFile(filepath.Join(out, SigFile))
	sums, _ := os.ReadFile(filepath.Join(out, SumsFile))
	if len(sig) != release.SigLen || !release.VerifySig(pub, sums, sig) {
		t.Fatalf("SHA256SUMS.sig: %d bytes, not the release format", len(sig))
	}
	c, err := Verify(out, pub)
	if err != nil || len(c.Files) != len(files)-1 || len(c.Unlisted) != 0 {
		t.Fatalf("%+v %v", c, err)
	}
	if _, err := Verify(out, release.PublicRaw(testKey(t))); !errors.Is(err, ErrSignature) {
		t.Errorf("another key: %v", err)
	}
	if _, err := Verify(out, pub[:64]); err == nil {
		t.Error("a short key taken")
	}

	// A file not in the release is reported, not checked
	os.WriteFile(filepath.Join(out, "notes.txt"), []byte("hello"), 0o644)
	if c, err := Verify(out, pub); err != nil || !slices.Equal(c.Unlisted, []string{"notes.txt"}) {
		t.Errorf("an unlisted file: %+v %v", c, err)
	}

	// A file changed, another gone: both named
	changed, gone := files[0], files[1]
	os.WriteFile(filepath.Join(out, changed), []byte("not the image"), 0o644)
	os.Remove(filepath.Join(out, gone))
	_, err = Verify(out, pub)
	if err == nil || !strings.Contains(err.Error(), changed+": not the file signed") || !strings.Contains(err.Error(), gone+": missing") {
		t.Errorf("tampered: %v", err)
	}

	// SHA256SUMS changed to match: the signature no longer does
	os.WriteFile(filepath.Join(out, SumsFile), append(sums, []byte(strings.Repeat("0", 64)+"  extra.bin\n")...), 0o644)
	if _, err := Verify(out, pub); !errors.Is(err, ErrSignature) {
		t.Errorf("SHA256SUMS changed: %v", err)
	}
}

// A node release's signed manifest isn't a signed SHA256SUMS: the same key's signature over
// a manifest never makes a release verify.
func TestManifestSignatureIsNotASumsSignature(t *testing.T) {
	k := testKey(t)
	h, err := release.Header(k, release.Firmware, release.KeyRelease, release.AnyNode, "esp32s3-octal", 1, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, SumsFile), h[:release.ManifestLen], 0o644)
	os.WriteFile(filepath.Join(dir, SigFile), h[release.ManifestLen:], 0o644)
	if _, err := Verify(dir, release.PublicRaw(k)); err == nil || errors.Is(err, ErrSignature) {
		t.Fatalf("a manifest as SHA256SUMS: %v, want it refused as no list of sums", err)
	}
	if err := Sign(dir, k); err == nil {
		t.Error("Sign signed a manifest as SHA256SUMS")
	}
}

func TestParseSums(t *testing.T) {
	sum := strings.Repeat("0a", 32)
	if s, err := ParseSums([]byte(sum + "  a.bin\n" + sum + "  b-1_2+x.tar.gz\n")); err != nil || len(s) != 2 || s[1].Name != "b-1_2+x.tar.gz" {
		t.Fatalf("%v %v", s, err)
	}
	for _, bad := range []string{
		"", sum + "  a.bin", sum + " a.bin\n", sum + "  ../a.bin\n", sum + "  dir/a.bin\n", sum + "  .hidden\n",
		strings.ToUpper(sum) + "  a.bin\n", sum[2:] + "  a.bin\n", sum + "  a.bin\n" + sum + "  a.bin\n",
		sum + "  SHA256SUMS\n", sum + "  SHA256SUMS.sig\n", sum + "  a\x00.bin\n", sum + "  a.bin\n\n", sum + "  a b\n",
	} {
		if _, err := ParseSums([]byte(bad)); err == nil {
			t.Errorf("%q taken", bad)
		}
	}
}

func mode(t *testing.T, p string) fs.FileMode {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

// Import puts a verified release's chip images in the data directory, private, replacing
// those there; a release that doesn't verify imports nothing.
func TestImport(t *testing.T) {
	out, _ := build(t, "0.0.4")
	k := testKey(t)
	pub := release.PublicRaw(k)
	data := t.TempDir()
	images := filepath.Join(data, "firmware", "images")
	if _, err := Import(out, pub, images); err == nil {
		t.Fatal("an unsigned release imported")
	}
	if _, err := os.Stat(images); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("an unsigned release made", images)
	}
	if err := Sign(out, k); err != nil {
		t.Fatal(err)
	}
	// One there before, with a stray file: replaced as a whole
	os.MkdirAll(filepath.Join(images, "esp32c6"), 0o700)
	os.WriteFile(filepath.Join(images, "esp32c6", "stale.bin"), []byte("old"), 0o600)
	done, err := Import(out, pub, images)
	if err != nil || !slices.Equal(slices.Sorted(slices.Values(done)), slices.Sorted(slices.Values(catalogImages))) {
		t.Fatalf("imported %v, %v", done, err)
	}
	chips, err := image.List(images)
	if err != nil || len(chips) != len(catalogImages) {
		t.Fatalf("%v %v", chips, err)
	}
	for _, c := range chips {
		if c.Version != "0.0.4" {
			t.Errorf("%s: version %s", c.Image, c.Version)
		}
		if mode(t, c.Dir()) != 0o700 || mode(t, filepath.Join(c.Dir(), "app.bin")) != 0o600 {
			t.Errorf("%s: modes %v %v", c.Image, mode(t, c.Dir()), mode(t, filepath.Join(c.Dir(), "app.bin")))
		}
		if b, _ := os.ReadFile(filepath.Join(c.Dir(), "app.bin")); !bytes.HasSuffix(b, []byte("the app of "+c.Image)) {
			t.Errorf("%s: app %q", c.Image, b)
		}
	}
	if _, err := os.Stat(filepath.Join(images, "esp32c6", "stale.bin")); !errors.Is(err, fs.ErrNotExist) {
		t.Error("the image imported over kept a stray file")
	}
	// Nothing left beside the images: no old image moved aside, no unfinished import
	ents, _ := os.ReadDir(images)
	for _, e := range ents {
		if !slices.Contains(catalogImages, e.Name()) {
			t.Errorf("left in %s: %s", images, e.Name())
		}
	}
	// The builder assembles from what was imported
	e, _ := boards.Find(catalogBoards(t), "ws-s3-eth")
	c, _ := image.Open(filepath.Join(images, "esp32s3-octal"))
	if _, err := Factory(c, e); err != nil {
		t.Error("factory from the imported image:", err)
	}
}

// A chip tarball, signed as it is, holding anything but its image's files is refused
// before anything is written: a path out of its directory, a link, another file.
func TestImportRefusesOddTarballs(t *testing.T) {
	for _, entry := range []struct {
		name string
		typ  byte
	}{{"esp32c6/../../escape.bin", tar.TypeReg}, {"esp32c6/app.bin", tar.TypeSymlink}, {"esp32c6/other.bin", tar.TypeReg},
		{"esp32s3-octal/app.bin", tar.TypeReg}, {"/etc/passwd", tar.TypeReg}} {
		dir := t.TempDir()
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gz)
		tw.WriteHeader(&tar.Header{Name: entry.name, Typeflag: entry.typ, Size: map[bool]int64{true: 1}[entry.typ == tar.TypeReg], Linkname: "/etc/passwd", Mode: 0o644})
		if entry.typ == tar.TypeReg {
			tw.Write([]byte("x"))
		}
		tw.Close()
		gz.Close()
		name := ChipFile("0.0.4", "esp32c6")
		os.WriteFile(filepath.Join(dir, name), buf.Bytes(), 0o644)
		sums, err := Sums(dir, []string{name})
		if err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(dir, SumsFile), sums, 0o644)
		k := testKey(t)
		if err := Sign(dir, k); err != nil {
			t.Fatal(err)
		}
		data := t.TempDir()
		images := filepath.Join(data, "firmware", "images")
		if _, err := Import(dir, release.PublicRaw(k), images); err == nil {
			t.Errorf("%s (%c): imported", entry.name, entry.typ)
		}
		var found []string
		filepath.WalkDir(data, func(p string, d fs.DirEntry, err error) error {
			if p != data {
				found = append(found, p)
			}
			return nil
		})
		if len(found) > 0 {
			t.Errorf("%s: wrote %v", entry.name, found)
		}
		if _, err := os.Stat(filepath.Join(filepath.Dir(dir), "escape.bin")); err == nil {
			t.Error("escaped")
		}
	}
}

// A chip tarball changed after Verify hashed it is refused, not unpacked: Import checks
// the bytes it reads against SHA256SUMS
func TestImportRefusesAChangeAfterVerify(t *testing.T) {
	out, _ := build(t, "0.0.4")
	k := testKey(t)
	if err := Sign(out, k); err != nil {
		t.Fatal(err)
	}
	c, err := Verify(out, release.PublicRaw(k))
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(out, ChipFile("0.0.4", "esp32c6"))
	b, _ := os.ReadFile(f)
	os.WriteFile(f, append(b, 0), 0o644)
	images := filepath.Join(t.TempDir(), "firmware", "images")
	if _, err := importChecked(out, c, images); err == nil || !strings.Contains(err.Error(), "changed since it was checked") {
		t.Fatalf("a tarball changed after Verify: %v", err)
	}
	if _, err := os.Stat(images); !errors.Is(err, fs.ErrNotExist) {
		t.Error("wrote", images)
	}
}
