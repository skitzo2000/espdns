package backup

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

// rawHeader is one ustar header block, written by hand: what tar.Writer won't write (a PAX
// header of any record, a sparse file's) a crafted backup can still hold.
func rawHeader(name string, typ byte, size int64) []byte {
	b := make([]byte, 512)
	copy(b[0:100], name)
	copy(b[100:108], "0000644\x00")
	copy(b[108:116], "0000000\x00")
	copy(b[116:124], "0000000\x00")
	copy(b[124:136], fmt.Sprintf("%011o\x00", size))
	copy(b[136:148], fmt.Sprintf("%011o\x00", time.Now().Unix()))
	b[156] = typ
	copy(b[257:263], "ustar\x00")
	copy(b[263:265], "00")
	copy(b[148:156], "        ")
	var sum int
	for _, c := range b {
		sum += int(c)
	}
	copy(b[148:156], fmt.Sprintf("%06o\x00 ", sum))
	return b
}

func pad(b []byte) []byte {
	if n := len(b) % 512; n != 0 {
		b = append(b, make([]byte, 512-n)...)
	}
	return b
}

// rawEntry is a header and its data, padded.
func rawEntry(name string, typ byte, data []byte) []byte {
	return append(rawHeader(name, typ, int64(len(data))), pad(append([]byte(nil), data...))...)
}

// pax is a PAX extended header ('x') of records, for the entry after it.
func pax(records ...[2]string) []byte {
	var body []byte
	for _, r := range records {
		rec := " " + r[0] + "=" + r[1] + "\n"
		l := len(rec) + len(fmt.Sprint(len(rec)))
		if len(fmt.Sprint(l)) > len(fmt.Sprint(len(rec))) {
			l++
		}
		body = append(body, fmt.Sprintf("%d%s", l, rec)...)
	}
	return rawEntry("PaxHeaders/x", 'x', body)
}

func jsonEntry(t *testing.T, name string, v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return rawEntry(name, '0', b)
}

// sealed is the raw tar stream given, encrypted to pass as a backup is.
func sealed(t *testing.T, raw []byte) []byte {
	r, _, _ := Passphrase(pass)
	var b bytes.Buffer
	aw, err := age.Encrypt(&b, r)
	if err != nil {
		t.Fatal(err)
	}
	aw.Write(raw)
	aw.Close()
	return b.Bytes()
}

func sumOf(data []byte) FileSum {
	s := sha256.Sum256(data)
	return FileSum{Size: int64(len(data)), SHA256: hex.EncodeToString(s[:])}
}

func TestCraftedRefusedMore(t *testing.T) {
	manifest := jsonEntry(t, ManifestName, Manifest{Kind: Kind, Format: Format, Created: time.Now()})
	trailer := make([]byte, 1024)
	end := func(files map[string]FileSum) []byte { return jsonEntry(t, EndName, End{Files: files}) }
	cat := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

	// A sparse file (PAX 1.0): stored as one byte and a map, read back as a megabyte.
	sparseMap := pad([]byte("1\n1048575\n1\n"))
	sparseData := append(sparseMap, 'x')
	full := append(make([]byte, 1048575), 'x')
	sparse := cat(pax([2]string{"GNU.sparse.major", "1"}, [2]string{"GNU.sparse.minor", "0"},
		[2]string{"GNU.sparse.name", "data/sp"}, [2]string{"GNU.sparse.realsize", "1048576"}),
		rawHeader("data/GNUSparseFile.0/sp", '0', int64(len(sparseData))), pad(sparseData))

	long := strings.Repeat("a", 256)
	cases := map[string]struct {
		raw  []byte
		want error
		text string
	}{
		"plain tar, not encrypted": {raw: nil, text: "not an espdns backup"},
		"PAX path out of data": {raw: cat(manifest, pax([2]string{"path", "data/../escaped"}), rawEntry("data/ok", '0', []byte("x")),
			end(map[string]FileSum{"ok": sumOf([]byte("x"))}), trailer), want: ErrRefused},
		"PAX path absolute": {raw: cat(manifest, pax([2]string{"path", "/tmp/escaped"}), rawEntry("data/ok", '0', []byte("x")),
			end(nil), trailer), want: ErrRefused},
		"PAX linkpath on a link": {raw: cat(manifest, pax([2]string{"linkpath", "/etc/shadow"}), rawEntry("data/l", '2', nil),
			end(nil), trailer), want: ErrRefused, text: "symbolic link"},
		"sparse":          {raw: cat(manifest, sparse, end(map[string]FileSum{"sp": sumOf(full)}), trailer), want: ErrRefused, text: "sparse"},
		"GNU sparse type": {raw: cat(manifest, rawEntry("data/sp", 'S', nil), end(nil), trailer)}, // (an invalid header to the reader)
		"file then directory": {raw: cat(manifest, rawEntry("data/x", '0', []byte("x")), rawEntry("data/x/", '5', nil),
			end(map[string]FileSum{"x": sumOf([]byte("x"))}), trailer), want: ErrRefused},
		"directory then file": {raw: cat(manifest, rawEntry("data/x/", '5', nil), rawEntry("data/x", '0', []byte("x")),
			end(map[string]FileSum{"x": sumOf([]byte("x"))}), trailer), want: ErrRefused},
		"a name over 255 bytes": {raw: cat(manifest, pax([2]string{"path", "data/" + long}), rawEntry("data/ok", '0', []byte("x")),
			end(map[string]FileSum{long: sumOf([]byte("x"))}), trailer), want: ErrRefused},
		"bidirectional override": {raw: cat(manifest, rawEntry("data/a‮nosj.exe", '0', []byte("x")),
			end(map[string]FileSum{"a‮nosj.exe": sumOf([]byte("x"))}), trailer), want: ErrRefused},
		"C1 control (CSI)": {raw: cat(manifest, rawEntry("data/a\u009b2J", '0', []byte("x")),
			end(map[string]FileSum{"a\u009b2J": sumOf([]byte("x"))}), trailer), want: ErrRefused},
		"an entry after the end": {raw: cat(manifest, end(nil), rawEntry("data/late", '0', []byte("x")), trailer), want: ErrRefused},
		"the end lists another file": {raw: cat(manifest, rawEntry("data/x", '0', []byte("x")),
			end(map[string]FileSum{"x": sumOf([]byte("x")), "y": sumOf(nil)}), trailer), want: ErrDamaged},
		"the end lies about a size": {raw: cat(manifest, rawEntry("data/x", '0', []byte("x")),
			end(map[string]FileSum{"x": {Size: 0, SHA256: sumOf([]byte("x")).SHA256}}), trailer), want: ErrDamaged},
		"no end, age whole":              {raw: cat(manifest, rawEntry("data/x", '0', []byte("x"))), want: ErrDamaged},
		"no end, trailer there":          {raw: cat(manifest, rawEntry("data/x", '0', []byte("x")), trailer), want: ErrDamaged},
		"cut short in a file, age whole": {raw: cat(manifest, rawHeader("data/x", '0', 4096), pad([]byte("x"))), want: ErrDamaged},
		"the manifest not first":         {raw: cat(rawEntry("data/x", '0', []byte("x")), manifest, end(nil), trailer), text: "not an espdns backup"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			var b []byte
			if c.raw == nil {
				var tb bytes.Buffer
				tw := tar.NewWriter(&tb)
				mb, _ := json.Marshal(Manifest{Kind: Kind, Format: Format})
				tw.WriteHeader(&tar.Header{Name: ManifestName, Mode: 0o600, Size: int64(len(mb))})
				tw.Write(mb)
				tw.Close()
				b = tb.Bytes()
			} else {
				b = sealed(t, c.raw)
			}
			base := t.TempDir()
			dst := filepath.Join(base, "a", "data")
			for _, dry := range []bool{true, false} {
				_, err := Restore(bytes.NewReader(b), ids(t, pass), dst, RestoreOptions{DryRun: dry})
				if err == nil || c.want != nil && !errors.Is(err, c.want) || c.text != "" && !strings.Contains(err.Error(), c.text) {
					t.Fatalf("dry run %v: got %v, want %v %q", dry, err, c.want, c.text)
				}
			}
			nothingRestored(t, dst)
			for _, d := range []string{base, filepath.Join(base, "a")} {
				if _, err := os.Lstat(filepath.Join(d, "escaped")); err == nil {
					t.Fatalf("written to %s", d)
				}
			}
		})
	}
	// The raw builder makes a backup a restore takes, so the refusals above are the cases'.
	good := sealed(t, cat(manifest, rawEntry("data/x", '0', []byte("x")), end(map[string]FileSum{"x": sumOf([]byte("x"))}), trailer))
	if _, err := Restore(bytes.NewReader(good), ids(t, pass), filepath.Join(t.TempDir(), "d"), RestoreOptions{}); err != nil {
		t.Fatalf("the good one: %v", err)
	}
}
