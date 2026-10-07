package web

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A tarball entry: a file (body) or, with link set, a symlink to link.
type tgzEntry struct{ name, body, link string }

func makeTgz(t *testing.T, entries []tgzEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		h := &tar.Header{Name: e.name, Mode: 0o644, Size: int64(len(e.body)), Typeflag: tar.TypeReg}
		if e.link != "" {
			h = &tar.Header{Name: e.name, Mode: 0o777, Typeflag: tar.TypeSymlink, Linkname: e.link}
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if e.link == "" {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func sri(b []byte) string {
	s := sha512.Sum512(b)
	return "sha512-" + base64.StdEncoding.EncodeToString(s[:])
}

// runVendorScript runs scripts/vendor-esp-web-tools.sh in a copy of the controller's layout
// (scripts/, web/vendor/esp-web-tools/ holding old.js and THIRD_PARTY.md), with a curl on
// PATH that hands it tgz. It returns the vendored directory and the script's error.
func runVendorScript(t *testing.T, tgz []byte, want string) (string, string, error) {
	t.Helper()
	for _, tool := range []string{"sh", "tar", "gzip"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("no %s", tool)
		}
	}
	has := func(tool string) bool { _, err := exec.LookPath(tool); return err == nil }
	if !has("openssl") && !(has("sha512sum") && has("xxd")) && !has("python3") {
		t.Skip("no openssl, sha512sum and xxd, or python3 for the script's sha512")
	}
	script, err := os.ReadFile("../scripts/vendor-esp-web-tools.sh")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	dest := filepath.Join(root, "web", "vendor", "esp-web-tools")
	bin := filepath.Join(root, "bin")
	for _, d := range []string{filepath.Join(root, "scripts"), dest, bin} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(p, s string, mode os.FileMode) {
		if err := os.WriteFile(p, []byte(s), mode); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(root, "scripts", "vendor-esp-web-tools.sh"), string(script), 0o755)
	write(filepath.Join(dest, "old.js"), "old", 0o644)
	write(filepath.Join(dest, "THIRD_PARTY.md"), "third party", 0o644)
	fixture := filepath.Join(root, "package.tgz")
	write(fixture, string(tgz), 0o644)
	// curl ... -o FILE URL: copies the fixture to FILE
	write(filepath.Join(bin, "curl"), `#!/bin/sh
while [ $# -gt 0 ]; do [ "$1" = -o ] && { cp "$FIXTURE" "$2"; exit; }; shift; done
exit 1
`, 0o755)

	cmd := exec.Command("sh", filepath.Join(root, "scripts", "vendor-esp-web-tools.sh"), "1.2.3", want)
	cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"), "FIXTURE="+fixture)
	out, err := cmd.CombinedOutput()

	// Whatever happened, the work directory is gone
	left, _ := filepath.Glob(filepath.Join(root, "web", "vendor", ".update.*"))
	if len(left) != 0 {
		t.Errorf("left behind: %v", left)
	}
	return dest, string(out), err
}

func TestVendorScript(t *testing.T) {
	good := []tgzEntry{
		{name: "package/LICENSE", body: "licence"},
		{name: "package/dist/web/install-button.js", body: `import"./b.js"`},
		{name: "package/dist/web/b.js", body: "b"},
		{name: "package/package.json", body: "{}"},
	}

	t.Run("vendors", func(t *testing.T) {
		tgz := makeTgz(t, good)
		dest, out, err := runVendorScript(t, tgz, sri(tgz))
		if err != nil {
			t.Fatalf("%v: %s", err, out)
		}
		files := map[string]string{}
		ents, _ := os.ReadDir(dest)
		for _, e := range ents {
			b, _ := os.ReadFile(filepath.Join(dest, e.Name()))
			files[e.Name()] = string(b)
		}
		want := map[string]string{
			"LICENSE": "licence", "install-button.js": `import"./b.js"`, "b.js": "b",
			"THIRD_PARTY.md": "third party", "VERSION": "esp-web-tools 1.2.3\n" + sri(tgz) + "\n",
		}
		for name, body := range want {
			if files[name] != body {
				t.Errorf("%s: %q, want %q", name, files[name], body)
			}
		}
		if _, ok := files["old.js"]; ok {
			t.Error("old.js kept")
		}
		var sums []string
		for _, name := range []string{"LICENSE", "THIRD_PARTY.md", "VERSION", "b.js", "install-button.js"} {
			s := sha256.Sum256([]byte(want[name]))
			sums = append(sums, hex.EncodeToString(s[:])+"  "+name)
		}
		if got := strings.TrimSpace(files["SHA256SUMS"]); got != strings.Join(sums, "\n") {
			t.Errorf("SHA256SUMS:\n%s\nwant\n%s", got, strings.Join(sums, "\n"))
		}
		if len(files) != len(want)+1 {
			t.Errorf("files: %v", files)
		}
	})

	refused := func(t *testing.T, entries []tgzEntry, wrongSum bool, says string) {
		tgz := makeTgz(t, entries)
		want := sri(tgz)
		if wrongSum {
			want = sri(append(tgz, 0))
		}
		dest, out, err := runVendorScript(t, tgz, want)
		if err == nil {
			t.Fatalf("not refused: %s", out)
		}
		if !strings.Contains(out, says) {
			t.Errorf("output %q, want %q in it", out, says)
		}
		ents, _ := os.ReadDir(dest)
		var names []string
		for _, e := range ents {
			names = append(names, e.Name())
		}
		if strings.Join(names, " ") != "THIRD_PARTY.md old.js" {
			t.Errorf("the directory changed: %v", names)
		}
	}
	t.Run("wrong sha512", func(t *testing.T) { refused(t, good, true, "refusing") })
	t.Run("LICENSE a symlink", func(t *testing.T) {
		refused(t, []tgzEntry{
			{name: "package/LICENSE", link: "/etc/passwd"},
			{name: "package/dist/web/install-button.js", body: "x"},
		}, false, "not a plain file: LICENSE")
	})
	t.Run("a script a symlink", func(t *testing.T) {
		refused(t, []tgzEntry{
			{name: "package/LICENSE", body: "licence"},
			{name: "package/dist/web/install-button.js", link: "/etc/passwd"},
		}, false, "not a plain file")
	})
	t.Run("not only scripts", func(t *testing.T) {
		refused(t, []tgzEntry{
			{name: "package/LICENSE", body: "licence"},
			{name: "package/dist/web/install-button.js", body: "x"},
			{name: "package/dist/web/x.wasm", body: "x"},
		}, false, "more than .js")
	})
}
