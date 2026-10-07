// scripts/bump-version.sh, the one way the version moves (docs/releasing.md): run on a copy
// of the repository's VERSION and CHANGELOG.md. (In pins_test's package: one per directory.)
package pins_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func bump(t *testing.T, root string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command("sh", append([]string{"../scripts/bump-version.sh"}, args...)...)
	cmd.Env = append(os.Environ(), "ESPDNS_ROOT="+root)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func repo(t *testing.T, version, changelog string) string {
	t.Helper()
	root := t.TempDir()
	for name, s := range map[string]string{"VERSION": version, "CHANGELOG.md": changelog} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

const changelog = "# Changelog\n\nIntro.\n\n## [Unreleased]\n\n### Fixed\n\n- A thing.\n\n## [0.0.1] - 2026-10-07\n\n- First.\n"

func TestBumpVersion(t *testing.T) {
	for _, c := range []struct{ from, arg, want string }{
		{"0.0.1", "patch", "0.0.2"}, {"0.0.9", "patch", "0.0.10"}, {"0.0.4", "minor", "0.1.0"},
		{"0.3.4", "major", "1.0.0"}, {"0.0.1", "0.0.4", "0.0.4"}, {"0.0.9", "0.1.0", "0.1.0"},
	} {
		root := repo(t, c.from+"\n", changelog)
		if out, err := bump(t, root, c.arg); err != nil {
			t.Errorf("%s %s: %v %s", c.from, c.arg, err, out)
			continue
		}
		if b, _ := os.ReadFile(filepath.Join(root, "VERSION")); string(b) != c.want+"\n" {
			t.Errorf("%s %s: VERSION %q, want %s", c.from, c.arg, b, c.want)
		}
		b, _ := os.ReadFile(filepath.Join(root, "CHANGELOG.md"))
		want := regexp.MustCompile(`(?s)^# Changelog\n\nIntro\.\n\n## \[Unreleased\]\n\n## \[` + regexp.QuoteMeta(c.want) +
			`\] - \d{4}-\d{2}-\d{2}\n\n### Fixed\n\n- A thing\.\n\n## \[0\.0\.1\] - 2026-10-07\n\n- First\.\n$`)
		if !want.Match(b) {
			t.Errorf("%s %s: CHANGELOG.md\n%s", c.from, c.arg, b)
		}
	}
}

// Refused, and nothing written: not a newer version, a VERSION that isn't one, no changelog
// for the version.
func TestBumpVersionRefused(t *testing.T) {
	for _, c := range []struct{ version, changelog, arg, why string }{
		{"0.0.4\n", changelog, "0.0.4", "not newer"},
		{"0.0.4\n", changelog, "0.0.3", "not newer"},
		{"0.1.0\n", changelog, "0.0.9", "not newer"},
		{"0.0.4\n", changelog, "v0.0.5", "usage"},
		{"0.0.4\n", changelog, "0.0.05", "usage"},
		{"0.0.4\n", changelog, "", "usage"},
		{"0.0.4\n", changelog, "0.0.99999999999999999999", "usage"},
		{"0.0.4\n", changelog, "0.0.1000000000", "usage"},
		{"0.0.999999999\n", changelog, "patch", "more than 9 digits"},
		{"0.0.1000000000\n", changelog, "patch", "not MAJOR.MINOR.PATCH"},
		{"3fbae0a\n", changelog, "patch", "not MAJOR.MINOR.PATCH"},
		{"0.0.4\n", "# Changelog\n\n## [0.0.4] - 2026-10-07\n", "patch", "no \"## [Unreleased]\""},
		{"0.0.4\n", "# Changelog\n\n## [Unreleased]\n\n## [0.0.4] - 2026-10-07\n\n- x\n", "patch", "is empty"},
	} {
		root := repo(t, c.version, c.changelog)
		out, err := bump(t, root, c.arg)
		if err == nil || !strings.Contains(out, c.why) {
			t.Errorf("%q %q %s: %v %q, want %q", c.version, c.arg, c.changelog, err, out, c.why)
		}
		if b, _ := os.ReadFile(filepath.Join(root, "VERSION")); string(b) != c.version {
			t.Errorf("%q %s: VERSION now %q", c.version, c.arg, b)
		}
		if b, _ := os.ReadFile(filepath.Join(root, "CHANGELOG.md")); string(b) != c.changelog {
			t.Errorf("%q %s: CHANGELOG.md changed", c.version, c.arg)
		}
		if m, _ := filepath.Glob(filepath.Join(root, ".bump.*")); len(m) > 0 {
			t.Errorf("left %v", m)
		}
	}
}

// The repository's own CHANGELOG.md has the section the script needs, and an entry for VERSION.
func TestChangelogHasVersion(t *testing.T) {
	v, err := os.ReadFile("../VERSION")
	if err != nil {
		t.Fatal(err)
	}
	log := read(t, "../CHANGELOG.md")
	for _, want := range []string{"\n## [Unreleased]\n", "\n## [" + strings.TrimSpace(string(v)) + "] - "} {
		if !strings.Contains(log, want) {
			t.Errorf("CHANGELOG.md: no %q", strings.TrimSpace(want))
		}
	}
}
