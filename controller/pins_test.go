// Package pins_test checks that every build input from outside the repository is pinned
// (firmware/README.md, Pinned versions): each container image by its digest, each CI
// action by its commit, the tag beside it; one Go version for go.mod, the controller's
// image and CI; and a committed component lock for every chip target the firmware builds.
package pins_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// An image reference pinned by digest, with the tag it was: name:tag@sha256:<64 hex>
var pinnedImage = regexp.MustCompile(`^[a-z0-9./_-]+:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}$`)

// An action pinned by commit, with the tag it was in a comment: owner/repo@<40 hex>  # vX
var pinnedAction = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}\s+#\s*v\S+`)

func goVersion(t *testing.T) string {
	m := regexp.MustCompile(`(?m)^go (\S+)$`).FindStringSubmatch(read(t, "go.mod"))
	if m == nil {
		t.Fatal("go.mod: no go line")
	}
	return m[1]
}

func TestDockerfileImagesPinned(t *testing.T) {
	froms := regexp.MustCompile(`(?m)^FROM\s+(\S+)`).FindAllStringSubmatch(read(t, "Dockerfile"), -1)
	if len(froms) == 0 {
		t.Fatal("Dockerfile: no FROM")
	}
	goTag := "golang:" + goVersion(t) + "-"
	sawGo := false
	for _, f := range froms {
		if !pinnedImage.MatchString(f[1]) {
			t.Errorf("Dockerfile: FROM %s is not pinned by digest (name:tag@sha256:...)", f[1])
		}
		if strings.HasPrefix(f[1], "golang:") {
			sawGo = true
			if !strings.HasPrefix(f[1], goTag) {
				t.Errorf("Dockerfile: FROM %s is not go.mod's Go (%s*)", f[1], goTag)
			}
		}
	}
	if !sawGo {
		t.Error("Dockerfile: no golang build stage")
	}
}

// Every workflow: CI on every push, the release on a version tag
func TestWorkflowPinned(t *testing.T) {
	files, err := filepath.Glob("../.gitea/workflows/*.yml")
	if err != nil || len(files) < 2 {
		t.Fatalf("workflows: %v %v", files, err)
	}
	for _, f := range files {
		workflowPinned(t, f)
	}
}

func workflowPinned(t *testing.T, path string) {
	name := filepath.Base(path)
	wf := read(t, path)
	images := regexp.MustCompile(`(?m)^\s+image:\s*(\S+)`).FindAllStringSubmatch(wf, -1)
	if len(images) == 0 {
		t.Fatal(name + ": no container image")
	}
	idf := regexp.MustCompile(`(?m)^IDF_IMAGE\s*\?=\s*(\S+)`).FindStringSubmatch(read(t, "../firmware/Makefile"))
	if idf == nil {
		t.Fatal("firmware/Makefile: no IDF_IMAGE")
	}
	if !pinnedImage.MatchString(idf[1]) {
		t.Errorf("firmware/Makefile: IDF_IMAGE %s is not pinned by digest", idf[1])
	}
	goTag := "golang:" + goVersion(t) + "-"
	for _, m := range images {
		img := m[1]
		if !pinnedImage.MatchString(img) {
			t.Errorf("%s: image %s is not pinned by digest (name:tag@sha256:...)", name, img)
		}
		if strings.HasPrefix(img, "espressif/idf:") && img != idf[1] {
			t.Errorf("%s: image %s is not firmware/Makefile's IDF_IMAGE %s", name, img, idf[1])
		}
		if strings.HasPrefix(img, "golang:") && !strings.HasPrefix(img, goTag) {
			t.Errorf("%s: image %s is not go.mod's Go (%s*)", name, img, goTag)
		}
	}
	uses := regexp.MustCompile(`(?m)^\s+(?:-\s+)?uses:\s*(.+)$`).FindAllStringSubmatch(wf, -1)
	if len(uses) == 0 {
		t.Fatal(name + ": no actions")
	}
	for _, u := range uses {
		if !pinnedAction.MatchString(strings.TrimSpace(u[1])) {
			t.Errorf("%s: uses %s is not pinned by commit with its tag in a comment (owner/repo@<sha>  # vX)", name, u[1])
		}
	}
}

func TestPinnedPatterns(t *testing.T) {
	for _, s := range []string{"golang:1.26-alpine", "golang@sha256:" + strings.Repeat("a", 64),
		"golang:1.26.7-alpine@sha256:abc", "espressif/idf:latest"} {
		if pinnedImage.MatchString(s) {
			t.Errorf("%s taken as pinned", s)
		}
	}
	for _, s := range []string{"actions/checkout@v4", "actions/checkout@" + strings.Repeat("a", 40),
		"actions/checkout@main  # v4"} {
		if pinnedAction.MatchString(s) {
			t.Errorf("%s taken as pinned", s)
		}
	}
	if !pinnedImage.MatchString("gcr.io/distroless/static-debian12:nonroot@sha256:" + strings.Repeat("0", 64)) {
		t.Error("a pinned image not taken")
	}
	if !pinnedAction.MatchString("actions/checkout@" + strings.Repeat("0", 40) + "  # v4.4.0 (v4)") {
		t.Error("a pinned action not taken")
	}
}

// Every chip target of firmware/images/* has its committed lock, firmware/dependencies.lock.<target>
// (firmware/CMakeLists.txt), naming that target, and every lock is one of them
func TestComponentLocks(t *testing.T) {
	defaults, err := filepath.Glob("../firmware/images/*/sdkconfig.defaults")
	if err != nil || len(defaults) == 0 {
		t.Fatalf("no firmware/images/*/sdkconfig.defaults (%v)", err)
	}
	re := regexp.MustCompile(`(?m)^CONFIG_IDF_TARGET="([^"]+)"`)
	targets := map[string]bool{}
	for _, d := range defaults {
		m := re.FindStringSubmatch(read(t, d))
		if m == nil {
			t.Fatalf("%s: no CONFIG_IDF_TARGET", d)
		}
		targets[m[1]] = true
	}
	for target := range targets {
		lock := "../firmware/dependencies.lock." + target
		b, err := os.ReadFile(lock)
		if err != nil {
			t.Errorf("no %s: make -C firmware components writes it", lock)
			continue
		}
		if !regexp.MustCompile(`(?m)^target: ` + regexp.QuoteMeta(target) + `$`).Match(b) {
			t.Errorf("%s is not for target %s", lock, target)
		}
		if !regexp.MustCompile(`(?m)^manifest_hash: [0-9a-f]{64}$`).Match(b) {
			t.Errorf("%s: no manifest_hash", lock)
		}
	}
	locks, _ := filepath.Glob("../firmware/dependencies.lock.*")
	var stray []string
	for _, l := range locks {
		if !targets[strings.TrimPrefix(filepath.Base(l), "dependencies.lock.")] {
			stray = append(stray, l)
		}
	}
	sort.Strings(stray)
	if len(stray) > 0 {
		t.Errorf("component locks for no chip image: %v", stray)
	}
	// The locks are committed, not ignored
	if regexp.MustCompile(`(?m)^/?dependencies\.lock`).MatchString(read(t, "../firmware/.gitignore")) {
		t.Error("firmware/.gitignore ignores the component locks")
	}
}
