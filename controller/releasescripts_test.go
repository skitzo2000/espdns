// scripts/release/: the release workflow's checks (check-version.sh, changelog.sh) and its
// draft release (publish.sh), run on a copy of the repository's VERSION and CHANGELOG.md and
// against a fake forge. (In pins_test's package: one per directory.)
package pins_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/skitzo2000/espdns/controller/internal/release"
)

func script(t *testing.T, root string, env []string, name string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command("sh", append([]string{"../scripts/release/" + name}, args...)...)
	cmd.Env = append(append(os.Environ(), "ESPDNS_ROOT="+root), env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

const releaseLog = "# Changelog\n\n## [Unreleased]\n\n- Next.\n\n## [0.0.4] - 2026-10-09\n\n" +
	"### Fixed\n\n- A \"quoted\" thing, a back\\slash and a\ttab.\n\n## [0.0.3] - 2026-10-08\n\n- Third.\n\n" +
	"## [0.0.2] - 2026-10-08\n\n## [0.0.1] - 2026-10-07\n\n- First.\n"

func TestChangelogSection(t *testing.T) {
	root := repo(t, "0.0.4\n", releaseLog)
	for v, want := range map[string]string{
		"0.0.4": "### Fixed\n\n- A \"quoted\" thing, a back\\slash and a\ttab.\n",
		"0.0.3": "- Third.\n",
		"0.0.1": "- First.\n",
	} {
		if out, err := script(t, root, nil, "changelog.sh", v); err != nil || out != want {
			t.Errorf("%s: %v %q, want %q", v, err, out, want)
		}
	}
	for v, why := range map[string]string{"0.0.2": "is empty", "0.0.5": "no \"## [0.0.5]", "0.0": "no \"## [0.0]", "Unreleased": "no \"## [Unreleased]"} {
		if out, err := script(t, root, nil, "changelog.sh", v); err == nil || !strings.Contains(out, why) {
			t.Errorf("%s: %v %q, want %q", v, err, out, why)
		}
	}
}

// The tag is v<VERSION>, and the version has its changelog; anything else stops a release.
func TestCheckVersion(t *testing.T) {
	if out, err := script(t, repo(t, "0.0.4\n", releaseLog), nil, "check-version.sh", "v0.0.4"); err != nil || out != "0.0.4\n" {
		t.Fatalf("%v %q", err, out)
	}
	for _, c := range []struct{ version, tag, why string }{
		{"0.0.4\n", "v0.0.3", "VERSION says 0.0.4"},
		{"0.0.4\n", "0.0.4", "VERSION says 0.0.4"},
		{"0.0.4\n", "v0.0.4-rc1", "VERSION says 0.0.4"},
		{"0.0.5\n", "v0.0.5", "no \"## [0.0.5]"},
		{"0.0.2\n", "v0.0.2", "is empty"},
		{"v0.0.4\n", "vv0.0.4", "not MAJOR.MINOR.PATCH"},
	} {
		if out, err := script(t, repo(t, c.version, releaseLog), nil, "check-version.sh", c.tag); err == nil || !strings.Contains(out, c.why) {
			t.Errorf("%q %s: %v %q, want %q", c.version, c.tag, err, out, c.why)
		}
	}
	// The repository's own VERSION has its changelog: tagging it would release
	v, _ := os.ReadFile("../VERSION")
	if out, err := script(t, "..", nil, "check-version.sh", "v"+strings.TrimSpace(string(v))); err != nil {
		t.Errorf("the repository's VERSION: %v %s", err, out)
	}
}

// A fake forge: the release API as publish.sh uses it
type forge struct {
	mu       sync.Mutex
	existing bool
	created  map[string]any
	assets   map[string]string
	tokens   []string
}

func (f *forge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tokens = append(f.tokens, r.Header.Get("Authorization"))
	switch {
	case r.Method == "GET" && r.URL.Path == "/api/v1/repos/owner/espdns/releases/tags/v0.0.4":
		if !f.existing {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(`{"id":3}`))
	case r.Method == "POST" && r.URL.Path == "/api/v1/repos/owner/espdns/releases":
		if err := json.NewDecoder(r.Body).Decode(&f.created); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		w.WriteHeader(201)
		w.Write([]byte(`{"id":42,"tag_name":"v0.0.4","draft":true,"assets":[]}`))
	case r.Method == "POST" && r.URL.Path == "/api/v1/repos/owner/espdns/releases/42/assets":
		file, _, err := r.FormFile("attachment")
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		b, _ := io.ReadAll(file)
		f.assets[r.URL.Query().Get("name")] = string(b)
		w.WriteHeader(201)
		w.Write([]byte(`{"id":1}`))
	default:
		http.Error(w, "unexpected "+r.Method+" "+r.URL.String(), 500)
	}
}

func TestPublish(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("no curl")
	}
	root := repo(t, "0.0.4\n", releaseLog)
	dist := t.TempDir()
	files := map[string]string{"SHA256SUMS": "sums\n", "espdns-0.0.4-factory-ws-s3-eth.bin": "\x00\x01image", "espdns-0.0.4-image-esp32.tar.gz": "tar"}
	for n, s := range files {
		os.WriteFile(filepath.Join(dist, n), []byte(s), 0o644)
	}
	f := &forge{assets: map[string]string{}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	env := []string{"FORGE_API=" + srv.URL + "/api/v1", "REPO=owner/espdns", "RELEASE_TOKEN=s3cret-token"}
	out, err := script(t, root, env, "publish.sh", "v0.0.4", dist)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if strings.Contains(out, "s3cret-token") {
		t.Error("the token in the output")
	}
	c := f.created
	notes, _ := c["body"].(string)
	if c["tag_name"] != "v0.0.4" || c["name"] != "espDNS 0.0.4" || c["draft"] != true || c["prerelease"] != true ||
		!strings.HasPrefix(notes, "### Fixed\n\n- A \"quoted\" thing, a back\\slash and a\ttab.\n\n---\n") ||
		!strings.Contains(notes, "docs/releasing.md") {
		t.Errorf("created %v\nnotes %q", c, notes)
	}
	if len(f.assets) != len(files) {
		t.Errorf("uploaded %v", f.assets)
	}
	for n, s := range files {
		if f.assets[n] != s {
			t.Errorf("%s: uploaded %q", n, f.assets[n])
		}
	}
	for _, tok := range f.tokens {
		if tok != "token s3cret-token" {
			t.Errorf("Authorization %q", tok)
		}
	}

	// A release already there is refused, nothing made; and a tag that isn't VERSION
	f2 := &forge{existing: true, assets: map[string]string{}}
	srv2 := httptest.NewServer(f2)
	defer srv2.Close()
	env2 := []string{"FORGE_API=" + srv2.URL + "/api/v1", "REPO=owner/espdns", "RELEASE_TOKEN=t"}
	if out, err := script(t, root, env2, "publish.sh", "v0.0.4", dist); err == nil || !strings.Contains(out, "already has a release") || f2.created != nil {
		t.Errorf("existing: %v %s", err, out)
	}
	if out, err := script(t, root, env, "publish.sh", "v0.0.3", dist); err == nil || !strings.Contains(out, "VERSION says 0.0.4") {
		t.Errorf("another tag: %v %s", err, out)
	}
	if out, err := script(t, root, env, "publish.sh", "v0.0.4", t.TempDir()); err == nil || !strings.Contains(out, "no SHA256SUMS") {
		t.Errorf("no SHA256SUMS: %v %s", err, out)
	}
	if out, err := script(t, root, []string{"FORGE_API=", "REPO=", "RELEASE_TOKEN="}, "publish.sh", "v0.0.4", dist); err == nil || !strings.Contains(out, "FORGE_API") {
		t.Errorf("no forge: %v %s", err, out)
	}
}

// The release workflow runs on a version tag only (or by hand), checks the tag first, and
// never has the signing key: no secret but the forge token, and nothing signs (#58). GitHub's
// (the public repository's) and, when it is there, a private forge's.
func TestReleaseWorkflow(t *testing.T) {
	releaseWorkflow(t, "../.github/workflows/release.yml", "GITHUB_TOKEN")
	if _, err := os.Stat("../.gitea/workflows/release.yml"); err == nil {
		releaseWorkflow(t, "../.gitea/workflows/release.yml", "RELEASE_TOKEN")
	}
}

func releaseWorkflow(t *testing.T, path, secret string) {
	t.Helper()
	wf := read(t, path)
	on := regexp.MustCompile(`(?ms)^on:\n(.*?)\n\S`).FindStringSubmatch(wf)
	if on == nil {
		t.Fatal(path + ": no on:")
	}
	var trig []string
	for _, l := range strings.Split(on[1], "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			trig = append(trig, l)
		}
	}
	if strings.Join(trig, "|") != "push:|tags: ['v*']|workflow_dispatch:" {
		t.Errorf("%s triggers on %q, want a v* tag push and workflow_dispatch only", path, trig)
	}
	for _, m := range regexp.MustCompile(`secrets\.([A-Za-z0-9_]+)`).FindAllStringSubmatch(wf, -1) {
		if m[1] != secret {
			t.Errorf("%s: secret %s: the only secret is the forge token %s (the release key never is one)", path, m[1], secret)
		}
	}
	for _, bad := range []string{"release sign", ".pem", "RELEASE_KEY", "keys import", "key import"} {
		if strings.Contains(wf, bad) {
			t.Errorf("%s: %q: CI never signs", path, bad)
		}
	}
	// Every job but the check waits for it
	_, wf, ok := strings.Cut(wf, "\njobs:\n")
	if !ok {
		t.Fatal(path + ": no jobs:")
	}
	jobs := regexp.MustCompile(`(?m)^  ([a-z][a-z0-9-]*):\n`).FindAllStringSubmatchIndex(wf, -1)
	if len(jobs) < 4 {
		t.Fatalf("%s: jobs %v", path, jobs)
	}
	for i, j := range jobs {
		name := wf[j[2]:j[3]]
		end := len(wf)
		if i+1 < len(jobs) {
			end = jobs[i+1][0]
		}
		body := wf[j[1]:end]
		if name == "version" {
			if !strings.Contains(body, "scripts/release/check-version.sh") {
				t.Errorf("%s: the version job doesn't run check-version.sh", path)
			}
			continue
		}
		if !regexp.MustCompile(`(?m)^    needs: (version|\[version[,\]])`).MatchString(body) {
			t.Errorf("%s: job %s doesn't need version", path, name)
		}
		// Nothing goes to the registry before every chip image has built
		if name == "controller-image" && !regexp.MustCompile(`(?m)^    needs: \[[^\]]*\bfirmware\b`).MatchString(body) {
			t.Errorf("%s: controller-image pushes before the firmware jobs have built", path)
		}
	}
}

// GitHub's workflows give the run's token only what each job writes: CI reads, the release
// writes its draft (contents) and the controller's image (packages), each in its own job.
func TestGitHubPermissions(t *testing.T) {
	top := regexp.MustCompile(`(?m)^permissions:(.*)$`)
	write := regexp.MustCompile(`(?m)^\s+([a-z-]+): write$`)
	ci := read(t, "../.github/workflows/ci.yml")
	if m := top.FindStringSubmatch(ci); m == nil || !strings.Contains(ci, "permissions:\n  contents: read\n") {
		t.Error("ci.yml: no top-level permissions: contents: read")
	}
	if w := write.FindAllString(ci, -1); len(w) > 0 || strings.Contains(ci, "write-all") {
		t.Errorf("ci.yml: CI writes nothing, permissions %v", w)
	}
	rel := read(t, "../.github/workflows/release.yml")
	if m := top.FindStringSubmatch(rel); m == nil || strings.TrimSpace(m[1]) != "{}" {
		t.Error("release.yml: the top-level permissions are not {}")
	}
	if strings.Contains(rel, "write-all") {
		t.Error("release.yml: write-all")
	}
	_, jobs, _ := strings.Cut(rel, "\njobs:\n")
	idx := regexp.MustCompile(`(?m)^  ([a-z][a-z0-9-]*):\n`).FindAllStringSubmatchIndex(jobs, -1)
	want := map[string]string{"controller-image": "packages", "draft": "contents"}
	for i, j := range idx {
		name := jobs[j[2]:j[3]]
		end := len(jobs)
		if i+1 < len(idx) {
			end = idx[i+1][0]
		}
		var got []string
		for _, m := range write.FindAllStringSubmatch(jobs[j[1]:end], -1) {
			got = append(got, m[1])
		}
		if strings.Join(got, " ") != want[name] {
			t.Errorf("release.yml: job %s writes %v, want %q", name, got, want[name])
		}
	}
}

// docs/releasing.md: its commands are docker and git (no make), its ESP-IDF image is the
// pinned one, and the release key's fingerprint it gives is firmware/keys/release.pub's.
func TestReleasingDoc(t *testing.T) {
	doc := read(t, "../docs/releasing.md")
	pub, err := os.ReadFile("../firmware/keys/release.pub")
	if err != nil {
		t.Fatal(err)
	}
	fp := release.Fingerprint(pub)
	if n := strings.Count(doc, "`"+fp+"`"); n < 2 {
		t.Errorf("releasing.md: the release key's fingerprint %s given %d times", fp, n)
	}
	if m := regexp.MustCompile("`[0-9a-f]{16}`").FindAllString(doc, -1); len(m) != strings.Count(doc, "`"+fp+"`") {
		t.Errorf("releasing.md: fingerprints %v, want only %s", m, fp)
	}
	idf := regexp.MustCompile(`(?m)^IDF_IMAGE\s*\?=\s*(\S+)`).FindStringSubmatch(read(t, "../firmware/Makefile"))[1]
	// The commands' ESP-IDF image, here and in the other docs that run it, is the pinned one
	for _, f := range []string{"../docs/releasing.md", "../README.md", "../docs/getting-started.md", "../CONTRIBUTING.md"} {
		for _, img := range regexp.MustCompile(`espressif/idf:\S+@\S+`).FindAllString(read(t, f), -1) {
			if img != idf {
				t.Errorf("%s: %s, not firmware/Makefile's IDF_IMAGE %s", f, img, idf)
			}
		}
	}
	// The firmware build mounts the whole checkout with network: a clean one, never the one
	// with the private keys in it (#58); the version bump needs no network
	if w, b := strings.Index(doc, "git worktree add"), strings.Index(doc, "scripts/release/build-firmware.sh build/release/images"); w < 0 || b < w {
		t.Error("releasing.md: the release built by hand isn't in a new worktree")
	}
	for _, f := range []string{"../docs/releasing.md"} {
		bumps := regexp.MustCompile(`docker run [^\n]*\\\n[^\n]*\\\n[^\n]*bump-version\.sh`).FindAllString(read(t, f), -1)
		if len(bumps) == 0 {
			t.Errorf("%s: no docker command for the version bump", f)
		}
		for _, c := range bumps {
			if !strings.Contains(c, "--network none") {
				t.Errorf("%s: the version bump runs with network: %s", f, c)
			}
		}
	}
	// Each command (continued lines joined, comments dropped, && and | split) is docker or git
	cmds := 0
	for _, block := range regexp.MustCompile("(?s)```sh\n(.*?)```").FindAllStringSubmatch(doc, -1) {
		text := regexp.MustCompile(`\\\n`).ReplaceAllString(block[1], " ")
		for _, l := range strings.Split(text, "\n") {
			l, _, _ = strings.Cut(l, "#")
			for _, c := range regexp.MustCompile(`&&|\|`).Split(l, -1) {
				f := strings.Fields(c)
				if len(f) == 0 {
					continue
				}
				cmds++
				if f[0] != "docker" && f[0] != "git" && !regexp.MustCompile(`^[A-Z]+=\S+$`).MatchString(strings.TrimSpace(c)) {
					t.Errorf("releasing.md: %q: a command other than docker or git", strings.TrimSpace(c))
				}
			}
		}
	}
	if cmds < 10 {
		t.Errorf("releasing.md: %d commands", cmds)
	}
}
