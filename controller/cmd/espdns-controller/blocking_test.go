package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/actionlog"
	"github.com/skitzo2000/espdns/controller/internal/auth"
	"github.com/skitzo2000/espdns/controller/internal/blocking"
	"github.com/skitzo2000/espdns/controller/internal/blocklist"
	"github.com/skitzo2000/espdns/controller/internal/fakenode"
	"github.com/skitzo2000/espdns/controller/internal/fleet"
	"github.com/skitzo2000/espdns/controller/internal/jobs"
	"github.com/skitzo2000/espdns/controller/internal/keys"
	"github.com/skitzo2000/espdns/controller/internal/nodes"
	"github.com/skitzo2000/espdns/controller/internal/pins"
	"github.com/skitzo2000/espdns/controller/internal/release"
	"github.com/skitzo2000/espdns/controller/internal/settings"
)

// blockEnv is a controller with the Blocking page's routes and the compile job, logged in.
type blockEnv struct {
	t      *testing.T
	dir    string
	h      http.Handler
	runner *jobs.Runner
	cookie string
	tok    string
	ns     []nodes.Node
	// fetch: the compile job's; serveFeed fills it in for its server.
	fetch *blocklist.Fetch
}

func newBlockEnv(t *testing.T) *blockEnv {
	e := &blockEnv{t: t, dir: t.TempDir(), fetch: &blocklist.Fetch{}}
	if err := auth.SetPassword(auth.Path(e.dir), "admin", testPassword); err != nil {
		t.Fatal(err)
	}
	e.runner = jobs.New(e.dir, map[string]jobs.Kind{"blocklist": compileKind{dataDir: e.dir, fetch: e.fetch}.kind})
	e.runner.Logf = t.Logf
	runJobs(t, e.runner)
	s := &server{dataDir: e.dir, auth: auth.New(auth.Path(e.dir)), runner: e.runner,
		key: keys.FileSource{Path: keys.Path(e.dir)}, builder: newBuilder(t.TempDir(), t.TempDir(), t.TempDir()),
		nodes: func() []nodes.Node { return e.ns }}
	e.h, _ = s.handler()
	e.cookie, e.tok = login(t, e.h)
	return e
}

// serveFeed is an https server on loopback for a URL source, which the compile job
// trusts and may connect to (blocklist.Fetch): no other inside address.
func (e *blockEnv) serveFeed(h http.Handler) *httptest.Server {
	srv := httptest.NewTLSServer(h)
	e.t.Cleanup(srv.Close)
	e.fetch.TLS = srv.Client().Transport.(*http.Transport).TLSClientConfig
	e.fetch.Allow = append(e.fetch.Allow, netip.MustParseAddrPort(srv.Listener.Addr().String()))
	return srv
}

func (e *blockEnv) do(method, path string, body any) (int, string) {
	e.t.Helper()
	var b []byte
	if body != nil {
		b, _ = json.Marshal(body)
	}
	r := httptest.NewRequest(method, "http://127.0.0.1:8480"+path, strings.NewReader(string(b)))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "http://127.0.0.1:8480")
	r.AddCookie(&http.Cookie{Name: auth.CookieName(r.Host), Value: e.cookie})
	r.Header.Set(auth.TokenHeader, e.tok)
	w := serve(e.h, r)
	return w.Code, w.Body.String()
}

// overview is GET /api/blocking.
type overview struct {
	Hash      string `json:"hash"`
	DefsError string `json:"defs_error"`
	Lists     []struct {
		blocking.List
		Kind    string    `json:"kind"`
		Command string    `json:"command"`
		Ready   string    `json:"ready"`
		Job     *jobs.Job `json:"job"`
	} `json:"lists"`
	Sources []sourceFile      `json:"sources"`
	Deleted []json.RawMessage `json:"deleted"`
	Files   []compiledFile    `json:"files"`
	Nodes   []blockingNode    `json:"nodes"`
	History []json.RawMessage `json:"history"`
	Extra   map[string]any    `json:"-"`
}

func (e *blockEnv) overview() overview {
	e.t.Helper()
	code, b := e.do("GET", "/api/blocking", nil)
	var o overview
	if code != 200 || json.Unmarshal([]byte(b), &o) != nil {
		e.t.Fatalf("overview: %d %s", code, b)
	}
	return o
}

func (e *blockEnv) saveSource(name, text, hash string) string {
	e.t.Helper()
	code, b := e.do("POST", "/api/blocking/sources/"+name, map[string]string{"text": text, "hash": hash})
	var r struct{ Hash string }
	if code != 200 || json.Unmarshal([]byte(b), &r) != nil {
		e.t.Fatalf("save %s: %d %s", name, code, b)
	}
	return r.Hash
}

func (e *blockEnv) compile(list string, accept bool) jobs.Job {
	e.t.Helper()
	j, err := e.runner.Start("blocklist", "admin", json.RawMessage(fmt.Sprintf(`{"list":%q,"accept_change":%v}`, list, accept)))
	if err != nil {
		e.t.Fatalf("compile %s: %v", list, err)
	}
	for range 2000 {
		if j, _ = e.runner.Get(j.ID); j.State.Ended() {
			return j
		}
		time.Sleep(5 * time.Millisecond)
	}
	e.t.Fatalf("compile %s: not done", list)
	return j
}

func names(prefix string, n int) string {
	var b strings.Builder
	b.WriteString("# a list\n")
	for i := range n {
		fmt.Fprintf(&b, "%s%d.example.com\n", prefix, i)
	}
	return b.String()
}

// The Blocking page's files: a source saved new, edited over its version only, a stale save
// refused; the definitions saved strictly and over their version; each source with the
// lists that read it; a source a list reads not deleted, one no list reads deleted and kept;
// a big file shown in part; every change in the action log with the user; names that aren't
// a source file never reach the disk.
func TestBlockingFiles(t *testing.T) {
	e := newBlockEnv(t)
	h1 := e.saveSource("pro.txt", "||ads.example^\n", "")
	if code, b := e.do("POST", "/api/blocking/sources/pro.txt", map[string]string{"text": "x", "hash": ""}); code != 400 ||
		!strings.Contains(b, "already exists") {
		t.Errorf("a second new pro.txt: %d %s", code, b)
	}
	h2 := e.saveSource("pro.txt", "||ads.example^\n||track.example^\n", h1)
	if code, b := e.do("POST", "/api/blocking/sources/pro.txt", map[string]string{"text": "x", "hash": h1}); code != 409 {
		t.Errorf("stale save: %d %s", code, b)
	}
	e.saveSource("ok.txt", "# allowed\nfine.example\n", "")
	e.saveSource("spare.txt", "spare.example\n", "")
	for _, bad := range []string{"..%2fsettings.json", "a.json", "A.txt", ".history"} {
		if code, b := e.do("POST", "/api/blocking/sources/"+bad, map[string]string{"text": "x", "hash": ""}); code == 200 {
			t.Errorf("%s saved: %s", bad, b)
		}
	}
	if _, err := os.Stat(filepath.Join(e.dir, "settings.json")); err == nil {
		t.Fatal("wrote settings.json")
	}
	code, b := e.do("GET", "/api/blocking/sources/pro.txt", nil)
	var got struct {
		Text    string            `json:"text"`
		Hash    string            `json:"hash"`
		History []json.RawMessage `json:"history"`
	}
	if code != 200 || json.Unmarshal([]byte(b), &got) != nil || got.Hash != h2 || !strings.Contains(got.Text, "track") || len(got.History) != 1 {
		t.Fatalf("read: %d %s", code, b)
	}

	// The definitions: refused when they don't parse (strictly), saved, stale refused.
	defs := map[string]any{"lists": []map[string]any{{"name": "list", "sources": []string{"adblock:pro.txt"}, "allow": []string{"domains:ok.txt"},
		"max_change": 30, "min_change": 0}}, "hash": ""}
	for _, bad := range []map[string]any{
		{"lists": []map[string]any{{"name": "list", "sources": []string{"adblock:/etc/passwd"}}}, "hash": ""},
		{"lists": []map[string]any{{"name": "overrides", "sources": []string{"adblock:pro.txt"}}}, "hash": ""},
		{"lists": []map[string]any{{"name": "list", "sources": []string{"adblock:pro.txt"}, "bits": 40}}, "hash": ""},
		{"lists": []any{}, "hash": "", "extra": true},
	} {
		if code, b := e.do("POST", "/api/blocking/defs", bad); code != 400 {
			t.Errorf("%v saved: %d %s", bad, code, b)
		}
	}
	code, b = e.do("POST", "/api/blocking/defs", defs)
	if code != 200 {
		t.Fatalf("defs: %d %s", code, b)
	}
	if code, _ := e.do("POST", "/api/blocking/defs", defs); code != 400 { // "" again: it exists now
		t.Errorf("second first save: %d", code)
	}
	o := e.overview()
	if o.DefsError != "" || o.Hash == "" || len(o.Lists) != 2 || o.Lists[0].Name != "overrides" || o.Lists[0].Kind != "overrides" ||
		o.Lists[0].Ready == "" || o.Lists[1].Name != "list" || o.Lists[1].Kind != "blocklist" || o.Lists[1].Ready != "" ||
		!strings.Contains(o.Lists[1].Command, "espdns blocklist -list adblock:"+e.dir+"/blocking/sources/pro.txt -allow domains:") ||
		!strings.Contains(o.Lists[1].Command, "-max-change 30 -min-change 0 -out "+e.dir+"/lists/list.bin") {
		t.Fatalf("overview: %+v", o)
	}
	used := map[string][]string{}
	for _, s := range o.Sources {
		used[s.Name] = s.UsedBy
	}
	if len(o.Sources) != 3 || strings.Join(used["pro.txt"], ",") != "list" || len(used["spare.txt"]) != 0 {
		t.Errorf("sources %+v", o.Sources)
	}
	defs["hash"] = o.Hash
	defs["lists"] = []map[string]any{{"name": "list", "sources": []string{"adblock:pro.txt", "hosts:missing.txt"}}}
	if code, b := e.do("POST", "/api/blocking/defs", defs); code != 200 {
		t.Fatalf("defs again: %d %s", code, b)
	}
	if code, b := e.do("POST", "/api/blocking/defs", defs); code != 409 {
		t.Errorf("stale defs: %d %s", code, b)
	}
	o = e.overview()
	if !strings.Contains(o.Lists[1].Ready, "missing.txt") || len(o.History) != 1 {
		t.Errorf("a missing file: %+v", o.Lists[1])
	}
	if _, err := e.runner.Start("blocklist", "admin", json.RawMessage(`{"list":"list"}`)); err == nil || !strings.Contains(err.Error(), "missing.txt") {
		t.Errorf("compile with a file missing: %v", err)
	}
	for _, p := range []string{`{"list":"nope"}`, `{}`, `{"list":"list","x":1}`} {
		if _, err := e.runner.Start("blocklist", "admin", json.RawMessage(p)); err == nil {
			t.Errorf("%s queued", p)
		}
	}

	// Deletes: a source a list reads isn't; one no list reads is, kept in the history.
	if code, b := e.do("POST", "/api/blocking/sources/pro.txt/delete", map[string]string{"hash": h2}); code != 409 || !strings.Contains(b, "the list list reads") {
		t.Errorf("delete a source in use: %d %s", code, b)
	}
	code, b = e.do("GET", "/api/blocking/sources/spare.txt", nil)
	json.Unmarshal([]byte(b), &got)
	if code, b := e.do("POST", "/api/blocking/sources/spare.txt/delete", map[string]string{"hash": got.Hash}); code != 200 {
		t.Errorf("delete: %d %s", code, b)
	}
	if o = e.overview(); len(o.Sources) != 2 || len(o.Deleted) != 1 {
		t.Errorf("after the delete: %+v %s", o.Sources, o.Deleted)
	}

	// A file over what the page edits is shown in part.
	big := names("big", 200000)
	e.saveSource("big.txt", big, "")
	code, b = e.do("GET", "/api/blocking/sources/big.txt", nil)
	var part struct {
		Text    string `json:"text"`
		Partial bool   `json:"partial"`
		Size    int    `json:"size"`
	}
	if code != 200 || json.Unmarshal([]byte(b), &part) != nil || !part.Partial || part.Size != len(big) || len(part.Text) > showHead ||
		!strings.HasSuffix(part.Text, "\n") {
		t.Errorf("big: %d partial %v size %d text %d", code, part.Partial, part.Size, len(part.Text))
	}

	es, _ := actionlog.Tail(e.dir, 0)
	var acts []string
	for _, en := range es {
		if en.Who != "admin" {
			t.Errorf("not the user: %+v", en)
		}
		acts = append(acts, en.Action+" "+en.Args[0])
	}
	if want := "blocking source save pro.txt|blocking source save pro.txt|blocking source save ok.txt|blocking source save spare.txt|" +
		"blocking lists save lists.json|blocking lists save lists.json|blocking source delete spare.txt|blocking source save big.txt"; strings.Join(acts, "|") != want {
		t.Errorf("action log:\n %s\nwant\n %s", strings.Join(acts, "|"), want)
	}
}

const rpzText = `$TTL 300
@ IN SOA rpz.example. admin.rpz.example. 1 3600 600 86400 300
@ IN NS ns.rpz.example.
bad.example CNAME .
*.worse.example CNAME .
ok.example CNAME rpz-passthru.
local.example A 192.0.2.1
32.1.2.0.192.rpz-ip CNAME .
`

// A compile through the job: local files, a URL (an httptest server) and an RPZ source, its
// counts per source in the result (RPZ's skipped by kind), lists/<name>.bin written where
// the Push page reads it; a much smaller build refused by the size-change check, nothing
// written, then taken by Accept this change once; the overrides compiled to overrides.bin;
// a node running a compiled file named as running it.
func TestBlockingCompile(t *testing.T) {
	e := newBlockEnv(t)
	feed := names("feed", 3000)
	var served = feed
	srv := e.serveFeed(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, served) }))
	e.saveSource("local.txt", names("local", 500), "")
	e.saveSource("feed.rpz", rpzText, "")
	e.saveSource("ok.txt", "local1.example.com\n", "")
	if code, b := e.do("POST", "/api/blocking/defs", map[string]any{"lists": []map[string]any{{"name": "main",
		"sources": []string{"domains:local.txt", "domains:" + srv.URL + "/feed.txt", "rpz:feed.rpz"}, "allow": []string{"domains:ok.txt"}}},
		"hash": ""}); code != 200 {
		t.Fatalf("defs: %d %s", code, b)
	}
	j := e.compile("main", false)
	var res compileResult
	if j.State != jobs.Done || json.Unmarshal(j.Result, &res) != nil || res.Result == nil || !res.Result.Written {
		t.Fatalf("compile: %+v", j)
	}
	r := res.Result
	if len(r.Sources) != 4 || r.Sources[0].Entries != 500 || r.Sources[1].Entries != 3000 || r.Sources[2].RPZ == nil ||
		r.Sources[2].RPZ.Blocked != 2 || r.Sources[2].RPZ.Allowed != 1 || r.Sources[2].RPZ.LocalData != 1 || r.Sources[2].RPZ.IP != 1 ||
		!r.Sources[3].Allow || res.Kind != "blocklist" || res.File != "main.bin" || r.Change.Previous != "" {
		t.Errorf("result %+v", res)
	}
	if !strings.Contains(strings.Join(logOf(e, j.ID), "\n"), "rpz:"+e.dir+"/blocking/sources/feed.rpz (block): 3 entries") {
		t.Errorf("log %v", logOf(e, j.ID))
	}
	out := filepath.Join(e.dir, "lists", "main.bin")
	first, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}

	// The feed shrinks to a tenth: refused, the file kept.
	served = names("feed", 300)
	j = e.compile("main", false)
	res = compileResult{}
	json.Unmarshal(j.Result, &res)
	if j.State != jobs.Failed || !res.Refused || !strings.Contains(j.Error, "refused by the size-change check") || res.Result == nil ||
		!res.Result.Change.Refused || res.Result.Written {
		t.Fatalf("refusal: %+v %s", j, j.Result)
	}
	if now, _ := os.ReadFile(out); string(now) != string(first) {
		t.Fatal("the refused build replaced the file")
	}
	o := e.overview()
	if o.Lists[1].Job == nil || o.Lists[1].Job.ID != j.ID {
		t.Errorf("last job: %+v", o.Lists[1].Job)
	}
	// Accepted once.
	j = e.compile("main", true)
	res = compileResult{}
	json.Unmarshal(j.Result, &res)
	if j.State != jobs.Done || !res.Accept || !res.Result.Change.Accepted || !strings.Contains(res.Command, "-accept-change") {
		t.Fatalf("accepted: %+v %s", j, j.Result)
	}
	if now, _ := os.ReadFile(out); string(now) == string(first) {
		t.Fatal("the accepted build wasn't written")
	}

	// The overrides.
	e.saveSource(blocking.OverridesBlock, "*.bad.example\n", "")
	j = e.compile("overrides", false)
	res = compileResult{}
	json.Unmarshal(j.Result, &res)
	if j.State != jobs.Done || res.Kind != "overrides" || res.File != "overrides.bin" || res.Result.File.Size == 0 {
		t.Fatalf("overrides: %+v %s", j, j.Result)
	}
	if !strings.Contains(res.Command, "-xor 0") {
		t.Errorf("overrides command: %s", res.Command)
	}

	// A node running main.bin (pushed to a fake node) is named as running it; the files are
	// the Push page's.
	k := newTestKey(t)
	fn := fakenode.New("b1", [6]byte{0x02, 0, 0, 0, 0x9, 1}, "esp32p4-rev1", "p4-ip101", release.PublicRaw(k))
	nsrv := httptest.NewServer(fn)
	t.Cleanup(nsrv.Close)
	fn.Addr = strings.TrimPrefix(nsrv.URL, "http://")
	main, _ := os.ReadFile(out)
	own := t.TempDir()
	pinAt(t, own, fn.Addr)
	if _, err := (&release.Pusher{Key: k, KeyID: release.KeyRelease, Pins: pins.Open(own)}).Push(context.Background(), fn.Addr,
		release.Blocklist, main); err != nil {
		t.Fatal(err)
	}
	e.ns = []nodes.Node{{Addr: fn.Addr, ID: fn.ID(), Online: true, Status: fakeStatus(fn)}}
	o = e.overview()
	if len(o.Nodes) != 1 || o.Nodes[0].Runs["blocklist"] != "main.bin" || o.Nodes[0].Runs["overrides"] != "" || o.Nodes[0].Blocking == nil {
		t.Errorf("nodes %+v", o.Nodes)
	}
	if len(o.Files) != 2 || o.Files[0].Name != "main.bin" || o.Files[0].List != "main" || o.Files[1].List != "overrides" {
		t.Errorf("files %+v", o.Files)
	}
}

func logOf(e *blockEnv, id string) []string {
	j, _ := e.runner.Get(id)
	var out []string
	for _, l := range j.Log {
		out = append(out, l.Text)
	}
	return out
}

// Pause and resume on a fake node, as espdns pause -for: /status paused_s says it, the node
// doesn't block meanwhile; a node not in settings.json, a pause over a week and a negative
// one refused before they are queued.
func TestPause(t *testing.T) {
	k := newTestKey(t)
	fn := fakenode.New("pz", [6]byte{0x02, 0, 0, 0, 0x9, 2}, "esp32p4-rev1", "p4-ip101", release.PublicRaw(k))
	srv := httptest.NewServer(fn)
	t.Cleanup(srv.Close)
	fn.Addr = strings.TrimPrefix(srv.URL, "http://")
	s := settings.Settings{Nodes: []string{fn.Addr}}
	paused := func() uint32 {
		t.Helper()
		st, err := (&fleet.Client{}).Status(context.Background(), fn.Addr)
		if err != nil || st.Blocking == nil {
			t.Fatalf("status: %+v %v", st, err)
		}
		return st.Blocking.PausedS
	}
	if paused() != 0 {
		t.Fatal("paused at the start")
	}
	j, err := runAction(t, k, s, "pause", `{"node":"`+fn.Addr+`","seconds":600}`)
	if err != nil || j.State != jobs.Done || !strings.Contains(string(j.Result), "paused for 600 s") {
		t.Fatalf("pause: %+v %v", j, err)
	}
	if p := paused(); p < 590 || p > 600 {
		t.Errorf("paused_s %d", p)
	}
	j, err = runAction(t, k, s, "pause", `{"node":"`+fn.Addr+`","seconds":0}`)
	if err != nil || j.State != jobs.Done || !strings.Contains(string(j.Result), "resumed") || paused() != 0 {
		t.Fatalf("resume: %+v %v", j, err)
	}
	j, err = runAction(t, k, s, "pause", `{"node":"`+fn.Addr+`"}`)
	if err != nil || j.State != jobs.Done || paused() < 290 {
		t.Fatalf("the default: %+v %v %d", j, err, paused())
	}
	for _, c := range []struct{ params, want string }{
		{`{"node":"192.0.2.9","seconds":60}`, "not in settings.json"},
		{`{"node":"` + fn.Addr + `","seconds":604801}`, "a week"},
		{`{"node":"` + fn.Addr + `","seconds":-1}`, "a week"},
		{`{"node":"` + fn.Addr + `","list":"blocklist"}`, "only for revert"},
	} {
		if _, err := runAction(t, k, s, "pause", c.params); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.params, err, c.want)
		}
	}
}

// A feed's URL can hold its key (in the user info or the query): the compile job's record
// (its log, command, result and error, on disk and read without a login while no password
// is set) names the URL with it hidden, whether the fetch works or fails; and with no
// password set, GET /api/blocking gives the nodes and the compiled files but not the
// definitions, and the definitions' versions and the source files need a login.
func TestBlockingSecretsHidden(t *testing.T) {
	e := newBlockEnv(t)
	fail := false
	srv := e.serveFeed(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail {
			http.Error(w, "gone", http.StatusNotFound)
			return
		}
		fmt.Fprint(w, names("feed", 50))
	}))
	feed := strings.Replace(srv.URL, "https://", "https://feeduser:hunter2pass@", 1) + "/feed.txt?key=s3cr3tkey&fmt=x"
	e.saveSource("local.txt", names("local", 50), "")
	if code, b := e.do("POST", "/api/blocking/defs", map[string]any{"hash": "", "lists": []map[string]any{
		{"name": "list", "sources": []string{"domains:local.txt", "domains:" + feed}}}}); code != 200 {
		t.Fatalf("defs: %d %s", code, b)
	}
	if o := e.overview(); len(o.Lists) != 2 || !strings.Contains(o.Lists[1].Command, "s3cr3tkey") {
		t.Errorf("logged in, the definitions as they are: %+v", o.Lists)
	}
	check := func(what string, j jobs.Job) {
		t.Helper()
		b, _ := json.Marshal(j)
		rec, _ := os.ReadFile(filepath.Join(e.dir, "log", "jobs", j.ID+".json"))
		for _, secret := range []string{"hunter2pass", "s3cr3tkey", "feeduser"} {
			if strings.Contains(string(b), secret) || strings.Contains(string(rec), secret) {
				t.Errorf("%s: %q in the job: %s", what, secret, b)
			}
		}
		if !strings.Contains(string(b), "key=xxxxx") {
			t.Errorf("%s: the URL not named at all: %s", what, b)
		}
	}
	j := e.compile("list", false)
	if j.State != jobs.Done {
		t.Fatalf("compile: %+v", j)
	}
	check("done", j)
	fail = true
	j = e.compile("list", false)
	if j.State != jobs.Failed || !strings.Contains(j.Error, "404") {
		t.Fatalf("a failed fetch: %+v", j)
	}
	check("failed", j)

	// No password set: read-only.
	s := &server{dataDir: e.dir, auth: auth.New(filepath.Join(t.TempDir(), "none")), runner: e.runner,
		key: keys.FileSource{Path: keys.Path(e.dir)}, builder: newBuilder(t.TempDir(), t.TempDir(), t.TempDir()),
		nodes: func() []nodes.Node { return nil }}
	h, _ := s.handler()
	get := func(p string) (int, string) {
		w := serve(h, httptest.NewRequest("GET", "http://127.0.0.1:8480"+p, nil))
		return w.Code, w.Body.String()
	}
	code, b := get("/api/blocking")
	if code != 200 || strings.Contains(b, "s3cr3tkey") || strings.Contains(b, "local.txt") || !strings.Contains(b, `"login_needed":true`) ||
		!strings.Contains(b, `"list.bin"`) {
		t.Errorf("read-only overview: %d %s", code, b)
	}
	for _, p := range []string{"/api/blocking/sources/local.txt", "/api/blocking/defs?version=x"} {
		if code, b := get(p); code != http.StatusForbidden || !strings.Contains(b, "passwd") {
			t.Errorf("%s read-only: %d %s", p, code, b)
		}
	}
}

// A compile job's log says a build taken under the floor as that ("within 2%" alone would
// be false for a 5% change), as the CLI.
func TestPrintResultWithinFloor(t *testing.T) {
	r := &blocklist.Result{Out: "l.bin", File: blocklist.FileStats{Size: 9450}, Change: blocklist.SizeChange{Previous: "l.bin",
		Old: &blocklist.Size{Blocked: 1000, Bytes: 9000}, New: blocklist.Size{Blocked: 1050, Bytes: 9450}, MaxChange: 2, MinChange: 100}}
	var b strings.Builder
	printResult(&b, r)
	if !strings.Contains(b.String(), "within 2% or 100 entries") {
		t.Errorf("printed %q", b.String())
	}
}

// A list server inside, over plain http: refused by the compile, saying how to allow it,
// until its host is on the internal allowlist (settings.json's internal_sources, saved
// through /api/settings); then fetched, and the command shows -internal.
func TestBlockingInternalSource(t *testing.T) {
	e := newBlockEnv(t)
	inside := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, names("inside", 50)) }))
	t.Cleanup(inside.Close)
	if code, b := e.do("POST", "/api/blocking/defs", map[string]any{"lists": []map[string]any{{"name": "lan",
		"sources": []string{"domains:" + inside.URL + "/feed.txt"}}}, "hash": ""}); code != 200 {
		t.Fatalf("defs: %d %s", code, b)
	}
	j := e.compile("lan", false)
	if j.State != jobs.Failed || !strings.Contains(j.Error, "plain http is refused") || !strings.Contains(j.Error, "internal_sources") {
		t.Fatalf("not allowed: %+v", j)
	}
	code, b := e.do("GET", "/api/settings", nil)
	var cur struct{ Version string }
	if code != 200 || json.Unmarshal([]byte(b), &cur) != nil {
		t.Fatal(code, b)
	}
	if code, b := e.do("POST", "/api/settings", map[string]any{"settings": map[string]any{"internal_sources": []string{"lists example"}},
		"version": cur.Version}); code != 400 || !strings.Contains(b, `"field":"internal_sources"`) {
		t.Fatalf("a bad host: %d %s", code, b)
	}
	if code, b := e.do("POST", "/api/settings", map[string]any{"settings": map[string]any{"internal_sources": []string{"127.0.0.1"}},
		"version": cur.Version}); code != 200 || !strings.Contains(b, `"internal_sources":["127.0.0.1"]`) {
		t.Fatalf("saved: %d %s", code, b)
	}
	j = e.compile("lan", false)
	var res compileResult
	if j.State != jobs.Done || json.Unmarshal(j.Result, &res) != nil || res.Result.Sources[0].Entries != 50 ||
		!strings.Contains(res.Command, "-internal 127.0.0.1") {
		t.Fatalf("allowed: %+v %s", j, j.Result)
	}
}
