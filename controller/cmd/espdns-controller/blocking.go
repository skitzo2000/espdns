package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/actionlog"
	"github.com/skitzo2000/espdns/controller/internal/auth"
	"github.com/skitzo2000/espdns/controller/internal/blocking"
	"github.com/skitzo2000/espdns/controller/internal/blocklist"
	"github.com/skitzo2000/espdns/controller/internal/filestore"
	"github.com/skitzo2000/espdns/controller/internal/fleet"
	"github.com/skitzo2000/espdns/controller/internal/jobs"
	"github.com/skitzo2000/espdns/controller/internal/nodes"
	"github.com/skitzo2000/espdns/controller/internal/release"
	"github.com/skitzo2000/espdns/controller/internal/rolling"
	"github.com/skitzo2000/espdns/controller/internal/secfile"
	"github.com/skitzo2000/espdns/controller/internal/settings"
)

// Blocking (the Blocking page): the deployment's lists (internal/blocking: what each list is
// compiled from, in blocking/lists.json; the local sources, allow lists and overrides, files
// in blocking/sources), compiled into lists/<name>.bin by the job "blocklist", which runs
// blocklist.Run on the request the definition makes, the same request espdns blocklist's
// flags make for it (the parity test); and each node's blocking as its /status says it.
//
//	GET  /api/blocking                        the definitions, the source files, the compiled files, the nodes,
//	                                          each list's last compile job and its CLI command
//	GET  /api/blocking/defs?version=<file>    a kept version of the definitions
//	POST /api/blocking/defs                   {"lists": [...], "hash"}: saves the definitions (hash: the version edited)
//	GET  /api/blocking/sources/{name}         one source file: its text (the start of a big one), hash, history (?version=)
//	POST /api/blocking/sources/{name}         {"text", "hash"}: saves it ("" hash: a new file)
//	POST /api/blocking/sources/{name}/delete  {"hash"}: deletes it, kept in the history (not one a list reads)
//	POST /api/jobs  {"kind": "blocklist", "params": {"list": "<name>", "accept_change": false}}   the compile
//	POST /api/jobs  {"kind": "pause", "params": {"node", "seconds"}}, {"kind": "revert", ...}     the nodes
//
// While the controller is read-only (no password set), GET /api/blocking gives only the
// nodes' blocking and the compiled files, as the node list is open; the definitions (a feed's
// URL can hold its key) and the source files need a login, as the configs and the zones
// do (a compile job's record, open as every job's, names a URL with its key hidden). Every
// change needs a login (the session's cookie and token), and is in the action log with the
// user. Nothing here pushes a list: the Push page does (kind blocklist or overrides), which
// the page opens with the file chosen.

const (
	// showMax is the most of a source file the page gets to edit; a bigger one is shown
	// in part, and replaced whole from a file.
	showMax  = 2 << 20
	showHead = 64 << 10
)

type blockingServer struct {
	dataDir string
	nodes   func() []nodes.Node
	runner  *jobs.Runner
}

// listSums are the compiled files' hashes, kept between the page's polls.
var listSums fileSums

func (b blockingServer) routes(mux *routes) {
	mux.HandleFunc("GET /api/blocking", b.list)
	mux.HandleFunc("GET /api/blocking/defs", needLogin("the list definitions need", b.defsVersion))
	mux.HandleFunc("POST /api/blocking/defs", needLogin("blocking needs", b.saveDefs))
	mux.HandleFunc("GET /api/blocking/sources/{name}", needLogin("the source files need", b.source))
	mux.HandleFunc("POST /api/blocking/sources/{name}", needLogin("blocking needs", b.saveSource))
	mux.HandleFunc("POST /api/blocking/sources/{name}/delete", needLogin("blocking needs", b.deleteSource))
}

// ---- the overview ----------------------------------------------------------------------------

type sourceFile struct {
	Name     string    `json:"name"`
	Size     int64     `json:"size"`
	Modified time.Time `json:"modified"`
	UsedBy   []string  `json:"used_by"`
}

type compiledFile struct {
	rolling.ListInfo
	SHA256 string `json:"sha256,omitempty"`
	// List is the definition it is compiled from ("" for a file made otherwise: make blocklist).
	List string `json:"list,omitempty"`
}

type listDef struct {
	blocking.List
	Kind    string    `json:"kind"`    // what the Push page pushes it as: blocklist or overrides
	File    string    `json:"file"`    // lists/<name>.bin
	Command string    `json:"command"` // espdns blocklist for the same compile
	Ready   string    `json:"ready,omitempty"`
	Job     *jobs.Job `json:"job,omitempty"` // the last compile
}

type blockingNode struct {
	Host     string                  `json:"host"`
	ID       string                  `json:"node_id,omitempty"`
	Online   bool                    `json:"online"`
	Listed   bool                    `json:"listed"`
	Read     bool                    `json:"read"`
	State    string                  `json:"state,omitempty"`
	Blocking *release.BlockingStatus `json:"blocking,omitempty"` // nil: firmware from before blocking (or no /status yet)
	Off      bool                    `json:"off,omitempty"`      // blocking off in its node config
	// Runs names the compiled file here each list is (by its hash), "" none.
	Runs map[string]string `json:"runs"`
}

func (b blockingServer) list(w http.ResponseWriter, r *http.Request) {
	defs, hash, derr := blocking.Load(b.dataDir)
	out := map[string]any{"dir": blocking.Path(b.dataDir), "sources_dir": filepath.Join(blocking.Path(b.dataDir), blocking.SourcesDir),
		"lists_dir": filepath.Join(b.dataDir, blocking.ListsDir), "hash": hash, "pause_max_s": pauseMax, "pause_default_s": pauseDefault,
		"max_source": blocking.MaxSource, "show_max": showMax}
	all := append([]blocking.List{blocking.Overrides(b.dataDir)}, defs.Lists...)
	if auth.User(r.Context()) == "" {
		// Read-only (no password set): the nodes' blocking and the compiled files only.
		out["hash"], out["login_needed"] = "", true
		out["lists"], out["sources"], out["deleted"], out["history"] = []listDef{}, []sourceFile{}, []filestore.Version{}, []filestore.Version{}
	} else {
		b.defs(out, all, derr)
	}
	b.compiled(out, all)
	writeJSON(w, out)
}

// defs puts the definitions, their history, the source files and the deleted ones in out.
func (b blockingServer) defs(out map[string]any, all []blocking.List, derr error) {
	if derr != nil {
		out["defs_error"] = derr.Error()
	}
	if h, err := blocking.History(b.dataDir); err == nil && h != nil {
		out["history"] = h
	} else {
		out["history"] = []filestore.Version{}
	}
	jobsOf := b.lastJobs()
	var ld []listDef
	for _, l := range all {
		d := listDef{List: l, Kind: "blocklist", File: l.Name + ".bin", Command: l.Command(b.dataDir, false)}
		if l.IsOverrides() {
			d.Kind = "overrides"
		}
		if err := l.Ready(b.dataDir); err != nil {
			d.Ready = err.Error()
		}
		if j, ok := jobsOf[l.Name]; ok {
			d.Job = &j
		}
		ld = append(ld, d)
	}
	out["lists"] = ld

	// The source files, and which lists read each.
	src := blocking.Sources(b.dataDir)
	files := []sourceFile{}
	names, _ := src.Names()
	for _, n := range names {
		fi, err := os.Stat(filepath.Join(src.Dir, n))
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		sf := sourceFile{Name: n, Size: fi.Size(), Modified: fi.ModTime(), UsedBy: []string{}}
		for _, l := range all {
			if l.Uses(n) {
				sf.UsedBy = append(sf.UsedBy, l.Name)
			}
		}
		files = append(files, sf)
	}
	out["sources"] = files
	deleted := []filestore.Version{}
	if kept, err := src.Kept(); err == nil {
		for _, v := range kept {
			deleted = append(deleted, v)
		}
		slices.SortFunc(deleted, func(a, b filestore.Version) int { return b.Time.Compare(a.Time) })
	}
	out["deleted"] = deleted
}

// compiled puts the compiled files in lists/ and each node's blocking in out.
func (b blockingServer) compiled(out map[string]any, all []blocking.List) {
	// The compiled files in lists/, each with its hash, to tell which one a node runs.
	compiled := []compiledFile{}
	bySum := map[string]string{}
	for _, li := range rolling.ReadLists(b.dataDir) {
		cf := compiledFile{ListInfo: li}
		if li.Error == "" {
			cf.SHA256 = listSums.sum(filepath.Join(b.dataDir, blocking.ListsDir, li.Name))
			if cf.SHA256 != "" {
				bySum[cf.SHA256] = li.Name
			}
		}
		for _, l := range all {
			if l.Name+".bin" == li.Name {
				cf.List = l.Name
			}
		}
		compiled = append(compiled, cf)
	}
	out["files"] = compiled

	// The nodes: the ones known, those in settings.json first.
	var listed []string
	if s, err := settings.Load(settings.Path(b.dataDir)); err == nil {
		listed = s.Nodes
	}
	ns := []blockingNode{}
	for _, n := range b.nodes() {
		bn := blockingNode{Host: n.Addr, ID: n.ID, Online: n.Online, Listed: slices.Contains(listed, n.Addr), Runs: map[string]string{}}
		if st, ok := status(n); ok {
			bn.Read, bn.Blocking, bn.Off = true, st.Blocking, st.ServiceOff("blocking")
			if st.Health != nil {
				bn.State = st.Health.State
			}
			if st.Blocking != nil {
				for k, l := range map[string]release.ListStatus{"blocklist": st.Blocking.List, "overrides": st.Blocking.Overrides} {
					if f := bySum[l.SHA256]; f != "" && l.State == "on" {
						bn.Runs[k] = f
					}
				}
			}
		}
		ns = append(ns, bn)
	}
	slices.SortStableFunc(ns, func(a, b blockingNode) int {
		switch {
		case a.Listed == b.Listed:
			return 0
		case a.Listed:
			return -1
		}
		return 1
	})
	out["nodes"] = ns
}

// lastJobs are the newest compile job of each list, by its name.
func (b blockingServer) lastJobs() map[string]jobs.Job {
	out := map[string]jobs.Job{}
	if b.runner == nil {
		return out
	}
	for _, j := range b.runner.List() { // newest first
		if j.Kind != "blocklist" || len(j.Args) == 0 {
			continue
		}
		var p compileParams
		if json.Unmarshal([]byte(j.Args[0]), &p) != nil || p.List == "" {
			continue
		}
		if _, ok := out[p.List]; !ok {
			out[p.List] = j
		}
	}
	return out
}

func (b blockingServer) defsVersion(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query().Get("version")
	if v == "" {
		httpErr(w, http.StatusBadRequest, errors.New("?version=<file>: a kept version (GET /api/blocking has the history)"))
		return
	}
	text, err := blocking.ReadVersion(b.dataDir, v)
	if err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, map[string]any{"version": v, "text": string(text)})
}

func (b blockingServer) saveDefs(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Lists []blocking.List `json:"lists"`
		Hash  string          `json:"hash"`
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, blocking.MaxDefs))
	d.DisallowUnknownFields()
	if err := d.Decode(&req); err != nil {
		httpErr(w, http.StatusBadRequest, fmt.Errorf("body: %v", err))
		return
	}
	old, _, _ := blocking.Load(b.dataDir)
	hash, err := blocking.Save(b.dataDir, blocking.Defs{Lists: req.Lists}, req.Hash)
	switch {
	case errors.Is(err, filestore.ErrChanged):
		httpErr(w, http.StatusConflict, err)
		return
	case err != nil:
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	var names, before []string
	for _, l := range req.Lists {
		names = append(names, l.Name)
	}
	for _, l := range old.Lists {
		before = append(before, l.Name)
	}
	b.log(r, "blocking lists save", blocking.DefsFile, fmt.Sprintf("lists %v (were %v)", names, before))
	writeJSON(w, map[string]any{"hash": hash})
}

// ---- the source files -------------------------------------------------------------------------

func (b blockingServer) source(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	src := blocking.Sources(b.dataDir)
	if v := r.URL.Query().Get("version"); v != "" {
		text, err := src.ReadVersion(name, v)
		if err != nil {
			httpErr(w, http.StatusBadRequest, err)
			return
		}
		out := map[string]any{"name": name, "version": v, "size": len(text)}
		shown(out, text)
		writeJSON(w, out)
		return
	}
	f, err := src.Read(name)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		httpErr(w, http.StatusNotFound, fmt.Errorf("no source file %s in %s", name, src.Dir))
		return
	case err != nil:
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	h, _ := src.History(name)
	if h == nil {
		h = []filestore.Version{}
	}
	out := map[string]any{"name": f.Name, "hash": f.Hash, "modified": f.Modified, "size": len(f.Text), "history": h}
	shown(out, f.Text)
	writeJSON(w, out)
}

// shown puts a file's text in out: whole up to showMax, else its start ("partial").
func shown(out map[string]any, text []byte) {
	if len(text) <= showMax {
		out["text"] = string(text)
		return
	}
	head := text[:showHead]
	if i := bytes.LastIndexByte(head, '\n'); i > 0 {
		head = head[:i+1]
	}
	out["text"], out["partial"] = string(head), true
}

func (b blockingServer) saveSource(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var req struct {
		Text string `json:"text"`
		Hash string `json:"hash"`
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2*blocking.MaxSource+4096))
	d.DisallowUnknownFields()
	if err := d.Decode(&req); err != nil {
		httpErr(w, http.StatusBadRequest, fmt.Errorf("body: %v", err))
		return
	}
	src := blocking.Sources(b.dataDir)
	if err := src.Save(name, []byte(req.Text), req.Hash); err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, filestore.ErrChanged) {
			code = http.StatusConflict
		}
		httpErr(w, code, err)
		return
	}
	f, err := src.Read(name)
	if err != nil {
		httpErr(w, http.StatusInternalServerError, err)
		return
	}
	what := fmt.Sprintf("%d bytes", len(req.Text))
	if req.Hash == "" {
		what = "new: " + what
	}
	b.log(r, "blocking source save", name, what)
	writeJSON(w, map[string]any{"name": name, "hash": f.Hash, "modified": f.Modified, "size": len(f.Text)})
}

func (b blockingServer) deleteSource(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var req struct {
		Hash string `json:"hash"`
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	d.DisallowUnknownFields()
	if err := d.Decode(&req); err != nil {
		httpErr(w, http.StatusBadRequest, fmt.Errorf("body: %v", err))
		return
	}
	if err := blocking.SourceName(name); err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	defs, _, err := blocking.Load(b.dataDir)
	if err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	for _, l := range defs.Lists {
		if l.Uses(name) {
			httpErr(w, http.StatusConflict, fmt.Errorf("the list %s reads %s: take it out of that list first", l.Name, name))
			return
		}
	}
	src := blocking.Sources(b.dataDir)
	switch err := src.Delete(name, req.Hash); {
	case errors.Is(err, filestore.ErrChanged):
		httpErr(w, http.StatusConflict, err)
		return
	case errors.Is(err, fs.ErrNotExist):
		httpErr(w, http.StatusNotFound, err)
		return
	case err != nil:
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	b.log(r, "blocking source delete", name, "kept in "+filepath.Join(blocking.Dir, blocking.SourcesDir, filestore.HistoryDir))
	writeJSON(w, map[string]any{"name": name, "deleted": true})
}

func (b blockingServer) log(r *http.Request, action, name, what string) {
	user := auth.User(r.Context())
	if err := actionlog.Append(b.dataDir, actionlog.Entry{Event: "save", ID: "blocking-" + time.Now().UTC().Format("20060102-150405"),
		Source: "controller", Who: user, Action: action, Args: []string{name, what}, Result: "ok"}); err != nil {
		log.Printf("blocking: %s (%s), but not in the action log: %v", name, action, err)
	}
	log.Printf("blocking: %s: %s by %s (%s)", name, action, user, what)
}

// ---- the compile ------------------------------------------------------------------------------

// compileKind is the job kind "blocklist": a list compiled into lists/<name>.bin, as
// espdns blocklist does it.
type compileKind struct {
	dataDir string
	// fetch: how URL sources are fetched besides blocklist's rules (nil in use; a test's
	// server).
	fetch *blocklist.Fetch
}

type compileParams struct {
	List         string `json:"list"`
	AcceptChange bool   `json:"accept_change,omitempty"`
}

// compileResult is a compile job's result: the library's, with the list and its command.
type compileResult struct {
	List    string            `json:"list"`
	Kind    string            `json:"kind"` // blocklist or overrides, as the Push page pushes it
	File    string            `json:"file"` // in lists/
	Command string            `json:"command"`
	Accept  bool              `json:"accept_change,omitempty"`
	Refused bool              `json:"refused,omitempty"` // the size-change check refused it: nothing written
	Result  *blocklist.Result `json:"result"`
}

// load is the list named, ready to compile.
func (c compileKind) load(name string) (blocking.List, error) {
	defs, _, err := blocking.Load(c.dataDir)
	if err != nil && name != blocking.OverridesName {
		return blocking.List{}, err
	}
	l, ok := defs.Lookup(c.dataDir, name)
	if !ok {
		return l, fmt.Errorf("no list %q in %s", name, filepath.Join(blocking.Dir, blocking.DefsFile))
	}
	return l, l.Ready(c.dataDir)
}

func (c compileKind) kind(raw json.RawMessage) (jobs.Func, error) {
	var p compileParams
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&p); err != nil {
		return nil, fmt.Errorf("params: %v", err)
	}
	if p.List == "" {
		return nil, errors.New(`params: need "list", the list's name`)
	}
	if _, err := c.load(p.List); err != nil {
		return nil, err
	}
	return func(ctx context.Context, run *jobs.Run) (any, error) { return c.run(ctx, run, p) }, nil
}

func (c compileKind) run(ctx context.Context, run *jobs.Run, p compileParams) (any, error) {
	// Read again: the definitions or the files may have changed while it waited.
	l, err := c.load(p.List)
	if err != nil {
		return nil, err
	}
	out, _, err := c.compile(ctx, run, l, p.AcceptChange)
	if out.List == "" {
		return nil, err
	}
	return out, err
}

// compile compiles the list into lists/<name>.bin (the job "blocklist", and an apply's
// compile step). A size-change refusal is returned as itself too (nothing written).
func (c compileKind) compile(ctx context.Context, run *jobs.Run, l blocking.List, accept bool) (compileResult, *blocklist.SizeChangeError, error) {
	p := compileParams{List: l.Name, AcceptChange: accept}
	req, err := l.Request(c.dataDir, p.AcceptChange)
	if err != nil {
		return compileResult{}, nil, err
	}
	if err := secfile.MkdirAll(filepath.Dir(req.Out)); err != nil {
		return compileResult{}, nil, err
	}
	// A URL's credentials stay out of the job's record (its log, result and error): it is
	// kept on disk and read without a login while no password is set.
	red := l.Redactor()
	logf := func(format string, args ...any) { run.Logf("%s", red.Replace(fmt.Sprintf(format, args...))) }
	out := compileResult{List: l.Name, Kind: "blocklist", File: l.Name + ".bin", Command: red.Replace(l.Command(c.dataDir, p.AcceptChange)), Accept: p.AcceptChange}
	if l.IsOverrides() {
		out.Kind = "overrides"
	}
	logf("compiling %s: %s", l.Name, out.Command)
	if p.AcceptChange {
		logf("the size-change check takes this build whatever its size (accepted once)")
	}
	// A stop ends the compile where it is (a fetch is cancelled); nothing is written.
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-run.Stop():
			cancel()
		case <-cctx.Done():
		}
	}()
	req.Fetch, req.Logf = c.fetch, logf
	res, err := blocklist.Run(cctx, req)
	if res != nil {
		for i := range res.Sources {
			res.Sources[i].Source = red.Replace(res.Sources[i].Source)
		}
	}
	out.Result = res
	var sc *blocklist.SizeChangeError
	switch {
	case errors.As(err, &sc):
		out.Refused = true
		logf("%v", err)
		return out, sc, fmt.Errorf("refused by the size-change check: %s; nothing written (Accept this change once compiles it again taking it)",
			joinOver(sc.Change.Over))
	case err != nil && cctx.Err() != nil && ctx.Err() == nil:
		return out, nil, fleet.ErrStopped
	case err != nil:
		return out, nil, errors.New(red.Replace(err.Error()))
	}
	c.logResult(run, res)
	return out, nil, nil
}

func joinOver(over []string) string {
	var b bytes.Buffer
	for i, o := range over {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(o)
	}
	return b.String()
}

func (c compileKind) logResult(run *jobs.Run, r *blocklist.Result) {
	var b bytes.Buffer
	printResult(&b, r)
	for _, line := range bytes.Split(bytes.TrimSpace(b.Bytes()), []byte("\n")) {
		run.Logf("%s", line)
	}
}

// printResult is the size check's outcome, as the CLI says it.
func printResult(w io.Writer, r *blocklist.Result) {
	c := r.Change
	n := r.BlockedExact + r.BlockedSuffix
	fmt.Fprintf(w, "%d domains blocked (%d exact, %d suffix), %d allowed; %d bytes; key %d tried, %d hash(es) dropped for popular names\n",
		n, r.BlockedExact, r.BlockedSuffix, r.AllowedExact+r.AllowedSuffix, r.File.Size, r.Tries, r.Dropped)
	switch {
	case c.Previous == "":
		fmt.Fprintf(w, "size: no previous build to compare with\n")
	case c.Old == nil:
		fmt.Fprintf(w, "size: previous build %s replaced (accepted): %s\n", c.Previous, joinOver(c.Over))
	case len(c.Over) == 0:
		fmt.Fprintf(w, "size: previous build: blocked %d → %d, allowed %d → %d, bytes %d → %d: within %g%% or %d entries\n",
			c.Old.Blocked, c.New.Blocked, c.Old.Allowed, c.New.Allowed, c.Old.Bytes, c.New.Bytes, c.MaxChange, c.MinChange)
	case c.Accepted:
		fmt.Fprintf(w, "size: %s: over %g%%, taken (accepted once)\n", joinOver(c.Over), c.MaxChange)
	}
}

// ---- hashes of the compiled files -----------------------------------------------------------

// fileSums keeps each compiled file's sha256 by its size and time, so a page that polls
// doesn't read every list again.
type fileSums struct {
	mu sync.Mutex
	m  map[string]fileSum
}

type fileSum struct {
	size int64
	mod  time.Time
	sum  string
}

func (f *fileSums) sum(path string) string {
	fi, err := os.Stat(path)
	if err != nil {
		return ""
	}
	f.mu.Lock()
	if s, ok := f.m[path]; ok && s.size == fi.Size() && s.mod.Equal(fi.ModTime()) {
		f.mu.Unlock()
		return s.sum
	}
	f.mu.Unlock()
	fh, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer fh.Close()
	h := sha256.New()
	if _, err := io.Copy(h, fh); err != nil {
		return ""
	}
	sum := hex.EncodeToString(h.Sum(nil))
	f.mu.Lock()
	if f.m == nil {
		f.m = map[string]fileSum{}
	}
	f.m[path] = fileSum{fi.Size(), fi.ModTime(), sum}
	f.mu.Unlock()
	return sum
}
