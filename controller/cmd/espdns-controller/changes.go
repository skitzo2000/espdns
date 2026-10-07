package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/actionlog"
	"github.com/skitzo2000/espdns/controller/internal/auth"
	"github.com/skitzo2000/espdns/controller/internal/blocking"
	"github.com/skitzo2000/espdns/controller/internal/changes"
	"github.com/skitzo2000/espdns/controller/internal/configs"
	"github.com/skitzo2000/espdns/controller/internal/jobs"
	"github.com/skitzo2000/espdns/controller/internal/nodecfg"
	"github.com/skitzo2000/espdns/controller/internal/nodes"
	"github.com/skitzo2000/espdns/controller/internal/release"
	"github.com/skitzo2000/espdns/controller/internal/rolling"
	"github.com/skitzo2000/espdns/controller/internal/settings"
)

// The pending changes (internal/changes; "collect, then Apply"): the pages add their edits
// here, the header lists them, and one apply job (apply.go) sends them all.
//
//	GET  /api/changes                    the pending changes, oldest first, each with what applying it does;
//	                                     the nodes that restart; the apply running or the last one
//	POST /api/changes                    {"kind", "name", "text" | "delete": true, "hash", "summary"}: a file change;
//	                                     {"kind": "firmware", "firmware", "nodes", "summary"}: a firmware update (201)
//	GET  /api/changes/file?kind=&name=   a file as the pending changes make it: what an edit starts from
//	POST /api/changes/{id}/discard       discards it, and the changes of its file stacked on it
//	POST /api/changes/discard            discards every one but the put-back ones
//	POST /api/jobs  {"kind": "apply", "params": {...}}   applies them (apply.go)
//
// Every one needs a login, the reads too (a config change holds the Wi-Fi password): a
// config's password is never in a reply, and a text that still has configs.Hidden keeps
// the password the file has. Each add and discard is in the action log, by the user.

type changesServer struct {
	dataDir string
	catalog string
	store   *changes.Store
	nodes   func() []nodes.Node
	runner  *jobs.Runner
}

func (c changesServer) routes(mux *routes) {
	need := func(h http.HandlerFunc) http.HandlerFunc { return needLogin("the pending changes need", h) }
	mux.HandleFunc("GET /api/changes", need(c.list))
	mux.HandleFunc("POST /api/changes", need(c.add))
	mux.HandleFunc("GET /api/changes/file", need(c.file))
	mux.HandleFunc("POST /api/changes/{id}/discard", need(c.discard))
	mux.HandleFunc("POST /api/changes/discard", need(c.discardAll))
}

// changeView is a pending change as the header lists it.
type changeView struct {
	changes.Change
	// Effect is what applying it does, in words; Restarts the nodes it restarts (one at a
	// time).
	Effect   string   `json:"effect"`
	Restarts []string `json:"restarts,omitempty"`
	Applying bool     `json:"applying,omitempty"` // an apply running now is sending it
}

func (c changesServer) list(w http.ResponseWriter, r *http.Request) {
	cs, err := c.store.List()
	if err != nil {
		httpErr(w, http.StatusInternalServerError, err)
		return
	}
	sts := map[string]nodes.Node{}
	for _, n := range c.nodes() {
		sts[n.Addr] = n
	}
	var listed []string
	if s, err := settings.Load(settings.Path(c.dataDir)); err == nil {
		listed = s.Nodes
	}
	out := []changeView{}
	restarts := []string{}
	for _, ch := range cs {
		v := changeView{Change: ch, Applying: c.store.Held(ch.ID)}
		v.Effect, v.Restarts = c.effect(ch, cs, listed, sts)
		for _, h := range v.Restarts {
			if !slices.Contains(restarts, h) {
				restarts = append(restarts, h)
			}
		}
		out = append(out, v)
	}
	reply := map[string]any{"changes": out, "restarts": restarts}
	// The apply running (or waiting), else the last one: the header's progress.
	if c.runner != nil {
		for _, j := range c.runner.List() { // newest first
			if j.Kind == "apply" {
				reply["apply"] = j
				break
			}
		}
	}
	writeJSON(w, reply)
}

// effect says what applying a change does, and which nodes it restarts.
func (c changesServer) effect(ch changes.Change, cs []changes.Change, listed []string, known map[string]nodes.Node) (string, []string) {
	prefix := ""
	if ch.Written {
		prefix = "Written, not on every node yet: "
	}
	switch ch.Kind {
	case changes.Firmware:
		return prefix + "Restarts " + strings.Join(ch.Nodes, ", ") + ", one at a time: the others keep answering", ch.Nodes
	case changes.Zone:
		return prefix + "Hosted zones: sent to every node, live (no restart)", nil
	case changes.Source, changes.Lists:
		return prefix + "Blocking: compiled again, then sent to the nodes, live (no restart)", nil
	case changes.Config:
		if ch.Delete {
			return prefix + "The file is deleted: no node changes", nil
		}
		text, err := c.store.Text(ch)
		if err != nil {
			return prefix + "Can't be read: " + err.Error(), nil
		}
		cfg, err := nodecfg.Parse(text)
		if err != nil {
			return prefix + err.Error(), nil
		}
		// The file as it is, and as it was before an apply that stopped wrote it: a change
		// that renames the node, or moves its address, goes to the node that runs it now.
		texts := [][]byte{text}
		if cur, err := changes.Current(c.dataDir, ch.Kind, ch.Name); err == nil && cur.Exists {
			texts = append(texts, cur.Text)
		}
		if i := slices.IndexFunc(cs, ch.Same); i >= 0 {
			texts = append(texts, c.store.Base(cs[i].ID))
		}
		sts := map[string]release.NodeStatus{}
		for _, h := range listed {
			if n, ok := known[h]; ok {
				if st, ok := status(n); ok {
					sts[h] = st
				}
			}
		}
		saved := assumedFile(c.dataDir, c.store, cs, ch.Name)
		var live, maybe, restart []string
		for _, h := range configNodes(c.dataDir, ch.Name, texts, listed, sts) {
			st := sts[h]
			runs := configs.NodeRuns(c.dataDir, ch.Name, saved, st)
			d := nodecfg.Compare(runs.Config, cfg, configs.RunningNetwork(st))
			switch {
			case d.NeedsReboot():
				restart = append(restart, h)
			case len(d.Maybe) > 0:
				maybe = append(maybe, h)
			default:
				live = append(live, h)
			}
		}
		var parts []string
		if len(restart) > 0 {
			parts = append(parts, strings.Join(restart, ", ")+" restarts, the others keep answering")
		}
		if len(maybe) > 0 {
			parts = append(parts, strings.Join(maybe, ", ")+" may restart")
		}
		if len(live) > 0 {
			parts = append(parts, strings.Join(live, ", ")+": live (no restart)")
		}
		if len(parts) == 0 {
			return prefix + "No node in settings.json runs it yet: saved, sent to none", nil
		}
		return prefix + strings.Join(parts, "; "), restart
	}
	return prefix, nil
}

// assumedFile is the config file name as a node that runs a config pushed without a record
// here is taken to run (configs.NodeRuns), as the config push takes it: the file as it is;
// or, when an apply that stopped wrote the file's pending changes, the file as it was before
// (a node without a record didn't take what was written). nil: none.
func assumedFile(dataDir string, store *changes.Store, cs []changes.Change, name string) *configs.File {
	probe := changes.Change{Kind: changes.Config, Name: name}
	if i := slices.IndexFunc(cs, probe.Same); i >= 0 && cs[i].Written {
		b := store.Base(cs[i].ID)
		if b == nil {
			return nil
		}
		cfg, err := nodecfg.Parse(b)
		if err != nil {
			return nil
		}
		return &configs.File{Name: name, Hash: configs.Hash(b), Size: int64(len(b)), Text: b, Config: cfg}
	}
	if f, err := configs.Read(dataDir, name); err == nil && f.Config != nil {
		return &f
	}
	return nil
}

// configNodes are the hosts (of those whose /status is in sts) that run the config file
// name: the node of one of its texts (the change's, the file's as it is, as it was), or
// the node the controller last pushed the file to, still on that push.
func configNodes(dataDir, name string, texts [][]byte, hosts []string, sts map[string]release.NodeStatus) []string {
	var cfgs []*nodecfg.Config
	for _, t := range texts {
		if t == nil {
			continue
		}
		if cfg, err := nodecfg.Parse(t); err == nil {
			cfgs = append(cfgs, cfg)
		}
	}
	var out []string
	for _, h := range hosts {
		st, ok := sts[h]
		if !ok {
			continue
		}
		match := slices.ContainsFunc(cfgs, func(cfg *nodecfg.Config) bool { return configs.Matches(cfg, h, st) })
		if !match && st.Config != nil && st.NodeID != "" {
			if p, err := configs.LoadPushed(dataDir, st.NodeID); err == nil && p != nil && p.File == name && p.Seq == st.Config.Seq {
				match = true
			}
		}
		if match {
			out = append(out, h)
		}
	}
	return out
}

// changeBody is POST /api/changes's body.
type changeBody struct {
	Kind     changes.Kind `json:"kind"`
	Name     string       `json:"name"`
	Text     *string      `json:"text"`
	Delete   bool         `json:"delete"`
	Hash     string       `json:"hash"`
	Firmware string       `json:"firmware"`
	Nodes    []string     `json:"nodes"`
	Summary  string       `json:"summary"`
}

func (c changesServer) add(w http.ResponseWriter, r *http.Request) {
	var b changeBody
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2*blocking.MaxSource+64<<10))
	d.DisallowUnknownFields()
	if err := d.Decode(&b); err != nil {
		httpErr(w, http.StatusBadRequest, fmt.Errorf("body: %v", err))
		return
	}
	e := changes.Edit{Kind: b.Kind, Name: b.Name, Delete: b.Delete, Hash: b.Hash, Firmware: b.Firmware, Nodes: b.Nodes,
		Summary: b.Summary, Who: auth.User(r.Context())}
	switch {
	case b.Kind != changes.Firmware && !b.Kind.File():
		_, err := changes.FileStore(c.dataDir, b.Kind)
		httpErr(w, http.StatusBadRequest, err)
		return
	case b.Kind == changes.Firmware:
		if b.Text != nil {
			httpErr(w, http.StatusBadRequest, errors.New("a firmware change has no text"))
			return
		}
		if err := firmwareThere(c.dataDir, c.catalog, b.Firmware); err != nil {
			httpErr(w, http.StatusBadRequest, err)
			return
		}
		s, err := settings.Load(settings.Path(c.dataDir))
		if err != nil {
			httpErr(w, http.StatusInternalServerError, err)
			return
		}
		for _, n := range b.Nodes {
			if !slices.Contains(s.Nodes, n) {
				httpErr(w, http.StatusBadRequest, fmt.Errorf("%s is not in settings.json: an update goes only to the nodes listed there", n))
				return
			}
		}
	case b.Kind.File() && !b.Delete:
		if b.Text == nil {
			httpErr(w, http.StatusBadRequest, errors.New(`"text": what the file becomes (or "delete": true)`))
			return
		}
		e.Text = []byte(*b.Text)
		if b.Kind == changes.Config {
			// The page shows the password hidden: a text that still has it keeps the one the
			// file has, as the pending changes make it.
			v, err := c.store.Effective(changes.Config, b.Name)
			if err != nil {
				httpErr(w, http.StatusBadRequest, err)
				return
			}
			if e.Text, err = configs.Unmask(e.Text, v.Text); err != nil {
				httpErr(w, http.StatusBadRequest, err)
				return
			}
		}
	case b.Text != nil:
		httpErr(w, http.StatusBadRequest, errors.New("a delete has no text"))
		return
	}
	ch, err := c.store.Add(e)
	if err != nil {
		httpErr(w, changeCode(err), err)
		return
	}
	c.log(r, "change add", ch, ch.Summary)
	w.Header().Set("Location", "/api/changes")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(ch)
}

// changeCode is the HTTP status of a pending change's error.
func changeCode(err error) int {
	switch {
	case errors.Is(err, changes.ErrChanged), errors.Is(err, changes.ErrHeld):
		return http.StatusConflict
	case errors.Is(err, changes.ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, changes.ErrFull):
		return http.StatusTooManyRequests
	}
	return http.StatusBadRequest
}

func (c changesServer) file(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	k, name := changes.Kind(q.Get("kind")), q.Get("name")
	if !k.File() {
		httpErr(w, http.StatusBadRequest, errors.New("?kind=config, zone, source or lists, and ?name=<the file>"))
		return
	}
	st, _ := changes.FileStore(c.dataDir, k)
	if err := st.Name(name); err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	v, err := c.store.Effective(k, name)
	if err != nil {
		httpErr(w, http.StatusInternalServerError, err)
		return
	}
	out := map[string]any{"kind": v.Kind, "name": v.Name, "hash": v.Hash, "exists": v.Exists, "pending": v.Pending}
	text := v.Text
	if k == changes.Config {
		text, _ = configs.Mask(text)
	}
	if v.Exists {
		out["size"] = len(v.Text)
		shown(out, text)
	}
	writeJSON(w, out)
}

func (c changesServer) discard(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	cs, _ := c.store.List()
	i := slices.IndexFunc(cs, func(ch changes.Change) bool { return ch.ID == id })
	d, err := c.store.Discard(id)
	if err != nil {
		httpErr(w, changeCode(err), err)
		return
	}
	ch := changes.Change{ID: id}
	if i >= 0 {
		ch = cs[i]
	}
	c.log(r, "change discard", ch, fmt.Sprintf("%s; discarded %s", ch.Summary, strings.Join(d.IDs, ", ")))
	for _, p := range d.PutBack {
		c.log(r, "change add", p, p.Summary)
	}
	writeJSON(w, d)
}

func (c changesServer) discardAll(w http.ResponseWriter, r *http.Request) {
	d, err := c.store.DiscardAll()
	if err != nil {
		httpErr(w, changeCode(err), err)
		return
	}
	if d.IDs == nil {
		d.IDs = []string{}
	}
	c.log(r, "change discard", changes.Change{}, fmt.Sprintf("all: %s", strings.Join(d.IDs, ", ")))
	for _, p := range d.PutBack {
		c.log(r, "change add", p, p.Summary)
	}
	writeJSON(w, d)
}

func (c changesServer) log(r *http.Request, action string, ch changes.Change, what string) {
	user := auth.User(r.Context())
	args := []string{what}
	if ch.ID != "" {
		args = []string{ch.ID, string(ch.Kind), ch.Name, what}
	}
	if err := actionlog.Append(c.dataDir, actionlog.Entry{Event: "save", ID: "change-" + time.Now().UTC().Format("20060102-150405"),
		Source: "controller", Who: user, Action: action, Args: args, Result: "ok"}); err != nil {
		log.Printf("changes: %s (%s), but not in the action log: %v", what, action, err)
	}
}

// firmwareThere refuses a firmware ("builds/<board>" or "images/<image>") that isn't in
// the data directory, read and checked as a rollout reads it.
func firmwareThere(dataDir, catalog, src string) error {
	_, spec, err := rolling.FirmwareSource(dataDir, catalog, src)
	if err != nil {
		return err
	}
	_, err = rolling.LoadFirmware([]string{spec}, "", func(string, ...any) {})
	return err
}
