package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"slices"
	"strings"

	"github.com/skitzo2000/espdns/controller/internal/auth"
	"github.com/skitzo2000/espdns/controller/internal/changes"
	"github.com/skitzo2000/espdns/controller/internal/configs"
	"github.com/skitzo2000/espdns/controller/internal/nodecfg"
	"github.com/skitzo2000/espdns/controller/internal/nodes"
	"github.com/skitzo2000/espdns/controller/internal/nodesettings"
	"github.com/skitzo2000/espdns/controller/internal/release"
	"github.com/skitzo2000/espdns/controller/internal/settings"
)

// A node's settings, as the node page's form (internal/nodesettings): read from the node's
// config file (internal/configs) as the pending changes make it, and what the node reports.
// An edit is checked as the node checks it and as a push would (the firmware it runs, its
// memory, its address), then added to the pending changes (changes.go) as a change of that
// config file, on the version the form was read from: it stacks on the changes of the file
// already pending, and the one apply job (apply.go) sends it to the node that runs it.
//
//	GET  /api/nodes/{id}/settings   the form: each field's value, where it is from and how a change
//	                                applies (live, or at a restart); the file's pending changes, if any
//	POST /api/nodes/{id}/settings   {"settings": <an edit>, "version"}: checked and added as a pending
//	                                change of the node's config file; the form again
//
// A pending change is discarded, and applied, as any other: /api/changes. {id} is the node's
// ID (its MAC, as /api/nodes has it): a change of address keeps it. Only a node in
// settings.json is changed. Every route needs a login, the read too (as the configs'); the
// Wi-Fi password is never in a reply.

type nodeSettingsServer struct {
	dataDir string
	catalog string
	nodes   func() []nodes.Node
	store   *changes.Store
	// known are the addresses of the nodes the controller knows besides settings.json's: a
	// move onto one is refused.
	known func() []string
}

func (n nodeSettingsServer) routes(mux *routes) {
	mux.HandleFunc("GET /api/nodes/{id}/settings", needLogin("a node's settings need", n.get))
	mux.HandleFunc("POST /api/nodes/{id}/settings", needLogin("a node's settings need", n.edit))
}

// statusErr is an error with its HTTP status.
type statusErr struct {
	code int
	err  error
}

func (e *statusErr) Error() string { return e.err.Error() }
func (e *statusErr) Unwrap() error { return e.err }

func fail(code int, format string, a ...any) error {
	return &statusErr{code: code, err: fmt.Errorf(format, a...)}
}

func writeErr(w http.ResponseWriter, err error) {
	var se *statusErr
	var fe *nodesettings.FieldError
	switch {
	case errors.As(err, &fe):
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error(), "field": fe.Field})
	case errors.As(err, &se):
		httpErr(w, se.code, se.err)
	default:
		httpErr(w, http.StatusInternalServerError, err)
	}
}

// nodeSettings is one node's settings as read for the form or an edit.
type nodeSettings struct {
	node  nodes.Node
	st    release.NodeStatus
	name  string // what the node is called in words: its name, else its address
	file  string // its config file's name
	saved *configs.File
	// view is the file as the pending changes make it, cfg its config (nil: no file, none
	// pending); pending the file's pending changes, oldest first.
	view    changes.View
	cfg     *nodecfg.Config
	pending []changes.Change
	// stale: the file changed since its pending changes were made on it.
	stale  error
	listed bool
}

func (s *nodeSettings) savedConfig() *nodecfg.Config {
	if s.saved == nil {
		return nil
	}
	return s.saved.Config
}

// load reads the node with the ID id, its config file and the file's pending changes.
func (n nodeSettingsServer) load(id string) (*nodeSettings, error) {
	all := n.nodes() // once: the list may change between two calls
	i := slices.IndexFunc(all, func(x nodes.Node) bool { return x.ID != "" && strings.EqualFold(x.ID, id) })
	if i < 0 {
		return nil, fail(http.StatusNotFound, "no node %s known (found over mDNS or in settings.json)", id)
	}
	s := &nodeSettings{node: all[i]}
	st, ok := status(s.node)
	if !ok {
		return nil, fail(http.StatusConflict, "%s: no /status read yet", s.node.Addr)
	}
	if st.Config == nil {
		return nil, fail(http.StatusConflict, "%s: %v: update its firmware first", s.node.Addr, configs.ErrNoConfig)
	}
	s.st, s.name = st, s.node.Addr
	if st.Config.Name != "" {
		s.name = st.Config.Name
	}
	if set, err := settings.Load(settings.Path(n.dataDir)); err == nil {
		s.listed = slices.Contains(set.Nodes, s.node.Addr)
	}
	cs, err := n.store.List()
	if err != nil {
		return nil, err
	}
	if s.file, err = n.configOf(s.node, st, cs); err != nil {
		return nil, err
	}
	f, err := configs.Read(n.dataDir, s.file)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return nil, err
	case f.Config == nil:
		return nil, fail(http.StatusConflict, "%s doesn't pass the node's checks (%s): fix it on the Configs page", s.file, f.Error)
	default:
		s.saved = &f
	}
	if s.view, err = n.store.Effective(changes.Config, s.file); err != nil {
		return nil, err
	}
	probe := changes.Change{Kind: changes.Config, Name: s.file}
	for _, c := range cs {
		if c.Same(probe) {
			s.pending = append(s.pending, c)
		}
	}
	if !s.view.Exists && s.saved != nil {
		return nil, fail(http.StatusConflict, "a pending change deletes %s: discard it first", s.file)
	}
	if s.view.Exists {
		if s.cfg, err = nodecfg.Parse(s.view.Text); err != nil {
			return nil, fail(http.StatusConflict, "%s as the pending changes make it doesn't read (%v): discard them", s.file, err)
		}
	}
	saved := ""
	if s.saved != nil {
		saved = s.saved.Hash
	}
	if len(s.pending) > 0 && !s.pending[0].Written && s.pending[0].Base != saved {
		s.stale = fail(http.StatusConflict, "%s changed since its pending changes were made: discard them, then edit again", s.file)
	}
	return s, nil
}

// configOf is the node's config file: the one file (as it is, or as the pending changes
// make it) the apply sends to it (configNodes: by its name or address, or the node it was
// last pushed to, still on that push). With none, a new file named for the node, unless it
// runs a pushed config this controller has no record of (a new file would drop what that
// one sets).
func (n nodeSettingsServer) configOf(node nodes.Node, st release.NodeStatus, cs []changes.Change) (string, error) {
	files, err := configs.List(n.dataDir)
	if err != nil {
		return "", err
	}
	texts := map[string][][]byte{}
	var names []string
	for _, f := range files {
		names = append(names, f.Name)
		if f.Config != nil {
			texts[f.Name] = append(texts[f.Name], f.Text)
		}
	}
	for _, c := range cs {
		if c.Kind == changes.Config && !slices.Contains(names, c.Name) {
			names = append(names, c.Name)
		}
	}
	host := []string{node.Addr}
	sts := map[string]release.NodeStatus{node.Addr: st}
	var match []string
	for _, name := range names {
		v, err := n.store.Effective(changes.Config, name)
		if err != nil {
			return "", err
		}
		if len(v.Pending) > 0 {
			if v.Exists {
				texts[name] = append(texts[name], v.Text)
			}
			// As it was before an apply that stopped wrote it, as the apply matches it.
			texts[name] = append(texts[name], n.store.Base(v.Pending[0]))
		}
		if len(configNodes(n.dataDir, name, texts[name], host, sts)) > 0 {
			match = append(match, name)
		}
	}
	switch {
	case len(match) == 1:
		return match[0], nil
	case len(match) > 1:
		return "", fail(http.StatusConflict, "%s is the node of several configs (%s): keep one on the Configs page",
			node.Addr, strings.Join(match, ", "))
	case st.Config.Source == "node":
		return "", fail(http.StatusConflict, "%s runs a pushed config (seq %d) with no file here: save it as its config "+
			"on the Configs page first, so a change keeps what it sets", node.Addr, st.Config.Seq)
	}
	// A new file, named for the node.
	for _, name := range []string{strings.ToLower(st.Config.Name) + ".json", "node-" + strings.ReplaceAll(strings.ToLower(st.NodeID), ":", "") + ".json"} {
		if configs.CheckName(name) == nil && !slices.Contains(names, name) {
			return name, nil
		}
	}
	return "", fail(http.StatusConflict, "%s: no config file, and none free to name for it", node.Addr)
}

// pendingView is the file's pending changes as the page sees them: never their text.
type pendingView struct {
	// Changes are the pending changes of the file, oldest first (/api/changes discards them).
	Changes []changes.Change `json:"changes"`
	// Settings are the form as they make it; Fields the fields they change from the file as
	// it is; Change, Restart and Effect what applying them does on the node.
	Settings nodesettings.Form `json:"settings"`
	Fields   []string          `json:"fields"`
	Change   nodecfg.Change    `json:"change"`
	Restart  string            `json:"restart"`
	Effect   string            `json:"effect"`
}

type settingsReply struct {
	Node struct {
		ID     string `json:"id"`
		Host   string `json:"host"`
		Name   string `json:"name"`
		Online bool   `json:"online"`
		// MAC is the MAC of the interface it uses (release.MAC; "" until it reports one):
		// what a DHCP reservation goes by, next to the address set here.
		MAC string `json:"mac,omitempty"`
		// Listed: in settings.json, so a change can be made and applied.
		Listed bool `json:"listed"`
	} `json:"node"`
	Config struct {
		File   string          `json:"file"`
		Exists bool            `json:"exists"` // the file is in the data directory now
		Runs   configs.Running `json:"runs"`
	} `json:"config"`
	// Version names what an edit builds on (the file as the pending changes make it): an
	// edit gives it back.
	Version string `json:"version"`
	// Settings are the form as the file is now; Pending, the pending changes of it.
	Settings        nodesettings.Form   `json:"settings"`
	Pending         *pendingView        `json:"pending"`
	TimeZones       []nodesettings.Zone `json:"time_zones"`
	QueryLogClients []string            `json:"querylog_clients"`
}

func (n nodeSettingsServer) reply(s *nodeSettings) settingsReply {
	var r settingsReply
	r.Node.ID, r.Node.Host, r.Node.Name, r.Node.Online, r.Node.Listed = s.node.ID, s.node.Addr, s.name, s.node.Online, s.listed
	r.Node.MAC = release.MAC(s.st.Net.MAC)
	r.Config.File, r.Config.Exists = s.file, s.saved != nil
	runs := configs.NodeRuns(n.dataDir, s.file, s.saved, s.st)
	r.Config.Runs = runs
	r.Version = s.view.Hash
	r.Settings = nodesettings.Read(s.savedConfig(), &s.st)
	if len(s.pending) > 0 {
		v := &pendingView{Changes: s.pending, Fields: nodesettings.Changed(s.savedConfig(), s.cfg)}
		if s.cfg != nil {
			v.Settings = nodesettings.Read(s.cfg, &s.st)
			from := runs.Config
			if runs.Assumed {
				// What a node without a record runs is taken to be the file (as /api/changes
				// takes it): as it was before an apply that stopped wrote it, if one did.
				from = nil
				if f := assumedFile(n.dataDir, n.store, s.pending, s.file); f != nil {
					from = f.Config
				}
			}
			v.Change = nodecfg.Compare(from, s.cfg, configs.RunningNetwork(s.st))
			v.Restart, v.Effect = nodesettings.Restart(v.Change), nodesettings.Effect(s.name, v.Change)
		}
		r.Pending = v
	}
	r.TimeZones, r.QueryLogClients = nodesettings.TimeZones, nodecfg.QueryLogClients
	return r
}

func (n nodeSettingsServer) get(w http.ResponseWriter, r *http.Request) {
	s, err := n.load(r.PathValue("id"))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, n.reply(s))
}

func (n nodeSettingsServer) edit(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Settings nodesettings.Edit `json:"settings"`
		Version  string            `json:"version"`
	}
	if err := body(w, r, &req); err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	id := r.PathValue("id")
	s, err := n.load(id)
	if err == nil {
		var ch changes.Change
		if ch, err = n.add(s, req.Settings, req.Version, auth.User(r.Context())); err == nil {
			changesServer{dataDir: n.dataDir}.log(r, "change add", ch, ch.Summary)
			s, err = n.load(id)
		}
	}
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, n.reply(s))
}

// add makes the edit into the node's config as the pending changes make it, checks it, and
// adds it to the pending changes as a change of the node's config file, on version.
func (n nodeSettingsServer) add(s *nodeSettings, e nodesettings.Edit, version, who string) (changes.Change, error) {
	if !s.listed {
		return changes.Change{}, fail(http.StatusBadRequest, "%s is not in settings.json: only the nodes listed there are changed", s.node.Addr)
	}
	if s.stale != nil {
		return changes.Change{}, s.stale
	}
	if version != s.view.Hash {
		return changes.Change{}, fail(http.StatusConflict, "%s's settings changed since the form was read: read them again", s.name)
	}
	base := s.cfg
	if base == nil {
		// A new file: it names the node as it is called, so the apply finds it.
		base = &nodecfg.Config{Name: s.st.Config.Name}
	}
	cfg, err := nodesettings.Apply(base, e)
	if err != nil {
		var fe *nodesettings.FieldError
		if errors.As(err, &fe) {
			return changes.Change{}, err
		}
		return changes.Change{}, &statusErr{code: http.StatusBadRequest, err: err}
	}
	if e.Name != nil {
		if err := n.nameFree(s, cfg.Name); err != nil {
			return changes.Change{}, &nodesettings.FieldError{Field: "name", Err: err}
		}
	}
	text, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return changes.Change{}, err
	}
	text = append(text, '\n')

	// As a push checks it: the firmware it runs, its memory, a hosted zone, its address.
	spec, err := configs.ParseSpec(s.node.Addr, s.file, text)
	if err != nil {
		return changes.Change{}, &statusErr{code: http.StatusBadRequest, err: err}
	}
	if err := spec.Refusal(s.st, n.catalog); err != nil {
		return changes.Change{}, &statusErr{code: http.StatusBadRequest, err: err}
	}
	set, err := settings.Load(settings.Path(n.dataDir))
	if err != nil {
		return changes.Change{}, err
	}
	var known []string
	if n.known != nil {
		known = n.known()
	}
	if err := spec.AddressRefusal(configs.Addressing{Settings: set, Known: known}, &s.st); err != nil {
		return changes.Change{}, &nodesettings.FieldError{Field: "network", Err: err}
	}
	// The apply's config rollout refuses a config that moves its node (configs.Payloads),
	// and would stop with the file written: a move goes through the Configs page's push,
	// which confirms the node on its new address.
	if a, ok := spec.Moves(); ok {
		return changes.Change{}, &nodesettings.FieldError{Field: "network", Err: fmt.Errorf("network: this moves %s to %s, "+
			"which an apply doesn't do: push it from the Configs page, which confirms the node on its new address", s.node.Addr, a)}
	}

	fields := nodesettings.Changed(base, cfg)
	if len(fields) == 0 {
		return changes.Change{}, &statusErr{code: http.StatusBadRequest, err: changes.ErrNoChange}
	}
	// The apply sends a config to the nodes it finds by the config's name or address, as
	// the file becomes, as it is, or as it was before an apply that stopped wrote it: this
	// node, and no other of settings.json's.
	texts := [][]byte{text}
	if s.saved != nil {
		texts = append(texts, s.saved.Text)
	}
	if len(s.pending) > 0 {
		texts = append(texts, n.store.Base(s.pending[0].ID))
	}
	sts := map[string]release.NodeStatus{s.node.Addr: s.st}
	for _, o := range n.nodes() {
		if o.Addr != s.node.Addr && slices.Contains(set.Nodes, o.Addr) {
			if st, ok := status(o); ok {
				sts[o.Addr] = st
			}
		}
	}
	to := configNodes(n.dataDir, s.file, texts, set.Nodes, sts)
	if !slices.Contains(to, s.node.Addr) {
		return changes.Change{}, fail(http.StatusBadRequest, "the apply wouldn't find %s by this config: it has no config file "+
			"yet, and the config has neither the name nor the address it runs on. Change its name and its address in separate applies", s.name)
	}
	if others := slices.DeleteFunc(to, func(h string) bool { return h == s.node.Addr }); len(others) > 0 {
		return changes.Change{}, fail(http.StatusConflict, "the apply would send %s's config to %s too (the same name, or address): "+
			"give each node its own name first (the Configs page)", s.name, strings.Join(others, ", "))
	}
	ch, err := n.store.Add(changes.Edit{Kind: changes.Config, Name: s.file, Text: text, Hash: version,
		Summary: nodesettings.Summary(s.name, fields), Who: who})
	if err != nil {
		return changes.Change{}, &statusErr{code: changeCode(err), err: err}
	}
	return ch, nil
}

// nameFree refuses a name another node reports, or another config has: a config is
// matched to its node by name (configs.Matches).
func (n nodeSettingsServer) nameFree(s *nodeSettings, name string) error {
	for _, o := range n.nodes() {
		if strings.EqualFold(o.ID, s.node.ID) {
			continue
		}
		if st, ok := status(o); ok && st.Config != nil && st.Config.Name == name {
			return fmt.Errorf("name: %s is called %s already", o.Addr, name)
		}
	}
	files, err := configs.List(n.dataDir)
	if err != nil {
		return err
	}
	for _, f := range files {
		if f.Name != s.file && f.Config != nil && f.Config.Name == name {
			return fmt.Errorf("name: the config %s has the name %s already", f.Name, name)
		}
	}
	// And as the pending changes make them: another node's rename, or a new file.
	cs, err := n.store.List()
	if err != nil {
		return err
	}
	for _, c := range cs {
		if c.Kind != changes.Config || c.Name == s.file {
			continue
		}
		v, err := n.store.Effective(changes.Config, c.Name)
		if err != nil || !v.Exists {
			continue
		}
		if cfg, err := nodecfg.Parse(v.Text); err == nil && cfg.Name == name {
			return fmt.Errorf("name: the config %s, as its pending changes make it, has the name %s already", c.Name, name)
		}
	}
	return nil
}
