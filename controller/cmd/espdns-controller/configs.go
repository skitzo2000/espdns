package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/actionlog"
	"github.com/skitzo2000/espdns/controller/internal/auth"
	"github.com/skitzo2000/espdns/controller/internal/configs"
	"github.com/skitzo2000/espdns/controller/internal/fleet"
	"github.com/skitzo2000/espdns/controller/internal/jobs"
	"github.com/skitzo2000/espdns/controller/internal/keys"
	"github.com/skitzo2000/espdns/controller/internal/nodecfg"
	"github.com/skitzo2000/espdns/controller/internal/nodes"
	"github.com/skitzo2000/espdns/controller/internal/pins"
	"github.com/skitzo2000/espdns/controller/internal/release"
	"github.com/skitzo2000/espdns/controller/internal/settings"
)

// The node configs (internal/configs: files in <data>/configs), for the editor page:
//
//	GET  /api/configs                    every config, and the nodes that run each
//	GET  /api/configs/{name}             one: its text (the Wi-Fi password hidden; ?reveal=1 shows it,
//	                                      with a grant of the password again in X-Reauth), its history
//	POST /api/configs/{name}/check       {"text", "board", "node"}: the checks (internal/configs, Check), never saved
//	POST /api/configs/{name}             {"text", "hash"} saves it (hash: the version edited; "" for a new file)
//
// Every one needs a login, the reads too (a config can hold a Wi-Fi password), even before
// a password is set (when the rest is read-only and open). The password is never in a
// reply but the reveal, nor in the action log: where the text still has configs.Hidden, a
// check or save puts the saved password back. A save is in the action log (which settings
// it changed, by name).
//
// A push is a job (POST /api/jobs, kind "config-push"), below.

// configsServer is what the config routes need.
type configsServer struct {
	dataDir string
	catalog string
	nodes   func() []nodes.Node
	auth    *auth.Auth // a reveal needs the password again (TakeReauth)
}

func (c configsServer) routes(mux *routes) {
	mux.HandleFunc("GET /api/configs", c.needLogin(c.list))
	mux.HandleFunc("GET /api/configs/{name}", c.needLogin(c.get))
	mux.HandleFunc("POST /api/configs/{name}/check", c.needLogin(c.check))
	mux.HandleFunc("POST /api/configs/{name}", c.needLogin(c.save))
}

func httpErr(w http.ResponseWriter, code int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

// needLogin refuses a request without a logged-in user: the configs are never open, not
// even while the controller is read-only for want of a password. The POSTs also take only
// JSON (jobs.Local), as the jobs' do.
func (c configsServer) needLogin(h http.HandlerFunc) http.HandlerFunc {
	return needLogin("the node configs need", h)
}

// needLogin refuses a request without a logged-in user, saying what needs one; a POST
// also takes only JSON (jobs.Local).
func needLogin(what string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if auth.User(r.Context()) == "" {
			httpErr(w, http.StatusForbidden, fmt.Errorf("read-only: %s a login, and no password is set "+
				"(espdns passwd: docs/getting-started.md, step 6)", what))
			return
		}
		if r.Method != http.MethodGet {
			if err := jobs.Local(r); err != nil {
				httpErr(w, http.StatusForbidden, err)
				return
			}
		}
		h(w, r)
	}
}

// status is a node's last /status as the fleet code reads it.
func status(n nodes.Node) (release.NodeStatus, bool) {
	var st release.NodeStatus
	if n.Status == nil {
		return st, false
	}
	b, err := json.Marshal(n.Status)
	if err != nil || json.Unmarshal(b, &st) != nil {
		return st, false
	}
	return st, true
}

// configNode is a node as the config list shows it.
type configNode struct {
	Host    string           `json:"host"`
	NodeID  string           `json:"node_id"`
	Name    string           `json:"name"` // the config name it reports
	Online  bool             `json:"online"`
	Listed  bool             `json:"listed"` // in settings.json: a push is offered
	Runs    *configs.Running `json:"runs,omitempty"`
	Board   string           `json:"board,omitempty"`
	Reboot  []string         `json:"reboot,omitempty"`
	Config  *string          `json:"config,omitempty"` // the file it matches, if any
	Seq     uint64           `json:"seq"`
	Address string           `json:"address,omitempty"`
}

type configEntry struct {
	configs.File
	ConfigName string       `json:"config_name"`
	Address    string       `json:"address,omitempty"`
	Services   []string     `json:"services,omitempty"`
	Password   bool         `json:"password"` // it holds a Wi-Fi password (hidden)
	Nodes      []configNode `json:"nodes"`
	// AtAddress are the nodes on the config's static address that report another name:
	// none of them runs it, and a push of it there would rename the node.
	AtAddress []configNode `json:"at_address,omitempty"`
}

func (c configsServer) listed() []string {
	s, err := settings.Load(settings.Path(c.dataDir))
	if err != nil {
		return nil
	}
	return s.Nodes
}

func (c configsServer) list(w http.ResponseWriter, r *http.Request) {
	files, err := configs.List(c.dataDir)
	if err != nil {
		httpErr(w, http.StatusInternalServerError, err)
		return
	}
	listed := c.listed()
	ns := c.nodes()
	out := struct {
		Dir     string        `json:"dir"`
		Configs []configEntry `json:"configs"`
		Nodes   []configNode  `json:"nodes"`
	}{Dir: configs.Path(c.dataDir), Configs: []configEntry{}, Nodes: []configNode{}}
	for _, f := range files {
		e := configEntry{File: f, Nodes: []configNode{}}
		_, e.Password = configs.Mask(f.Text)
		if f.Config != nil {
			e.ConfigName, e.Services = f.Config.Name, f.Config.Services()
			if f.Config.Network != nil {
				e.Address = f.Config.Network.Address
			}
		}
		out.Configs = append(out.Configs, e)
	}
	for _, n := range ns {
		cn := configNode{Host: n.Addr, NodeID: n.ID, Online: n.Online, Listed: slices.Contains(listed, n.Addr)}
		st, ok := status(n)
		if ok {
			cn.Board = st.Board
			if st.Config != nil {
				cn.Name, cn.Seq, cn.Address = st.Config.Name, st.Config.Seq, st.Config.IP
			}
			if st.Reboot != nil && st.Reboot.Pending {
				cn.Reboot = st.Reboot.Reasons
			}
		}
		for i := range out.Configs {
			f := &out.Configs[i]
			if !ok {
				continue
			}
			if !configs.Matches(f.Config, n.Addr, st) && !pushedHere(c.dataDir, st, f.Name) {
				if configs.AtAddress(f.Config, n.Addr, st) {
					f.AtAddress = append(f.AtAddress, cn)
				}
				continue
			}
			m := cn
			runs := configs.NodeRuns(c.dataDir, f.Name, &f.File, st)
			m.Runs = &runs
			f.Nodes = append(f.Nodes, m)
			if cn.Config == nil {
				name := f.Name
				cn.Config = &name
			}
		}
		out.Nodes = append(out.Nodes, cn)
	}
	writeJSON(w, out)
}

// pushedHere says whether the config last pushed to the node, and still its seq, is name.
func pushedHere(dataDir string, st release.NodeStatus, name string) bool {
	if st.Config == nil || st.NodeID == "" {
		return false
	}
	p, err := configs.LoadPushed(dataDir, st.NodeID)
	return err == nil && p != nil && p.Seq == st.Config.Seq && p.File == name
}

func (c configsServer) get(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	f, err := configs.Read(c.dataDir, name)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		httpErr(w, http.StatusNotFound, fmt.Errorf("no config %s in %s", name, configs.Path(c.dataDir)))
		return
	case err != nil:
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	reveal := r.URL.Query().Get("reveal") == "1"
	if reveal && !c.auth.TakeReauth(w, r) { // the password again: a session taken over can't read it
		return
	}
	text, hidden := configs.Mask(f.Text)
	if reveal {
		text = f.Text
		log.Printf("configs: %s shown with its Wi-Fi password to %s", name, auth.User(r.Context()))
	}
	h, _ := configs.History(c.dataDir, name)
	if h == nil {
		h = []configs.Version{}
	}
	writeJSON(w, map[string]any{"name": f.Name, "text": string(text), "hash": f.Hash, "modified": f.Modified,
		"error": f.Error, "password": hidden, "revealed": hidden && reveal, "history": h})
}

// body reads a JSON request body into v (unknown fields refused).
func body(w http.ResponseWriter, r *http.Request, v any) error {
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2*configs.MaxFile))
	d.DisallowUnknownFields()
	return d.Decode(v)
}

// saved is the config as saved, nil if there is none yet.
func (c configsServer) saved(name string) (*configs.File, error) {
	f, err := configs.Read(c.dataDir, name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &f, nil
}

func (c configsServer) check(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var req struct {
		Text  string `json:"text"`
		Board string `json:"board"`
		Node  string `json:"node"`
	}
	if err := body(w, r, &req); err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	if err := configs.CheckName(name); err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	saved, err := c.saved(name)
	if err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	var savedText []byte
	if saved != nil {
		savedText = saved.Text
	}
	text, err := configs.Unmask([]byte(req.Text), savedText)
	if err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	ck := configs.Check{Name: name, Text: text, Saved: saved, Catalog: c.catalog, Board: req.Board, DataDir: c.dataDir}
	if req.Node != "" {
		i := slices.IndexFunc(c.nodes(), func(n nodes.Node) bool { return n.Addr == req.Node })
		if i < 0 {
			httpErr(w, http.StatusBadRequest, fmt.Errorf("%s is not a node the controller knows", req.Node))
			return
		}
		// Its /status now (a push may have just changed it), else the node list's last.
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		st, err := (&fleet.Client{}).Status(ctx, req.Node)
		cancel()
		ok := err == nil
		if !ok {
			st, ok = status(c.nodes()[i])
		}
		if !ok {
			httpErr(w, http.StatusBadRequest, fmt.Errorf("%s: no /status read yet", req.Node))
			return
		}
		ck.Host, ck.Status = req.Node, &st
		// Its address as a push checks it: no DHCP on a no_dhcp network, a move only onto
		// a free address (asking the network, as adoption does).
		s, err := settings.Load(settings.Path(c.dataDir))
		if err != nil {
			httpErr(w, http.StatusInternalServerError, err)
			return
		}
		var known []string
		for _, n := range c.nodes() {
			known = append(known, n.Addr)
		}
		ck.Addressing = &configs.Addressing{Settings: s, Known: known, Free: func(addr string) error {
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()
			return (&fleet.Client{}).AddressFree(ctx, addr, st.NodeID, st.Net.MAC)
		}}
	}
	writeJSON(w, ck.Run())
}

func (c configsServer) save(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var req struct {
		Text string `json:"text"`
		Hash string `json:"hash"`
	}
	if err := body(w, r, &req); err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	if err := configs.CheckName(name); err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	saved, err := c.saved(name)
	if err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	var savedText []byte
	var old *nodecfg.Config
	if saved != nil {
		savedText, old = saved.Text, saved.Config
	}
	text, err := configs.Unmask([]byte(req.Text), savedText)
	if err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	f, err := configs.Save(c.dataDir, name, text, req.Hash)
	switch {
	case errors.Is(err, configs.ErrChanged):
		httpErr(w, http.StatusConflict, err)
		return
	case err != nil:
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	changed := configs.ChangedKeys(old, f.Config)
	what := "changed: " + strings.Join(changed, ", ")
	switch {
	case saved == nil:
		what = "new"
	case len(changed) == 0:
		what = "same settings, text changed"
	}
	user := auth.User(r.Context())
	if err := actionlog.Append(c.dataDir, actionlog.Entry{Event: "save", ID: "config-" + time.Now().UTC().Format("20060102-150405"),
		Source: "controller", Who: user, Action: "config save", Args: []string{name, what}, Result: "ok"}); err != nil {
		log.Printf("configs: %s saved, but not in the action log: %v", name, err)
	}
	log.Printf("configs: %s saved by %s (%s)", name, user, what)
	masked, _ := configs.Mask(f.Text)
	writeJSON(w, map[string]any{"name": f.Name, "text": string(masked), "hash": f.Hash, "modified": f.Modified, "changed": changed})
}

// ---- the push ----------------------------------------------------------------------

// configPush is the job kind "config-push": one node's config, from <data>/configs, pushed
// as make fleet-rollout KIND=config CONFIGS="<node>=<file>" does (internal/fleet, Rollout:
// the rule before the node is touched, the push, a coordinated reboot if the node waits for
// one, the checks after), with the same refusals (internal/configs). A config that moves the
// node to another address goes as espdns config -reboot does it: pushed, the node rebooted
// once another node or a DNS peer answers, and confirmed on its new address before its
// trial ends (fleet.ConfirmConfig); settings.json then still lists the old address.
//
//	{"node": "192.0.2.52", "config": "node2.json", "dry_run": true}
//	{"node": "192.0.2.52", "config": "node2.json", "after": "<the dry run's job ID>"}
//
// Only for a node in settings.json. A push must name a dry run of the same node and file
// that passed in the last 15 minutes, of the file as it still is: the page shows the dry
// run's log and asks before it pushes.
type configPush struct {
	actions
	catalog string
	// job is the runner's job of an ID (the dry run a push names).
	job func(id string) (jobs.Job, bool)
	// secret keys the dry run's fingerprint of what it checked (node, file and payload), so a
	// job record has no hash of a config's password; new at every start of the controller.
	secret []byte
}

// dryRunValid is how long a dry run stands for the push after it.
const dryRunValid = 15 * time.Minute

type pushParams struct {
	Node   string `json:"node"`
	Config string `json:"config"`
	DryRun bool   `json:"dry_run,omitempty"`
	After  string `json:"after,omitempty"`
}

type pushResult struct {
	Node        string         `json:"node"`
	Config      string         `json:"config"`
	DryRun      bool           `json:"dry_run"`
	Fingerprint string         `json:"fingerprint"`
	Change      nodecfg.Change `json:"change"`
	Moves       string         `json:"moves,omitempty"`
	Seq         uint64         `json:"seq,omitempty"`
	Done        bool           `json:"done"`
}

func newSecret() []byte {
	b := make([]byte, 32)
	rand.Read(b)
	return b
}

func (p configPush) fingerprint(node, name string, payload []byte) string {
	m := hmac.New(sha256.New, p.secret)
	m.Write([]byte(node + "\x00" + name + "\x00"))
	m.Write(payload)
	return hex.EncodeToString(m.Sum(nil))
}

// load reads the config for the node, checked as the node checks it.
func (p configPush) load(pp pushParams) (configs.Spec, error) {
	f, err := configs.Read(p.dataDir, pp.Config)
	if err != nil {
		return configs.Spec{}, err
	}
	return configs.ParseSpec(pp.Node, f.Name, f.Text)
}

func (p configPush) kind(raw json.RawMessage) (jobs.Func, error) {
	var pp pushParams
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&pp); err != nil {
		return nil, fmt.Errorf("params: %v", err)
	}
	if pp.Node == "" || pp.Config == "" {
		return nil, errors.New(`params: need "node" (the node's address) and "config" (the file name)`)
	}
	s, err := settings.Load(settings.Path(p.dataDir))
	if err != nil {
		return nil, err
	}
	if !slices.Contains(s.Nodes, pp.Node) {
		return nil, fmt.Errorf("%s is not in settings.json: configs are pushed only to the nodes listed there", pp.Node)
	}
	spec, err := p.load(pp)
	if err != nil {
		return nil, err
	}
	// Its address, from what is known here (the network is asked when the job runs).
	if err := spec.AddressRefusal(configs.Addressing{Settings: s, Known: p.known()}, nil); err != nil {
		return nil, err
	}
	if pp.DryRun {
		if pp.After != "" {
			return nil, errors.New(`params: "after" is for the push after a dry run`)
		}
	} else {
		if _, err := p.signer(); err != nil {
			return nil, err
		}
		if err := p.dryRunFor(pp, spec); err != nil {
			return nil, err
		}
	}
	return func(ctx context.Context, run *jobs.Run) (any, error) { return p.run(ctx, run, pp) }, nil
}

// hostOf is an address without its port.
func hostOf(a string) string {
	if h, _, err := net.SplitHostPort(a); err == nil {
		return h
	}
	return a
}

// dryRunFor checks that pp.After is a dry run that passed for this node and this file as
// it is now, not long ago.
func (p configPush) dryRunFor(pp pushParams, spec configs.Spec) error {
	if pp.After == "" {
		return errors.New(`a push needs a dry run first: run it with "dry_run": true, then push with "after": its job ID`)
	}
	j, ok := p.job(pp.After)
	var res pushResult
	switch {
	case !ok || j.Kind != "config-push":
		return fmt.Errorf("no config-push dry run %s", pp.After)
	case j.State != jobs.Done:
		return fmt.Errorf("the dry run %s didn't pass (%s): fix what it says and run it again", pp.After, j.State)
	case json.Unmarshal(j.Result, &res) != nil || !res.DryRun:
		return fmt.Errorf("%s is not a dry run", pp.After)
	case res.Node != pp.Node || res.Config != pp.Config:
		return fmt.Errorf("the dry run %s was for %s on %s, not %s on %s", pp.After, res.Config, res.Node, pp.Config, pp.Node)
	case time.Since(j.Ended) > dryRunValid:
		return fmt.Errorf("the dry run %s is over %v old: run it again", pp.After, dryRunValid)
	case !hmac.Equal([]byte(res.Fingerprint), []byte(p.fingerprint(pp.Node, pp.Config, spec.Payload))):
		return fmt.Errorf("%s changed since the dry run %s (or the controller restarted): run it again", pp.Config, pp.After)
	}
	return nil
}

func (p configPush) run(ctx context.Context, run *jobs.Run, pp pushParams) (any, error) {
	host := pp.Node
	// Read again: the file, the settings and the key as they are now.
	spec, err := p.load(pp)
	if err != nil {
		return nil, err
	}
	res := pushResult{Node: host, Config: pp.Config, DryRun: pp.DryRun, Fingerprint: p.fingerprint(host, pp.Config, spec.Payload)}
	if !pp.DryRun {
		if err := p.dryRunFor(pp, spec); err != nil {
			return nil, err
		}
	}
	s, err := settings.Load(settings.Path(p.dataDir))
	if err != nil {
		return nil, err
	}
	if !slices.Contains(s.Nodes, host) {
		return nil, fmt.Errorf("%s is no longer in settings.json: not pushed", host)
	}
	c := p.client()
	c.Logf = run.Logf
	if k, err := p.signer(); err == nil {
		c.Pusher = &release.Pusher{Key: k, KeyID: release.KeyRelease, Pins: pins.Open(p.dataDir), Client: c.HTTP}
		run.Logf("signing with the release key %s", keys.Fingerprint(k))
	} else if !pp.DryRun {
		return nil, err
	} else {
		run.Logf("%v: a dry run goes on without it", err)
	}
	st, err := c.Status(ctx, host)
	if err != nil {
		return nil, err
	}
	// Its address (internal/configs, AddressRefusal): no DHCP on a no_dhcp network; a move
	// onto no address another node or a DNS peer is known by, nor one something answers on
	// (adoption's check, fleet.Client.AddressFree), the wrong node's config picked by mistake
	// putting two hosts on one address.
	if err := spec.AddressRefusal(configs.Addressing{Settings: s, Known: p.known(), Free: func(addr string) error {
		return c.AddressFree(ctx, addr, st.NodeID, st.Net.MAC)
	}}, &st); err != nil {
		return nil, err
	}
	run.Logf("%s: %s, %d bytes, services: %s", pp.Config, map[bool]string{true: "dry run", false: "pushing"}[pp.DryRun],
		len(spec.Payload), strings.Join(spec.Config.Services(), ", "))

	// What it does there: live, or with a reboot, from what the node runs.
	f, _ := configs.Read(p.dataDir, pp.Config)
	runs := configs.NodeRuns(p.dataDir, pp.Config, &f, st)
	run.Logf("%s %s", host, runs.Text)
	res.Change = nodecfg.Compare(runs.Config, spec.Config, configs.RunningNetwork(st))
	logChange(run, host, res.Change, runs)

	plan := fleet.Plan{Targets: []string{host}, Checks: fleet.Checks{Forwarded: []string{"example.com"}}, DryRun: pp.DryRun, Stop: run.Stop()}
	for _, d := range s.DNSPeers {
		plan.DNSPeers = append(plan.DNSPeers, fleet.DNSPeer{Addr: d, Zones: s.DNSPeerZones})
	}
	if len(s.DNSPeers) > 0 {
		run.Logf("DNS peers: %s", strings.Join(s.DNSPeers, ", "))
	}
	ns, err := c.Discover(ctx, 0, s.Nodes)
	if err != nil {
		return nil, err
	}
	c.Count(ctx, &plan, ns, nil)

	if a, ok := spec.Moves(); ok {
		res.Moves = a.String()
		return p.move(ctx, run, c, plan, spec, st, res)
	}
	payloads, err := configs.Payloads([]configs.Spec{spec}, []string{host}, p.catalog)
	if err != nil {
		return nil, err
	}
	r, err := c.Rollout(ctx, plan, fleet.Change{Kind: release.Config, Payload: payloads})
	if err != nil {
		if errors.Is(err, fleet.ErrSingle) {
			err = fmt.Errorf("%w (add the other nodes or a DNS peer to settings.json; the CLI's -allow-single is not offered here)", err)
		}
		return nil, err
	}
	if pp.DryRun {
		run.Logf("dry run passed: nothing was pushed")
		return res, nil
	}
	res.Done = slices.Contains(r.Done, host)
	p.record(ctx, run, c, host, pp.Config, spec.Payload, &res)
	return res, nil
}

// logChange says in the job's log what the config changes on the node.
func logChange(run *jobs.Run, host string, ch nodecfg.Change, runs configs.Running) {
	if runs.Assumed {
		run.Logf("compared with the file as saved (what the node runs isn't recorded here)")
	}
	if len(ch.Live) > 0 {
		run.Logf("applies live: %s", strings.Join(ch.Live, ", "))
	}
	switch {
	case len(ch.Reboot) > 0:
		run.Logf("needs a reboot: %s (the node waits for it; it is rebooted coordinated, only while another node or a DNS peer answers)",
			strings.Join(ch.Reboot, ", "))
	case len(ch.Maybe) > 0:
		run.Logf("may need a reboot: %s (unless the board's or firmware's value is the same; the node says, and is then rebooted coordinated)",
			strings.Join(ch.Maybe, ", "))
	case len(ch.Live) == 0 && runs.Config != nil && !runs.Assumed:
		run.Logf("%s runs these settings already", host)
	}
}

// record keeps the config as the one the node runs, at the seq its /status says.
func (p configPush) record(ctx context.Context, run *jobs.Run, c *fleet.Client, host, name string, payload []byte, res *pushResult) {
	st, err := c.Status(ctx, host)
	if err == nil && st.Config == nil {
		err = configs.ErrNoConfig
	}
	if err == nil {
		res.Seq = st.Config.Seq
		err = configs.RecordPushed(p.dataDir, configs.Pushed{NodeID: st.NodeID, Host: host, File: name, Seq: st.Config.Seq,
			Payload: payload, By: "controller"})
	}
	if err != nil {
		run.Logf("%s: not recorded as the config it runs: %v", host, err)
	}
}

// move pushes a config that moves the node to another static address, as espdns config
// -reboot does: the rule first, the push, the node rebooted (coordinated) onto its new
// address, where it comes up on trial and is confirmed by being reached there.
func (p configPush) move(ctx context.Context, run *jobs.Run, c *fleet.Client, plan fleet.Plan, spec configs.Spec,
	before release.NodeStatus, res pushResult) (any, error) {
	host, to := spec.Host, res.Moves
	run.Logf("%s moves %s to %s: the node is rebooted onto it (coordinated) and comes up on trial; it keeps the config only "+
		"once reached there within %v", spec.Path, host, to, fleet.TrialWindow)
	if err := spec.Refusal(before, p.catalog); err != nil {
		return nil, fmt.Errorf("%s: %w", host, err)
	}
	if plan.DryRun {
		if err := c.RebootNow(ctx, plan, host, true); err != nil {
			return nil, err
		}
		run.Logf("dry run passed: nothing was pushed; settings.json lists %s, which the push leaves for you to change to %s", host, to)
		return res, nil
	}
	// The rule before anything is pushed, as a rollout checks it.
	check := plan
	check.DryRun = true
	if err := c.RebootNow(ctx, check, host, true); err != nil {
		return nil, err
	}
	r, err := c.Pusher.PushRelease(ctx, host, release.Config, spec.Payload)
	if err != nil {
		return nil, err
	}
	run.Logf("%s: %s", host, r.Reply)
	pending, reasons := c.RebootPending(ctx, host, r.Node)
	trial := configs.OnTrial(r.Node, pending, reasons, spec.Config, host)
	if pending {
		run.Logf("%s waits for a reboot (%s)", host, strings.Join(reasons, ", "))
		if !trial {
			if err := c.Reboot(ctx, plan, host, true); err != nil {
				return nil, err
			}
		} else if err := c.RebootNow(ctx, plan, host, true); err != nil {
			return nil, err
		}
	}
	if trial {
		run.Logf("waiting for %s on %s ...", host, to)
		locate := func(context.Context) []string { return []string{to} }
		st, at, err := c.ConfirmConfig(ctx, locate, r.Before.NodeID, r.Seq, fleet.TrialWindow+30*time.Second)
		if err != nil {
			return nil, err
		}
		run.Logf("%s: config seq %d confirmed (%s address)", at, st.Seq, st.Address)
		host = at
	}
	res.Done = true
	p.record(ctx, run, c, host, res.Config, spec.Payload, &res)
	run.Logf("settings.json still lists %s: change it to %s (the controller doesn't edit settings.json)", spec.Host, to)
	return res, nil
}
