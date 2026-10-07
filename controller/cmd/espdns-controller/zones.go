package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/actionlog"
	"github.com/skitzo2000/espdns/controller/internal/auth"
	"github.com/skitzo2000/espdns/controller/internal/nodes"
	"github.com/skitzo2000/espdns/controller/internal/release"
	"github.com/skitzo2000/espdns/controller/internal/settings"
	"github.com/skitzo2000/espdns/controller/internal/zonefiles"
	"github.com/skitzo2000/espdns/controller/internal/zones"
)

// The hosted zones (internal/zonefiles: files in <data>/zones), for the zone editor page:
//
//	GET  /api/zones                   every zone file, the nodes serving each, the nodes, the deleted
//	GET  /api/zones/{name}            one: its text, its hash, its history (?version=<file>: a kept version's text)
//	GET  /api/zones/{name}/new        a new zone's text from the template (SOA, NS for the nodes in settings.json)
//	POST /api/zones/{name}/check      {"text"}: espdns zones -check (internal/zones, Check), then against each node
//	POST /api/zones/{name}/serial     {"text"}: the text with the SOA serial raised (above the saved file's and the nodes')
//	POST /api/zones/{name}            {"text", "hash"} saves it (hash: the version edited; "" for a new file)
//	POST /api/zones/{name}/delete     {"hash"}: deletes it, kept in the history
//
// Every one needs a login, as the configs' do. A save and a delete are in the action log. A
// push is the Push page's (kind zones): the page opens it with the zones chosen.

type zonesServer struct {
	dataDir string
	nodes   func() []nodes.Node
}

func (z zonesServer) routes(mux *routes) {
	need := func(h http.HandlerFunc) http.HandlerFunc { return needLogin("the hosted zones need", h) }
	mux.HandleFunc("GET /api/zones", need(z.list))
	mux.HandleFunc("GET /api/zones/{name}", need(z.get))
	mux.HandleFunc("GET /api/zones/{name}/new", need(z.template))
	mux.HandleFunc("POST /api/zones/{name}/check", need(z.check))
	mux.HandleFunc("POST /api/zones/{name}/serial", need(z.serial))
	mux.HandleFunc("POST /api/zones/{name}", need(z.save))
	mux.HandleFunc("POST /api/zones/{name}/delete", need(z.delete))
}

func (z zonesServer) listed() []string {
	s, err := settings.Load(settings.Path(z.dataDir))
	if err != nil {
		return nil
	}
	return s.Nodes
}

// zoneNode is a node as the zones page shows it.
type zoneNode struct {
	Host      string                `json:"host"`
	NodeID    string                `json:"node_id,omitempty"`
	Online    bool                  `json:"online"`
	Listed    bool                  `json:"listed"`
	Hosted    *release.HostedStatus `json:"hosted,omitempty"` // nil: firmware from before hosted zones (or no /status yet)
	LimitKB   int                   `json:"limit_kb,omitempty"`
	Secondary []string              `json:"secondary,omitempty"`
	// Pushed is the set last pushed to it, while it still serves that set.
	Pushed *zonefiles.Pushed `json:"pushed,omitempty"`
	// Unfiled are zones it serves that have no file here.
	Unfiled []string `json:"unfiled,omitempty"`
	Read    bool     `json:"read"` // a /status was read from it
}

type zoneEntry struct {
	zonefiles.File
	Nodes []zonefiles.Serving `json:"nodes"`
}

func (z zonesServer) list(w http.ResponseWriter, r *http.Request) {
	files, err := zonefiles.List(z.dataDir)
	if err != nil {
		httpErr(w, http.StatusInternalServerError, err)
		return
	}
	listed := z.listed()
	out := struct {
		Dir     string              `json:"dir"`
		Zones   []zoneEntry         `json:"zones"`
		Nodes   []zoneNode          `json:"nodes"`
		Deleted []zonefiles.Version `json:"deleted"`
		Max     int                 `json:"max_zones"`
	}{Dir: zonefiles.Path(z.dataDir), Zones: []zoneEntry{}, Nodes: []zoneNode{}, Deleted: []zonefiles.Version{}, Max: zones.MaxZones}
	for _, f := range files {
		out.Zones = append(out.Zones, zoneEntry{File: f, Nodes: []zonefiles.Serving{}})
	}
	for _, n := range z.nodes() {
		zn := zoneNode{Host: n.Addr, NodeID: n.ID, Online: n.Online, Listed: slices.Contains(listed, n.Addr)}
		st, ok := status(n)
		if ok {
			zn.Read, zn.Hosted, zn.Secondary = true, st.Hosted, zonefiles.Secondary(st)
			if st.Hosted != nil {
				zn.LimitKB = st.Hosted.LimitBytes / 1024
				if p, err := zonefiles.LoadPushed(z.dataDir, st.NodeID); err == nil && p != nil && p.Seq == st.Hosted.Seq {
					zn.Pushed = p
				}
				for _, hz := range st.Hosted.Zones {
					name := strings.ToLower(strings.TrimSuffix(hz.Name, ".")) + ".zone"
					if !slices.ContainsFunc(files, func(f zonefiles.File) bool { return f.Name == name }) {
						zn.Unfiled = append(zn.Unfiled, hz.Name)
					}
				}
			}
			m := zonefiles.SetMatch(files, st)
			for i := range out.Zones {
				if s, ok := zonefiles.Serves(z.dataDir, out.Zones[i].File, n.Addr, st, m); ok {
					out.Zones[i].Nodes = append(out.Zones[i].Nodes, s)
				}
			}
		}
		out.Nodes = append(out.Nodes, zn)
	}
	if del, err := zonefiles.Deleted(z.dataDir); err == nil {
		for _, v := range del {
			out.Deleted = append(out.Deleted, v)
		}
		slices.SortFunc(out.Deleted, func(a, b zonefiles.Version) int { return b.Time.Compare(a.Time) })
	}
	writeJSON(w, out)
}

func (z zonesServer) get(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if v := r.URL.Query().Get("version"); v != "" {
		b, err := zonefiles.ReadVersion(z.dataDir, name, v)
		if err != nil {
			httpErr(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, map[string]any{"name": name, "version": v, "text": string(b)})
		return
	}
	f, err := zonefiles.Read(z.dataDir, name)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		httpErr(w, http.StatusNotFound, fmt.Errorf("no zone file %s in %s", name, zonefiles.Path(z.dataDir)))
		return
	case err != nil:
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	h, _ := zonefiles.History(z.dataDir, name)
	if h == nil {
		h = []zonefiles.Version{}
	}
	writeJSON(w, map[string]any{"name": f.Name, "zone": f.Zone, "text": string(f.Text), "hash": f.Hash, "modified": f.Modified,
		"error": f.Error, "history": h})
}

// template is a new zone's text: its SOA (today's date serial), an NS for each node in
// settings.json with its address, as the nodes are the zone's name servers.
func (z zonesServer) template(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := zonefiles.CheckName(name); err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, map[string]any{"name": name, "text": zoneTemplate(zonefiles.ZoneOf(name), z.listed(), time.Now())})
}

func zoneTemplate(zone string, listed []string, now time.Time) string {
	var addrs []netip.Addr
	for _, h := range listed {
		if a, err := netip.ParseAddr(hostOf(h)); err == nil {
			addrs = append(addrs, a)
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "; %s: a hosted zone, served by the nodes it is pushed to (the Push page, kind zones).\n", zone)
	b.WriteString("$TTL 3600\n")
	fmt.Fprintf(&b, "@       IN SOA  ns1.%s. hostmaster.%s. (\n", zone, zone)
	fmt.Fprintf(&b, "                %d ; serial: raise it with every change\n", now.Year()*1000000+int(now.Month())*10000+now.Day()*100+1)
	b.WriteString("                3600       ; refresh\n                600        ; retry\n" +
		"                604800     ; expire\n                300 )      ; negative answers' TTL\n")
	if len(addrs) == 0 {
		b.WriteString("        IN NS   ns1\nns1     IN A    192.0.2.1 ; a node's address\n")
		return b.String()
	}
	for i := range addrs {
		fmt.Fprintf(&b, "        IN NS   ns%d\n", i+1)
	}
	for i, a := range addrs {
		t := "A   "
		if a.Is6() {
			t = "AAAA"
		}
		fmt.Fprintf(&b, "ns%-5d IN %s %s\n", i+1, t, a)
	}
	return b.String()
}

// saved is the zone file as saved, nil if there is none yet.
func (z zonesServer) saved(name string) (*zonefiles.File, error) {
	f, err := zonefiles.Read(z.dataDir, name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &f, nil
}

// zoneBody reads a request's {"text"} (and "hash"), the name checked.
func (z zonesServer) zoneBody(w http.ResponseWriter, r *http.Request, v any) (string, bool) {
	name := r.PathValue("name")
	if err := zoneJSON(w, r, v); err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return "", false
	}
	if err := zonefiles.CheckName(name); err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return "", false
	}
	return name, true
}

// zoneJSON is body for a zone's size.
func zoneJSON(w http.ResponseWriter, r *http.Request, v any) error {
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2*zonefiles.MaxFile+4096))
	d.DisallowUnknownFields()
	return d.Decode(v)
}

// run checks text as the zone name against every node the controller knows.
func (z zonesServer) run(r *http.Request, name string, text []byte, saved *zonefiles.File) zonefiles.Result {
	listed := z.listed()
	var ns []zonefiles.Node
	for _, n := range z.nodes() {
		zn := zonefiles.Node{Host: n.Addr, Listed: slices.Contains(listed, n.Addr)}
		if st, ok := status(n); ok {
			zn.Status = &st
		}
		ns = append(ns, zn)
	}
	return zonefiles.Check{DataDir: z.dataDir, Name: name, Text: text, Saved: saved, Nodes: ns}.Run(r.Context())
}

func (z zonesServer) check(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Text string `json:"text"`
	}
	name, ok := z.zoneBody(w, r, &req)
	if !ok {
		return
	}
	saved, err := z.saved(name)
	if err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, z.run(r, name, []byte(req.Text), saved))
}

func (z zonesServer) serial(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Text string `json:"text"`
	}
	name, ok := z.zoneBody(w, r, &req)
	if !ok {
		return
	}
	saved, err := z.saved(name)
	if err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	res := z.run(r, name, []byte(req.Text), saved)
	if res.Error != "" {
		httpErr(w, http.StatusBadRequest, fmt.Errorf("the zone doesn't pass its checks: %s", res.Error))
		return
	}
	text, err := zones.SetSerial(zonefiles.ZoneOf(name), []byte(req.Text), res.NextSerial)
	if err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, map[string]any{"text": string(text), "serial": res.NextSerial, "was": res.Serial})
}

func (z zonesServer) save(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Text string `json:"text"`
		Hash string `json:"hash"`
	}
	name, ok := z.zoneBody(w, r, &req)
	if !ok {
		return
	}
	saved, err := z.saved(name)
	if err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	f, err := zonefiles.Save(z.dataDir, name, []byte(req.Text), req.Hash)
	switch {
	case errors.Is(err, zonefiles.ErrChanged):
		httpErr(w, http.StatusConflict, err)
		return
	case err != nil:
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	what := fmt.Sprintf("new: serial %d, %d records", f.Serial, f.Records)
	if saved != nil {
		what = fmt.Sprintf("serial %d to %d, %d records to %d", saved.Serial, f.Serial, saved.Records, f.Records)
	}
	z.log(r, "zone save", name, what)
	writeJSON(w, map[string]any{"name": f.Name, "hash": f.Hash, "modified": f.Modified, "serial": f.Serial, "records": f.Records})
}

func (z zonesServer) delete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Hash string `json:"hash"`
	}
	name, ok := z.zoneBody(w, r, &req)
	if !ok {
		return
	}
	saved, err := z.saved(name)
	if err != nil || saved == nil {
		httpErr(w, http.StatusNotFound, fmt.Errorf("no zone file %s in %s", name, zonefiles.Path(z.dataDir)))
		return
	}
	err = zonefiles.Delete(z.dataDir, name, req.Hash)
	switch {
	case errors.Is(err, zonefiles.ErrChanged):
		httpErr(w, http.StatusConflict, err)
		return
	case err != nil:
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	z.log(r, "zone delete", name, fmt.Sprintf("serial %d, %d records, kept in %s/.history", saved.Serial, saved.Records, zonefiles.Dir))
	writeJSON(w, map[string]any{"name": name, "deleted": true})
}

func (z zonesServer) log(r *http.Request, action, name, what string) {
	user := auth.User(r.Context())
	if err := actionlog.Append(z.dataDir, actionlog.Entry{Event: "save", ID: "zone-" + time.Now().UTC().Format("20060102-150405"),
		Source: "controller", Who: user, Action: action, Args: []string{name, what}, Result: "ok"}); err != nil {
		log.Printf("zones: %s (%s), but not in the action log: %v", name, action, err)
	}
	log.Printf("zones: %s: %s by %s (%s)", name, action, user, what)
}
