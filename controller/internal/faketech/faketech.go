// Package faketech is a fake Technitium DNS Server API for tests and browser checks: the
// zone options a node's adoption reads and sets (/api/zones/options/get and /set, as
// internal/primary's Technitium driver calls them), checked against one token. Nothing here reaches
// a network: the caller serves it.
package faketech

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"sync"
)

// Zone is one zone's transfer and NOTIFY options.
type Zone struct {
	Transfer     string   // zoneTransfer
	TransferList []string // zoneTransferNameServers, or zoneTransferNetworkACL on an ACL server
	Notify       string   // notify
	NotifyList   []string // notifyNameServers
}

// Server is the fake API. Set Token and ACL before it serves.
type Server struct {
	Token string
	// ACL: a newer server, whose zone transfer list is a network ACL.
	ACL bool

	mu    sync.Mutex
	zones map[string]*Zone
	sets  []map[string]string
	calls []string
}

// New is a server with the zones as Technitium makes a new one: transfers to the zone's
// own name servers, NOTIFY to them.
func New(token string, zones ...string) *Server {
	s := &Server{Token: token, zones: map[string]*Zone{}}
	for _, z := range zones {
		s.zones[z] = &Zone{Transfer: "AllowOnlyZoneNameServers", Notify: "ZoneNameServers"}
	}
	return s
}

// SetZone sets a zone's options.
func (s *Server) SetZone(name string, z Zone) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.zones == nil {
		s.zones = map[string]*Zone{}
	}
	s.zones[name] = &z
}

// Zone is a zone's options now.
func (s *Server) Zone(name string) (Zone, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	z, ok := s.zones[name]
	if !ok {
		return Zone{}, false
	}
	c := *z
	c.TransferList, c.NotifyList = slices.Clone(z.TransferList), slices.Clone(z.NotifyList)
	return c, true
}

// Sets are the option sets made, each the form without the token.
func (s *Server) Sets() []map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.sets)
}

// Calls are the API paths called, in order, with a good token or not.
func (s *Server) Calls() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.calls)
}

func reply(w http.ResponseWriter, v map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func listOf(v string) []string {
	if v == "false" || v == "" {
		return []string{}
	}
	var out []string
	for _, e := range strings.Split(v, ",") {
		if e = strings.TrimSpace(e); e != "" {
			out = append(out, e)
		}
	}
	return out
}

// ServeHTTP is the API.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, r.URL.Path)
	if r.Form.Get("token") != s.Token || s.Token == "" {
		reply(w, map[string]any{"status": "invalid-token", "errorMessage": "Invalid token or session expired."})
		return
	}
	name := r.Form.Get("zone")
	z, ok := s.zones[name]
	switch r.URL.Path {
	case "/api/zones/options/get", "/api/zones/options/set":
		if !ok {
			reply(w, map[string]any{"status": "error", "errorMessage": "No such zone was found: " + name})
			return
		}
	default:
		http.NotFound(w, r)
		return
	}
	if r.URL.Path == "/api/zones/options/set" {
		set := map[string]string{}
		for k := range r.Form {
			if k != "token" {
				set[k] = r.Form.Get(k)
			}
		}
		s.sets = append(s.sets, set)
		if v, ok := r.Form["zoneTransfer"]; ok {
			z.Transfer = v[0]
		}
		if v, ok := r.Form["zoneTransferNameServers"]; ok && !s.ACL {
			z.TransferList = listOf(v[0])
		}
		if v, ok := r.Form["zoneTransferNetworkACL"]; ok && s.ACL {
			z.TransferList = listOf(v[0])
		}
		if v, ok := r.Form["notify"]; ok {
			z.Notify = v[0]
		}
		if v, ok := r.Form["notifyNameServers"]; ok {
			z.NotifyList = listOf(v[0])
		}
		reply(w, map[string]any{"status": "ok", "response": map[string]any{}})
		return
	}
	list := z.TransferList
	if list == nil {
		list = []string{}
	}
	notify := z.NotifyList
	if notify == nil {
		notify = []string{}
	}
	resp := map[string]any{"name": name, "type": "Primary", "zoneTransfer": z.Transfer, "notify": z.Notify, "notifyNameServers": notify}
	if s.ACL {
		resp["zoneTransferNetworkACL"] = list
	} else {
		resp["zoneTransferNameServers"] = list
	}
	reply(w, map[string]any{"status": "ok", "response": resp})
}
