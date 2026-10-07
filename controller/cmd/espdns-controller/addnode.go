package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/adoption"
	"github.com/skitzo2000/espdns/controller/internal/configs"
	"github.com/skitzo2000/espdns/controller/internal/nodes"
	"github.com/skitzo2000/espdns/controller/internal/settings"
)

// The node lookup behind Nodes' "+ Add node": the nodes found on the network that aren't in
// settings.json yet, and one looked up at an address typed, each shown as what it is (its
// board, image, firmware and name, from its /status) and what comes next. Adding it is the
// Adopt flow (adopt.go: POST /api/adopt/preview, then the adopt jobs), or the settings-add
// job for one adopted already; nothing here changes a node or a file.
//
//	GET  /api/nodes/found   the nodes found over mDNS or looked up, not in settings.json
//	POST /api/nodes/lookup  {"address": "192.0.2.10"}: the node at that address, read there only
//
// A lookup reads /status at the address typed, and nowhere else, within a few seconds
// (nodes.Registry.Lookup): no name is resolved (an IPv4 address only), no other host is
// asked, and an address in settings.json isn't read at all (it is polled already). A node
// that answers is listed from then on, as one found over mDNS is (pruned when it is gone),
// so the adoption finds it as it finds those: a node on a network without DHCP, or one mDNS
// doesn't reach, is added by its address.

// nodeLookupTimeout bounds a lookup's request: the registry's own wait is the shorter.
const nodeLookupTimeout = 5 * time.Second

// nodeLookup reads the node at an address typed, there only (nodes.Registry.Lookup).
type nodeLookup func(ctx context.Context, addr string) (nodes.Node, error)

type addNodeServer struct {
	adopt  adoptKind
	lookup nodeLookup
}

// Next says what adds a found node.
const (
	nextAdopt       = "adopt"        // POST /api/adopt/preview with {"node": host, "node_id": id, ...}, then the adopt jobs
	nextSettingsAdd = "settings-add" // adopted already: the settings-add job with {"node": host}
)

// foundNode is a node as Add node shows it: as the Adopt page describes it, and what adds
// it ("" when nothing can yet: Refusals say why).
type foundNode struct {
	adoptNode
	Next string `json:"next"`
}

func (a addNodeServer) routes(mux *routes) {
	mux.HandleFunc("GET /api/nodes/found", needLogin("adding a node needs", a.found))
	mux.HandleFunc("POST /api/nodes/lookup", needLogin("adding a node needs", a.lookupNode))
}

// view is n described for Add node.
func (a addNodeServer) view(n nodes.Node, all []nodes.Node, s settings.Settings, files []configs.File) foundNode {
	an := a.adopt.describe(n, all, s, files)
	f := foundNode{adoptNode: an}
	switch {
	case len(an.Refusals) > 0 || an.Listed:
	case !an.Adopted:
		f.Next = nextAdopt
	default:
		f.Next = nextSettingsAdd
	}
	return f
}

func (a addNodeServer) found(w http.ResponseWriter, r *http.Request) {
	s, err := settings.Load(settings.Path(a.adopt.dataDir))
	if err != nil {
		httpErr(w, http.StatusInternalServerError, err)
		return
	}
	files, _ := configs.List(a.adopt.dataDir)
	all := a.adopt.nodes()
	out := []foundNode{}
	for _, n := range all {
		if n.Source == nodes.SourceSettings || listed(s, n.Addr) {
			continue
		}
		out = append(out, a.view(n, all, s, files))
	}
	writeJSON(w, map[string]any{"nodes": out})
}

// lookupReply is POST /api/nodes/lookup's answer.
type lookupReply struct {
	Address  string     `json:"address"`
	Listed   bool       `json:"listed"`   // in settings.json: one of the nodes already (not read)
	Found    bool       `json:"found"`    // an espDNS node answered there
	Answered bool       `json:"answered"` // something answered HTTP there (not found: not a node)
	Error    string     `json:"error,omitempty"`
	Node     *foundNode `json:"node,omitempty"`
}

func (a addNodeServer) lookupNode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Address string `json:"address"`
	}
	if err := body(w, r, &req); err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	addr, err := lookupAddress(req.Address)
	if err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	s, err := settings.Load(settings.Path(a.adopt.dataDir))
	if err != nil {
		httpErr(w, http.StatusInternalServerError, err)
		return
	}
	out := lookupReply{Address: addr}
	files, _ := configs.List(a.adopt.dataDir)
	if listed(s, addr) {
		out.Listed = true
		all := a.adopt.nodes()
		if i := slices.IndexFunc(all, func(n nodes.Node) bool { return adoption.HostOnly(n.Addr) == addr }); i >= 0 {
			f := a.view(all[i], all, s, files)
			out.Node = &f
		}
		writeJSON(w, out)
		return
	}
	if a.lookup == nil {
		httpErr(w, http.StatusInternalServerError, errors.New("no node lookup here"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), nodeLookupTimeout)
	defer cancel()
	n, err := a.lookup(ctx, addr)
	if err != nil {
		out.Answered, out.Error = errors.Is(err, nodes.ErrNotNode), fmt.Sprintf("%s: %v", addr, err)
		writeJSON(w, out)
		return
	}
	out.Found = true
	f := a.view(n, a.adopt.nodes(), s, files)
	out.Node = &f
	writeJSON(w, out)
}

// listed says whether settings.json lists addr (with or without a port).
func listed(s settings.Settings, addr string) bool {
	return slices.ContainsFunc(s.Nodes, func(h string) bool { return h == addr || adoption.HostOnly(h) == adoption.HostOnly(addr) })
}

// Addresses no node has, beyond what netip names: "this network" (0.0.0.0/8) and the
// reserved block with the broadcast address (240.0.0.0/4, 255.255.255.255 in it).
var (
	thisNetwork = netip.MustParsePrefix("0.0.0.0/8")
	reserved    = netip.MustParsePrefix("240.0.0.0/4")
)

// lookupAddress is the address typed, checked: one IPv4 unicast address, as a node has
// (no name: nothing is resolved; no port: a node serves HTTP on 80). Private LAN ranges are
// where nodes live; loopback, link-local (169.254.0.0/16, the cloud metadata address in it),
// multicast, 0.0.0.0/8 and 240.0.0.0/4 are no node's, so nothing is sent there.
func lookupAddress(s string) (string, error) {
	a, err := netip.ParseAddr(s)
	switch {
	case s == "":
		return "", errors.New("address: type the node's IPv4 address")
	case err != nil || !a.Is4():
		return "", fmt.Errorf("address: %q is not an IPv4 address (a node's, like 192.0.2.10; names aren't looked up)", s)
	case a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsMulticast() || thisNetwork.Contains(a) || reserved.Contains(a):
		return "", fmt.Errorf("address: %s is no node's address", s)
	}
	return a.String(), nil
}
