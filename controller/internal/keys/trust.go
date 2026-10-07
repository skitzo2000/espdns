package keys

import (
	"bytes"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/skitzo2000/espdns/controller/internal/release"
)

// NodeKeys is one node's trusted keys as its /status lists them (slot 0 the release key,
// slot 1 the recovery key, by fingerprint), or why it couldn't be read. Listed: the node is
// one of settings.json's (an address you put there), not only found over mDNS, which any
// host on the LAN can advertise: only a listed node vouches for a key.
type NodeKeys struct {
	Addr   string
	Keys   []string
	Error  string
	Listed bool
}

// TrustReport is what Trust found.
type TrustReport struct {
	Fingerprint string
	PubFile     string   // the public key file compared with, if any
	PubMatch    bool     // it is that file's key
	Trusting    []string // nodes in settings.json that trust it in slot 0
	Unlisted    []string // nodes found only over mDNS that trust it: not counted
	Other       []string // nodes that trust another release key ("addr (fingerprint)")
	Unread      []string // nodes not read ("addr: why")
}

// Lines are the report for a person.
func (r TrustReport) Lines() []string {
	out := []string{"release key fingerprint " + r.Fingerprint}
	if r.PubFile != "" {
		if r.PubMatch {
			out = append(out, "it is the key in "+r.PubFile+" (the firmware's built-in release key)")
		} else {
			out = append(out, "NOT the key in "+r.PubFile)
		}
	}
	if len(r.Trusting) > 0 {
		out = append(out, "trusted by "+strings.Join(r.Trusting, ", "))
	}
	if len(r.Unlisted) > 0 {
		out = append(out, "trusted by "+strings.Join(r.Unlisted, ", ")+", found over mDNS only: not counted (only the nodes in settings.json vouch for a key)")
	}
	if len(r.Other) > 0 {
		out = append(out, "NOT trusted by "+strings.Join(r.Other, ", ")+": they trust another release key")
	}
	for _, u := range r.Unread {
		out = append(out, "not read: "+u)
	}
	return out
}

// Trust checks k is a release key the fleet trusts before it is imported: the public key
// the firmware is built with (pub, firmware/keys/release.pub, 65 bytes; nil if not given),
// or a node in settings.json (Listed) trusting it in slot 0. A node found only over mDNS
// never vouches: any host on the LAN can advertise one and list any key. A key nothing
// trusts is refused: the controller would sign releases every node rejects. So is the
// recovery key (recoveryPub, or slot 1 on any node, listed or not): it is kept offline,
// never in the controller.
func Trust(k *ecdsa.PrivateKey, pubFile string, pub, recoveryPub []byte, nodes []NodeKeys) (TrustReport, error) {
	raw := release.PublicRaw(k)
	fp := release.Fingerprint(raw)
	r := TrustReport{Fingerprint: fp, PubFile: pubFile}
	if len(recoveryPub) > 0 && bytes.Equal(recoveryPub, raw) {
		return r, errors.New("this is the recovery key (key slot 1): it stays offline, never in the controller")
	}
	if len(pub) > 0 {
		if len(pub) != len(raw) {
			return r, fmt.Errorf("%s: %d bytes, not a raw P-256 public key (65)", pubFile, len(pub))
		}
		r.PubMatch = bytes.Equal(pub, raw)
	}
	for _, n := range nodes {
		switch {
		case n.Error != "":
			r.Unread = append(r.Unread, n.Addr+": "+n.Error)
		case len(n.Keys) == 0:
			r.Unread = append(r.Unread, n.Addr+": lists no keys (firmware from before signed releases)")
		case len(n.Keys) > 1 && n.Keys[1] == fp:
			return r, fmt.Errorf("this is the recovery key: %s trusts it in slot 1; it stays offline, never in the controller", n.Addr)
		case n.Keys[0] == fp && n.Listed:
			r.Trusting = append(r.Trusting, n.Addr)
		case n.Keys[0] == fp:
			r.Unlisted = append(r.Unlisted, n.Addr)
		default:
			r.Other = append(r.Other, n.Addr+" ("+n.Keys[0]+")")
		}
	}
	slices.Sort(r.Trusting)
	if !r.PubMatch && len(r.Trusting) == 0 {
		why := "no node in settings.json trusts it"
		if !slices.ContainsFunc(nodes, func(n NodeKeys) bool { return n.Listed }) {
			why = "no node in settings.json was asked"
		}
		if pubFile != "" {
			why += " and it isn't the key in " + pubFile
		}
		return r, fmt.Errorf("not imported: %s: every release it signs would be rejected", why)
	}
	return r, nil
}
