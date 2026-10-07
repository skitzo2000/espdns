// Package pins is the signer's own record of the nodes it signs releases for (docs/design.md,
// Signed releases; issue #55): each node's ID, pinned to the address it was adopted on, and
// the last seq signed for it, per release kind. A node's /status says who it is and which
// seqs it took, but anything that answers on its address can send a /status: a release is
// signed for the ID pinned to the address, with a seq above the one recorded here, and never
// for what a /status says.
//
// A node is pinned when it is adopted (internal/fleet, Adopt), when espdns recover lists it,
// or by hand (espdns pin), and moves with it when a config it took moves it to another
// address (fleet.ConfirmConfig). One file per node in <data>/pins/, written whole or not at
// all; every change to a node goes under the fleet lock, so two writers never race a seq.
package pins

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/filestore"
)

// Dir is the record's directory in the data directory.
const Dir = "pins"

// ErrNotPinned: no node is pinned to the address.
var ErrNotPinned = errors.New("no node is pinned to this address")

// Record is one node.
type Record struct {
	ID string `json:"id"` // its node ID (chip MAC), lowercase
	// Addr is the address it is pinned to; "" once another node was pinned there (its seqs
	// are kept, for when it is pinned again).
	Addr   string    `json:"addr"`
	Pinned time.Time `json:"pinned"`
	// Seq is the last seq signed for it, per kind (/status's names: "config", ...).
	Seq map[string]uint64 `json:"seq,omitempty"`
}

// Ledger is the record in one data directory.
type Ledger struct {
	dir string
	now func() time.Time
}

// mu serializes the record's changes within a process (the controller's jobs, its tests);
// the fleet lock does it between processes.
var mu sync.Mutex

// Open is the record in dataDir; nothing is read or made until it is used.
func Open(dataDir string) *Ledger {
	return &Ledger{dir: filepath.Join(dataDir, Dir), now: time.Now}
}

var idRE = regexp.MustCompile(`^[0-9a-f]{2}(:[0-9a-f]{2}){5}$`)

// normID is a node ID as the record keeps it, or an error for one that isn't a MAC address.
func normID(id string) (string, error) {
	n := strings.ToLower(strings.ReplaceAll(id, "-", ":"))
	if !idRE.MatchString(n) {
		return "", fmt.Errorf("node ID %q: not a MAC address", id)
	}
	return n, nil
}

func (l *Ledger) path(id string) string {
	return filepath.Join(l.dir, strings.ReplaceAll(id, ":", "")+".json")
}

// read is one node's record, nil if there is none.
func (l *Ledger) read(id string) (*Record, error) {
	b, err := os.ReadFile(l.path(id))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var r Record
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("%s: %w", l.path(id), err)
	}
	if r.ID != id {
		return nil, fmt.Errorf("%s: names node %q", l.path(id), r.ID)
	}
	return &r, nil
}

func (l *Ledger) write(r *Record) error {
	if err := os.MkdirAll(l.dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return filestore.WriteFile(l.path(r.ID), append(b, '\n'))
}

// all is every record. One that can't be read fails it: a record skipped could be the pin
// that says an address is another node's.
func (l *Ledger) all() ([]*Record, error) {
	ents, err := os.ReadDir(l.dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []*Record
	for _, e := range ents {
		name, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok || strings.HasPrefix(name, ".") {
			continue
		}
		if len(name) != 12 {
			return nil, fmt.Errorf("%s: not a node's record", filepath.Join(l.dir, e.Name()))
		}
		var mac []string
		for i := 0; i < 12; i += 2 {
			mac = append(mac, name[i:i+2])
		}
		id, err := normID(strings.Join(mac, ":"))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Join(l.dir, e.Name()), err)
		}
		r, err := l.read(id)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

// List is every node in the record, by address (those pinned to none last).
func (l *Ledger) List() ([]Record, error) {
	mu.Lock()
	defer mu.Unlock()
	rs, err := l.all()
	if err != nil {
		return nil, err
	}
	out := make([]Record, 0, len(rs))
	for _, r := range rs {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool {
		if (out[i].Addr == "") != (out[j].Addr == "") {
			return out[j].Addr == ""
		}
		return out[i].Addr < out[j].Addr || out[i].Addr == out[j].Addr && out[i].ID < out[j].ID
	})
	return out, nil
}

// Pinned is the ID of the node pinned to addr, or ErrNotPinned.
func (l *Ledger) Pinned(addr string) (string, error) {
	mu.Lock()
	defer mu.Unlock()
	r, err := l.at(addr)
	if err != nil {
		return "", err
	}
	if r == nil {
		return "", fmt.Errorf("%s: %w", addr, ErrNotPinned)
	}
	return r.ID, nil
}

// at is the record pinned to addr, nil for none. Call with mu held.
func (l *Ledger) at(addr string) (*Record, error) {
	rs, err := l.all()
	if err != nil {
		return nil, err
	}
	var found *Record
	for _, r := range rs {
		if addr != "" && r.Addr == addr {
			if found != nil {
				return nil, fmt.Errorf("%s: nodes %s and %s are both pinned to it: pin the one that is there (espdns pin)",
					addr, found.ID, r.ID)
			}
			found = r
		}
	}
	return found, nil
}

// Pin pins node id to addr: a node new to the record starts with no seqs; one in it moves
// there and keeps them. A node pinned to addr before is unpinned from it (its seqs kept).
// It returns the ID of that node, "" for none.
func (l *Ledger) Pin(id, addr string) (replaced string, err error) {
	id, err = normID(id)
	if err != nil {
		return "", err
	}
	if addr == "" {
		return "", errors.New("pin: no address")
	}
	mu.Lock()
	defer mu.Unlock()
	old, err := l.at(addr)
	if err != nil {
		return "", err
	}
	if old != nil && old.ID == id {
		return "", nil
	}
	r, err := l.read(id)
	if err != nil {
		return "", err
	}
	if r == nil {
		r = &Record{ID: id}
	}
	r.Addr, r.Pinned = addr, l.now().UTC()
	if old != nil {
		old.Addr = ""
		if err := l.write(old); err != nil {
			return "", err
		}
		replaced = old.ID
	}
	return replaced, l.write(r)
}

// Unpinned puts node id in the record pinned to no address, for a release to a node not
// adopted yet (identify, on the Adopt page): a node new to the record gets one with no
// address and no seqs, so the seqs signed for it are recorded (and kept when adoption pins
// it); one pinned to an address is refused, as it is signed for there alone. It returns
// the ID as the record keeps it.
func (l *Ledger) Unpinned(id string) (string, error) {
	id, err := normID(id)
	if err != nil {
		return "", err
	}
	mu.Lock()
	defer mu.Unlock()
	r, err := l.read(id)
	if err != nil {
		return "", err
	}
	if r == nil {
		return id, l.write(&Record{ID: id, Pinned: l.now().UTC()})
	}
	if r.Addr != "" {
		return "", fmt.Errorf("node %s is pinned to %s: releases for it are signed there alone", id, r.Addr)
	}
	return id, nil
}

// Seq is the last seq signed for node id of kind, 0 for none. A node not in the record is
// ErrNotPinned.
func (l *Ledger) Seq(id, kind string) (uint64, error) {
	id, err := normID(id)
	if err != nil {
		return 0, err
	}
	mu.Lock()
	defer mu.Unlock()
	r, err := l.read(id)
	if err != nil {
		return 0, err
	}
	if r == nil {
		return 0, fmt.Errorf("node %s: %w", id, ErrNotPinned)
	}
	return r.Seq[kind], nil
}

// SetSeq records seq as signed for node id of kind, before the release is sent: one that
// may have been taken is never signed again. A seq not above the one recorded is refused.
func (l *Ledger) SetSeq(id, kind string, seq uint64) error {
	id, err := normID(id)
	if err != nil {
		return err
	}
	mu.Lock()
	defer mu.Unlock()
	r, err := l.read(id)
	if err != nil {
		return err
	}
	if r == nil {
		return fmt.Errorf("node %s: %w", id, ErrNotPinned)
	}
	return l.setSeq(r, kind, seq)
}

// Next picks and records the seq to sign for node id of kind, as one step: next gets the
// last one recorded (0 for none) and returns the new one, which is recorded before Next
// returns it. Two pushes at once to one node never read the same last seq, so neither is
// refused for a seq the other recorded first.
func (l *Ledger) Next(id, kind string, next func(last uint64) (uint64, error)) (uint64, error) {
	id, err := normID(id)
	if err != nil {
		return 0, err
	}
	mu.Lock()
	defer mu.Unlock()
	r, err := l.read(id)
	if err != nil {
		return 0, err
	}
	if r == nil {
		return 0, fmt.Errorf("node %s: %w", id, ErrNotPinned)
	}
	seq, err := next(r.Seq[kind])
	if err != nil {
		return 0, err
	}
	if err := l.setSeq(r, kind, seq); err != nil {
		return 0, err
	}
	return seq, nil
}

// setSeq records seq in r and writes it; one not above the last is refused. Call with mu held.
func (l *Ledger) setSeq(r *Record, kind string, seq uint64) error {
	if last := r.Seq[kind]; seq <= last {
		return fmt.Errorf("node %s: %s seq %d is not above %d, the last signed for it", r.ID, kind, seq, last)
	}
	if r.Seq == nil {
		r.Seq = map[string]uint64{}
	}
	r.Seq[kind] = seq
	return l.write(r)
}
