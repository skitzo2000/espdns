// Package changes is the controller's pending changes ("collect, then Apply"): edits made
// in the browser wait here, shown in the header, until one apply job (the job kind
// "apply") sends them all to the nodes as one safe rolling change. Nothing in the data
// directory's files changes until then.
//
//	changes/pending.json   the pending changes, oldest first
//	changes/<id>.txt       what a file change makes the file (none for a delete)
//	changes/<id>.base      the file as it was before an apply wrote the change (an apply
//	                       that stopped part way): what a discard puts back
//	changes/sent.json      by blocklist, the compiled files (their SHA-256) the nodes ran
//	                       when an apply compiled it again and stopped before every node
//	                       took the new one: the nodes it still goes to
//
// A change is an edit of one file the rolling pushes read (a node config, a hosted zone, a
// blocking source or the list definitions), or a firmware update of some nodes. A file
// change names the version it edits by its hash, as the editors' saves do: the file as it
// is, or what the pending changes before it make it, so edits of one file stack, each on
// the one before. Discarding a change discards the ones stacked on it too.
//
// An apply that stops after writing the files (a node failed, or a stop was asked for)
// leaves its changes pending, marked written: applying again finishes them. Discarding a
// written change puts the file back as it was before the change, and, when no change of
// that file is left, leaves a pending "put back" change, so the nodes that took it get the
// file as it is again at the next apply: the files and the nodes never quietly differ.
package changes

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/skitzo2000/espdns/controller/internal/blocking"
	"github.com/skitzo2000/espdns/controller/internal/configs"
	"github.com/skitzo2000/espdns/controller/internal/filestore"
	"github.com/skitzo2000/espdns/controller/internal/secfile"
	"github.com/skitzo2000/espdns/controller/internal/zonefiles"
)

const (
	Dir       = "changes"      // in the data directory
	IndexFile = "pending.json" // in Dir
	SentFile  = "sent.json"    // in Dir
	// MaxSums is the most compiled files remembered for one list (the oldest dropped).
	MaxSums = 16
	// MaxChanges is the most changes pending at once; MaxBytes the most their texts hold
	// together (a blocking source may hold 32 MiB).
	MaxChanges = 100
	MaxBytes   = 64 << 20
	// MaxSummary is the most a change's summary (its words in the header) holds.
	MaxSummary = 200
)

// Kind is what a change changes.
type Kind string

const (
	Config   Kind = "config"   // configs/<name>.json, a node config
	Zone     Kind = "zone"     // zones/<zone>.zone, a hosted zone
	Source   Kind = "source"   // blocking/sources/<file>, a blocking source (the overrides too)
	Lists    Kind = "lists"    // blocking/lists.json, the list definitions
	Firmware Kind = "firmware" // a firmware update of some nodes
)

// Kinds are the kinds, in the order an apply pushes them.
var Kinds = []Kind{Config, Zone, Source, Lists, Firmware}

// File says whether the kind is an edit of a file.
func (k Kind) File() bool { return k != Firmware && slices.Contains(Kinds, k) }

// FileStore is the store a file change of kind k writes through: its name rule, its
// checks (the node's), its history.
func FileStore(dataDir string, k Kind) (filestore.Store, error) {
	switch k {
	case Config:
		return configs.Store(dataDir), nil
	case Zone:
		return zonefiles.Store(dataDir), nil
	case Source:
		return blocking.Sources(dataDir), nil
	case Lists:
		return blocking.DefsStore(dataDir), nil
	}
	return filestore.Store{}, fmt.Errorf("kind %q: config, zone, source, lists or firmware", k)
}

// Change is one pending change.
type Change struct {
	ID   string `json:"id"`
	Kind Kind   `json:"kind"`
	// Name is the file's name (a file change): dns2.json, example.com.zone, overrides.txt,
	// lists.json.
	Name   string `json:"name,omitempty"`
	Delete bool   `json:"delete,omitempty"` // the change deletes the file
	// Base is the hash of the version it edits ("" none: a new file); Hash the hash of what
	// it makes ("" deleted).
	Base string `json:"base,omitempty"`
	Hash string `json:"hash,omitempty"`
	// Firmware: the build ("builds/<board>" or "images/<image>") and the nodes it goes to.
	Firmware string   `json:"firmware,omitempty"`
	Nodes    []string `json:"nodes,omitempty"`
	// Summary is the change in words, as the header lists it.
	Summary string    `json:"summary"`
	Who     string    `json:"who"`
	Created time.Time `json:"created"`
	// Written: an apply wrote it into the file and stopped before every node had it.
	Written bool `json:"written,omitempty"`
	// PutBack: a written change was discarded; this sends the file as it is again.
	PutBack bool `json:"put_back,omitempty"`
}

// key is the file a change edits ("" for firmware).
func (c Change) key() string {
	if !c.Kind.File() {
		return ""
	}
	return string(c.Kind) + "/" + c.Name
}

// Same says whether two changes edit the same file.
func (c Change) Same(o Change) bool { return c.key() != "" && c.key() == o.key() }

// Errors, the API's 409, 404, 400 and 429.
var (
	ErrChanged  = filestore.ErrChanged
	ErrHeld     = errors.New("an apply running now is sending it: wait for it to end, or stop it")
	ErrNotFound = errors.New("no such pending change")
	ErrNoChange = errors.New("that is what it already is: nothing to change")
	ErrFull     = fmt.Errorf("too many pending changes (at most %d, %d MiB of text): apply or discard some first", MaxChanges, MaxBytes>>20)
)

// Store is the pending changes in a data directory. One Store per controller: it holds
// the changes an apply running now takes (Hold), which can't be discarded meanwhile.
type Store struct {
	dataDir string
	mu      sync.Mutex
	held    map[string]bool
}

// New is the pending changes of dataDir.
func New(dataDir string) *Store { return &Store{dataDir: dataDir, held: map[string]bool{}} }

func (s *Store) dir() string                { return filepath.Join(s.dataDir, Dir) }
func (s *Store) path(id, ext string) string { return filepath.Join(s.dir(), id+ext) }

type index struct {
	Changes []Change `json:"changes"`
}

// load reads the index; none is no changes.
func (s *Store) load() ([]Change, error) {
	b, err := os.ReadFile(filepath.Join(s.dir(), IndexFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var x index
	if err := json.Unmarshal(b, &x); err != nil {
		return nil, fmt.Errorf("%s: %v", filepath.Join(s.dir(), IndexFile), err)
	}
	return x.Changes, nil
}

func (s *Store) save(cs []Change) error {
	if cs == nil {
		cs = []Change{}
	}
	b, err := json.MarshalIndent(index{cs}, "", " ")
	if err != nil {
		return err
	}
	if err := secfile.MkdirAll(s.dir()); err != nil {
		return err
	}
	return filestore.WriteFile(filepath.Join(s.dir(), IndexFile), append(b, '\n'))
}

func (s *Store) writeText(path string, b []byte) error {
	if err := secfile.MkdirAll(s.dir()); err != nil {
		return err
	}
	return filestore.WriteFile(path, b)
}

// remove drops a change's files.
func (s *Store) remove(id string) {
	os.Remove(s.path(id, ".txt"))
	os.Remove(s.path(id, ".base"))
}

// List is the pending changes, oldest first.
func (s *Store) List() ([]Change, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cs, err := s.load()
	if cs == nil {
		cs = []Change{}
	}
	return cs, err
}

// Held says whether an apply running now holds the change.
func (s *Store) Held(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.held[id]
}

// Base is the file as it was before an apply wrote the changes of a file whose first
// change is id (nil: none kept, or there was no file).
func (s *Store) Base(id string) []byte {
	b, err := os.ReadFile(s.path(id, ".base"))
	if err != nil {
		return nil
	}
	return b
}

// Text is what a file change makes the file (nil for a delete).
func (s *Store) Text(c Change) ([]byte, error) {
	if c.Delete || !c.Kind.File() {
		return nil, nil
	}
	b, err := os.ReadFile(s.path(c.ID, ".txt"))
	if err == nil && filestore.Hash(b) != c.Hash {
		err = fmt.Errorf("%s: not the text the change was made with", s.path(c.ID, ".txt"))
	}
	return b, err
}

// View is a file as the pending changes make it.
type View struct {
	Kind   Kind   `json:"kind"`
	Name   string `json:"name"`
	Text   []byte `json:"-"`
	Hash   string `json:"hash"` // "" none
	Exists bool   `json:"exists"`
	// Pending are the changes that make it so, oldest first (none: the file as it is).
	Pending []string `json:"pending"`
}

// Current is the file as it is now in the data directory.
func Current(dataDir string, k Kind, name string) (View, error) {
	st, err := FileStore(dataDir, k)
	if err != nil {
		return View{}, err
	}
	v := View{Kind: k, Name: name, Pending: []string{}}
	f, err := st.Read(name)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return v, nil
	case err != nil:
		return v, err
	}
	v.Text, v.Hash, v.Exists = f.Text, f.Hash, true
	return v, nil
}

// Effective is the file as the pending changes make it: what an edit starts from.
func (s *Store) Effective(k Kind, name string) (View, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cs, err := s.load()
	if err != nil {
		return View{}, err
	}
	return s.effective(cs, k, name)
}

func (s *Store) effective(cs []Change, k Kind, name string) (View, error) {
	v, err := Current(s.dataDir, k, name)
	if err != nil {
		return v, err
	}
	probe := Change{Kind: k, Name: name}
	var last *Change
	for i := range cs {
		if cs[i].Same(probe) {
			last = &cs[i]
			v.Pending = append(v.Pending, cs[i].ID)
		}
	}
	if last == nil {
		return v, nil
	}
	text, err := s.Text(*last)
	if err != nil {
		return v, err
	}
	v.Text, v.Hash, v.Exists = text, last.Hash, !last.Delete
	return v, nil
}

// Edit is a change asked for.
type Edit struct {
	Kind Kind
	Name string
	// Text is what the file becomes; Delete deletes it instead.
	Text   []byte
	Delete bool
	// Hash is the version the edit started from (Effective's Hash; "" a new file).
	Hash     string
	Firmware string
	Nodes    []string
	Summary  string
	Who      string
}

// CheckSummary refuses a summary that isn't one plain line.
func CheckSummary(s string) error {
	if len(s) > MaxSummary {
		return fmt.Errorf("summary: at most %d bytes", MaxSummary)
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return errors.New("summary: one line of plain text")
		}
	}
	return nil
}

// DefaultSummary says a change in words when the page gave none.
func DefaultSummary(c Change) string {
	what := map[Kind]string{Config: "node config", Zone: "zone", Source: "blocking source", Lists: "blocklists"}[c.Kind]
	name := c.Name
	switch c.Kind {
	case Zone:
		name = zonefiles.ZoneOf(name)
	case Lists:
		return "Change the blocklists"
	case Firmware:
		return "Update " + strings.Join(c.Nodes, ", ") + " to " + c.Firmware
	}
	if c.Delete {
		return "Delete " + what + " " + name
	}
	if c.Base == "" {
		return "Add " + what + " " + name
	}
	return "Change " + what + " " + name
}

func newID() string {
	b := make([]byte, 3)
	rand.Read(b)
	return time.Now().UTC().Format("20060102-150405") + "-" + hex.EncodeToString(b)
}

// Add adds a change: a file change checked as its store checks a save (the node's checks),
// on the version it names (ErrChanged if that isn't the file as the pending changes make
// it); a firmware update for nodes no other pending update has.
func (s *Store) Add(e Edit) (Change, error) {
	cs, err := s.AddAll([]Edit{e})
	if err != nil {
		return Change{}, err
	}
	return cs[0], nil
}

// AddAll adds changes as Add does, all of them or, when one is refused, none: each checked
// on the pending changes and the ones before it, in one save.
func (s *Store) AddAll(es []Edit) ([]Change, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cs, err := s.load()
	if err != nil {
		return nil, err
	}
	var added []Change
	undo := func() {
		for _, c := range added {
			s.remove(c.ID)
		}
	}
	for _, e := range es {
		c, err := s.add(cs, e)
		if err != nil {
			undo()
			return nil, err
		}
		cs = append(cs, c)
		added = append(added, c)
	}
	if err := s.save(cs); err != nil {
		undo()
		return nil, err
	}
	return added, nil
}

// add checks one change on the pending changes cs and writes its text: the change to add
// to them (the index not saved).
func (s *Store) add(cs []Change, e Edit) (Change, error) {
	if err := CheckSummary(e.Summary); err != nil {
		return Change{}, err
	}
	c := Change{Kind: e.Kind, Name: e.Name, Delete: e.Delete, Summary: strings.TrimSpace(e.Summary), Who: e.Who,
		Created: time.Now().UTC()}
	if len(cs) >= MaxChanges {
		return Change{}, ErrFull
	}
	switch {
	case e.Kind == Firmware:
		if e.Name != "" || e.Text != nil || e.Delete || e.Hash != "" {
			return Change{}, errors.New("a firmware change names the firmware and the nodes only")
		}
		if e.Firmware == "" || len(e.Nodes) == 0 {
			return Change{}, errors.New("a firmware change names the firmware and the nodes")
		}
		for i, n := range e.Nodes {
			if n == "" || slices.Contains(e.Nodes[:i], n) {
				return Change{}, fmt.Errorf("nodes: %q empty or twice", n)
			}
			for _, o := range cs {
				if o.Kind == Firmware && slices.Contains(o.Nodes, n) {
					return Change{}, fmt.Errorf("%s already has a firmware update pending (%s): discard that one first", n, o.Summary)
				}
			}
		}
		c.Firmware, c.Nodes = e.Firmware, slices.Clone(e.Nodes)
	case e.Kind.File():
		if e.Firmware != "" || len(e.Nodes) > 0 {
			return Change{}, errors.New("a file change names no firmware or nodes")
		}
		st, _ := FileStore(s.dataDir, e.Kind)
		if err := st.Name(e.Name); err != nil {
			return Change{}, err
		}
		v, err := s.effective(cs, e.Kind, e.Name)
		if err != nil {
			return Change{}, err
		}
		if e.Hash != v.Hash {
			return Change{}, fmt.Errorf("%s: %w", e.Name, ErrChanged)
		}
		c.Base = v.Hash
		if e.Delete {
			if e.Text != nil {
				return Change{}, errors.New("a delete has no text")
			}
			if !v.Exists {
				return Change{}, fmt.Errorf("%s: no such file to delete", e.Name)
			}
		} else {
			if int64(len(e.Text)) > st.Max {
				return Change{}, fmt.Errorf("%s: over %d bytes", e.Name, st.Max)
			}
			if st.Check != nil {
				if err := st.Check(e.Name, e.Text); err != nil {
					return Change{}, err
				}
			}
			c.Hash = filestore.Hash(e.Text)
			if v.Exists && c.Hash == v.Hash {
				return Change{}, ErrNoChange
			}
			total := int64(len(e.Text))
			for _, o := range cs {
				if fi, err := os.Stat(s.path(o.ID, ".txt")); err == nil {
					total += fi.Size()
				}
			}
			if total > MaxBytes {
				return Change{}, ErrFull
			}
		}
	default:
		_, err := FileStore(s.dataDir, e.Kind)
		return Change{}, err
	}
	if c.Summary == "" {
		c.Summary = DefaultSummary(c)
	}
	c.ID = newID()
	for slices.ContainsFunc(cs, func(o Change) bool { return o.ID == c.ID }) {
		c.ID = newID()
	}
	if c.Kind.File() && !c.Delete {
		if err := s.writeText(s.path(c.ID, ".txt"), e.Text); err != nil {
			s.remove(c.ID)
			return Change{}, err
		}
	}
	return c, nil
}

// Chains are the file changes grouped by file, each group oldest first, the groups in the
// order of their first change.
func Chains(cs []Change) [][]Change {
	var out [][]Change
	for _, c := range cs {
		if !c.Kind.File() {
			continue
		}
		i := slices.IndexFunc(out, func(g []Change) bool { return g[0].Same(c) })
		if i < 0 {
			out = append(out, []Change{c})
		} else {
			out[i] = append(out[i], c)
		}
	}
	return out
}

// Hold marks changes as taken by an apply running now: they can't be discarded until
// Release. It refuses changes no longer pending.
func (s *Store) Hold(ids []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cs, err := s.load()
	if err != nil {
		return err
	}
	for _, id := range ids {
		if !slices.ContainsFunc(cs, func(c Change) bool { return c.ID == id }) {
			return fmt.Errorf("%s: %w", id, ErrNotFound)
		}
	}
	for _, id := range ids {
		s.held[id] = true
	}
	return nil
}

// Release ends a Hold.
func (s *Store) Release(ids []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range ids {
		delete(s.held, id)
	}
}

// MarkWritten marks changes as written into their files by an apply. bases are the files
// as they were before, by the ID of the first change of each file the apply wrote (nil:
// there was no file): what a discard puts back.
func (s *Store) MarkWritten(ids []string, bases map[string][]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, b := range bases {
		if b != nil {
			if err := s.writeText(s.path(id, ".base"), b); err != nil {
				return err
			}
		}
	}
	cs, err := s.load()
	if err != nil {
		return err
	}
	for i := range cs {
		if slices.Contains(ids, cs[i].ID) {
			cs[i].Written = true
		}
	}
	return s.save(cs)
}

// Unwritten undoes MarkWritten for changes whose file the apply didn't write after all (its
// save failed): a discard then leaves the file as it is.
func (s *Store) Unwritten(ids []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cs, err := s.load()
	if err != nil {
		return err
	}
	for i := range cs {
		if slices.Contains(ids, cs[i].ID) {
			cs[i].Written = false
		}
	}
	if err := s.save(cs); err != nil {
		return err
	}
	for _, id := range ids {
		os.Remove(s.path(id, ".base"))
	}
	return nil
}

// Applied removes changes every node has: the apply that sent them ended well.
func (s *Store) Applied(ids []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cs, err := s.load()
	if err != nil {
		return err
	}
	cs = slices.DeleteFunc(cs, func(c Change) bool { return slices.Contains(ids, c.ID) })
	if err := s.save(cs); err != nil {
		return err
	}
	for _, id := range ids {
		s.remove(id)
	}
	return nil
}

// Discarded is what a discard did.
type Discarded struct {
	IDs []string `json:"discarded"`
	// PutBack are the changes left to send files put back to the nodes (written changes).
	PutBack []Change `json:"put_back,omitempty"`
}

// Discard discards a change and the changes of its file stacked on it. A written one puts
// its file back as it was before it (Store doc).
func (s *Store) Discard(id string) (Discarded, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cs, err := s.load()
	if err != nil {
		return Discarded{}, err
	}
	var d Discarded
	cs, err = s.discard(cs, id, &d)
	if err != nil {
		return Discarded{}, err
	}
	return d, s.finish(cs, d)
}

// DiscardAll discards every pending change but the put-back ones (each discarded only by
// itself); none if an apply holds any.
func (s *Store) DiscardAll() (Discarded, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cs, err := s.load()
	if err != nil {
		return Discarded{}, err
	}
	for _, c := range cs {
		if s.held[c.ID] {
			return Discarded{}, fmt.Errorf("%s: %w", c.Summary, ErrHeld)
		}
	}
	var d Discarded
	for len(cs) > 0 {
		// The oldest change left: its file's changes go with it. A put-back change is kept,
		// made here or before: the nodes may hold what was written, and only an apply (or
		// discarding that one change) says otherwise.
		i := slices.IndexFunc(cs, func(c Change) bool { return !c.PutBack })
		if i < 0 {
			break
		}
		if cs, err = s.discard(cs, cs[i].ID, &d); err != nil {
			return Discarded{}, err
		}
	}
	return d, s.finish(cs, d)
}

// finish saves the index after a discard and drops the discarded changes' files.
func (s *Store) finish(cs []Change, d Discarded) error {
	if err := s.save(cs); err != nil {
		return err
	}
	for _, id := range d.IDs {
		s.remove(id)
	}
	return nil
}

// discard takes the change and those stacked on it out of cs, putting a written file
// back; locked.
func (s *Store) discard(cs []Change, id string, d *Discarded) ([]Change, error) {
	i := slices.IndexFunc(cs, func(c Change) bool { return c.ID == id })
	if i < 0 {
		return cs, fmt.Errorf("%s: %w", id, ErrNotFound)
	}
	c := cs[i]
	if !c.Kind.File() {
		if s.held[c.ID] {
			return cs, fmt.Errorf("%s: %w", c.Summary, ErrHeld)
		}
		d.IDs = append(d.IDs, c.ID)
		return slices.Delete(cs, i, i+1), nil
	}
	var chain []Change
	for _, o := range cs {
		if o.Same(c) {
			chain = append(chain, o)
		}
	}
	at := slices.IndexFunc(chain, func(o Change) bool { return o.ID == id })
	gone := chain[at:]
	for _, o := range gone {
		if s.held[o.ID] {
			return cs, fmt.Errorf("%s: %w", o.Summary, ErrHeld)
		}
	}
	if slices.ContainsFunc(gone, func(o Change) bool { return o.Written }) {
		// The file holds what was written: put back what it was before this change.
		var before []byte
		exists := true
		switch {
		case at > 0:
			before, exists = nil, !chain[at-1].Delete
			if exists {
				var err error
				if before, err = s.Text(chain[at-1]); err != nil {
					return cs, err
				}
			}
		case chain[0].Base == "":
			exists = false
		default:
			var err error
			if before, err = os.ReadFile(s.path(chain[0].ID, ".base")); err != nil {
				return cs, fmt.Errorf("the file before %s isn't kept: %v", chain[0].Summary, err)
			}
		}
		if err := s.restore(c.Kind, c.Name, before, exists); err != nil {
			return cs, err
		}
		if at == 0 {
			// No change of the file is left to send it: one that sends it as it is now.
			p := Change{ID: newID(), Kind: c.Kind, Name: c.Name, Delete: !exists, Base: "", Hash: "", PutBack: true,
				Summary: "Put back on the nodes: " + strings.TrimPrefix(c.Summary, "Put back on the nodes: "),
				Who:     c.Who, Created: time.Now().UTC()}
			if exists {
				p.Base, p.Hash = filestore.Hash(before), filestore.Hash(before)
				if err := s.writeText(s.path(p.ID, ".txt"), before); err != nil {
					return cs, err
				}
			}
			cs = append(cs, p)
			d.PutBack = append(d.PutBack, p)
		}
	}
	for _, o := range gone {
		d.IDs = append(d.IDs, o.ID)
	}
	return slices.DeleteFunc(cs, func(o Change) bool { return slices.ContainsFunc(gone, func(g Change) bool { return g.ID == o.ID }) }), nil
}

// restore makes the file text (or none), through its store, kept in its history.
func (s *Store) restore(k Kind, name string, text []byte, exists bool) error {
	st, _ := FileStore(s.dataDir, k)
	cur, err := Current(s.dataDir, k, name)
	if err != nil {
		return err
	}
	switch {
	case !exists && !cur.Exists:
		return nil
	case !exists:
		return st.Delete(name, cur.Hash)
	case cur.Exists && cur.Hash == filestore.Hash(text):
		return nil
	}
	return st.Save(name, text, cur.Hash)
}

// sums is sent.json: by list, the compiled files' SHA-256 the nodes may still run.
func (s *Store) sums() (map[string][]string, error) {
	m := map[string][]string{}
	b, err := os.ReadFile(filepath.Join(s.dir(), SentFile))
	if errors.Is(err, fs.ErrNotExist) {
		return m, nil
	}
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return map[string][]string{}, fmt.Errorf("%s: %v", filepath.Join(s.dir(), SentFile), err)
	}
	return m, nil
}

func (s *Store) saveSums(m map[string][]string) error {
	b, err := json.MarshalIndent(m, "", " ")
	if err != nil {
		return err
	}
	return s.writeText(filepath.Join(s.dir(), SentFile), append(b, '\n'))
}

// ListSums are the compiled files of a list (SHA-256, hex) the nodes ran when an apply
// compiled it again and didn't end well: a node running one of them is the list's node,
// though the compiled file is the newer one already.
func (s *Store) ListSums(list string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, _ := s.sums()
	return m[list]
}

// RememberListSum keeps a list's compiled file (its SHA-256) before an apply compiles it
// again, until an apply sending the list ends well (ForgetListSums).
func (s *Store) RememberListSum(list, sum string) error {
	if sum == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.sums()
	if err != nil {
		return err
	}
	if slices.Contains(m[list], sum) {
		return nil
	}
	m[list] = append(m[list], sum)
	if n := len(m[list]); n > MaxSums {
		m[list] = m[list][n-MaxSums:]
	}
	return s.saveSums(m)
}

// ForgetListSums drops the lists' remembered compiled files: every node they go to has
// the new one.
func (s *Store) ForgetListSums(lists []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.sums()
	if err != nil {
		return err
	}
	n := len(m)
	for _, l := range lists {
		delete(m, l)
	}
	if len(m) == n {
		return nil
	}
	return s.saveSums(m)
}
