package zonefiles

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/configs"
	"github.com/skitzo2000/espdns/controller/internal/fleet"
	"github.com/skitzo2000/espdns/controller/internal/nodecfg"
	"github.com/skitzo2000/espdns/controller/internal/release"
	"github.com/skitzo2000/espdns/controller/internal/zones"
)

// ---- which nodes serve a zone ------------------------------------------------------------

// Serving is a node that serves a zone, and whether it is the file as saved.
type Serving struct {
	Host    string `json:"host"`
	Serial  uint32 `json:"serial"`
	Records int    `json:"records"`
	// State: "file" (the file as saved), "other" (another version of the zone: pushed from
	// a file that changed since, or from elsewhere), "unrecorded" (no record here of the
	// set it serves, nor a hash to compare: compared by serial and records only).
	State string `json:"state"`
	Text  string `json:"text"`
}

// served is the zone's entry in the node's /status hosted zones.
func served(st release.NodeStatus, zone string) (uint32, int, bool) {
	if st.Hosted == nil {
		return 0, 0, false
	}
	for _, z := range st.Hosted.Zones {
		if strings.EqualFold(strings.TrimSuffix(z.Name, "."), zone) {
			return z.Serial, z.Records, true
		}
	}
	return 0, 0, false
}

// Match is whether the node's whole hosted set is the files here, by the hash it reports
// of the bundle it runs.
type Match int

const (
	MatchUnknown Match = iota // a zone it serves has no file here that passes, or no hash reported
	MatchFiles                // the bundle of the files here for the zones it serves is the one it runs
	MatchNot                  // it is not: at least one of its zones differs from its file
)

// SetMatch compares the bundle the node at st runs with the bundle of the files here for
// the zones it serves (byte for byte, by its hash): equal, every zone it serves is its file
// as saved, however it was pushed.
func SetMatch(files []File, st release.NodeStatus) Match {
	if st.Hosted == nil || st.Hosted.SHA256 == "" || len(st.Hosted.Zones) == 0 {
		return MatchUnknown
	}
	set := &zones.Set{}
	for _, hz := range st.Hosted.Zones {
		name := strings.ToLower(strings.TrimSuffix(hz.Name, ".")) + ".zone"
		i := slices.IndexFunc(files, func(f File) bool { return f.Name == name })
		if i < 0 || files[i].Parsed == nil {
			return MatchUnknown
		}
		set.Zones = append(set.Zones, files[i].Parsed)
	}
	b, err := set.Bundle(0)
	if err != nil {
		return MatchUnknown
	}
	sum := sha256.Sum256(b)
	if strings.EqualFold(hex.EncodeToString(sum[:]), st.Hosted.SHA256) {
		return MatchFiles
	}
	return MatchNot
}

// Serves says whether the node at host, whose /status is st, serves the zone of f, and
// whether what it serves is f as saved: by m (SetMatch, its whole set by hash), else by the
// record of the zones last pushed to it, which holds while its hosted seq is the one
// recorded, else by serial and records only.
func Serves(dataDir string, f File, host string, st release.NodeStatus, m Match) (Serving, bool) {
	serial, records, ok := served(st, f.Zone)
	if !ok {
		return Serving{}, false
	}
	s := Serving{Host: host, Serial: serial, Records: records}
	if m == MatchFiles {
		s.State, s.Text = "file", fmt.Sprintf("serves this file as saved (serial %d, hosted seq %d: the set it runs is the files here, by its hash)",
			serial, st.Hosted.Seq)
		return s, true
	}
	p, err := LoadPushed(dataDir, st.NodeID)
	if err == nil && p != nil && p.Seq == st.Hosted.Seq {
		if h, ok := p.Files[f.Name]; ok {
			at := p.Time.Format("2006-01-02 15:04")
			if h == f.Hash {
				s.State, s.Text = "file", fmt.Sprintf("serves this file as saved (serial %d, hosted seq %d, pushed %s)", serial, p.Seq, at)
			} else {
				s.State, s.Text = "other", fmt.Sprintf("serves another version of this zone (serial %d, hosted seq %d, pushed %s): "+
					"not the file as saved", serial, p.Seq, at)
			}
			return s, true
		}
	}
	if m == MatchNot && len(st.Hosted.Zones) == 1 {
		s.State, s.Text = "other", fmt.Sprintf("serves another version of this zone (serial %d, %d records): not the file as saved, "+
			"by the hash of the set it runs", serial, records)
		return s, true
	}
	s.State = "unrecorded"
	switch {
	case f.Error != "":
		s.Text = fmt.Sprintf("serves serial %d, %d records (the file doesn't pass its checks)", serial, records)
	case serial == f.Serial && records == f.Records && m == MatchNot:
		s.Text = fmt.Sprintf("serves serial %d, %d records, as the file; but the set it runs is not the files here, by its hash: "+
			"this zone or another differs (pushed without a record here)", serial, records)
	case serial == f.Serial && records == f.Records:
		s.Text = fmt.Sprintf("serves serial %d, %d records, as the file (pushed without a record here: compared by serial only)", serial, records)
	default:
		s.Text = fmt.Sprintf("serves serial %d, %d records; the file has serial %d, %d records (pushed without a record here)",
			serial, records, f.Serial, f.Records)
	}
	return s, true
}

// NodeConfig is the node config the node runs, for the editor's check of its secondary and
// forward zones: the config last pushed to it, while its seq is the node's; else none (its
// /status secondary and forward zones are checked either way). from says which.
func NodeConfig(dataDir string, st release.NodeStatus) (*nodecfg.Config, string) {
	if st.Config == nil {
		return nil, ""
	}
	if st.Config.Source != "node" {
		return &nodecfg.Config{}, "no pushed config: the board's and firmware's settings"
	}
	if p, err := configs.LoadPushed(dataDir, st.NodeID); err == nil && p != nil && p.Seq == st.Config.Seq {
		if c, err := nodecfg.Parse(p.Payload); err == nil {
			return c, fmt.Sprintf("%s, as pushed to it (config seq %d)", p.File, p.Seq)
		}
	}
	return nil, ""
}

// Secondary are the node's secondary zones as its /status reports them.
func Secondary(st release.NodeStatus) []string {
	var out []string
	for _, z := range st.Zones {
		out = append(out, z.Name)
	}
	return out
}

// ---- the editor's check -----------------------------------------------------------------

// Node is a node the check runs against.
type Node struct {
	Host   string
	Listed bool                // in settings.json: a push goes to it
	Status *release.NodeStatus // nil: no /status read yet
}

// Check is one zone's text checked for the editor: espdns zones -check (internal/zones,
// Check: the same code), then, for each node, the set it would get from here (the zones it
// serves now that have files here, with this one as edited) checked as a push to it checks
// it: its limit, its config's secondary and forward zones and the secondary zones it
// reports, the rollout's refusals (fleet.Change.Prepare).
type Check struct {
	DataDir string
	Name    string // home.example.zone
	Text    []byte
	Saved   *File // the file as saved; nil for a new one
	Nodes   []Node
	Now     time.Time
}

// NodeResult is the check against one node.
type NodeResult struct {
	Host   string `json:"host"`
	Listed bool   `json:"listed"`
	// Serves: the node serves the zone now, at Serial.
	Serves bool   `json:"serves"`
	Serial uint32 `json:"serial,omitempty"`
	// Set is the zone files the set checked holds; Missing the zones the node serves that
	// have no file here that passes (a push from here leaves them out: the node drops them).
	Set     []string `json:"set"`
	Missing []string `json:"missing,omitempty"`
	// Lines is what espdns zones -check says of the set with the node's limit and config.
	Lines     []string `json:"lines,omitempty"`
	Mem       int      `json:"mem"`
	Bytes     int      `json:"bytes"`
	LimitKB   int      `json:"limit_kb"`
	Config    string   `json:"config,omitempty"`    // where its secondary and forward zones are read from
	Secondary []string `json:"secondary,omitempty"` // its secondary zones, as it reports them
	Refused   string   `json:"refused,omitempty"`
}

// Result is a Check's outcome.
type Result struct {
	OK bool `json:"ok"` // passes alone and against every node
	// Error is why the zone itself doesn't pass (espdns zones -check's error).
	Error   string   `json:"error,omitempty"`
	Command string   `json:"command"` // the CLI's equivalent
	Lines   []string `json:"lines"`   // what it says
	Zone    string   `json:"zone"`
	Serial  uint32   `json:"serial"`
	Records int      `json:"records"`
	Mem     int      `json:"mem"`
	Bytes   int      `json:"bytes"`
	LimitKB int      `json:"limit_kb"`
	// The records as the node gets them (at most MaxShown), More the rest's count.
	List []zones.RecordText `json:"list"`
	More int                `json:"more,omitempty"`
	// The serial: the saved file's, and whether the edit raised it above the saved file's
	// and above what the nodes serve; NextSerial is the one "bump" sets.
	SavedSerial uint32             `json:"saved_serial,omitempty"`
	SerialWarn  string             `json:"serial_warn,omitempty"`
	NextSerial  uint32             `json:"next_serial,omitempty"`
	Nodes       []NodeResult       `json:"nodes"`
	Diff        []configs.DiffLine `json:"diff,omitempty"`
}

// MaxShown is how many records the check lists.
const MaxShown = 500

// Run checks the zone. It never fails: what doesn't pass is in the result.
func (c Check) Run(ctx context.Context) Result {
	r := Result{Zone: ZoneOf(c.Name), Nodes: []NodeResult{}, List: []zones.RecordText{},
		Command: fmt.Sprintf("espdns zones -zone %s -check", c.Name), LimitKB: zones.DefaultLimitKB}
	if c.Saved != nil {
		r.Diff = configs.Diff(c.Saved.Text, c.Text)
		r.SavedSerial = c.Saved.Serial
	}
	if err := CheckName(c.Name); err != nil {
		r.Error = err.Error()
		return r
	}
	// espdns zones -zone <name> -check: the file parsed (zones.LoadFile), then zones.Check.
	z, err := zones.ParseMaster(r.Zone, bytes.NewReader(c.Text), c.Name)
	if err != nil {
		r.Error = err.Error()
		return r
	}
	ck, err := zones.Check(&zones.Set{Zones: []*zones.Zone{z}}, nil, zones.DefaultLimitKB)
	r.Lines, r.Mem, r.Bytes = ck.Lines, ck.Mem, len(ck.Payload)
	if err != nil {
		r.Error = err.Error()
		return r
	}
	r.Serial, r.Records = z.Serial(), len(z.Records)
	r.List = z.Texts(MaxShown)
	r.More = len(z.Records) - len(r.List)

	files, _ := List(c.DataDir)
	r.OK = true
	var servedSerials []uint32
	for _, n := range c.Nodes {
		nr := c.node(ctx, n, z, files)
		if nr.Serves {
			servedSerials = append(servedSerials, nr.Serial)
		}
		if nr.Refused != "" && n.Listed {
			r.OK = false
		}
		r.Nodes = append(r.Nodes, nr)
	}
	// The serial: raised with every change, so what serves it can tell an edit (and a
	// person reading the SOA can).
	edited := c.Saved == nil || !bytes.Equal(c.Saved.Text, c.Text)
	top, from := uint32(0), ""
	if c.Saved != nil && c.Saved.Error == "" {
		top, from = c.Saved.Serial, "the saved file's"
	}
	for _, s := range servedSerials {
		if from == "" || zones.SerialAbove(s, top) {
			top, from = s, "what a node serves"
		}
	}
	// Compared as a secondary compares serials (RFC 1982).
	if edited && from != "" && !zones.SerialAbove(r.Serial, top) {
		r.SerialWarn = fmt.Sprintf("the SOA serial %d is not above %s (%d): raise it with every change", r.Serial, from, top)
	}
	above := servedSerials
	if c.Saved != nil && c.Saved.Error == "" {
		above = append(above, c.Saved.Serial)
	}
	now := c.Now
	if now.IsZero() {
		now = time.Now()
	}
	r.NextSerial = zones.NextSerial(r.Serial, above, now)
	return r
}

// node checks the set the node would get from here.
func (c Check) node(ctx context.Context, n Node, z *zones.Zone, files []File) NodeResult {
	nr := NodeResult{Host: n.Host, Listed: n.Listed, Set: []string{c.Name}}
	if n.Status == nil {
		nr.Refused = "no /status read from it yet"
		return nr
	}
	st := *n.Status
	nr.Secondary = Secondary(st)
	nr.Serial, _, nr.Serves = served(st, ZoneOf(c.Name))
	set := &zones.Set{}
	if st.Hosted != nil {
		nr.LimitKB = st.Hosted.LimitBytes / 1024
		for _, hz := range st.Hosted.Zones {
			name := strings.ToLower(strings.TrimSuffix(hz.Name, ".")) + ".zone"
			if name == c.Name {
				continue
			}
			i := slices.IndexFunc(files, func(f File) bool { return f.Name == name })
			if i < 0 || files[i].Parsed == nil {
				nr.Missing = append(nr.Missing, strings.TrimSuffix(name, ".zone"))
				continue
			}
			set.Zones = append(set.Zones, files[i].Parsed)
			nr.Set = append(nr.Set, name)
		}
	}
	set.Zones = append(set.Zones, z)
	slices.Sort(nr.Set)
	cfg, from := NodeConfig(c.DataDir, st)
	nr.Config = from
	if st.Hosted == nil {
		_, err := set.Payload(n.Host, st)
		nr.Refused = err.Error()
		return nr
	}
	// espdns zones -check -limit-kb <its limit> -config <its config>, on the set.
	ck, err := zones.Check(set, cfg, nr.LimitKB)
	nr.Lines, nr.Mem, nr.Bytes = ck.Lines, ck.Mem, len(ck.Payload)
	if err != nil {
		nr.Refused = err.Error()
		if cfg != nil && strings.Contains(err.Error(), "secondary or forward zone") {
			nr.Refused += " (" + from + ")"
		}
		return nr
	}
	// The rollout's own refusals for the node (hosted zones off in its config, a secondary
	// zone it reports, ...): the same code as a push's (fleet.Change.Prepare).
	ch := fleet.Change{Kind: release.Zones, Payload: func(_ context.Context, h string, st release.NodeStatus) ([]byte, error) {
		return set.Payload(h, st)
	}}
	if _, _, err := ch.Prepare(ctx, n.Host, st); err != nil {
		nr.Refused = err.Error()
	}
	return nr
}
