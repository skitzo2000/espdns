package configs

import (
	"encoding/json"
	"fmt"

	"github.com/skitzo2000/espdns/controller/internal/memplan"
	"github.com/skitzo2000/espdns/controller/internal/nodecfg"
	"github.com/skitzo2000/espdns/controller/internal/release"
)

// Check is one config checked for the editor: espdns config -check (the node's checks, the
// payload), the memory plan on a catalog board (-check -board) and on the node it is for,
// the refusals a config rollout makes for that node, what the change does on the node
// (live, or with a reboot) and the diff against the file as saved.
type Check struct {
	Name    string
	Text    []byte // the text checked, with any Hidden password already put back (Unmask)
	Saved   *File  // the file as saved, nil for a new one
	Catalog string // the board catalog
	Board   string // a catalog board to plan on, as -board ("" for none)
	// The node the config is for, if any: its address and /status.
	Host    string
	Status  *release.NodeStatus
	DataDir string
	// Addressing, if set, checks the config's address for the node (AddressRefusal: no DHCP
	// on a no_dhcp network, a move only onto a free address).
	Addressing *Addressing
}

// Result is a Check's outcome. Nothing in it holds the Wi-Fi password: the payload, the
// config and the diff have Hidden in its place.
type Result struct {
	// OK: the config passes its checks, its memory plans fit, and the node (if one is
	// given) takes it.
	OK bool `json:"ok"`
	// Error is the config's own check, as espdns config -check says it ("" if it passes).
	Error    string          `json:"error,omitempty"`
	Bytes    int             `json:"bytes,omitempty"`
	Payload  string          `json:"payload,omitempty"`
	Config   json.RawMessage `json:"config,omitempty"`
	Services []string        `json:"services,omitempty"`
	Memory   []Memory        `json:"memory,omitempty"`
	CPU      []CPU           `json:"cpu,omitempty"`
	Node     *Node           `json:"node,omitempty"`
	// Diff is against the file as saved (none for a new file, or when it is the same).
	Diff    []DiffLine `json:"diff,omitempty"`
	Changed bool       `json:"changed"`
}

// Memory is the memory plan on one board, in KB.
type Memory struct {
	Board      string              `json:"board"`
	From       string              `json:"from"` // "catalog board", "as it reports", ...
	Fits       bool                `json:"fits"`
	Error      string              `json:"error,omitempty"`
	InternalKB [2]int64            `json:"internal_kb"` // used, capacity
	PSRAMKB    [2]int64            `json:"psram_kb"`
	Shares     map[string][2]int64 `json:"shares_kb,omitempty"` // per service: internal, PSRAM
}

func memoryOf(board, from string, p memplan.Plan, err error) Memory {
	m := Memory{Board: board, From: from, Fits: err == nil,
		InternalKB: [2]int64{kb(p.Total[memplan.Internal]), p.Capacity[memplan.Internal] / 1024},
		PSRAMKB:    [2]int64{kb(p.Total[memplan.PSRAM]), p.Capacity[memplan.PSRAM] / 1024}, Shares: map[string][2]int64{}}
	if err != nil {
		m.Error = err.Error()
	}
	for s, v := range p.Shares {
		if v[0]+v[1] > 0 {
			m.Shares[s] = [2]int64{kb(v[0]), kb(v[1])}
		}
	}
	return m
}

func kb(n int64) int64 { return (n + 1023) / 1024 }

// CPU is the clock scaling the config gives on a board or node.
type CPU struct {
	On     string `json:"on"` // the board or node
	DFS    bool   `json:"dfs"`
	From   string `json:"from"` // "config", "board", "image", or "unchanged (...)"
	MaxMHz int    `json:"max_mhz,omitempty"`
	MinMHz int    `json:"min_mhz,omitempty"`
	Known  bool   `json:"known"` // false: the node's default, which only the node knows
}

// Node is the check against the node the config is for.
type Node struct {
	Host   string `json:"host"`
	NodeID string `json:"node_id"`
	// Refusal is why a config rollout refuses the config for this node ("" if it doesn't).
	Refusal string `json:"refusal,omitempty"`
	// Address is why a push refuses the config's address for this node (AddressRefusal: DHCP
	// on a network with none, a move onto a taken address); "" if it doesn't.
	Address string `json:"address,omitempty"`
	// Moves is the new address, when the config moves the node: the push then reboots it
	// there and confirms it (as espdns config -reboot), and it comes up on trial.
	Moves   string         `json:"moves,omitempty"`
	Running Running        `json:"running"`
	Change  nodecfg.Change `json:"change"`
	// Pending is a reboot the node already waits for, before this config.
	Pending []string `json:"pending,omitempty"`
}

// Run checks the config. It never fails: what doesn't pass is in the result.
func (c Check) Run() Result {
	var r Result
	if c.Saved != nil {
		a, _ := Mask(c.Saved.Text)
		b, _ := Mask(c.Text)
		r.Diff = Diff(a, b)
		r.Changed = string(c.Saved.Text) != string(c.Text)
	} else {
		r.Changed = true
	}
	path := c.Name
	if path == "" {
		path = "config"
	}
	spec, err := ParseSpec(c.Host, path, c.Text)
	if err != nil {
		r.Error = err.Error()
		return r
	}
	masked, _ := Mask(spec.Payload)
	r.Bytes, r.Payload, r.Services = len(spec.Payload), string(masked), spec.Config.Services()
	if cfg, err := json.Marshal(spec.Config); err == nil {
		r.Config, _ = Mask(cfg)
	}
	r.OK = true

	// The memory plan on a catalog board, as -check -board.
	if c.Board != "" {
		b, err := CatalogBoard(c.Catalog, c.Board)
		if err != nil {
			r.Memory = append(r.Memory, Memory{Board: c.Board, From: "catalog board", Error: err.Error()})
			r.OK = false
		} else {
			p, err := BoardPlan(spec.Config, c.Board, b)
			r.Memory = append(r.Memory, memoryOf(c.Board, "catalog board", p, err))
			r.OK = r.OK && err == nil
			cpu := CPU{On: "catalog board " + c.Board, From: "board", Known: true}
			cpu.DFS, cpu.MaxMHz, cpu.MinMHz = b.CPUPlan()
			if b.CPU == nil || b.CPU.DFS == nil {
				cpu.From = "image"
			}
			if spec.Config.CPU != nil && spec.Config.CPU.DFS != nil {
				cpu.DFS, cpu.From = *spec.Config.CPU.DFS, "config"
			}
			r.CPU = append(r.CPU, cpu)
		}
	}

	// The node it is for: its memory, the rollout's refusals, what the change does there.
	if c.Status != nil {
		st := *c.Status
		n := &Node{Host: c.Host, NodeID: st.NodeID}
		if mb, from, ok := NodeMemory(st, c.Catalog); ok {
			p, err := memplan.Make(mb, spec.Config.Services())
			board := st.Board
			if board == "" {
				board = c.Host
			}
			r.Memory = append(r.Memory, memoryOf(board, "node "+c.Host+", "+from, p, err))
		}
		if a, ok := spec.Moves(); ok {
			n.Moves = a.String()
		}
		if err := spec.Refusal(st, c.Catalog); err != nil {
			n.Refusal = err.Error()
			r.OK = false
		}
		if c.Addressing != nil {
			if err := spec.AddressRefusal(*c.Addressing, &st); err != nil {
				n.Address = err.Error()
				r.OK = false
			}
		}
		if st.Reboot != nil && st.Reboot.Pending {
			n.Pending = st.Reboot.Reasons
		}
		n.Running = NodeRuns(c.DataDir, c.Name, c.Saved, st)
		n.Change = nodecfg.Compare(n.Running.Config, spec.Config, RunningNetwork(st))
		if n.Running.Config == nil && n.Running.State == "unknown" {
			n.Change = nodecfg.Change{}
		}
		r.Node = n
		if st.CPU != nil {
			cpu := CPU{On: "node " + c.Host, DFS: st.CPU.DFS, MaxMHz: st.CPU.MaxMHz, MinMHz: st.CPU.MinMHz, Known: true,
				From: fmt.Sprintf("unchanged (%s)", st.CPU.From)}
			switch {
			case spec.Config.CPU != nil && spec.Config.CPU.DFS != nil:
				cpu.DFS, cpu.From = *spec.Config.CPU.DFS, "config"
			case st.CPU.From == "config":
				cpu.From, cpu.Known = "the board's or image's default (the config no longer says)", false
			}
			r.CPU = append(r.CPU, cpu)
		}
	}
	for _, m := range r.Memory {
		r.OK = r.OK && m.Fits
	}
	return r
}
