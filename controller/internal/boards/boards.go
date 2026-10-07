// Package boards is the board catalog: board definitions as data (docs/design.md, Boards and
// images). It loads them, checks them the way the firmware does plus each chip's pin rules,
// and packs one into a node's `board` partition.
package boards

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/skitzo2000/espdns/controller/internal/memplan"
	"github.com/skitzo2000/espdns/controller/internal/nodecfg"
	"github.com/skitzo2000/espdns/controller/internal/secfile"
)

// Board is one catalog file (boards/README.md). Pins are pointers: nil is "not connected" or
// "the chip's default".
type Board struct {
	Name     string    `json:"name"`
	Title    string    `json:"title,omitempty"`
	Image    string    `json:"image"`
	FlashMB  int       `json:"flash_mb,omitempty"`
	PSRAMMB  *int      `json:"psram_mb,omitempty"` // nil: not given (the chip's, as the node finds it)
	Tier     string    `json:"tier,omitempty"`
	SPI      []SPIBus  `json:"spi,omitempty"`
	Ethernet *Ethernet `json:"ethernet,omitempty"`
	SD       *SD       `json:"sd,omitempty"`
	LED      *LED      `json:"led,omitempty"`
	WiFi     *WiFi     `json:"wifi,omitempty"`
	Memory   *Memory   `json:"memory,omitempty"`
	CPU      *CPU      `json:"cpu,omitempty"`
	// Network is the node's address until a node config gives one. Per node, not hardware:
	// the builder adds it to the board partition of the node it flashes, and catalog and
	// saved boards leave it out. A node with none has no address: it never asks DHCP on its
	// own (docs/design.md, Adoption and addressing).
	Network *nodecfg.Network `json:"network,omitempty"`
	Notes   string           `json:"notes,omitempty"`
}

type SPIBus struct {
	Host int  `json:"host"`
	SCLK *int `json:"sclk,omitempty"`
	MOSI *int `json:"mosi,omitempty"`
	MISO *int `json:"miso,omitempty"`
}

type Ethernet struct {
	Kind     string `json:"kind"`
	Optional bool   `json:"optional,omitempty"`
	// Built-in MAC ("emac")
	PHY       string     `json:"phy,omitempty"`
	Addr      *int       `json:"addr,omitempty"`
	Reset     *int       `json:"reset,omitempty"`
	Power     *int       `json:"power,omitempty"`
	MDC       *int       `json:"mdc,omitempty"`
	MDIO      *int       `json:"mdio,omitempty"`
	RMIIClock *RMIIClock `json:"rmii_clock,omitempty"`
	// SPI chip ("w5500")
	SPIHost int  `json:"spi_host,omitempty"`
	CS      *int `json:"cs,omitempty"`
	Int     *int `json:"int,omitempty"`
	Rst     *int `json:"rst,omitempty"`
	MHz     int  `json:"mhz,omitempty"`
}

type RMIIClock struct {
	Mode string `json:"mode"`
	GPIO *int   `json:"gpio,omitempty"`
}

type SD struct {
	Kind    string `json:"kind"`
	Slot    *int   `json:"slot,omitempty"`
	Width   int    `json:"width,omitempty"`
	LDO     *int   `json:"ldo,omitempty"`
	SPIHost int    `json:"spi_host,omitempty"`
	CS      *int   `json:"cs,omitempty"`
}

type LED struct {
	Kind      string `json:"kind"`
	Pin       *int   `json:"pin,omitempty"`
	ActiveLow bool   `json:"active_low,omitempty"`
}

type WiFi struct {
	TxPowerDBm int `json:"tx_power_dbm,omitempty"`
}

// Memory holds the board's memory plan values (internal/memplan; firmware memplan.h), in KB
// except CacheEntries; one left out (nil) is the chip image's default.
type Memory struct {
	// InternalKB: internal RAM the services may take, besides the system's.
	InternalKB *int `json:"internal_kb,omitempty"`
	// CacheKB and CacheEntries: the DNS cache, and the most answers it holds.
	CacheKB      *int `json:"cache_kb,omitempty"`
	CacheEntries *int `json:"cache_entries,omitempty"`
	// BlocklistKB: the lists and overrides, two copies of each during a live swap.
	// BlocklistIndexKB: internal RAM for their indexes; 0 puts them with the lists.
	BlocklistKB      *int `json:"blocklist_kb,omitempty"`
	BlocklistIndexKB *int `json:"blocklist_index_kb,omitempty"`
	// HostedZonesKB: the most the hosted zones may take (firmware hzone.h; zones.Set.Mem).
	HostedZonesKB *int `json:"hosted_zones_kb,omitempty"`
	// SecondaryZonesKB: every secondary zone, with a new copy during a transfer.
	SecondaryZonesKB *int `json:"secondary_zones_kb,omitempty"`
	// QueryLogKB: the query log's ring of recent queries (160 bytes each); 0: no query log.
	QueryLogKB *int `json:"querylog_kb,omitempty"`
	// FwdPending: how many upstream queries may be outstanding at once (a count, not KB).
	FwdPending *int `json:"fwd_pending,omitempty"`
}

// MemoryKeys are the board's settings for the memory plan.
func (b Board) MemoryKeys() memplan.Keys {
	k := memplan.Keys{}
	if b.PSRAMMB != nil {
		k.PSRAMMB = b.PSRAMMB
	}
	if m := b.Memory; m != nil {
		k.InternalKB, k.CacheKB, k.CacheEntries = m.InternalKB, m.CacheKB, m.CacheEntries
		k.BlocklistKB, k.BlocklistIndexKB = m.BlocklistKB, m.BlocklistIndexKB
		k.HostedZonesKB, k.SecondaryZonesKB = m.HostedZonesKB, m.SecondaryZonesKB
		k.QueryLogKB, k.FwdPending = m.QueryLogKB, m.FwdPending
	}
	return k
}

// Entry is a board in the catalog, with where it came from and what the checks found.
type Entry struct {
	Board    Board    `json:"board"`
	Source   string   `json:"source"` // "catalog" (shipped) or "custom" (data/boards)
	Errors   []string `json:"errors"`
	Warnings []string `json:"warnings"`
	raw      []byte   // the file as written, so a shipped board packs byte-for-byte as tools/boardpart.py does
}

// Parse reads a board definition, refusing unknown fields (a typo would otherwise be silently
// ignored, and the firmware would run without that setting).
func Parse(b []byte) (Board, error) {
	var bd Board
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&bd); err != nil {
		return bd, err
	}
	return bd, nil
}

// Load reads every *.json in the catalog directory (shipped boards) and the custom directory
// (data/boards). A custom board with a shipped board's name is left out, with an error entry.
func Load(catalogDir, customDir string) ([]Entry, error) {
	var out []Entry
	seen := map[string]bool{}
	for _, src := range []struct{ dir, name string }{{catalogDir, "catalog"}, {customDir, "custom"}} {
		if src.dir == "" {
			continue
		}
		files, err := filepath.Glob(filepath.Join(src.dir, "*.json"))
		if err != nil {
			return nil, err
		}
		sort.Strings(files)
		for _, f := range files {
			raw, err := os.ReadFile(f)
			if err != nil {
				return nil, err
			}
			e := Entry{Source: src.name, raw: raw}
			bd, err := Parse(raw)
			e.Board = bd
			if err != nil {
				e.Board.Name = strings.TrimSuffix(filepath.Base(f), ".json")
				e.Errors = []string{fmt.Sprintf("%s: %v", filepath.Base(f), err)}
				e.Warnings = []string{}
			} else {
				e.Errors, e.Warnings = Check(bd)
				if seen[bd.Name] {
					e.Errors = append(e.Errors, fmt.Sprintf("another board is already called %s", bd.Name))
				}
			}
			seen[e.Board.Name] = true
			out = append(out, e)
		}
	}
	return out, nil
}

// Find returns the entry called name.
func Find(entries []Entry, name string) (Entry, bool) {
	for _, e := range entries {
		if e.Board.Name == name {
			return e, true
		}
	}
	return Entry{}, false
}

// Save writes a custom board to dir as <name>.json, refusing a shipped board's name.
func Save(dir string, bd Board, entries []Entry) error {
	if e, ok := Find(entries, bd.Name); ok && e.Source == "catalog" {
		return fmt.Errorf("%s is a catalog board: save yours under another name", bd.Name)
	}
	if bd.Network != nil {
		return errors.New("network: the address is per node, given when it is flashed, not saved with the board")
	}
	if errs, _ := Check(bd); len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	if err := secfile.MkdirAll(dir); err != nil {
		return err
	}
	b, err := json.MarshalIndent(bd, "", "  ")
	if err != nil {
		return err
	}
	return secfile.WriteFile(filepath.Join(dir, bd.Name+".json"), append(b, '\n'))
}

const (
	partSize   = 4096
	partHeader = 16
)

// Pack builds the `board` partition (firmware/main/board_def.h): "EDBD", version 1, 0, JSON
// length, CRC-32 of the JSON, the JSON; padded with 0xFF to 4 KB.
func (e Entry) Pack() ([]byte, error) {
	var body []byte
	if e.raw != nil {
		var buf bytes.Buffer
		if err := json.Compact(&buf, e.raw); err != nil {
			return nil, err
		}
		body = buf.Bytes()
	} else {
		var err error
		if body, err = json.Marshal(e.Board); err != nil {
			return nil, err
		}
	}
	return PackJSON(body)
}

// PackJSON wraps a compact JSON definition in the partition header.
func PackJSON(body []byte) ([]byte, error) {
	if len(body) > partSize-partHeader {
		return nil, fmt.Errorf("board definition is %d bytes; at most %d fit", len(body), partSize-partHeader)
	}
	p := bytes.Repeat([]byte{0xFF}, partSize)
	copy(p, "EDBD")
	binary.LittleEndian.PutUint16(p[4:], 1)
	binary.LittleEndian.PutUint16(p[6:], 0)
	binary.LittleEndian.PutUint32(p[8:], uint32(len(body)))
	binary.LittleEndian.PutUint32(p[12:], crc32.ChecksumIEEE(body))
	copy(p[partHeader:], body)
	return p, nil
}

// WithChanges returns the entry with b as its board, packed from b (not the original file).
func (e Entry) WithChanges(b Board) Entry {
	e.Board = b
	e.raw = nil
	e.Errors, e.Warnings = Check(b)
	return e
}
