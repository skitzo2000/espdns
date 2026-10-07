package blocklist

import (
	"encoding/binary"
	"errors"

	"github.com/skitzo2000/espdns/controller/internal/blockfmt"
)

// Where a node puts a list (firmware/main/block.h, blk_plan and blk_place; docs/design.md,
// Lookup tiers), worked out here so a rollout knows before it pushes: the RAM tier, the SD
// tier, or refused, and whether it loads now or at the next reboot. The C and this give the
// same answers on the shared vectors (firmware/tests/place_vectors.json).

// Need is what loading a list file costs in each tier, bytes (blk_need_t).
type Need struct {
	Front   int64  // before the sectors: the header, indexes and filters
	Index   int64  // every table's index
	Sectors int64  // the rest of the file
	Entries uint32 // hashes in the block tables
}

// PlanNeed reads what a list file costs from its first FileHeader bytes and its length.
func PlanNeed(hdr []byte, fileLen int64) (Need, error) {
	var n Need
	if len(hdr) < FileHeader || string(hdr[:8]) != FileMagic {
		return n, errors.New("not a blocklist")
	}
	le := binary.LittleEndian.Uint32
	n.Front = int64(le(hdr[32+12:]))
	if n.Front < 96 || hdr[8] != 1 && hdr[8] != 2 {
		return Need{}, errors.New("not a blocklist")
	}
	if n.Front > fileLen {
		return Need{}, errors.New("list cut short")
	}
	tables := NTables
	if hdr[8] == 1 {
		tables = 2
	}
	for i := 0; i < tables; i++ {
		sectors := int64(le(hdr[32+32*i+4:]))
		if sectors > fileLen/blockfmt.Sector {
			return Need{}, errors.New("bad table size")
		}
		n.Index += 8 * sectors
	}
	n.Entries = le(hdr[32:]) + le(hdr[64:])
	n.Sectors = fileLen - n.Front
	return n, nil
}

// Room is the blocking service's share of the node's memory plan and what is in it, bytes
// (blk_room_t): never free heap.
type Room struct {
	Budget, Used, Held                int64 // the lists' memory (memory.blocklist_kb): the share, what the lists take, what the one replaced takes of that
	IndexBudget, IndexUsed, IndexHeld int64 // internal RAM for indexes (memory.blocklist_index_kb), the same
	RAMTier                           bool  // the lists' memory is PSRAM: whole tables fit there
	Overrides                         bool  // the overrides: the RAM tier, and live only
}

// Tier is where a list's lookups read their sectors.
type Tier int

const (
	RAMTier Tier = iota
	SDTier
)

func (t Tier) String() string {
	if t == SDTier {
		return "SD tier"
	}
	return "RAM tier"
}

// Placement is where a list goes (blk_place_t).
type Placement struct {
	Tier          Tier
	IndexInternal bool // its indexes in internal RAM (loading now)
	Now           bool // it fits next to the list it replaces: loaded live; else at the next reboot
}

// The node's refusals, as it words them.
var (
	ErrListTooBig      = errors.New("list too big for this board's blocking memory (memory.blocklist_kb)")
	ErrOverridesTooBig = errors.New("overrides too big for this board's blocking memory (memory.blocklist_kb)")
)

func room(budget, used int64) int64 { return max(budget-used, 0) }

// Place is blk_place: the RAM tier if the whole table fits the share once the list it
// replaces is gone, else the SD tier (the front and indexes in memory), else refused. The
// indexes go to internal RAM while what is left of IndexBudget holds them, else with the
// list. Overrides take the RAM tier and must fit now.
func Place(n Need, r Room) (Placement, error) {
	var out Placement
	idxNow := room(r.IndexBudget, r.IndexUsed)
	idxAfter := room(r.IndexBudget, r.IndexUsed-min(r.IndexHeld, r.IndexUsed))
	now, after := room(r.Budget, r.Used), room(r.Budget, r.Used-min(r.Held, r.Used))
	intNow, intAfter := n.Index > 0 && n.Index <= idxNow, n.Index > 0 && n.Index <= idxAfter
	// Loading the RAM tier holds the front and the indexes, then the indexes and the sectors.
	big := max(n.Front, n.Sectors)
	ext := func(internal bool) int64 {
		if internal {
			return 0
		}
		return n.Index
	}
	ramNow, ramAfter := ext(intNow)+big, ext(intAfter)+big
	sdNow, sdAfter := ext(intNow)+n.Front, ext(intAfter)+n.Front
	out.IndexInternal = intNow
	switch {
	case r.Overrides:
		out.Tier, out.Now = RAMTier, true
		if ramNow > now {
			return out, ErrOverridesTooBig
		}
	case r.RAMTier && ramAfter <= after:
		out.Tier, out.Now = RAMTier, ramNow <= now
	case sdAfter <= after:
		out.Tier, out.Now = SDTier, sdNow <= now
	default:
		return out, ErrListTooBig
	}
	return out, nil
}

// InTier is what the list takes of the lists' memory in tier t, bytes, its indexes in
// internal RAM if indexRoom holds them: in the RAM tier the whole table (the larger of the
// front and the sectors, held in turn while loading), in the SD tier the front.
func (n Need) InTier(t Tier, indexRoom int64) int64 {
	ext := n.Index
	if n.Index > 0 && n.Index <= indexRoom {
		ext = 0
	}
	if t == RAMTier {
		return ext + max(n.Front, n.Sectors)
	}
	return ext + n.Front
}
