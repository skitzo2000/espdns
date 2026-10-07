package fleet

import (
	"fmt"

	"github.com/skitzo2000/espdns/controller/internal/blockfmt"
	"github.com/skitzo2000/espdns/controller/internal/blocklist"
	"github.com/skitzo2000/espdns/controller/internal/release"
)

// ovrMax is the biggest overrides file a node takes (firmware/main/blocking.c OVR_MAX).
const ovrMax = 1 << 20

// ListPlacement is where the node at host would put a blocklist or overrides payload, from
// its /status: the board's blocking memory (memory.blocklist_kb, blocklist_index_kb) and the
// lists it holds, as the node decides it (blocklist.Place). It says how ("RAM tier, live
// swap"), or why the node would refuse it. "" and no error for a node on firmware from
// before the memory plan: the node decides.
func ListPlacement(host string, kind release.Kind, payload []byte, fileLen int64, st release.NodeStatus) (string, error) {
	if st.Memory == nil {
		return "", nil
	}
	ovr := kind == release.Overrides
	if ovr && fileLen > ovrMax {
		return "", fmt.Errorf("%s: the overrides are %d KB, a node takes at most %d KB", host,
			kb(fileLen), ovrMax/1024)
	}
	need, err := blocklist.PlanNeed(payload, fileLen)
	if err != nil {
		return "", fmt.Errorf("%s: %w", host, err)
	}
	b := st.Memory.Board
	psram := b.PSRAMKB > 0
	base := blocklist.Room{Budget: int64(b.BlocklistKB) * 1024, RAMTier: psram, Overrides: ovr}
	if psram { // without PSRAM the indexes go with the lists: no separate share
		base.IndexBudget = int64(b.BlocklistIndexKB) * 1024
	}
	// What the lists it holds take, as the node counts them for place(). Firmware from before
	// data_bytes and internal_bytes doesn't say where a list's index is: both ways are tried,
	// and the list is refused only if it fits neither (the node decides the rest).
	estimated := false
	fill := func(guessInternal bool) blocklist.Room {
		r := base
		bs := st.Blocking
		if bs == nil {
			return r
		}
		// The overrides first: the order the node loads them at boot.
		for _, l := range []struct {
			s    release.ListStatus
			this bool
		}{{bs.Overrides, ovr}, {bs.List, !ovr}} {
			if l.s.State != "on" {
				continue
			}
			var data, internal int64
			if l.s.DataBytes != nil && l.s.InternalBytes != nil {
				data, internal = *l.s.DataBytes, *l.s.InternalBytes
			} else {
				data, internal = listSplit(l.s, r.IndexBudget-r.IndexUsed, guessInternal)
				estimated = true
			}
			if !psram {
				data, internal = data+internal, 0
			}
			r.Used += data
			r.IndexUsed += internal
			if l.this {
				r.Held, r.IndexHeld = data, internal
			}
		}
		return r
	}
	r := fill(true)
	pl, err := blocklist.Place(need, r)
	if err != nil && estimated {
		if r2 := fill(false); r2 != r {
			if pl2, err2 := blocklist.Place(need, r2); err2 == nil {
				r, pl, err = r2, pl2, nil
			}
		}
	}
	if err != nil {
		var msg string
		if ovr {
			// The overrides must fit now, next to everything the node holds.
			idxRoom := max(r.IndexBudget-r.IndexUsed, 0)
			msg = fmt.Sprintf("the overrides need %d KB in the RAM tier", kb(need.InTier(blocklist.RAMTier, idxRoom)))
		} else {
			idxRoom := max(r.IndexBudget-(r.IndexUsed-min(r.IndexHeld, r.IndexUsed)), 0)
			msg = fmt.Sprintf("the list needs %d KB even in the SD tier", kb(need.InTier(blocklist.SDTier, idxRoom)))
			if psram {
				msg += fmt.Sprintf(" (%d KB in the RAM tier)", kb(need.InTier(blocklist.RAMTier, idxRoom)))
			}
		}
		taken, fix := "", "give it a smaller list"
		if ovr {
			fix = "give it fewer overrides"
			if r.Used > 0 {
				taken = fmt.Sprintf(", %d KB of it taken by the lists it holds", kb(r.Used))
			}
		} else if rest := r.Used - min(r.Held, r.Used); rest > 0 {
			taken = fmt.Sprintf(", %d KB of it taken by the overrides", kb(rest))
		}
		return "", fmt.Errorf("%s: %s, board %s's blocking memory (memory.blocklist_kb) is %d KB%s, so the node "+
			"would refuse it: leave it out of the rollout, or %s", host, msg, st.Board, b.BlocklistKB, taken, fix)
	}
	desc := pl.Tier.String()
	switch {
	case ovr:
		desc += ", live"
	case pl.Now:
		desc += ", live swap"
	default:
		desc += ", at the next reboot: two copies don't fit"
	}
	if pl.Now && need.Index > 0 && r.IndexBudget > 0 && !pl.IndexInternal {
		desc += "; its index with the list, not in internal RAM, until a reboot"
	}
	if estimated {
		desc += "; estimated: its firmware doesn't say where its lists' indexes are"
	}
	return desc, nil
}

func kb(n int64) int64 { return (n + 1023) / 1024 }

// listSplit estimates where a loaded list's bytes are when the node doesn't say: a list in
// the RAM tier is its sectors and an 8-byte index entry per sector (520 bytes a sector);
// with internal, its index is in internal RAM if it fits what is left of the index share
// (as at boot, or a load with nothing to replace), else (a live swap puts the new copy's
// index with the list) with the list. A list in the SD tier: all in the lists' memory.
func listSplit(l release.ListStatus, indexRoom int64, internal bool) (data, idx int64) {
	if l.Tier != "ram" {
		return l.Bytes, 0
	}
	index := l.Bytes / (blockfmt.Sector + 8) * 8
	if internal && index > 0 && index <= indexRoom {
		return l.Bytes - index, index
	}
	return l.Bytes, 0
}
