// Package memplan is the node's memory plan (firmware/main/memplan.h; docs/design.md, Node
// OS): how much memory each service a node config enables gets, from the board definition's
// fixed values (else the chip image's defaults), and whether they fit the board. A node
// refuses a config whose plan doesn't fit; the controller checks the same before it pushes
// one. The C and this give the same answers on the shared vectors
// (firmware/tests/memplan_vectors.json).
package memplan

import "fmt"

// PSRAM kept for the system (ESP-IDF, lwIP, the HTTP server, TLS), KB.
const PSRAMSystemKB = 1024

// The services' fixed parts, as the firmware is built (memplan.h).
const (
	udpWorkers     = 4
	tcpWorkers     = 2
	workerStack    = 12288
	listenerStack  = 4096
	udpItems       = 64 + udpWorkers + 1
	udpItem        = 1536
	builder        = 4096
	udpOut         = 1232
	tcpMsg         = 65535
	scratch        = 65535
	xfrStack       = 8192
	xfrBuffers     = 2 * 65535
	hostedStack    = 8192
	blockingStack  = 8192
	blockingIO     = 4096
	hostedZonesDef = 64
	cacheFixed     = 8192
	cacheEntry     = 40 + 68
	fwdSlot        = 1600   // one outstanding upstream query (firmware flight.h)
	fwdStack       = 6144   // the forward loop and its TCP task, each (firmware fwdq.h)
	fwdTCP         = tcpMsg // the forward loop's TCP retry buffer
	// QueryLogEntry is one query log entry (firmware qlog.h): memory.querylog_kb holds
	// querylog_kb*1024/QueryLogEntry of them.
	QueryLogEntry = 160
)

// Services are the node's services (firmware/main/svc.h), in its order.
var Services = []string{"dns", "forwarding", "forward_zones", "secondary", "hosted", "blocking", "querylog"}

// Board is the board's memory, as the node runs with it and reports it in /status
// "memory"."board": KB, except CacheEntries (answers) and FwdPending (queries).
type Board struct {
	PSRAMKB          int `json:"psram_kb"`
	InternalKB       int `json:"internal_kb"`
	CacheKB          int `json:"cache_kb"`
	CacheEntries     int `json:"cache_entries"`
	BlocklistKB      int `json:"blocklist_kb"`
	BlocklistIndexKB int `json:"blocklist_index_kb"`
	HostedZonesKB    int `json:"hosted_zones_kb"`
	SecondaryZonesKB int `json:"secondary_zones_kb"`
	// QueryLogKB is the query log's ring; 0 on firmware from before it (and on a board
	// without PSRAM: no query log).
	QueryLogKB int `json:"querylog_kb"`
	// FwdPending is how many upstream queries may be outstanding at once (the table's
	// slots); 0 on firmware from before it.
	FwdPending int `json:"fwd_pending"`
}

// Keys are a board definition's settings for the plan: psram_mb and "memory". nil is left
// out: the chip image's default.
type Keys struct {
	PSRAMMB          *int
	InternalKB       *int
	CacheKB          *int
	CacheEntries     *int
	BlocklistKB      *int
	BlocklistIndexKB *int
	HostedZonesKB    *int
	SecondaryZonesKB *int
	QueryLogKB       *int
	FwdPending       *int
}

type defaults struct{ internal, cache, entries, blocklist, index, secondary, querylog, fwdPending int }

// Each chip image's defaults with PSRAM (firmware memplan.c); a board without PSRAM gets
// noPSRAM, an image not listed other.
var imageDefaults = map[string]defaults{
	"esp32p4-rev1":  {320, 4096, 8192, 20480, 160, 1024, 1024, 32},
	"esp32p4":       {320, 4096, 8192, 20480, 160, 1024, 1024, 32},
	"esp32s3-octal": {160, 2944, 8192, 2048, 0, 256, 64, 32},
	"esp32s3-quad":  {160, 1024, 2048, 512, 0, 128, 32, 32},
	"esp32":         {96, 1024, 2048, 512, 0, 128, 32, 32},
	"esp32c3":       {128, 64, 512, 128, 0, 64, 16, 32},
	"esp32c6":       {160, 64, 512, 128, 0, 64, 16, 32},
}

var (
	other   = defaults{96, 64, 512, 128, 0, 64, 16, 32}
	noPSRAM = defaults{0, 64, 512, 128, 0, 64, 0, 8} // no query log, 8 upstream queries
)

func pick(v *int, def int) int {
	if v != nil {
		return *v
	}
	return def
}

// Values is the board's memory from its keys on the chip image named image. chipPSRAMKB is
// the PSRAM the chip has, or -1 if unknown (the controller, which then takes psram_mb);
// on the node never more than the chip has.
func Values(k Keys, image string, chipPSRAMKB int) Board {
	d, ok := imageDefaults[image]
	if !ok {
		d = other
	}
	psram := chipPSRAMKB
	if k.PSRAMMB != nil {
		psram = *k.PSRAMMB * 1024
	}
	psram = max(psram, 0)
	if chipPSRAMKB >= 0 {
		psram = min(psram, chipPSRAMKB)
	}
	s := d
	if psram == 0 {
		s = noPSRAM
	}
	return Board{
		PSRAMKB:          psram,
		InternalKB:       pick(k.InternalKB, d.internal),
		CacheKB:          pick(k.CacheKB, s.cache),
		CacheEntries:     pick(k.CacheEntries, s.entries),
		BlocklistKB:      pick(k.BlocklistKB, s.blocklist),
		BlocklistIndexKB: pick(k.BlocklistIndexKB, s.index),
		HostedZonesKB:    pick(k.HostedZonesKB, hostedZonesDef),
		SecondaryZonesKB: pick(k.SecondaryZonesKB, s.secondary),
		QueryLogKB:       pick(k.QueryLogKB, s.querylog),
		FwdPending:       pick(k.FwdPending, s.fwdPending),
	}
}

// Pools: what each share is in.
const (
	Internal = 0
	PSRAM    = 1
)

// Plan is what each service gets, in bytes, per pool (Internal, PSRAM).
type Plan struct {
	Capacity [2]int64
	Total    [2]int64
	Shares   map[string][2]int64
}

// Make works out the plan for the services named (dns always runs) on board b. The error
// says which pool doesn't fit, or that cache_kb can't hold cache_entries answers, as the
// node says it.
func Make(b Board, services []string) (Plan, error) {
	p := Plan{Shares: map[string][2]int64{}}
	for _, s := range Services {
		p.Shares[s] = [2]int64{}
	}
	p.Capacity[Internal] = int64(b.InternalKB) * 1024
	if b.PSRAMKB > PSRAMSystemKB {
		p.Capacity[PSRAM] = int64(b.PSRAMKB-PSRAMSystemKB) * 1024
	}
	data := Internal
	if b.PSRAMKB > 0 {
		data = PSRAM
	}
	on := map[string]bool{"dns": true}
	for _, s := range services {
		on[s] = true
	}
	add := func(svc string, pool int, n int64) {
		v := p.Shares[svc]
		v[pool] += n
		p.Shares[svc] = v
	}
	add("dns", Internal, (udpWorkers+tcpWorkers)*workerStack+2*listenerStack+2*fwdStack)
	add("dns", data, int64(b.CacheKB)*1024+udpWorkers*(udpOut+scratch+builder)+
		tcpWorkers*(2*tcpMsg+2+scratch+builder)+udpItems*udpItem+int64(b.FwdPending)*fwdSlot+fwdTCP)
	if on["secondary"] {
		add("secondary", Internal, xfrStack)
		add("secondary", data, int64(b.SecondaryZonesKB)*1024+xfrBuffers)
	}
	if on["hosted"] {
		add("hosted", Internal, hostedStack)
		add("hosted", data, 3*int64(b.HostedZonesKB)*1024)
	}
	if on["blocking"] {
		add("blocking", Internal, blockingStack+int64(b.BlocklistIndexKB)*1024)
		add("blocking", data, int64(b.BlocklistKB)*1024+blockingIO)
	}
	if on["querylog"] {
		add("querylog", data, int64(b.QueryLogKB)*1024)
	}
	for _, v := range p.Shares {
		p.Total[Internal] += v[Internal]
		p.Total[PSRAM] += v[PSRAM]
	}
	if cacheMin := int64(cacheFixed) + int64(b.CacheEntries)*cacheEntry; int64(b.CacheKB)*1024 < cacheMin {
		return p, fmt.Errorf("cache: %d answers need at least %d KB, memory.cache_kb is %d", b.CacheEntries,
			(cacheMin+1023)/1024, b.CacheKB)
	}
	for k, name := range []string{"internal RAM", "PSRAM"} {
		if p.Total[k] > p.Capacity[k] {
			return p, fmt.Errorf("%s: the services need %d KB, the board has %d KB for them", name,
				(p.Total[k]+1023)/1024, p.Capacity[k]/1024)
		}
	}
	return p, nil
}
