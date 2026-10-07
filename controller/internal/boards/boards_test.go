package boards

import (
	"strings"
	"testing"

	"github.com/skitzo2000/espdns/controller/internal/nodecfg"
)

func p(n int) *int { return &n }

func has(list []string, s string) bool {
	for _, l := range list {
		if strings.Contains(l, s) {
			return true
		}
	}
	return false
}

// The shipped boards pass the checks.
func TestCatalog(t *testing.T) {
	entries, err := Load("../../../boards", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) < 3 {
		t.Fatalf("%d boards in the catalog", len(entries))
	}
	for _, e := range entries {
		if len(e.Errors) > 0 {
			t.Errorf("%s: %v", e.Board.Name, e.Errors)
		}
	}
}

func TestChecks(t *testing.T) {
	s3 := func() Board {
		return Board{Name: "x", Image: "esp32s3-octal", FlashMB: 8,
			SPI:      []SPIBus{{Host: 2, SCLK: p(7), MOSI: p(9), MISO: p(8)}},
			Ethernet: &Ethernet{Kind: "w5500", SPIHost: 2, CS: p(1), Int: p(2), Rst: p(3)},
			SD:       &SD{Kind: "spi", SPIHost: 2, CS: p(21)}}
	}
	cases := []struct {
		name  string
		edit  func(*Board)
		error string
		warn  string
	}{
		{"fine", func(b *Board) {}, "", ""},
		{"octal PSRAM pin", func(b *Board) { b.LED = &LED{Kind: "gpio", Pin: p(35)} }, "octal PSRAM", ""},
		{"flash pin", func(b *Board) { b.LED = &LED{Kind: "gpio", Pin: p(28)} }, "flash and PSRAM", ""},
		{"no such pin", func(b *Board) { b.LED = &LED{Kind: "gpio", Pin: p(23)} }, "doesn't exist", ""},
		{"pin twice", func(b *Board) { b.LED = &LED{Kind: "gpio", Pin: p(21)} }, "GPIO 21 used twice", ""},
		{"strapping", func(b *Board) { b.LED = &LED{Kind: "gpio", Pin: p(0)} }, "", "strapping"},
		{"usb", func(b *Board) { b.LED = &LED{Kind: "gpio", Pin: p(19)} }, "", "USB port"},
		{"undefined bus", func(b *Board) { b.SD.SPIHost = 3 }, "no such SPI bus", ""},
		{"no int", func(b *Board) { b.Ethernet.Int = nil }, "", "polled"},
		{"tx power", func(b *Board) { b.WiFi = &WiFi{TxPowerDBm: 25} }, "tx_power_dbm", ""},
		{"no emac on S3", func(b *Board) { b.Ethernet = &Ethernet{Kind: "emac"} }, "no built-in Ethernet MAC", ""},
		{"unknown image", func(b *Board) { b.Image = "esp8266" }, "not one of the chip images", ""},
		{"too much flash", func(b *Board) { b.Image = "esp32c3"; b.FlashMB = 32; b.SD = nil }, "at most 16 MB", ""},
		{"C3 has no SPI3", func(b *Board) { b.Image = "esp32c3"; b.SPI[0].Host = 3 }, "only SPI2", ""},
		{"address", func(b *Board) {
			b.Network = &nodecfg.Network{Address: "192.0.2.252/23", Gateway: "192.0.2.1"}
		}, "", ""},
		{"dhcp", func(b *Board) { b.Network = &nodecfg.Network{Address: "dhcp"} }, "", ""},
		{"address without gateway", func(b *Board) { b.Network = &nodecfg.Network{Address: "192.0.2.252/23"} }, "gateway: required", ""},
		{"address without prefix", func(b *Board) {
			b.Network = &nodecfg.Network{Address: "192.0.2.252", Gateway: "192.0.2.1"}
		}, "prefix length", ""},
		{"memory out of range", func(b *Board) { b.Memory = &Memory{CacheEntries: p(4)} }, "cache_entries", ""},
		{"psram out of range", func(b *Board) { b.PSRAMMB = p(100) }, "psram_mb", ""},
		{"index share of 0", func(b *Board) { b.PSRAMMB = p(8); b.Memory = &Memory{BlocklistIndexKB: p(0)} }, "", ""},
		{"no query log", func(b *Board) { b.PSRAMMB = p(8); b.Memory = &Memory{QueryLogKB: p(0)} }, "", ""},
		{"query log out of range", func(b *Board) { b.Memory = &Memory{QueryLogKB: p(70000)} }, "querylog_kb", ""},
		{"one upstream query", func(b *Board) { b.Memory = &Memory{FwdPending: p(1)} }, "fwd_pending", ""},
		{"upstream queries", func(b *Board) { b.PSRAMMB = p(8); b.Memory = &Memory{FwdPending: p(16)} }, "", ""},
		{"a query log that doesn't fit", func(b *Board) { b.PSRAMMB = p(8); b.Memory = &Memory{QueryLogKB: p(4096)} },
			"", "every service at once doesn't fit (PSRAM"},
		{"every service doesn't fit", func(b *Board) { b.PSRAMMB = p(8); b.Memory = &Memory{BlocklistKB: p(8000)} },
			"", "every service at once doesn't fit (PSRAM"},
		{"P4 needs fixed Ethernet", func(b *Board) {
			b.Image = "esp32p4"
			b.Ethernet.Optional = true
			b.SPI[0] = SPIBus{Host: 2, SCLK: p(7), MOSI: p(9), MISO: p(8)}
		}, "no Wi-Fi", ""},
	}
	for _, c := range cases {
		b := s3()
		c.edit(&b)
		errs, warns := Check(b)
		if c.error == "" && len(errs) > 0 {
			t.Errorf("%s: unexpected errors %v", c.name, errs)
		}
		if c.error != "" && !has(errs, c.error) {
			t.Errorf("%s: want an error with %q, got %v", c.name, c.error, errs)
		}
		if c.warn != "" && !has(warns, c.warn) {
			t.Errorf("%s: want a warning with %q, got %v", c.name, c.warn, warns)
		}
	}

	// ESP32: input-only pins can't drive the PHY's reset.
	b := Board{Name: "x", Image: "esp32", Ethernet: &Ethernet{Kind: "emac", PHY: "lan87xx", Reset: p(35)}}
	if errs, _ := Check(b); !has(errs, "input-only") {
		t.Errorf("input-only pin as an output: %v", errs)
	}
}

func TestParseRefusesUnknownFields(t *testing.T) {
	if _, err := Parse([]byte(`{"name":"x","image":"esp32","etherent":{"kind":"emac"}}`)); err == nil {
		t.Fatal("a misspelt field was accepted")
	}
}

// The node's address is per node: packed into its partition, never saved with a board.
func TestNetwork(t *testing.T) {
	b := Board{Name: "x", Image: "esp32", Network: &nodecfg.Network{Address: "198.51.100.5/24", Gateway: "198.51.100.1"}}
	part, err := Entry{}.WithChanges(b).Pack()
	if err != nil || !strings.Contains(string(part[16:]), `"network":{"address":"198.51.100.5/24","gateway":"198.51.100.1"}`) {
		t.Fatal(err, string(part[16:80]))
	}
	if err := Save(t.TempDir(), b, nil); err == nil || !strings.Contains(err.Error(), "per node") {
		t.Fatal(err)
	}
	b.Network = nil
	if err := Save(t.TempDir(), b, nil); err != nil {
		t.Fatal(err)
	}
}

func TestPackFormat(t *testing.T) {
	def := []byte(`{"name":"x","image":"esp32"}`)
	part, err := PackJSON(def)
	if err != nil {
		t.Fatal(err)
	}
	if string(part[:4]) != "EDBD" || part[4] != 1 || int(part[8]) != len(def) || len(part) != 4096 || part[4095] != 0xFF {
		t.Fatalf("header % x", part[:16])
	}
}
