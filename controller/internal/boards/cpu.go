package boards

import (
	"fmt"
	"slices"
	"strings"
)

// CPU is the board's clock scaling (firmware cpuplan.h; boards/README.md): DFS on or off,
// and the clock it idles at. One left out (nil) is the chip image's default; a node config's
// "cpu": {"dfs"} turns scaling on or off live.
type CPU struct {
	DFS    *bool `json:"dfs,omitempty"`
	MinMHz *int  `json:"min_mhz,omitempty"`
}

// ImageClocks are a chip image's clocks, MHz, as firmware cpuplan.c has them: its clock, the
// idle floor while the EMAC or Wi-Fi holds the APB clock, whether scaling is on by default,
// the default idle clock and the idle clocks a board may choose.
type ImageClocks struct {
	MaxMHz, APBMHz int
	DFS            bool
	MinMHz         int
	Mins           []int
}

// Clocks are the chip images' clocks (firmware cpuplan.c, the same test vectors in
// firmware/tests/cpu_vectors.json).
var Clocks = map[string]ImageClocks{
	"esp32p4-rev1":  {360, 90, false, 180, []int{90, 180}},
	"esp32p4":       {400, 100, true, 200, []int{100, 200}},
	"esp32s3-octal": {240, 80, true, 80, []int{40, 80, 160}},
	"esp32s3-quad":  {240, 80, true, 80, []int{40, 80, 160}},
	"esp32":         {240, 240, false, 40, []int{40}},
	"esp32c3":       {160, 80, true, 80, []int{40, 80}},
	"esp32c6":       {160, 80, true, 80, []int{40, 80}},
}

// CPUPlan is the board's clock scaling before a node config has its say: on or off, and
// its clock and idle clock, MHz.
func (b Board) CPUPlan() (dfs bool, maxMHz, minMHz int) {
	c, ok := Clocks[b.Image]
	if !ok {
		return false, 0, 0
	}
	dfs, minMHz = c.DFS, c.MinMHz
	if b.CPU != nil && b.CPU.DFS != nil {
		dfs = *b.CPU.DFS
	}
	if b.CPU != nil && b.CPU.MinMHz != nil && slices.Contains(c.Mins, *b.CPU.MinMHz) {
		minMHz = *b.CPU.MinMHz
	}
	return dfs, c.MaxMHz, minMHz
}

// checkCPU checks the board's "cpu" as the firmware does (board_def.c).
func checkCPU(b Board) error {
	c, ok := Clocks[b.Image]
	if b.CPU == nil || b.CPU.MinMHz == nil || !ok || slices.Contains(c.Mins, *b.CPU.MinMHz) {
		return nil
	}
	mins := make([]string, len(c.Mins))
	for i, m := range c.Mins {
		mins[i] = fmt.Sprint(m)
	}
	return fmt.Errorf("cpu min_mhz: %s on %s, or leave it out for the image's %d", strings.Join(mins, ", "), b.Image, c.MinMHz)
}
