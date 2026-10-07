package image

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/skitzo2000/espdns/controller/internal/boards"
)

// The firmware tree, for the chip images exported by `make export-images` and the factory
// images tools/factory.py made with esptool from them (`make factory BOARD=...`).
const firmware = "../../../firmware"

// Assembling a catalog board in Go gives the same bytes esptool's merge_bin gave.
func TestAssembleMatchesFactory(t *testing.T) {
	for _, tc := range []struct{ board string }{{"xiao-s3-sense"}, {"p4-ip101"}} {
		want, err := os.ReadFile(filepath.Join(firmware, "dist", tc.board, "dns2-"+tc.board+".bin"))
		if err != nil {
			t.Skipf("no factory image for %s (run make factory in firmware/): %v", tc.board, err)
		}
		entries, err := boards.Load("../../../boards", "")
		if err != nil {
			t.Fatal(err)
		}
		e, ok := boards.Find(entries, tc.board)
		if !ok {
			t.Fatalf("%s not in the catalog", tc.board)
		}
		chip, err := Open(filepath.Join(firmware, "dist", "images", e.Board.Image))
		if err != nil {
			t.Skipf("no exported chip image %s: %v", e.Board.Image, err)
		}
		part, err := e.Pack()
		if err != nil {
			t.Fatal(err)
		}
		got, err := chip.Assemble(e.Board.FlashMB, part)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			n := len(got)
			if len(want) < n {
				n = len(want)
			}
			for i := 0; i < n; i++ {
				if got[i] != want[i] {
					t.Fatalf("%s: %d bytes vs esptool's %d; first difference at 0x%x", tc.board, len(got), len(want), i)
				}
			}
			t.Fatalf("%s: %d bytes vs esptool's %d", tc.board, len(got), len(want))
		}
	}
}

func TestSetFlashSizeRejectsNonImages(t *testing.T) {
	if _, err := setFlashSize([]byte("not an image at all, just some bytes"), 3); err == nil {
		t.Fatal("accepted something that isn't an ESP image")
	}
}
