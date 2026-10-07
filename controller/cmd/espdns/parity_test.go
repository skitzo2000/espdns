package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skitzo2000/espdns/controller/internal/configs"
)

// The controller's editor checks a config as espdns config -check does (internal/configs):
// on the production configs and on bad ones, with and without a board, the same verdict
// and the same reason.
func TestCheckParity(t *testing.T) {
	dir := t.TempDir()
	catalog := t.TempDir()
	// A catalog with a board whose PSRAM a blocklist this big doesn't leave room in, and one
	// without psram_mb.
	ws, err := os.ReadFile("../../../boards/ws-s3-eth.json")
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(catalog, "ws-s3-eth.json"), ws, 0o644)
	tiny := strings.Replace(strings.Replace(string(ws), `"ws-s3-eth"`, `"tiny"`, 1), `"blocklist_kb": 2048`, `"blocklist_kb": 4096`, 1)
	os.WriteFile(filepath.Join(catalog, "tiny.json"), []byte(tiny), 0o644)
	nops := strings.Replace(strings.Replace(string(ws), `"ws-s3-eth"`, `"nops"`, 1), `"psram_mb": 8,`, ``, 1)
	os.WriteFile(filepath.Join(catalog, "nops.json"), []byte(nops), 0o644)

	files := map[string]string{}
	// Two whole configs: the repo's example and the site defaults example spelled out.
	for name, path := range map[string]string{"node.json": "../../../configs/example-node.json",
		"site.json": "../../../firmware/tests/config_example.json"} {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		files[name] = string(b)
	}
	files["unknown.json"] = `{"fowarders":["9.9.9.9"]}`
	files["addr.json"] = `{"network":{"address":"192.0.2.252","gateway":"192.0.2.1"}}`
	files["fwd.json"] = `{"forwarders":["1.1.1.1","1.1.1.2","1.1.1.3","1.1.1.4","1.1.1.5"]}`
	files["zones.json"] = `{"secondary":{"zones":["local"]},"forward_zones":[{"zone":"local","forwarder":"198.51.100.1"}]}`
	files["blockoff.json"] = `{"blocking":{"enabled":false}}`
	files["trailing.json"] = `{"name":"x"} {}`
	files["big.json"] = `{"name":"` + strings.Repeat("x", 40) + `"}`

	for name, text := range files {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte(text), 0o600)
		for _, board := range []string{"", "ws-s3-eth", "tiny", "nops"} {
			var out bytes.Buffer
			cliErr := checkConfig(&out, p, board, catalog)
			r := configs.Check{Name: p, Text: []byte(text), Catalog: catalog, Board: board}.Run()
			apiErr := r.Error
			for _, m := range r.Memory {
				if m.Error != "" && apiErr == "" {
					apiErr = m.Error
				}
			}
			switch {
			case cliErr == nil && !r.OK:
				t.Errorf("%s on %q: the CLI passes it, the editor says %q", name, board, apiErr)
			case cliErr != nil && r.OK:
				t.Errorf("%s on %q: the editor passes it, the CLI says %v", name, board, cliErr)
			case cliErr != nil && !strings.Contains(cliErr.Error(), apiErr):
				t.Errorf("%s on %q: the CLI says %q, the editor %q", name, board, cliErr, apiErr)
			case cliErr == nil && !strings.Contains(out.String(), r.Payload):
				t.Errorf("%s on %q: payloads differ: %s / %s", name, board, out.String(), r.Payload)
			}
		}
	}
	// The boards that don't fit, or can't be planned on, refuse it in both.
	for board, want := range map[string]string{"tiny": "PSRAM: the services need", "nops": "doesn't say psram_mb"} {
		err := checkConfig(&bytes.Buffer{}, filepath.Join(dir, "node.json"), board, catalog)
		r := configs.Check{Name: "node.json", Text: []byte(files["node.json"]), Catalog: catalog, Board: board}.Run()
		if err == nil || !strings.Contains(err.Error(), want) || r.OK || len(r.Memory) != 1 || !strings.Contains(r.Memory[0].Error, want) {
			t.Errorf("%s: %v / %+v", board, err, r.Memory)
		}
	}
	// The whole configs pass on the boards of the reference site's nodes.
	for name, board := range map[string]string{"node.json": "p4-ip101", "site.json": "ws-s3-eth"} {
		if err := checkConfig(&bytes.Buffer{}, filepath.Join(dir, name), board, "../../../boards"); err != nil {
			t.Errorf("%s on %s: %v", name, board, err)
		}
		r := configs.Check{Name: name, Text: []byte(files[name]), Catalog: "../../../boards", Board: board}.Run()
		if !r.OK {
			t.Errorf("%s on %s in the editor: %+v", name, board, r)
		}
	}
}
