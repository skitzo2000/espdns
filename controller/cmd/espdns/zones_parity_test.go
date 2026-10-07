package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skitzo2000/espdns/controller/internal/configs"
	"github.com/skitzo2000/espdns/controller/internal/release"
	"github.com/skitzo2000/espdns/controller/internal/zonefiles"
)

// stdout runs f and returns what it printed.
func stdout(t *testing.T, f func() error) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	done := make(chan []byte)
	go func() { b, _ := io.ReadAll(r); done <- b }()
	ferr := f()
	w.Close()
	os.Stdout = old
	return string(<-done), ferr
}

// The controller's zone editor checks a zone as espdns zones -check does (internal/zones,
// Check): good and bad zones the same lines and the same error; against a node, the set
// over its limit as -limit-kb, and a zone that is one of its secondary zones as -config.
func TestZonesCheckParity(t *testing.T) {
	dir := t.TempDir()
	home, err := os.ReadFile("../../internal/zones/testdata/home.example.zone")
	if err != nil {
		t.Fatal(err)
	}
	soa := "@ IN SOA ns hostmaster 1 3600 600 86400 300\n@ IN NS ns\nns IN A 192.0.2.1\n"
	texts := map[string]string{
		"home.example.zone":   string(home),
		"nosoa.example.zone":  "@ IN NS ns\nns IN A 192.0.2.1\n",
		"two.example.zone":    soa + "@ IN SOA ns hostmaster 2 3600 600 86400 300\n",
		"out.example.zone":    soa + "www.other.example. IN A 192.0.2.2\n",
		"cname.example.zone":  soa + "www IN CNAME ns\nwww IN A 192.0.2.3\n",
		"dnssec.example.zone": soa + "@ IN DNSKEY 257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n",
		"syntax.example.zone": soa + "www IN A 999.1.1.1\n",
		"deleg.example.zone":  soa + "lab IN NS ns.lab\nns.lab IN A 192.0.2.4\nlab IN TXT \"x\"\n",
		"wild.example.zone":   soa + "a.*.b IN A 192.0.2.5\n",
		"wildns.example.zone": soa + "*.lab IN NS ns\n",
		"ok.example.zone":     soa + "*.dev IN A 192.0.2.6\n",
	}
	for name, text := range texts {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte(text), 0o600)
		out, cliErr := stdout(t, func() error { return cmdZones([]string{"-zone", p, "-check"}) })
		r := zonefiles.Check{DataDir: t.TempDir(), Name: name, Text: []byte(text)}.Run(context.Background())
		lines := strings.Join(r.Lines, "\n")
		if lines != "" {
			lines += "\n"
		}
		switch {
		case (cliErr == nil) != (r.Error == ""):
			t.Errorf("%s: the CLI says %v, the editor %q", name, cliErr, r.Error)
		case cliErr != nil && cliErr.Error() != strings.Replace(r.Error, name, p, 1) && cliErr.Error() != r.Error:
			t.Errorf("%s: the CLI says %q, the editor %q", name, cliErr, r.Error)
		case out != lines:
			t.Errorf("%s: the CLI prints %q, the editor %q", name, out, lines)
		case (name == "home.example.zone" || name == "ok.example.zone") && (cliErr != nil || !strings.Contains(out, "ok: 1 zones")):
			t.Errorf("%s: %v %q", name, cliErr, out)
		case name != "home.example.zone" && name != "ok.example.zone" && cliErr == nil:
			t.Errorf("%s: passed both, a zone the node refuses", name)
		}
	}
	if r := (zonefiles.Check{DataDir: t.TempDir(), Name: "home.example.zone", Text: home}).Run(context.Background()); !r.OK {
		t.Errorf("home.example: %+v", r)
	}

	// Against a node: its limit, as -limit-kb; the secondary zones of the config pushed to
	// it, as -config.
	p := filepath.Join(dir, "home.example.zone")
	data := t.TempDir()
	cfg := `{"name":"n1","secondary":{"primary":"192.0.2.254","zones":["home.example"]}}`
	if _, err := configs.Save(data, "n1.json", []byte(cfg), ""); err != nil {
		t.Fatal(err)
	}
	if err := configs.RecordPushed(data, configs.Pushed{NodeID: "02:00:00:00:00:02", Host: "clash", File: "n1.json", Seq: 4,
		Payload: json.RawMessage(cfg)}); err != nil {
		t.Fatal(err)
	}
	var small, clash release.NodeStatus
	json.Unmarshal([]byte(`{"node_id":"02:00:00:00:00:01","hosted":{"state":"on","seq":1,"limit_bytes":1024}}`), &small)
	json.Unmarshal([]byte(`{"node_id":"02:00:00:00:00:02","config":{"source":"node","seq":4,"name":"n1"},"hosted":{"state":"on","seq":1,"limit_bytes":65536}}`), &clash)
	r := zonefiles.Check{DataDir: data, Name: "home.example.zone", Text: home,
		Nodes: []zonefiles.Node{{Host: "small", Listed: true, Status: &small}, {Host: "clash", Listed: true, Status: &clash}}}.Run(context.Background())

	out, cliErr := stdout(t, func() error { return cmdZones([]string{"-zone", p, "-check", "-limit-kb", "1"}) })
	if n := r.Nodes[0]; cliErr == nil || n.Refused != cliErr.Error() || strings.Join(n.Lines, "\n")+"\n" != out {
		t.Errorf("over the limit: the CLI %v %q, the editor %+v", cliErr, out, n)
	}
	cf := filepath.Join(dir, "n1.json")
	os.WriteFile(cf, []byte(cfg), 0o600)
	_, cliErr = stdout(t, func() error { return cmdZones([]string{"-zone", p, "-check", "-config", cf}) })
	if n := r.Nodes[1]; cliErr == nil || !strings.HasPrefix(n.Refused, cliErr.Error()+" (n1.json") {
		t.Errorf("secondary: the CLI %v, the editor %+v", cliErr, n)
	}
	// And the node's own word for it: a secondary zone in its /status.
	var sec release.NodeStatus
	json.Unmarshal([]byte(`{"node_id":"02:00:00:00:00:03","hosted":{"state":"on","seq":1,"limit_bytes":65536},"zones":[{"name":"home.example"}]}`), &sec)
	r = zonefiles.Check{DataDir: data, Name: "home.example.zone", Text: home,
		Nodes: []zonefiles.Node{{Host: "sec", Listed: true, Status: &sec}}}.Run(context.Background())
	if r.OK || !strings.Contains(r.Nodes[0].Refused, "both a hosted zone and a secondary zone of sec") {
		t.Errorf("secondary in /status: %+v", r.Nodes)
	}
}
