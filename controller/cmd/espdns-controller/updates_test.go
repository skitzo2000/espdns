package main

import (
	"fmt"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/skitzo2000/espdns/controller/internal/actionlog"
	"github.com/skitzo2000/espdns/controller/internal/changes"
	"github.com/skitzo2000/espdns/controller/internal/fakenode"
	"github.com/skitzo2000/espdns/controller/internal/nodes"
	"github.com/skitzo2000/espdns/controller/internal/settings"
	"github.com/skitzo2000/espdns/controller/internal/updates"
)

// nodeStatus is a node's /status as the registry keeps it: its image, board, firmware and
// config name.
func nodeStatus(image, board, version, elf, built, name string) map[string]any {
	return map[string]any{"node_id": "02:00:00:00:00:11", "image": image, "board": board, "version": version, "elf_sha256": elf,
		"built": built, "config": map[string]any{"name": name}}
}

// updatesEnv is the controller with two P4 nodes and an S3 listed (no network: their
// /status as last polled), a newer P4 build and the S3's build in its data directory.
func updatesEnv(t *testing.T) *changesEnv {
	catalog := t.TempDir()
	writeFile(t, filepath.Join(catalog, "p4-board.json"), []byte(`{"image": "esp32p4-rev1"}`))
	ns := []nodes.Node{
		{Addr: "192.0.2.52", Online: true, Status: nodeStatus("esp32p4-rev1", "p4-board", "0.0.1", "00000000000000a1", "Oct  3 2026 12:00:00", "dns2")},
		{Addr: "192.0.2.53", Online: true, Status: nodeStatus("esp32s3", "s3-board", "0.0.3", "00000000000000c1", "Oct  5 2026 08:00:00", "dns3")},
		{Addr: "192.0.2.54", Online: true, Status: nodeStatus("esp32p4-rev1", "p4-board", "0.0.1", "00000000000000a1", "Oct  3 2026 12:00:00", "dns4")},
	}
	e := &changesEnv{t: t}
	e.h, _ = testServer(t, true, func(s *server) {
		e.dir, e.store = s.dataDir, changes.New(s.dataDir)
		s.changes, s.catalog = e.store, catalog
		s.nodes = func() []nodes.Node { return ns }
	})
	e.cookie, e.token = login(t, e.h)
	if err := settings.Save(settings.Path(e.dir), settings.Settings{Nodes: []string{"192.0.2.52", "192.0.2.53", "192.0.2.54", "192.0.2.55"}}); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(e.dir, "firmware/builds/p4-board/dns2.bin"), fakenode.AppBuilt("0.0.4", "00000000000000b2", "Oct  7 2026", "09:30:00"))
	writeFile(t, filepath.Join(e.dir, "firmware/images/esp32s3/image.json"), []byte(`{"image": "esp32s3", "chip": "esp32s3"}`))
	writeFile(t, filepath.Join(e.dir, "firmware/images/esp32s3/app.bin"), fakenode.AppBuilt("0.0.3", "00000000000000c1", "Oct  5 2026", "08:00:00"))
	return e
}

// Each listed node's firmware against the newest build for it, as versions.
func TestUpdatesList(t *testing.T) {
	e := updatesEnv(t)
	var rep updates.Report
	e.json(e.do("GET", "/api/updates", ""), http.StatusOK, &rep)
	if rep.Scheme != updates.Scheme || len(rep.Builds) != 2 || len(rep.Nodes) != 4 {
		t.Fatalf("report %+v", rep)
	}
	states := []string{}
	for _, n := range rep.Nodes {
		states = append(states, n.State)
	}
	if !slices.Equal(states, []string{updates.Available, updates.Current, updates.Available, updates.Unknown}) {
		t.Errorf("states %v", states)
	}
	dns2 := rep.Nodes[0]
	if dns2.Name != "dns2" || dns2.Runs.Text != "0.0.1" || dns2.Newest.Text != "0.0.4" || dns2.Newest.Build != "00000000000000b2" ||
		dns2.Newest.Source != "builds/p4-board" || !dns2.Online || !dns2.Listed {
		t.Errorf("dns2 %+v", dns2)
	}
	if !slices.Equal(rep.Available, []string{"192.0.2.52", "192.0.2.54"}) {
		t.Errorf("available %v", rep.Available)
	}
	// The read never shows a path.
	if w := e.do("GET", "/api/updates", ""); strings.Contains(w.Body.String(), e.dir) {
		t.Errorf("a path: %s", w.Body)
	}
}

// An update is a pending firmware change, never a push: one per build, in the action log,
// shown as pending afterwards; a second for the same node is refused.
func TestUpdatesQueue(t *testing.T) {
	e := updatesEnv(t)
	var out struct {
		Changes []changes.Change `json:"changes"`
	}
	e.json(e.do("POST", "/api/updates", jsonBody(map[string]any{"nodes": []string{"192.0.2.52"},
		"builds": map[string]string{"192.0.2.52": "00000000000000b2"}})), http.StatusCreated, &out)
	if len(out.Changes) != 1 {
		t.Fatalf("changes %+v", out)
	}
	ch := out.Changes[0]
	if ch.Kind != changes.Firmware || ch.Firmware != "builds/p4-board" || !slices.Equal(ch.Nodes, []string{"192.0.2.52"}) ||
		ch.Summary != "Update dns2 from 0.0.1 to 0.0.4" || ch.Who != "admin" {
		t.Errorf("change %+v", ch)
	}
	cs, _ := e.store.List()
	if len(cs) != 1 || cs[0].ID != ch.ID {
		t.Errorf("pending %+v", cs)
	}
	es, _ := actionlog.Tail(e.dir, 10)
	if len(es) == 0 || es[len(es)-1].Action != "change add" || !slices.Contains(es[len(es)-1].Args, ch.Summary) {
		t.Errorf("action log %+v", es)
	}
	var rep updates.Report
	e.json(e.do("GET", "/api/updates", ""), http.StatusOK, &rep)
	if rep.Nodes[0].Pending != ch.ID || !slices.Equal(rep.Available, []string{"192.0.2.54"}) {
		t.Errorf("after: %+v %v", rep.Nodes[0], rep.Available)
	}
	if w := e.do("POST", "/api/updates", jsonBody(map[string]any{"nodes": []string{"192.0.2.52"}})); w.Code != http.StatusBadRequest ||
		!strings.Contains(w.Body.String(), "already has a firmware update pending") {
		t.Errorf("again: %d %s", w.Code, w.Body)
	}
	// Update all: the rest offered.
	e.json(e.do("POST", "/api/updates", "{}"), http.StatusCreated, &out)
	if len(out.Changes) != 1 || !slices.Equal(out.Changes[0].Nodes, []string{"192.0.2.54"}) {
		t.Errorf("all: %+v", out)
	}
	if w := e.do("POST", "/api/updates", "{}"); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "no node has an update") {
		t.Errorf("none left: %d %s", w.Code, w.Body)
	}
}

func TestUpdatesRefused(t *testing.T) {
	e := updatesEnv(t)
	for _, bad := range []string{
		jsonBody(map[string]any{"nodes": []string{"192.0.2.53"}}),         // up to date
		jsonBody(map[string]any{"nodes": []string{"192.0.2.55"}}),         // not seen
		jsonBody(map[string]any{"nodes": []string{"192.0.2.99"}}),         // not listed
		jsonBody(map[string]any{"nodes": []string{"192.0.2.52"}, "x": 1}), // unknown field
		"not json",
	} {
		if w := e.do("POST", "/api/updates", bad); w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", bad, w.Code, w.Body)
		}
	}
	// The page showed another build: look again.
	if w := e.do("POST", "/api/updates", jsonBody(map[string]any{"nodes": []string{"192.0.2.52"},
		"builds": map[string]string{"192.0.2.52": "00000000000000a9"}})); w.Code != http.StatusConflict {
		t.Errorf("moved: %d %s", w.Code, w.Body)
	}
	// A build that can't be read as a rollout reads it is never queued.
	writeFile(t, filepath.Join(e.dir, "firmware/builds/p4-board/dns2.bin"), []byte("not an image"))
	if w := e.do("POST", "/api/updates", jsonBody(map[string]any{"nodes": []string{"192.0.2.52"}})); w.Code != http.StatusBadRequest {
		t.Errorf("broken build: %d %s", w.Code, w.Body)
	}
	if cs, _ := e.store.List(); len(cs) != 0 {
		t.Errorf("pending %+v", cs)
	}
}

// A queue that fails part way (the pending changes full after its first) leaves none of
// its changes.
func TestUpdatesAllOrNone(t *testing.T) {
	e := updatesEnv(t)
	writeFile(t, filepath.Join(e.dir, "firmware/images/esp32s3/app.bin"), fakenode.AppBuilt("0.0.5", "00000000000000d2", "Oct  6 2026", "08:00:00"))
	for i := 0; i < changes.MaxChanges-1; i++ {
		if _, err := e.store.Add(changes.Edit{Kind: changes.Firmware, Firmware: "images/esp32s3", Nodes: []string{fmt.Sprintf("n%d", i)}, Who: "admin"}); err != nil {
			t.Fatal(err)
		}
	}
	if w := e.do("POST", "/api/updates", "{}"); w.Code != http.StatusTooManyRequests {
		t.Errorf("full: %d %s", w.Code, w.Body)
	}
	if cs, _ := e.store.List(); len(cs) != changes.MaxChanges-1 {
		t.Errorf("pending %d", len(cs))
	}
}

// Without a login: the read is open (read-only, as /api/nodes), an update refused.
func TestUpdatesNoLogin(t *testing.T) {
	h, _ := testServer(t, false)
	if w := serve(h, request("GET /api/updates")); w.Code != http.StatusOK {
		t.Errorf("read: %d %s", w.Code, w.Body)
	}
	if w := serve(h, request("POST /api/updates")); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "passwd") {
		t.Errorf("update: %d %s", w.Code, w.Body)
	}
}

// The open read says why a build can't be offered without the data directory's path.
func TestUpdatesBrokenBuildNoPath(t *testing.T) {
	e := updatesEnv(t)
	writeFile(t, filepath.Join(e.dir, "firmware/images/esp32s3/app.bin"), []byte("not an image"))
	w := e.do("GET", "/api/updates", "")
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), e.dir) || !strings.Contains(w.Body.String(), "firmware/images/esp32s3/app.bin") {
		t.Errorf("%d %s", w.Code, w.Body)
	}
}
