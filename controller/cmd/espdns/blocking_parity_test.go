package main

import (
	"reflect"
	"slices"
	"testing"

	"github.com/skitzo2000/espdns/controller/internal/blocking"
	"github.com/skitzo2000/espdns/controller/internal/settings"
)

// The Blocking page compiles a list through blocklist.Run with the request its definition
// makes; the CLI's flags for the same definition (what the page shows as its command) make
// the same request: every source, its kind and path, allow or block, the widths, the
// popular and must-resolve names, the out file and the size-change check, the internal
// allowlist's hosts a URL source is fetched from (settings.json's internal_sources), the
// overrides too.
func TestBlockingParity(t *testing.T) {
	dir := t.TempDir()
	src := blocking.Sources(dir)
	for name, text := range map[string]string{"pro.txt": "||ads.example^\n", "hosts.txt": "0.0.0.0 tracker.example\n",
		"ok.txt": "fine.example\n", "top.csv": "1,popular.example\n", "must.txt": "must.example\n",
		blocking.OverridesBlock: "*.bad.example\n", blocking.OverridesAllow: "good.example\n"} {
		if err := src.Save(name, []byte(text), ""); err != nil {
			t.Fatal(err)
		}
	}
	ptrF := func(v float64) *float64 { return &v }
	ptrI := func(v int) *int { return &v }
	lists := []blocking.List{
		{Name: "list", Sources: []string{"adblock:pro.txt", "hosts:hosts.txt"}},
		{Name: "full", Sources: []string{"adblock:pro.txt", "rpz:https://feeds.example/rpz.zone?key=a&b=c"}, Allow: []string{"domains:ok.txt"},
			Popular: "top.csv", MustResolve: "must.txt", Xor: ptrI(8), MaxChange: ptrF(35.5), MinChange: ptrI(250)},
		{Name: "nofloor", Allow: []string{"wildcard:ok.txt"}, Xor: ptrI(0), MaxChange: ptrF(5), MinChange: ptrI(0)},
		{Name: "frozen", Sources: []string{"hosts:hosts.txt"}, MaxChange: ptrF(0), MinChange: ptrI(0)},
		{Name: "nomax", Sources: []string{"hosts:hosts.txt"}, MaxChange: ptrF(0)},
		// A server inside, its host on settings.json's internal allowlist: -internal
		{Name: "inside", Sources: []string{"hosts:http://LISTS.example/hosts.txt", "rpz:https://feeds.example/rpz.zone"}},
		blocking.Overrides(dir),
	}
	if err := settings.Save(settings.Path(dir), settings.Settings{InternalSources: []string{"192.0.2.10", "lists.example"}}); err != nil {
		t.Fatal(err)
	}
	for _, l := range lists {
		for _, accept := range []bool{false, true} {
			page, err := l.Request(dir, accept)
			if err != nil {
				t.Fatal(err)
			}
			cli, asJSON, err := blocklistRequest(l.Args(dir, accept))
			if err != nil {
				t.Fatalf("%s: %v (%v)", l.Name, err, l.Args(dir, accept))
			}
			if asJSON || !reflect.DeepEqual(page, cli) {
				t.Errorf("%s (accept %v):\n page %+v\n cli  %+v", l.Name, accept, page, cli)
			}
			if want := map[bool][]string{true: {"lists.example"}}[l.Name == "inside"]; !slices.Equal(page.Internal, want) {
				t.Errorf("%s: internal %v", l.Name, page.Internal)
			}
		}
	}
}
