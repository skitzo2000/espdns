package nodecfg

import (
	"slices"
	"strings"
	"testing"
)

// "querylog": {"enabled", "client"} turns the query log off and on and says how much of a
// client's address it keeps, live; firmware from before it refuses the key.
func TestQueryLog(t *testing.T) {
	c, err := Parse([]byte(`{"querylog":{"enabled":false,"client":"subnet"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if p, _ := c.Payload(); string(p) != `{"format":1,"querylog":{"enabled":false,"client":"subnet"}}` || !c.SetsQueryLog() {
		t.Errorf("payload %s", p)
	}
	if slices.Contains(c.Services(), "querylog") {
		t.Errorf("off, still among the services: %v", c.Services())
	}
	for _, client := range QueryLogClients {
		if _, err := Parse([]byte(`{"querylog":{"client":"` + client + `"}}`)); err != nil {
			t.Errorf("%s: %v", client, err)
		}
	}
	if c, err = Parse([]byte(`{"name":"a"}`)); err != nil || c.SetsQueryLog() || !slices.Contains(c.Services(), "querylog") {
		t.Fatal(err, c.Services())
	}
	if _, err := Parse([]byte(`{"querylog":{"client":"some"}}`)); err == nil || !strings.Contains(err.Error(), "querylog.client") {
		t.Fatal(err)
	}
	if _, err := Parse([]byte(`{"querylog":{"size_kb":64}}`)); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatal(err)
	}
	// Live, as the node applies it (cfg_copy_live).
	from, _ := Parse([]byte(`{}`))
	to, _ := Parse([]byte(`{"querylog":{"client":"hidden"}}`))
	if ch := Compare(from, to, nil); len(ch.Reboot) != 0 || !slices.Equal(ch.Live, []string{"querylog"}) {
		t.Errorf("%+v", ch)
	}
}
