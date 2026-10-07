package configs

import (
	"encoding/json"

	"github.com/skitzo2000/espdns/controller/internal/nodecfg"
)

// ChangedKeys are the config's top-level settings that differ from old to new (nil old: a
// new config, every key it has), by name only: what the action log says a save changed,
// never a value (a Wi-Fi password is just "wifi").
func ChangedKeys(old, new *nodecfg.Config) []string {
	top := func(c *nodecfg.Config) map[string]json.RawMessage {
		m := map[string]json.RawMessage{}
		if c != nil {
			b, _ := json.Marshal(c)
			json.Unmarshal(b, &m)
		}
		return m
	}
	a, b := top(old), top(new)
	var out []string
	for _, k := range []string{"name", "network", "wifi", "forwarders", "upstream_timeout_ms", "forward_zones",
		"secondary", "hosted", "time", "blocking", "cpu", "querylog"} {
		if string(a[k]) != string(b[k]) {
			out = append(out, k)
		}
	}
	return out
}
