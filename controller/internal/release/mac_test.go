package release

import (
	"encoding/json"
	"testing"
)

func TestMAC(t *testing.T) {
	for in, want := range map[string]string{
		"aa:bb:0c:d0:01:ff":       "aa:bb:0c:d0:01:ff",
		"AA:BB:0C:D0:01:FF":       "aa:bb:0c:d0:01:ff", // older firmware's case: shown lower
		"":                        "",
		"00:00:00:00:00:00":       "", // the interface wasn't up
		"aa-bb-0c-d0-01-ff":       "",
		"aabb.0cd0.01ff":          "",
		"aa:bb:0c:d0:01":          "",
		"aa:bb:0c:d0:01:ff:00:11": "",
		"<b>:bb:0c:d0:01:ff":      "",
		"aa:bb:0c:d0:01:fg":       "",
	} {
		if got := MAC(in); got != want {
			t.Errorf("MAC(%q) = %q, want %q", in, got, want)
		}
	}
}

// /status's net.mac is decoded into NodeStatus.
func TestNodeStatusMAC(t *testing.T) {
	var st NodeStatus
	if err := json.Unmarshal([]byte(`{"node_id":"aa:bb:cc:00:00:01","net":{"kind":"ethernet","mac":"aa:bb:cc:00:00:04"}}`), &st); err != nil {
		t.Fatal(err)
	}
	if st.Net.MAC != "aa:bb:cc:00:00:04" || MAC(st.Net.MAC) != "aa:bb:cc:00:00:04" {
		t.Fatalf("net.mac: %q", st.Net.MAC)
	}
}
