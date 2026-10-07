package main

import (
	"testing"

	"github.com/skitzo2000/espdns/controller/internal/nodecfg"
	"github.com/skitzo2000/espdns/controller/internal/release"
)

// A config on trial is told from the node's JSON reply and reboot reasons, and from the
// plain-text reply of firmware from before JSON replies.
func TestOnTrial(t *testing.T) {
	moves, err := nodecfg.Parse([]byte(`{"network":{"address":"192.0.2.20/24","gateway":"192.0.2.1"}}`))
	if err != nil {
		t.Fatal(err)
	}
	stays := &nodecfg.Config{}
	jsonReply := func(pending bool) release.Reply {
		return release.ParseReply(`{"ok":true,"message":"ok, config seq 5 stored","reboot_pending":` +
			map[bool]string{true: "true", false: "false"}[pending] + `,"rebooting":false}`)
	}
	for _, tc := range []struct {
		name    string
		reply   release.Reply
		pending bool
		reasons []string
		cfg     *nodecfg.Config
		want    bool
	}{
		{"old firmware, new address", release.ParseReply("ok, config seq 5 stored in slot 1, on trial; rebooting"), false, nil, moves, true},
		{"old firmware, live", release.ParseReply("ok, config seq 5 applied live"), false, nil, moves, false},
		{"address reason", jsonReply(true), true, []string{"config: address"}, stays, true},
		{"wifi reason", jsonReply(true), true, []string{"config: wifi"}, stays, true},
		{"zones only", jsonReply(true), true, []string{"config: zones"}, moves, false},
		{"no status: a new static address", jsonReply(true), true, nil, moves, true},
		{"no status: the same address", jsonReply(true), true, nil, stays, false},
		{"applied live", jsonReply(false), false, []string{}, moves, false},
	} {
		if got := onTrial(tc.reply, tc.pending, tc.reasons, tc.cfg, "192.0.2.10"); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}
