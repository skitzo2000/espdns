package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/skitzo2000/espdns/controller/internal/actionlog"
	"github.com/skitzo2000/espdns/controller/internal/fleet"
	"github.com/skitzo2000/espdns/controller/internal/jobs"
	"github.com/skitzo2000/espdns/controller/internal/settings"
)

// fakeNode serves /status and /health as a node does; pending says a reboot waits.
func fakeNode(t *testing.T, pending bool) string {
	st := map[string]any{"node_id": "aa:bb", "board": "p4-ip101", "image": "esp32p4-rev1", "project": "dns2",
		"version": "v2", "elf_sha256": "0102030405060708", "slot": "ota_0", "ota_state": "valid", "uptime_s": 100,
		"zones":  []map[string]any{{"name": "home.example"}},
		"config": map[string]any{"source": "node", "seq": 3, "address": "static"},
		"reboot": map[string]any{"pending": pending, "reasons": []string{"config"}}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/status":
			json.NewEncoder(w).Encode(st)
		case "/health":
			json.NewEncoder(w).Encode(map[string]any{"state": "healthy", "answering": true, "reasons": []string{}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}

// answers every query: the SOA authoritatively, anything else with an address. It records
// what it was asked.
type answers struct{ asked chan string }

func (a answers) Exchange(_ context.Context, host string, m *dns.Msg) (*dns.Msg, error) {
	q := m.Question[0]
	select {
	case a.asked <- host + " " + dns.TypeToString[q.Qtype] + " " + q.Name:
	default:
	}
	if strings.HasPrefix(host, "203.0.113.9") {
		return nil, errors.New("timeout")
	}
	r := new(dns.Msg)
	r.SetReply(m)
	switch {
	case q.Qtype == dns.TypeSOA:
		r.Authoritative = true
		rr, _ := dns.NewRR(q.Name + " 60 IN SOA ns. host. 1 60 60 60 60")
		r.Answer = append(r.Answer, rr)
	case strings.HasSuffix(q.Name, ".invalid."):
		r.Rcode = dns.RcodeNameError
	default:
		r.Answer = append(r.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A: net.IPv4(192, 0, 2, 1)})
	}
	return r, nil
}

func runCheck(t *testing.T, s settings.Settings) (jobs.Job, []string) {
	dir := t.TempDir()
	if err := settings.Save(settings.Path(dir), s); err != nil {
		t.Fatal(err)
	}
	a := answers{asked: make(chan string, 100)}
	k := checker{dataDir: dir, client: func() *fleet.Client { return &fleet.Client{DNS: a, PeerDNS: a} }}
	r := jobs.New(dir, map[string]jobs.Kind{"check": k.kind})
	r.Logf = t.Logf
	runJobs(t, r)
	if _, err := r.Start("check", "test", json.RawMessage(`{"x": 1}`)); err == nil {
		t.Fatal("params taken")
	}
	j, err := r.Start("check", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	for range 400 {
		if j, _ = r.Get(j.ID); j.State.Ended() {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if es, _ := actionlog.Tail(dir, 0); len(es) != 2 || es[0].Action != "job check" {
		t.Fatalf("%+v", es)
	}
	close(a.asked)
	var asked []string
	for q := range a.asked {
		asked = append(asked, q)
	}
	return j, asked
}

// Every node in the settings in service, and the DNS peer answering: the check passes,
// having asked what a rollout asks after a change. A node waiting for a reboot, or a peer
// not answering, fails it.
func TestCheckJob(t *testing.T) {
	a, b := fakeNode(t, false), fakeNode(t, false)
	j, asked := runCheck(t, settings.Settings{Nodes: []string{a, b}, DNSPeers: []string{"198.51.100.254"}})
	if j.State != jobs.Done {
		t.Fatalf("%+v", j)
	}
	var res checkResult
	if err := json.Unmarshal(j.Result, &res); err != nil || !res.OK || len(res.Nodes) != 2 || len(res.DNSPeers) != 1 ||
		res.Nodes[0].State != "healthy" || res.DNSPeers[0].Zones[0] != "home.example" {
		t.Fatalf("%s %v", j.Result, err)
	}
	all := strings.Join(asked, "\n")
	for _, want := range []string{a + " SOA home.example.", a + " A example.com.", b + " A espdns.check.invalid.",
		"198.51.100.254 SOA home.example.", "198.51.100.254 A example.com."} {
		if !strings.Contains(all, want) {
			t.Errorf("not asked %q:\n%s", want, all)
		}
	}
	last := j.Log[len(j.Log)-1].Text
	if last != "all 2 node(s) and 1 DNS peer(s) in service" {
		t.Fatal(last)
	}

	c := fakeNode(t, true)
	j, _ = runCheck(t, settings.Settings{Nodes: []string{a, c}, DNSPeers: []string{"203.0.113.9"}})
	if j.State != jobs.Failed || !strings.Contains(j.Error, "2 problem(s)") || !strings.Contains(j.Error, c+": reboot pending (config)") ||
		!strings.Contains(j.Error, "DNS peer 203.0.113.9") {
		t.Fatalf("%+v", j)
	}

	j, _ = runCheck(t, settings.Settings{})
	if j.State != jobs.Failed || !strings.Contains(j.Error, "no nodes") {
		t.Fatalf("%+v", j)
	}
}
