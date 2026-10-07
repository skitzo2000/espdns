package fleet

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/skitzo2000/espdns/controller/internal/blocklist"
	"github.com/skitzo2000/espdns/controller/internal/fakenode"
	"github.com/skitzo2000/espdns/controller/internal/pins"
	"github.com/skitzo2000/espdns/controller/internal/release"
)

// listWorld is fake nodes (internal/fakenode, which revert as the firmware does) for a list
// rollout, and the lists to push: each blocks its own names on a node (fakenode.Lists).
type listWorld struct {
	t     *testing.T
	nodes []*fakenode.Node
	hosts []string
	fl    fakenode.Fleet
	key   *ecdsa.PrivateKey
	pins  *pins.Ledger
	names map[string][]string // the names each list file blocks, by its bytes
	mu    sync.Mutex
	steps map[string][]Step // what Progress heard, per node
	hook  func(host string, s Step)
	// miss, if set, says whether node i's answer to a GET of path is lost (a 503 with no
	// body, as a busy node or a lost packet gives).
	miss func(i int, path string) bool
}

// listBytes is a blocklist file blocking names (and filler).
func listBytes(t *testing.T, names ...string) []byte {
	es := []blocklist.Entry{}
	for _, n := range names {
		es = append(es, blocklist.Entry{Name: n})
	}
	for i := range 500 {
		es = append(es, blocklist.Entry{Name: fmt.Sprintf("ads%d.example.net", i)})
	}
	b, _, err := blocklist.Build(blocklist.Compile(es), blocklist.BuildOptions{Bits: 44, XorBits: 8, Keys: 1})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func newListWorld(t *testing.T, n int, set func(i int, fn *fakenode.Node)) *listWorld {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	w := &listWorld{t: t, fl: fakenode.Fleet{}, key: k, pins: pins.Open(t.TempDir()), names: map[string][]string{}, steps: map[string][]Step{}}
	for i := range n {
		fn := fakenode.New(fmt.Sprintf("n%d", i), [6]byte{2, 0, 0, 0, 1, byte(i + 1)}, "esp32p4-rev1", "p4-ip101",
			release.PublicRaw(k))
		fn.DownFor = 20 * time.Millisecond
		fn.Queries = release.QueryCounts{Total: 10000, Servfail: 10}
		fn.Lists = func(_ release.Kind, p []byte) []string {
			w.mu.Lock()
			defer w.mu.Unlock()
			return w.names[string(p)]
		}
		if set != nil {
			set(i, fn)
		}
		srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			w.mu.Lock()
			miss := w.miss
			w.mu.Unlock()
			if r.Method == http.MethodGet && miss != nil && miss(i, r.URL.Path) {
				rw.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			fn.ServeHTTP(rw, r)
		}))
		t.Cleanup(srv.Close)
		fn.Addr = strings.TrimPrefix(srv.URL, "http://")
		if _, err := w.pins.Pin(fn.ID(), fn.Addr); err != nil {
			t.Fatal(err)
		}
		w.fl[fn.Addr] = fn
		w.nodes = append(w.nodes, fn)
		w.hosts = append(w.hosts, fn.Addr)
	}
	return w
}

// list is a list file that blocks names, known to the nodes.
func (w *listWorld) list(names ...string) []byte {
	b := listBytes(w.t, names...)
	w.mu.Lock()
	w.names[string(b)] = names
	w.mu.Unlock()
	return b
}

func (w *listWorld) client() *Client {
	return &Client{Pusher: &release.Pusher{Key: w.key, Pins: w.pins, Client: loopback}, HTTP: loopback, DNS: w.fl, PeerDNS: w.fl,
		Poll: 3 * time.Millisecond, Logf: w.t.Logf,
		Progress: func(h string, s Step, _ string) {
			w.mu.Lock()
			w.steps[h] = append(w.steps[h], s)
			hook := w.hook
			w.mu.Unlock()
			if hook != nil {
				hook(h, s)
			}
		}}
}

func (w *listWorld) stepsOf(h string) []Step {
	w.mu.Lock()
	defer w.mu.Unlock()
	return slices.Clone(w.steps[h])
}

func (w *listWorld) plan(canary string) Plan {
	return Plan{Targets: w.hosts, Canary: canary, Soak: 40 * time.Millisecond, RebootWait: 5 * time.Second,
		ConfirmWait: 400 * time.Millisecond,
		Checks: Checks{Forwarded: []string{"example.com"}, Blocked: []string{"doubleclick.net"},
			MustResolve: []string{"wikipedia.org"}}}
}

func listChange(kind release.Kind, payload []byte) Change {
	return Change{Kind: kind, Payload: func(context.Context, string, release.NodeStatus) ([]byte, error) { return payload, nil }}
}

// status is the node's /status, as the controller reads it.
func status(t *testing.T, n *fakenode.Node) release.NodeStatus {
	rec := httptest.NewRecorder()
	n.ServeHTTP(rec, httptest.NewRequest("GET", "http://"+n.Addr+"/status", nil)) // its address, as the controller sends it
	var st release.NodeStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	return st
}

// blocks says whether the node answers name as blocked.
func blocks(n *fakenode.Node, name string) bool {
	m := new(dns.Msg)
	m.SetQuestion(name+".", dns.TypeA)
	r := n.Answer(m)
	return r != nil && blockedAnswer(r)
}

// A list goes to the canary first, is checked there (in service, its seq on in /status, the
// blocked and must-resolve names), soaked and watched, then to each other node the same
// way, the last one soaked too.
func TestListRolloutCanaryAndSoak(t *testing.T) {
	w := newListWorld(t, 3, nil)
	a, b, c := w.hosts[0], w.hosts[1], w.hosts[2]
	good := w.list("doubleclick.net", "tracker.example")
	res, err := w.client().Rollout(context.Background(), w.plan(b), listChange(release.Blocklist, good))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(res.Done, []string{b, a, c}) || len(res.Reverted)+len(res.NotReverted) != 0 || res.Failed != "" {
		t.Fatalf("%+v", res)
	}
	for i, n := range w.nodes {
		st := status(t, n)
		if l := st.List(release.Blocklist); l.State != "on" || l.Seq != st.Seq["blocklist"] || l.Seq == 1 || l.RevertedFrom != 0 {
			t.Errorf("%s: %+v", w.hosts[i], l)
		}
		if !blocks(n, "tracker.example") {
			t.Errorf("%s doesn't block the new list's name", w.hosts[i])
		}
		// Every node soaked, the last one too, and checked again after.
		steps := w.stepsOf(w.hosts[i])
		if !slices.Contains(steps, StepSoaking) || steps[len(steps)-1] != StepDone {
			t.Errorf("%s: %v", w.hosts[i], steps)
		}
	}
	if ev := w.nodes[1].Events(); !slices.Equal(ev, []string{"push blocklist"}) {
		t.Errorf("canary: %v", ev)
	}
	// The plan says it so, for a dry run too.
	d := strings.Join(w.plan(b).Describe(release.Blocklist), "\n")
	for _, want := range []string{"canary " + b + " first", "then one at a time, the same way: " + a + ", " + c,
		"the last node too", "servfail", "every node that took this blocklist goes back"} {
		if !strings.Contains(d, want) {
			t.Errorf("plan: no %q in %q", want, d)
		}
	}
}

// The canary's list doesn't block a CHECK_BLOCKED name: the canary goes back to the list it
// had, live, the rollout stops, and the other nodes are never touched.
func TestListCanaryFailsReverted(t *testing.T) {
	w := newListWorld(t, 3, nil)
	a, b, c := w.hosts[0], w.hosts[1], w.hosts[2]
	bad := w.list("tracker.example") // not doubleclick.net
	res, err := w.client().Rollout(context.Background(), w.plan(b), listChange(release.Blocklist, bad))
	if err == nil || !strings.Contains(err.Error(), "doubleclick.net: not blocked") {
		t.Fatal(err)
	}
	if res.Failed != b || !slices.Equal(res.Reverted, []string{b}) || len(res.Done) != 0 || !slices.Equal(res.Left, []string{a, c}) {
		t.Fatalf("%+v", res)
	}
	st := status(t, w.nodes[1])
	l := st.List(release.Blocklist)
	if l.Seq != 1 || l.State != "on" || l.RevertedFrom != st.Seq["blocklist"] {
		t.Errorf("canary after the revert: %+v (it took seq %d)", l, st.Seq["blocklist"])
	}
	if !blocks(w.nodes[1], "doubleclick.net") || blocks(w.nodes[1], "tracker.example") {
		t.Error("the canary doesn't answer as its old list again")
	}
	if ev := w.nodes[1].Events(); !slices.Equal(ev, []string{"push blocklist", "push control"}) {
		t.Errorf("canary: %v", ev)
	}
	for _, n := range []*fakenode.Node{w.nodes[0], w.nodes[2]} {
		if len(n.Events()) != 0 {
			t.Errorf("%s touched: %v", n.Addr, n.Events())
		}
	}
	if s := w.stepsOf(b); !slices.Contains(s, StepReverting) || s[len(s)-1] != StepReverted {
		t.Errorf("canary steps %v", s)
	}
}

// The second node fails after the canary passed: every node that took the list goes back
// (the failed one first, then the canary), so the fleet runs one list; the third is never
// touched. Here it is MUST_RESOLVE: the list blocks a name that must resolve, on that node.
func TestListSecondNodeFailsAllReverted(t *testing.T) {
	w := newListWorld(t, 3, nil)
	a, b, c := w.hosts[0], w.hosts[1], w.hosts[2]
	good := w.list("doubleclick.net")
	w.nodes[1].Lists = func(release.Kind, []byte) []string { return []string{"doubleclick.net", "wikipedia.org"} }
	res, err := w.client().Rollout(context.Background(), w.plan(a), listChange(release.Blocklist, good))
	if err == nil || !strings.Contains(err.Error(), "must-resolve wikipedia.org: blocked") {
		t.Fatal(err)
	}
	if res.Failed != b || !slices.Equal(res.Reverted, []string{b, a}) || len(res.Done) != 0 || !slices.Equal(res.Left, []string{c}) {
		t.Fatalf("%+v", res)
	}
	for _, n := range w.nodes[:2] {
		if l := status(t, n).List(release.Blocklist); l.Seq != 1 || l.RevertedFrom == 0 {
			t.Errorf("%s: %+v", n.Addr, l)
		}
	}
	if len(w.nodes[2].Events()) != 0 {
		t.Errorf("third touched: %v", w.nodes[2].Events())
	}
}

// The soak is watched: servfail jumping on the canary while it soaks fails it, and it goes
// back. Overrides, the same way.
func TestListSoakWatched(t *testing.T) {
	w := newListWorld(t, 2, nil)
	a, b := w.hosts[0], w.hosts[1]
	ovr := listBytes(t, "local.example")
	// Into the soak, after its start was read: at the first look's /status (no timer, so a
	// slow test machine can't let the soak end first).
	var mu sync.Mutex
	soaking, reads := false, 0
	w.hook = func(h string, s Step) {
		mu.Lock()
		defer mu.Unlock()
		if h == a && s == StepSoaking {
			soaking, reads = true, 0
		}
	}
	w.miss = func(i int, path string) bool {
		mu.Lock()
		defer mu.Unlock()
		if i == 0 && soaking && path == "/status" {
			if reads++; reads == 2 {
				w.nodes[0].Do(func(n *fakenode.Node) { n.Queries.Total += 200; n.Queries.Servfail += 120 })
			}
		}
		return false
	}
	// The overrides' first push: the node has none, so nothing older to go back to.
	res, err := w.client().Rollout(context.Background(), w.plan(a), listChange(release.Overrides, ovr))
	if err == nil || !strings.Contains(err.Error(), "servfail jumped: 120 of 200 queries") {
		t.Fatal(err)
	}
	if res.Failed != a || len(res.Reverted) != 0 || len(res.NotReverted) != 1 || !slices.Equal(res.Left, []string{b}) {
		t.Fatalf("%+v", res)
	}
	nr := res.NotReverted[0]
	if nr.Host != a || !strings.Contains(nr.Why, "no previous overrides to revert to") ||
		!strings.Contains(nr.WayOn, "push the overrides it should run") {
		t.Errorf("%+v", nr)
	}
	// A second overrides push: the first is the older copy now, so it goes back to it.
	ovr2 := listBytes(t, "local2.example")
	res, err = w.client().Rollout(context.Background(), w.plan(a), listChange(release.Overrides, ovr2))
	if err == nil || !slices.Equal(res.Reverted, []string{a}) || len(w.nodes[1].Events()) != 0 {
		t.Fatalf("%v %+v", err, res)
	}
	if l := status(t, w.nodes[0]).List(release.Overrides); l.State != "on" || l.RevertedFrom == 0 {
		t.Errorf("%+v", l)
	}
}

// A node that never had a list refuses the revert (nothing older): it is named, with the
// way on (pause blocking on it, push the list it should run); nothing else is touched.
func TestListRevertRefused(t *testing.T) {
	w := newListWorld(t, 2, func(i int, n *fakenode.Node) { n.NoList = i == 0 })
	a, b := w.hosts[0], w.hosts[1]
	bad := w.list("tracker.example")
	res, err := w.client().Rollout(context.Background(), w.plan(a), listChange(release.Blocklist, bad))
	if err == nil || res.Failed != a || len(res.Reverted) != 0 || len(res.NotReverted) != 1 || !slices.Equal(res.Left, []string{b}) {
		t.Fatalf("%v %+v", err, res)
	}
	nr := res.NotReverted[0]
	if !strings.Contains(nr.Why, "the revert was refused") || !strings.Contains(nr.Why, "no previous list to revert to") ||
		!strings.Contains(nr.WayOn, "espdns pause -host "+a) {
		t.Errorf("%+v", nr)
	}
	if s := w.stepsOf(a); s[len(s)-1] != StepNotReverted {
		t.Errorf("steps %v", s)
	}
}

// A list that needs a reboot to load (two copies don't fit) is rebooted into, coordinated;
// when it fails, its revert needs one too, coordinated the same way. If the rule then holds
// the reboot back (no other node answering), the node is left with the revert pending and
// named: never the last healthy node.
func TestListRevertWithReboot(t *testing.T) {
	w := newListWorld(t, 2, func(i int, n *fakenode.Node) { n.ListReboot = i == 0 })
	a := w.hosts[0]
	bad := w.list("tracker.example")
	res, err := w.client().Rollout(context.Background(), w.plan(a), listChange(release.Blocklist, bad))
	if err == nil || !slices.Equal(res.Reverted, []string{a}) {
		t.Fatalf("%v %+v", err, res)
	}
	want := []string{"push blocklist", "push control", "reboot", "up", "push control", "push control", "reboot", "up"}
	if ev := w.nodes[0].Events(); !slices.Equal(ev, want) {
		t.Errorf("events %v, want %v", ev, want)
	}
	if l := status(t, w.nodes[0]).List(release.Blocklist); l.Seq != 1 || l.RevertedFrom == 0 {
		t.Errorf("%+v", l)
	}

	// Again, and the other node goes down as the revert starts: its reboot is held back.
	w2 := newListWorld(t, 2, func(i int, n *fakenode.Node) { n.ListReboot = i == 0 })
	a2 := w2.hosts[0]
	w2.hook = func(h string, s Step) {
		if h == a2 && s == StepReverting {
			w2.nodes[1].Break(true)
		}
	}
	res, err = w2.client().Rollout(context.Background(), w2.plan(a2), listChange(release.Blocklist, w2.list("tracker.example")))
	if err == nil || len(res.NotReverted) != 1 {
		t.Fatalf("%v %+v", err, res)
	}
	nr := res.NotReverted[0]
	if !strings.Contains(nr.Why, "the last healthy node") || !strings.Contains(nr.WayOn, "espdns reboot -host "+a2+" -if-pending") {
		t.Errorf("%+v", nr)
	}
	if st := status(t, w2.nodes[0]); st.Reboot == nil || !st.Reboot.Pending {
		t.Errorf("no reboot pending: %+v", st.Reboot)
	}
}

// The rule holding the next node back is not the list's failure: nothing is reverted, the
// canary keeps the list, as after a stop.
func TestListRuleStopRevertsNothing(t *testing.T) {
	w := newListWorld(t, 3, nil)
	a, b, c := w.hosts[0], w.hosts[1], w.hosts[2]
	w.hook = func(h string, s Step) {
		if h == a && s == StepDone {
			w.nodes[2].Break(true)
		}
	}
	res, err := w.client().Rollout(context.Background(), w.plan(a), listChange(release.Blocklist, w.list("doubleclick.net")))
	if err == nil || !strings.Contains(err.Error(), "not started") {
		t.Fatal(err)
	}
	if res.Failed != b || !slices.Equal(res.Done, []string{a}) || len(res.Reverted)+len(res.NotReverted) != 0 ||
		!slices.Equal(res.Left, []string{c}) {
		t.Fatalf("%+v", res)
	}
	if ev := w.nodes[0].Events(); !slices.Equal(ev, []string{"push blocklist"}) {
		t.Errorf("%v", ev)
	}
}

// A revert sends back only this rollout's list: a node that took a newer one since (another
// push, from elsewhere) is not reverted, which would undo that one; it is named, with the
// way on. The failed node, still on this rollout's, goes back.
func TestListRevertOnlyThisRolloutsList(t *testing.T) {
	w := newListWorld(t, 3, nil)
	a, b, c := w.hosts[0], w.hosts[1], w.hosts[2]
	good := w.list("doubleclick.net")
	newer := w.list("doubleclick.net", "newer.example")
	w.nodes[1].Lists = func(release.Kind, []byte) []string { return []string{"doubleclick.net", "wikipedia.org"} }
	pusher := &release.Pusher{Key: w.key, Pins: w.pins, Client: loopback}
	w.hook = func(h string, s Step) {
		if h == b && s == StepPushing { // another push reaches the canary meanwhile
			if _, err := pusher.PushRelease(context.Background(), a, release.Blocklist, newer); err != nil {
				t.Error(err)
			}
		}
	}
	res, err := w.client().Rollout(context.Background(), w.plan(a), listChange(release.Blocklist, good))
	if err == nil || !strings.Contains(err.Error(), "must-resolve wikipedia.org: blocked") {
		t.Fatal(err)
	}
	if res.Failed != b || !slices.Equal(res.Reverted, []string{b}) || len(res.NotReverted) != 1 || !slices.Equal(res.Left, []string{c}) {
		t.Fatalf("%+v", res)
	}
	nr := res.NotReverted[0]
	if nr.Host != a || !strings.Contains(nr.Why, "since this rollout's seq") || !strings.Contains(nr.WayOn, "espdns revert -host "+a) {
		t.Errorf("%+v", nr)
	}
	st := status(t, w.nodes[0])
	if l := st.List(release.Blocklist); l.Seq != st.Seq["blocklist"] || l.RevertedFrom != 0 || !blocks(w.nodes[0], "newer.example") {
		t.Errorf("the canary's newer list was touched: %+v", l)
	}
	if ev := w.nodes[0].Events(); slices.Contains(ev, "push control") {
		t.Errorf("canary: %v", ev)
	}
}

// A node a failed rollout thought may have taken the list (it couldn't be read after its
// push failed) but didn't: nothing is sent back there (a revert would go back past the
// list it had), and it is neither reverted nor named not reverted.
func TestListRevertNotTaken(t *testing.T) {
	w := newListWorld(t, 2, nil)
	a := w.hosts[0]
	c := w.client()
	before := status(t, w.nodes[0])
	p := w.plan(a)
	res := Result{}
	outs := map[string]applyOut{a: {pushed: true, before: before}} // the push's seq unknown: it failed
	_, err := c.failed(context.Background(), p, listChange(release.Blocklist, nil), &res, w.hosts, 0, true, outs,
		fmt.Errorf("%s: the push failed", a))
	if err == nil || len(res.Reverted)+len(res.NotReverted) != 0 || res.Failed != a {
		t.Fatalf("%v %+v", err, res)
	}
	if ev := w.nodes[0].Events(); len(ev) != 0 {
		t.Errorf("%v", ev)
	}
	if l := status(t, w.nodes[0]).List(release.Blocklist); l.Seq != 1 || l.RevertedFrom != 0 {
		t.Errorf("%+v", l)
	}
}

// The rollout ending (the controller shutting down) during the revert: every node that
// took the list and wasn't sent back is named, with this rollout's seq and the way on.
func TestListRevertEnded(t *testing.T) {
	w := newListWorld(t, 3, nil)
	a, b := w.hosts[0], w.hosts[1]
	w.nodes[1].Lists = func(release.Kind, []byte) []string { return []string{"doubleclick.net", "wikipedia.org"} }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.hook = func(h string, s Step) {
		if h == b && s == StepReverting {
			cancel()
		}
	}
	res, err := w.client().Rollout(ctx, w.plan(a), listChange(release.Blocklist, w.list("doubleclick.net")))
	if err == nil || len(res.Reverted) != 0 || len(res.NotReverted) != 2 {
		t.Fatalf("%v %+v", err, res)
	}
	for i, h := range []string{b, a} {
		nr := res.NotReverted[i]
		if nr.Host != h || !strings.Contains(nr.Why, "the rollout ended") || !strings.Contains(nr.WayOn, "espdns revert -host "+h) ||
			!strings.Contains(nr.WayOn, "this rollout's blocklist seq ") {
			t.Errorf("%+v", nr)
		}
	}
}

// One look that can't read a soaking node (a lost answer) isn't its failure: the soak goes
// on and the list stays; looks failing soakMisses times in a row are.
func TestListSoakMissedLook(t *testing.T) {
	w := newListWorld(t, 2, nil)
	a, b := w.hosts[0], w.hosts[1]
	var mu sync.Mutex
	lost := map[int]int{} // how many more /health reads of node i are lost
	w.miss = func(i int, path string) bool {
		mu.Lock()
		defer mu.Unlock()
		if path == "/health" && lost[i] > 0 {
			lost[i]--
			return true
		}
		return false
	}
	w.hook = func(h string, s Step) {
		if h == a && s == StepSoaking {
			mu.Lock()
			lost[0] = soakMisses - 1
			mu.Unlock()
		}
	}
	p := w.plan(a)
	p.Soak = 80 * time.Millisecond
	res, err := w.client().Rollout(context.Background(), p, listChange(release.Blocklist, w.list("doubleclick.net")))
	if err != nil || !slices.Equal(res.Done, []string{a, b}) {
		t.Fatalf("%v %+v", err, res)
	}

	// Lost all along: the node is failed, and sent back.
	w2 := newListWorld(t, 2, nil)
	a2 := w2.hosts[0]
	var on sync.Once
	soaking := make(chan struct{})
	w2.hook = func(h string, s Step) {
		if h == a2 && s == StepSoaking {
			on.Do(func() { close(soaking) })
		}
	}
	w2.miss = func(i int, path string) bool {
		select {
		case <-soaking:
			return i == 0 && path == "/health"
		default:
			return false
		}
	}
	p2 := w2.plan(a2)
	p2.Soak = 80 * time.Millisecond
	res, err = w2.client().Rollout(context.Background(), p2, listChange(release.Blocklist, w2.list("doubleclick.net")))
	if err == nil || !strings.Contains(err.Error(), "didn't answer 3 looks in a row") || res.Failed != a2 {
		t.Fatalf("%v %+v", err, res)
	}
}
