package jobs

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/actionlog"
	"github.com/skitzo2000/espdns/controller/internal/fleet"
	"github.com/skitzo2000/espdns/controller/internal/fleetlock"
)

// kinds for the tests: "lines" logs its params' lines and returns their count; "gated"
// logs, waits for the test (or a stop), logs again; "fail" fails.
type testKinds struct {
	gate    chan struct{}
	started chan string
}

func newKinds() *testKinds {
	return &testKinds{gate: make(chan struct{}), started: make(chan string, 10)}
}

func (k *testKinds) kinds() map[string]Kind {
	return map[string]Kind{
		"lines": func(params json.RawMessage) (Func, error) {
			var lines []string
			if err := json.Unmarshal(params, &lines); err != nil {
				return nil, err
			}
			return func(ctx context.Context, run *Run) (any, error) {
				for _, l := range lines {
					run.Logf("%s", l)
				}
				return map[string]int{"lines": len(lines)}, nil
			}, nil
		},
		"gated": func(json.RawMessage) (Func, error) {
			return func(ctx context.Context, run *Run) (any, error) {
				run.Logf("waiting")
				k.started <- run.ID
				select {
				case <-k.gate:
				case <-run.Stop():
					run.Logf("stopping")
					return nil, fleet.ErrStopped
				case <-ctx.Done():
					return nil, ctx.Err()
				}
				run.Logf("through")
				return nil, nil
			}, nil
		},
		"stopfail": func(json.RawMessage) (Func, error) {
			return func(ctx context.Context, run *Run) (any, error) {
				k.started <- run.ID
				<-run.Stop()
				return nil, errors.New("node 198.51.100.2: not in service after its change")
			}, nil
		},
		"progress": func(json.RawMessage) (Func, error) {
			return func(ctx context.Context, run *Run) (any, error) {
				run.SetProgress(map[string]string{"a": "pushing"})
				k.started <- run.ID
				<-k.gate
				run.SetProgress(map[string]string{"a": "done"})
				<-k.gate
				return nil, nil
			}, nil
		},
		"fail": func(json.RawMessage) (Func, error) {
			return func(context.Context, *Run) (any, error) { return nil, errors.New("node 198.51.100.2: unhealthy") }, nil
		},
	}
}

func newRunner(t *testing.T, k *testKinds) (*Runner, string, context.CancelFunc) {
	dir := t.TempDir()
	r := New(dir, k.kinds())
	r.Logf = t.Logf
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return r, dir, cancel
}

func waitEnd(t *testing.T, r *Runner, id string) Job {
	t.Helper()
	for range 500 {
		if j, _ := r.Get(id); j.State.Ended() {
			return j
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("job %s didn't end", id)
	return Job{}
}

func TestLifecycle(t *testing.T) {
	r, dir, _ := newRunner(t, newKinds())
	if _, err := r.Start("push", "test", nil); !errors.Is(err, ErrUnknownKind) {
		t.Fatal(err)
	}
	if _, err := r.Start("lines", "test", json.RawMessage(`"not a list"`)); err == nil {
		t.Fatal("bad params queued")
	}
	j, err := r.Start("lines", "test", json.RawMessage(`["a: healthy", "b: healthy"]`))
	if err != nil || j.State != Queued || j.ID == "" {
		t.Fatal(j, err)
	}
	j = waitEnd(t, r, j.ID)
	if j.State != Done || j.Error != "" || string(j.Result) != `{"lines":2}` || j.Lines != 2 ||
		len(j.Log) != 2 || j.Log[1].N != 2 || j.Log[1].Text != "b: healthy" || j.Started.IsZero() || j.Ended.Before(j.Started) {
		t.Fatalf("%+v", j)
	}
	// The list has no logs, but each job's last line: where it is.
	if l := r.List(); len(l) != 1 || l[0].Log != nil || l[0].ID != j.ID || l[0].Last != "b: healthy" {
		t.Fatalf("%+v", l)
	}
	es, _ := actionlog.Tail(dir, 0)
	if len(es) != 2 || es[0].Event != "start" || es[1].Event != "end" || es[1].Result != "ok" ||
		es[0].ID != j.ID || es[0].Action != "job lines" || es[0].Source != "controller" || es[0].Who != "test" {
		t.Fatalf("%+v", es)
	}
	if _, held, _ := fleetlock.Held(fleetlock.Path(dir)); held {
		t.Fatal("lock still held")
	}

	f, _ := r.Start("fail", "test", nil)
	if f = waitEnd(t, r, f.ID); f.State != Failed || f.Error != "node 198.51.100.2: unhealthy" {
		t.Fatalf("%+v", f)
	}

	// The records outlast the controller.
	if _, err := os.Stat(filepath.Join(dir, "log", "jobs", j.ID+".json")); err != nil {
		t.Fatal(err)
	}
	r2 := New(dir, nil)
	if got, ok := r2.Get(j.ID); !ok || got.State != Done || len(got.Log) != 2 {
		t.Fatalf("%+v", got)
	}
	if l := r2.List(); len(l) != 2 || l[0].ID != f.ID {
		t.Fatalf("%+v", l)
	}
}

// A job is recorded when it starts: one the controller was killed during comes back
// failed, saying so.
func TestKilledDuringJob(t *testing.T) {
	k := newKinds()
	dir := t.TempDir()
	r := New(dir, k.kinds())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()
	a, _ := r.Start("gated", "test", nil)
	<-k.started
	b, err := os.ReadFile(filepath.Join(dir, "log", "jobs", a.ID+".json"))
	if err != nil || !strings.Contains(string(b), `"running"`) {
		t.Fatalf("%s %v", b, err)
	}
	// As if killed now: a new runner on the same directory, the old one never ending.
	r2 := New(dir, nil)
	if j, ok := r2.Get(a.ID); !ok || j.State != Failed || !strings.Contains(j.Error, "controller ended") {
		t.Fatalf("%+v", j)
	}
	close(k.gate)
	waitEnd(t, r, a.ID)
	cancel()
	<-done
}

// One job at a time, under the fleet lock; a second waits queued.
func TestOneAtATime(t *testing.T) {
	k := newKinds()
	r, dir, _ := newRunner(t, k)
	a, _ := r.Start("gated", "test", nil)
	b, _ := r.Start("gated", "test", nil)
	<-k.started
	if ja, _ := r.Get(a.ID); ja.State != Running {
		t.Fatal(ja.State)
	}
	if jb, _ := r.Get(b.ID); jb.State != Queued {
		t.Fatal(jb.State)
	}
	h, held, _ := fleetlock.Held(fleetlock.Path(dir))
	if !held || h.Who != "espdns-controller job "+a.ID || !strings.Contains(h.What, "gated, started by test") {
		t.Fatal(h, held)
	}
	// The CLI can't take it meanwhile.
	if _, err := fleetlock.Acquire(fleetlock.Path(dir), fleetlock.Self("espdns rollout", "")); !errors.Is(err, fleetlock.ErrLocked) ||
		!strings.Contains(err.Error(), a.ID) {
		t.Fatal(err)
	}
	k.gate <- struct{}{}
	if id := <-k.started; id != b.ID {
		t.Fatal(id)
	}
	k.gate <- struct{}{}
	if j := waitEnd(t, r, b.ID); j.State != Done {
		t.Fatal(j)
	}
}

// With the CLI holding the lock, a job fails at once, saying who has it.
func TestLockedByCLI(t *testing.T) {
	r, dir, _ := newRunner(t, newKinds())
	l, err := fleetlock.Acquire(fleetlock.Path(dir), fleetlock.Self("espdns rollout", "rollout -kind firmware"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Release()
	j, _ := r.Start("lines", "test", json.RawMessage(`["x"]`))
	j = waitEnd(t, r, j.ID)
	if j.State != Failed || !strings.Contains(j.Error, "locked by espdns rollout (rollout -kind firmware)") ||
		len(j.Log) != 1 || !strings.HasPrefix(j.Log[0].Text, "not started") {
		t.Fatalf("%+v", j)
	}
	es, _ := actionlog.Tail(dir, 0)
	if len(es) != 1 || es[0].Event != "refused" {
		t.Fatalf("%+v", es)
	}
}

// Stop: a running job ends at its next safe point, a queued one never starts; ending the
// controller stops the running job.
func TestStop(t *testing.T) {
	k := newKinds()
	r, dir, cancel := newRunner(t, k)
	a, _ := r.Start("gated", "test", nil)
	b, _ := r.Start("gated", "test", nil)
	<-k.started
	if j, err := r.Stop(b.ID); err != nil || j.State != Stopped {
		t.Fatal(j, err)
	}
	if j, err := r.Stop(a.ID); err != nil || !j.Stopping || j.State != Running {
		t.Fatal(j, err)
	}
	ja := waitEnd(t, r, a.ID)
	if ja.State != Stopped || ja.Log[len(ja.Log)-1].Text != "stopping" {
		t.Fatalf("%+v", ja)
	}
	if _, err := r.Stop(a.ID); !errors.Is(err, ErrEnded) {
		t.Fatal(err)
	}
	if _, err := r.Stop("nope"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	es, _ := actionlog.Tail(dir, 0)
	if len(es) != 2 || es[1].Result != "stopped" {
		t.Fatalf("%+v", es)
	}

	// Asked to stop, but failed before its safe point: failed, not stopped.
	f, _ := r.Start("stopfail", "test", nil)
	<-k.started
	r.Stop(f.ID)
	if j := waitEnd(t, r, f.ID); j.State != Failed || !strings.Contains(j.Error, "not in service") {
		t.Fatalf("%+v", j)
	}

	c, _ := r.Start("gated", "test", nil)
	<-k.started
	d, _ := r.Start("gated", "test", nil)
	cancel()
	if j := waitEnd(t, r, c.ID); j.State != Stopped || !strings.Contains(j.Error, "shut down") {
		t.Fatalf("%+v", j)
	}
	// The one queued at the shutdown never starts: stopped, and not in the action log.
	if j := waitEnd(t, r, d.ID); j.State != Stopped || !j.Started.IsZero() || !strings.Contains(j.Error, "before it started") {
		t.Fatalf("%+v", j)
	}
	es, _ = actionlog.Tail(dir, 0)
	for _, e := range es {
		if e.ID == d.ID {
			t.Fatalf("%+v", e)
		}
	}
}

// event is one Server-Sent Event.
type event struct {
	id, name, data string
}

func readEvents(t *testing.T, resp *http.Response, out chan<- event) {
	defer close(out)
	sc := bufio.NewScanner(resp.Body)
	var e event
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			if e.name != "" {
				out <- e
			}
			e = event{}
		case strings.HasPrefix(line, "id: "):
			e.id = line[4:]
		case strings.HasPrefix(line, "event: "):
			e.name = line[7:]
		case strings.HasPrefix(line, "data: "):
			e.data = line[6:]
		}
	}
}

func next(t *testing.T, ch <-chan event) event {
	t.Helper()
	select {
	case e, ok := <-ch:
		if !ok {
			t.Fatal("stream closed")
		}
		return e
	case <-time.After(5 * time.Second):
		t.Fatal("no event")
	}
	return event{}
}

func post(t *testing.T, url, body string) *http.Response {
	t.Helper()
	resp, err := http.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// The API end to end: start, follow live over SSE, end; resume after a line.
func TestHTTP(t *testing.T) {
	k := newKinds()
	r, _, _ := newRunner(t, k)
	mux := http.NewServeMux()
	r.Routes(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp := post(t, srv.URL+"/api/jobs", `{"kind": "gated"}`)
	var j Job
	json.NewDecoder(resp.Body).Decode(&j)
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted || j.ID == "" || resp.Header.Get("Location") != "/api/jobs/"+j.ID ||
		!strings.HasPrefix(j.Who, "web (127.0.0.1)") {
		t.Fatal(resp.Status, j)
	}
	<-k.started

	resp, err := http.Get(srv.URL + "/api/jobs/" + j.ID + "/events")
	if err != nil || resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatal(err, resp.Header)
	}
	defer resp.Body.Close()
	ch := make(chan event)
	go readEvents(t, resp, ch)
	if e := next(t, ch); e.name != "state" || !strings.Contains(e.data, `"state":"running"`) {
		t.Fatal(e)
	}
	if e := next(t, ch); e.name != "log" || e.id != "1" || !strings.Contains(e.data, `"text":"waiting"`) {
		t.Fatal(e)
	}
	k.gate <- struct{}{} // live from here
	if e := next(t, ch); e.name != "log" || e.id != "2" || !strings.Contains(e.data, `"text":"through"`) {
		t.Fatal(e)
	}
	if e := next(t, ch); e.name != "state" || !strings.Contains(e.data, `"state":"done"`) {
		t.Fatal(e)
	}
	if e := next(t, ch); e.name != "end" {
		t.Fatal(e)
	}
	if _, ok := <-ch; ok {
		t.Fatal("stream not closed after the end")
	}

	// A reconnect after line 1 gets line 2 and the end.
	req, _ := http.NewRequest("GET", srv.URL+"/api/jobs/"+j.ID+"/events", nil)
	req.Header.Set("Last-Event-ID", "1")
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	ch2 := make(chan event)
	go readEvents(t, resp2, ch2)
	var names []string
	for e := range ch2 {
		names = append(names, e.name+e.id)
	}
	if strings.Join(names, " ") != "state log2 end" {
		t.Fatal(names)
	}

	// The list and one job.
	var list []Job
	lr, _ := http.Get(srv.URL + "/api/jobs")
	json.NewDecoder(lr.Body).Decode(&list)
	lr.Body.Close()
	if len(list) != 1 || list[0].State != Done {
		t.Fatal(list)
	}
	if gr, _ := http.Get(srv.URL + "/api/jobs/nope"); gr.StatusCode != http.StatusNotFound {
		t.Fatal(gr.Status)
	}
	if sr := post(t, srv.URL+"/api/jobs/"+j.ID+"/stop", "{}"); sr.StatusCode != http.StatusConflict {
		t.Fatal(sr.Status)
	}
	if sr := post(t, srv.URL+"/api/jobs", `{"kind": "push"}`); sr.StatusCode != http.StatusBadRequest {
		t.Fatal(sr.Status)
	}
}

// A job's progress (Run.SetProgress) is in its state first, then a "progress" event at each
// change; kept in its record, left out of the list.
func TestHTTPProgress(t *testing.T) {
	k := newKinds()
	r, _, _ := newRunner(t, k)
	mux := http.NewServeMux()
	r.Routes(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	j, err := r.Start("progress", "admin", nil)
	if err != nil {
		t.Fatal(err)
	}
	<-k.started
	resp, err := http.Get(srv.URL + "/api/jobs/" + j.ID + "/events")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	ch := make(chan event)
	go readEvents(t, resp, ch)
	if e := next(t, ch); e.name != "state" || !strings.Contains(e.data, `"progress":{"a":"pushing"}`) {
		t.Fatal(e)
	}
	k.gate <- struct{}{}
	if e := next(t, ch); e.name != "progress" || e.data != `{"a":"done"}` {
		t.Fatal(e)
	}
	k.gate <- struct{}{}
	if e := next(t, ch); e.name != "state" || !strings.Contains(e.data, `"state":"done"`) {
		t.Fatal(e)
	}
	if got, _ := r.Get(j.ID); string(got.Progress) != `{"a":"done"}` {
		t.Fatal(string(got.Progress))
	}
	if l := r.List(); len(l) != 1 || l[0].Progress != nil {
		t.Fatal(l)
	}
}

// Only JSON, from this page, to a localhost name, starts or stops a job.
func TestHTTPLocalOnly(t *testing.T) {
	r, _, _ := newRunner(t, newKinds())
	mux := http.NewServeMux()
	r.Routes(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	for name, set := range map[string]func(*http.Request){
		"form":       func(req *http.Request) { req.Header.Set("Content-Type", "application/x-www-form-urlencoded") },
		"text":       func(req *http.Request) { req.Header.Set("Content-Type", "text/plain") },
		"origin":     func(req *http.Request) { req.Header.Set("Origin", "http://evil.example") },
		"cross-site": func(req *http.Request) { req.Header.Set("Sec-Fetch-Site", "cross-site") },
		"null":       func(req *http.Request) { req.Header.Set("Origin", "null") },
		"rebound DNS": func(req *http.Request) {
			req.Host = "evil.example:8480"
			req.Header.Set("Origin", "http://evil.example:8480")
		},
	} {
		req, _ := http.NewRequest("POST", srv.URL+"/api/jobs", strings.NewReader(`{"kind": "lines", "params": ["x"]}`))
		req.Header.Set("Content-Type", "application/json")
		set(req)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s: %s", name, resp.Status)
		}
	}
	if len(r.List()) != 0 {
		t.Fatal("a job was started")
	}
	req, _ := http.NewRequest("POST", srv.URL+"/api/jobs", strings.NewReader(`{"kind": "lines", "params": ["x"]}`))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Origin", srv.URL)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != http.StatusAccepted {
		t.Fatal(resp, err)
	}
}

// LocalOnly: every API request needs a localhost Host, the GETs too (a page elsewhere
// can't read the logs through a rebound DNS name); a POST anywhere under /api/ also needs
// no other site's Origin. Pages outside /api/ and /build/ are served to anyone.
func TestHTTPLocalOnlyAPI(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/actions", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("[]")) })
	mux.HandleFunc("POST /api/boards", func(w http.ResponseWriter, _ *http.Request) {})
	mux.HandleFunc("GET /jobs.html", func(w http.ResponseWriter, _ *http.Request) {})
	srv := httptest.NewServer(LocalOnly(mux))
	defer srv.Close()
	for _, c := range []struct {
		method, path, host, origin string
		want                       int
	}{
		{"GET", "/api/actions", "", "", http.StatusOK},
		{"GET", "/api/actions", "localhost:8480", "", http.StatusOK},
		{"GET", "/api/actions", "[::1]:8480", "", http.StatusOK},
		{"GET", "/api/actions", "[::1]", "", http.StatusOK},
		{"GET", "/api/actions", "LOCALHOST", "", http.StatusOK},
		{"GET", "/api/actions", "evil.example:8480", "", http.StatusForbidden},
		{"GET", "/api/actions", "192.0.2.10:8480", "", http.StatusForbidden},
		{"GET", "/jobs.html", "evil.example:8480", "", http.StatusOK},
		{"POST", "/api/boards", "", "", http.StatusOK},
		{"POST", "/api/boards", "", "http://evil.example", http.StatusForbidden},
		{"POST", "/api/boards", "", "null", http.StatusForbidden},
		{"POST", "/api/boards", "evil.example", "", http.StatusForbidden},
	} {
		req, _ := http.NewRequest(c.method, srv.URL+c.path, strings.NewReader("{}"))
		if c.host != "" {
			req.Host = c.host
		}
		if c.origin != "" {
			req.Header.Set("Origin", c.origin)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != c.want {
			t.Errorf("%s %s Host %q Origin %q: %s", c.method, c.path, c.host, c.origin, resp.Status)
		}
	}
}
