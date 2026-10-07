// Package jobs is the controller's job runner: fleet operations run one at a time, each
// under the fleet lock (internal/fleetlock) the CLI takes too, with its progress kept as a
// log the browser follows live (http.go). A job is queued, then running, then done, failed
// or stopped. Every job that runs is in the action log (internal/actionlog), and its record,
// with its whole progress log, is kept in <data>/log/jobs/<id>.json after it ends.
package jobs

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/actionlog"
	"github.com/skitzo2000/espdns/controller/internal/fleet"
	"github.com/skitzo2000/espdns/controller/internal/fleetlock"
	"github.com/skitzo2000/espdns/controller/internal/secfile"
)

// State is where a job is.
type State string

const (
	Queued  State = "queued"
	Running State = "running"
	Done    State = "done"
	Failed  State = "failed"
	Stopped State = "stopped"
)

// Ended says whether the job is over.
func (s State) Ended() bool { return s == Done || s == Failed || s == Stopped }

const (
	maxQueued = 8    // jobs waiting at once
	maxLines  = 5000 // progress lines a job keeps (the newest)
	keepJobs  = 200  // job records kept in log/jobs
	JobsDir   = "jobs"
)

// Line is one line of a job's progress, numbered from 1.
type Line struct {
	N    int       `json:"n"`
	Time time.Time `json:"time"`
	Text string    `json:"text"`
}

// Job is a job as the API shows it.
type Job struct {
	ID       string          `json:"id"`
	Kind     string          `json:"kind"`
	Who      string          `json:"who"`
	Args     []string        `json:"args,omitempty"` // its params, as the action log has them
	State    State           `json:"state"`
	Stopping bool            `json:"stopping,omitempty"` // a stop was asked for; it ends at the next safe point
	Created  time.Time       `json:"created"`
	Started  time.Time       `json:"started,omitzero"`
	Ended    time.Time       `json:"ended,omitzero"`
	Error    string          `json:"error,omitempty"`
	Result   json.RawMessage `json:"result,omitempty"`
	// Progress is where the job is, as it last said (Run.SetProgress): a rollout's state per
	// node. Only for one job (Get, the events), not the list.
	Progress json.RawMessage `json:"progress,omitempty"`
	Lines    int             `json:"lines"` // the last line's number
	// Last is the last line's text: where the job is, for the list (the pages' header
	// shows a running job's), which has no log.
	Last string `json:"last,omitempty"`
	Log  []Line `json:"log,omitempty"` // only for one job (Get), not the list
}

// Run is what a running job gets: where its progress goes, and the stop request.
type Run struct {
	ID   string
	r    *Runner
	j    *job
	stop chan struct{}
}

// Logf adds a line to the job's progress (fleet.Client's Logf).
func (run *Run) Logf(format string, args ...any) { run.r.logf(run.j, fmt.Sprintf(format, args...)) }

// SetProgress replaces where the job says it is (any JSON value), which the browser follows
// live (the "progress" event) and the job's record keeps.
func (run *Run) SetProgress(v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	r := run.r
	r.mu.Lock()
	defer r.mu.Unlock()
	run.j.Progress = b
	r.changedLocked(run.j)
}

// Stop is closed when a stop is asked for: the job should end at its next safe point
// (fleet.Plan.Stop) and return fleet.ErrStopped (the job ends "stopped"), or the error
// that ended it first ("failed").
func (run *Run) Stop() <-chan struct{} { return run.stop }

// Func does one job. Its result (JSON) goes into the job's record. ctx is cancelled only
// when the controller shuts down.
type Func func(ctx context.Context, run *Run) (result any, err error)

// Kind makes a job from its parameters (the API's "params"), checking them before the job
// is queued.
type Kind func(params json.RawMessage) (Func, error)

// ErrUnknownKind, ErrQueueFull, ErrNotFound and ErrEnded are the API's 400, 429, 404 and 409.
var (
	ErrUnknownKind = errors.New("no such job kind")
	ErrQueueFull   = errors.New("too many jobs waiting")
	ErrNotFound    = errors.New("no such job")
	ErrEnded       = errors.New("the job has ended")
)

type job struct {
	Job
	fn       Func
	stop     chan struct{}
	stopOnce sync.Once
	changed  chan struct{} // closed and replaced on every change
}

// Runner runs jobs one at a time.
type Runner struct {
	dataDir string
	kinds   map[string]Kind
	mu      sync.Mutex
	jobs    map[string]*job
	order   []string // IDs, oldest first
	queue   []*job
	wake    chan struct{}
	// Logf, if set, also gets every progress line ("job <id>: ..."); nil: log.Printf.
	Logf func(format string, args ...any)
	// Who, if set, names who sent a request that starts a job (the logged-in user); nil or
	// "": "web (<address>)".
	Who func(*http.Request) string
}

// New returns a runner for the data directory (the fleet lock, the action log and the job
// records are there), with the jobs it keeps from before.
func New(dataDir string, kinds map[string]Kind) *Runner {
	r := &Runner{dataDir: dataDir, kinds: kinds, jobs: map[string]*job{}, wake: make(chan struct{}, 1)}
	r.load()
	return r
}

func (r *Runner) jobsDir() string { return filepath.Join(r.dataDir, actionlog.Dir, JobsDir) }

// load reads the kept job records, the newest keepJobs.
func (r *Runner) load() {
	ents, err := os.ReadDir(r.jobsDir())
	if err != nil {
		return
	}
	var names []string
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	slices.Sort(names) // IDs start with the time, to the second
	if len(names) > keepJobs {
		names = names[len(names)-keepJobs:]
	}
	var loaded []*job
	for _, n := range names {
		b, err := os.ReadFile(filepath.Join(r.jobsDir(), n))
		if err != nil {
			continue
		}
		j := &job{changed: make(chan struct{})}
		if json.Unmarshal(b, &j.Job) != nil || j.ID == "" || j.ID+".json" != n {
			continue
		}
		if !j.State.Ended() {
			// Saved when it started, and the controller ended (killed, or the host went
			// down) before the job did: what it did to the nodes is unknown.
			j.State, j.Ended = Failed, time.Now()
			j.Error = "the controller ended while the job was running: see the nodes (the Nodes page, or espdns status) and the action log"
			r.save(j.Job)
		}
		loaded = append(loaded, j)
	}
	slices.SortStableFunc(loaded, func(a, b *job) int { return a.Created.Compare(b.Created) })
	for _, j := range loaded {
		r.jobs[j.ID] = j
		r.order = append(r.order, j.ID)
	}
}

func newID() string {
	b := make([]byte, 2)
	rand.Read(b)
	return time.Now().UTC().Format("20060102-150405") + "-" + hex.EncodeToString(b)
}

// Start queues a job of kind; who started it goes into its record and the action log.
func (r *Runner) Start(kind, who string, params json.RawMessage) (Job, error) {
	k, ok := r.kinds[kind]
	if !ok {
		return Job{}, fmt.Errorf("%w: %q", ErrUnknownKind, kind)
	}
	fn, err := k(params)
	if err != nil {
		return Job{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.queue) >= maxQueued {
		return Job{}, ErrQueueFull
	}
	j := &job{Job: Job{ID: newID(), Kind: kind, Who: who, Args: argsOf(params), State: Queued, Created: time.Now()}, fn: fn,
		stop: make(chan struct{}), changed: make(chan struct{})}
	for r.jobs[j.ID] != nil {
		j.ID = newID()
	}
	r.jobs[j.ID] = j
	r.order = append(r.order, j.ID)
	r.queue = append(r.queue, j)
	select {
	case r.wake <- struct{}{}:
	default:
	}
	return j.Job, nil
}

// argsOf is a job's params for its record and the action log: the JSON, compacted, or none.
func argsOf(params json.RawMessage) []string {
	var b bytes.Buffer
	if json.Compact(&b, params) != nil || b.Len() == 0 || b.String() == "null" || b.String() == "{}" {
		return nil
	}
	return []string{b.String()}
}

// Stop asks a job to stop: a queued one never starts, a running one ends at its next safe
// point.
func (r *Runner) Stop(id string) (Job, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	j := r.jobs[id]
	switch {
	case j == nil:
		return Job{}, ErrNotFound
	case j.State.Ended():
		return j.Job, ErrEnded
	case j.State == Queued:
		r.queue = slices.DeleteFunc(r.queue, func(q *job) bool { return q == j })
		j.State, j.Ended, j.Error = Stopped, time.Now(), "stopped before it started"
		r.changedLocked(j)
		go r.save(j.Job)
	default:
		j.Stopping = true
		j.stopOnce.Do(func() { close(j.stop) })
		r.changedLocked(j)
	}
	return j.Job, nil
}

// Get returns a job with its progress log.
func (r *Runner) Get(id string) (Job, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	j := r.jobs[id]
	if j == nil {
		return Job{}, false
	}
	out := j.Job
	out.Log = slices.Clone(j.Log)
	return out, true
}

// List returns every job the runner keeps, newest first, without their logs.
func (r *Runner) List() []Job {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Job, 0, len(r.order))
	for i := len(r.order) - 1; i >= 0; i-- {
		jb := r.jobs[r.order[i]]
		j := jb.Job
		if n := len(jb.Log); n > 0 {
			j.Last = jb.Log[n-1].Text
		}
		j.Log, j.Progress = nil, nil
		out = append(out, j)
	}
	return out
}

// follow returns the job's lines after line n, the job, and a channel closed at its next
// change.
func (r *Runner) follow(id string, n int) ([]Line, Job, <-chan struct{}, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	j := r.jobs[id]
	if j == nil {
		return nil, Job{}, nil, false
	}
	i, _ := slices.BinarySearchFunc(j.Log, n+1, func(l Line, n int) int { return l.N - n })
	lines := slices.Clone(j.Log[i:])
	out := j.Job
	out.Log = nil
	return lines, out, j.changed, true
}

func (r *Runner) changedLocked(j *job) {
	close(j.changed)
	j.changed = make(chan struct{})
}

func (r *Runner) logf(j *job, text string) {
	if r.Logf != nil {
		r.Logf("job %s: %s", j.ID, text)
	} else {
		log.Printf("job %s: %s", j.ID, text)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	j.Lines++
	j.Log = append(j.Log, Line{N: j.Lines, Time: time.Now(), Text: text})
	if len(j.Log) > maxLines {
		j.Log = j.Log[len(j.Log)-maxLines:]
	}
	r.changedLocked(j)
}

// Run runs the queued jobs, one at a time, until ctx ends. A job running then is cancelled
// (and ends stopped) before Run returns; the jobs still queued end stopped, never started.
func (r *Runner) Run(ctx context.Context) {
	for {
		r.mu.Lock()
		var j *job
		if ctx.Err() != nil {
			var saves []Job
			for _, q := range r.queue {
				q.State, q.Ended, q.Error = Stopped, time.Now(), "the controller shut down before it started"
				r.changedLocked(q)
				saves = append(saves, q.Job)
			}
			r.queue = nil
			r.mu.Unlock()
			for _, rec := range saves {
				r.save(rec)
			}
			return
		}
		if len(r.queue) > 0 {
			j, r.queue = r.queue[0], r.queue[1:]
		}
		r.mu.Unlock()
		if j != nil {
			r.run(ctx, j)
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-r.wake:
		}
	}
}

// run runs one job under the fleet lock.
func (r *Runner) run(ctx context.Context, j *job) {
	r.mu.Lock()
	j.State, j.Started = Running, time.Now()
	r.changedLocked(j)
	started := j.Job
	r.mu.Unlock()
	r.save(started) // so a controller killed during the job leaves a record of it (load)
	entry := actionlog.Entry{ID: j.ID, Source: "controller", Who: j.Who, Action: "job " + j.Kind, Args: j.Args}
	run := &Run{ID: j.ID, r: r, j: j, stop: j.stop}

	var result any
	lk, err := fleetlock.Acquire(fleetlock.Path(r.dataDir),
		fleetlock.Self("espdns-controller job "+j.ID, j.Kind+", started by "+j.Who))
	if err != nil {
		run.Logf("not started: %v", err)
		entry.Event, entry.Result, entry.Error = "refused", string(Failed), err.Error()
		if lerr := actionlog.Append(r.dataDir, entry); lerr != nil {
			run.Logf("action log: %v", lerr)
		}
	} else {
		entry.Event = "start"
		if lerr := actionlog.Append(r.dataDir, entry); lerr != nil {
			run.Logf("action log: %v", lerr)
		}
		result, err = func() (res any, err error) {
			defer func() {
				if p := recover(); p != nil {
					err = fmt.Errorf("job panicked: %v", p)
				}
			}()
			return j.fn(ctx, run)
		}()
	}

	// The job's end: logged, the lock released and the record saved before anyone sees it
	// ended, so whoever waits for it can take the lock at once.
	r.mu.Lock()
	rec := j.Job
	r.mu.Unlock()
	rec.Ended = time.Now()
	switch {
	case err == nil:
		rec.State = Done
	case errors.Is(err, fleet.ErrStopped) || ctx.Err() != nil && lk != nil:
		// Stopped on request at a safe point, or cancelled by the shutdown. A job asked
		// to stop that fails first (the node being changed failed its checks) failed.
		rec.State = Stopped
	default:
		rec.State = Failed
	}
	if err != nil {
		rec.Error = err.Error()
		if ctx.Err() != nil && !rec.Stopping {
			rec.Error = "the controller shut down: " + rec.Error
		}
	}
	if result != nil {
		if b, merr := json.Marshal(result); merr == nil {
			rec.Result = b
		}
	}
	if lk != nil {
		entry.Event, entry.Result, entry.Error = "end", string(rec.State), rec.Error
		if rec.State == Done {
			entry.Result = "ok" // as the CLI's: ok, failed or stopped
		}
		entry.Time, entry.Duration = time.Time{}, rec.Ended.Sub(rec.Started).Seconds()
		if lerr := actionlog.Append(r.dataDir, entry); lerr != nil {
			run.Logf("action log: %v", lerr)
		}
		lk.Release()
	}
	r.mu.Lock()
	j.State, j.Ended, j.Error, j.Result = rec.State, rec.Ended, rec.Error, rec.Result
	rec = j.Job
	rec.Log = slices.Clone(j.Log)
	r.mu.Unlock()
	r.save(rec)
	r.mu.Lock()
	r.changedLocked(j)
	r.mu.Unlock()
}

// save writes the job's record to log/jobs/<id>.json, and drops the oldest records past
// keepJobs (in memory too).
func (r *Runner) save(j Job) {
	dir := r.jobsDir()
	if err := secfile.MkdirAll(dir); err != nil {
		log.Printf("job %s: %v", j.ID, err)
		return
	}
	b, _ := json.MarshalIndent(j, "", " ")
	if err := secfile.WriteFile(filepath.Join(dir, j.ID+".json"), append(b, '\n')); err != nil {
		log.Printf("job %s: %v", j.ID, err)
	}
	ents, err := os.ReadDir(dir)
	if err != nil || len(ents) <= keepJobs {
		return
	}
	var names []string
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	slices.Sort(names)
	for _, n := range names[:max(len(names)-keepJobs, 0)] {
		os.Remove(filepath.Join(dir, n))
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for len(r.order) > keepJobs {
		if old := r.jobs[r.order[0]]; old != nil && !old.State.Ended() {
			break
		}
		delete(r.jobs, r.order[0])
		r.order = r.order[1:]
	}
}
