package jobs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// The API:
//
//	POST /api/jobs                {"kind": "check", "params": {...}}: queues a job (202, the job)
//	GET  /api/jobs                every job kept, newest first, without logs
//	GET  /api/jobs/{id}           one job with its progress log
//	POST /api/jobs/{id}/stop      stop it at its next safe point (202, the job)
//	GET  /api/jobs/{id}/events    its progress as Server-Sent Events (below)
//
// Events: "state" (the job, without its log) first and at every change of state; "log" for
// each progress line, with the line's number as the event ID, so a reconnecting EventSource
// (Last-Event-ID) or ?after=<n> resumes after line n; "progress" (the job's Progress) when it changes; "end" (the job) once it has ended and
// every line is sent, after which the stream closes: the page closes its EventSource then,
// or the browser would reconnect. A comment every 15 s keeps the connection open.
//
// The controller listens on localhost, behind its login (internal/auth: a session, its
// cookie and the page's token on every API request). The POSTs also take only JSON, from a
// page on the controller itself, by a localhost name. A web page elsewhere can't send them (no JSON without CORS,
// which the controller doesn't answer), nor through a DNS name rebound to 127.0.0.1 (the
// Host check). LocalOnly puts the Host check on every API request, the GETs too.

// Mux is where routes go: an *http.ServeMux, or something that records them.
type Mux interface {
	HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request))
}

// Routes adds the API to mux.
func (r *Runner) Routes(mux Mux) {
	mux.HandleFunc("POST /api/jobs", r.handleStart)
	mux.HandleFunc("GET /api/jobs", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusOK, r.List()) })
	mux.HandleFunc("GET /api/jobs/{id}", func(w http.ResponseWriter, req *http.Request) {
		j, ok := r.Get(req.PathValue("id"))
		if !ok {
			httpError(w, http.StatusNotFound, ErrNotFound)
			return
		}
		writeJSON(w, http.StatusOK, j)
	})
	mux.HandleFunc("POST /api/jobs/{id}/stop", r.handleStop)
	mux.HandleFunc("GET /api/jobs/{id}/events", r.handleEvents)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("write json: %v", err)
	}
}

func httpError(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}

// Local says whether a request that changes something may: JSON, from no other site, to a
// localhost name. The error says why not.
func Local(req *http.Request) error {
	if mt, _, _ := mime.ParseMediaType(req.Header.Get("Content-Type")); mt != "application/json" {
		return errors.New("send JSON (Content-Type: application/json)")
	}
	return sameSite(req)
}

// sameSite: to a localhost name and, for anything but a GET, from no other site (no other
// Origin, not Sec-Fetch-Site cross-site).
func sameSite(req *http.Request) error {
	if !loopback(req.Host) {
		return fmt.Errorf("the controller is reached by localhost only, not %q", req.Host)
	}
	if req.Method == http.MethodGet || req.Method == http.MethodHead {
		return nil
	}
	if o := req.Header.Get("Origin"); o != "" {
		u, err := url.Parse(o)
		if err != nil || u.Host != req.Host {
			return fmt.Errorf("not from this page (Origin %s)", o)
		}
	}
	if req.Header.Get("Sec-Fetch-Site") == "cross-site" {
		return errors.New("not from this page (cross-site)")
	}
	return nil
}

// LocalOnly guards the controller's API (/api/ and /build/, every method), in front of
// the login: a localhost Host, so a page elsewhere can't reach the API through a DNS name
// rebound to 127.0.0.1, and for a POST no other site's Origin. The jobs' POSTs (Local)
// also take only JSON.
func LocalOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if p := req.URL.Path; strings.HasPrefix(p, "/api/") || strings.HasPrefix(p, "/build/") {
			if err := sameSite(req); err != nil {
				httpError(w, http.StatusForbidden, err)
				return
			}
		}
		next.ServeHTTP(w, req)
	})
}

// loopback: localhost, or a loopback address ([::1] for IPv6), with any port.
func loopback(host string) bool {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	} else {
		host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (r *Runner) handleStart(w http.ResponseWriter, req *http.Request) {
	if err := Local(req); err != nil {
		httpError(w, http.StatusForbidden, err)
		return
	}
	var body struct {
		Kind   string          `json:"kind"`
		Params json.RawMessage `json:"params"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, req.Body, 1<<20)).Decode(&body); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	who := ""
	if r.Who != nil {
		who = r.Who(req)
	}
	if who == "" {
		who = "web"
		if h, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
			who += " (" + h + ")"
		}
	}
	j, err := r.Start(body.Kind, who, body.Params)
	switch {
	case errors.Is(err, ErrQueueFull):
		httpError(w, http.StatusTooManyRequests, err)
	case err != nil:
		httpError(w, http.StatusBadRequest, err)
	default:
		w.Header().Set("Location", "/api/jobs/"+j.ID)
		writeJSON(w, http.StatusAccepted, j)
	}
}

func (r *Runner) handleStop(w http.ResponseWriter, req *http.Request) {
	if err := Local(req); err != nil {
		httpError(w, http.StatusForbidden, err)
		return
	}
	j, err := r.Stop(req.PathValue("id"))
	switch {
	case errors.Is(err, ErrNotFound):
		httpError(w, http.StatusNotFound, err)
	case errors.Is(err, ErrEnded):
		httpError(w, http.StatusConflict, err)
	default:
		writeJSON(w, http.StatusAccepted, j)
	}
}

// keepAlive is how often an idle event stream gets a comment.
var keepAlive = 15 * time.Second

func (r *Runner) handleEvents(w http.ResponseWriter, req *http.Request) {
	id := req.PathValue("id")
	after := 0
	for _, s := range []string{req.Header.Get("Last-Event-ID"), req.URL.Query().Get("after")} {
		if n, err := strconv.Atoi(s); err == nil && n > after {
			after = n
		}
	}
	lines, j, changed, ok := r.follow(id, after)
	if !ok {
		httpError(w, http.StatusNotFound, ErrNotFound)
		return
	}
	fl, _ := w.(http.Flusher)
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	send := func(event string, id int, v any) error {
		b, _ := json.Marshal(v)
		if id > 0 {
			if _, err := fmt.Fprintf(w, "id: %d\n", id); err != nil {
				return err
			}
		}
		_, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, b)
		return err
	}
	tick := time.NewTicker(keepAlive)
	defer tick.Stop()
	// The job first, then its lines, then the job again whenever its state changes: after
	// the lines that led to the change.
	if send("state", 0, j) != nil {
		return
	}
	last := j
	for {
		for _, l := range lines {
			if send("log", l.N, l) != nil {
				return
			}
			after = l.N
		}
		if j.State != last.State || j.Stopping != last.Stopping {
			if send("state", 0, j) != nil {
				return
			}
			last = j
		} else if !bytes.Equal(j.Progress, last.Progress) {
			if send("progress", 0, j.Progress) != nil {
				return
			}
			last = j
		}
		if j.State.Ended() {
			send("end", 0, j)
			if fl != nil {
				fl.Flush()
			}
			return
		}
		if fl != nil {
			fl.Flush()
		}
	wait:
		for {
			select {
			case <-req.Context().Done():
				return
			case <-tick.C:
				if _, err := fmt.Fprint(w, ": keep-alive\n\n"); err != nil {
					return
				}
				if fl != nil {
					fl.Flush()
				}
			case <-changed:
				break wait
			}
		}
		lines, j, changed, _ = r.follow(id, after)
	}
}
