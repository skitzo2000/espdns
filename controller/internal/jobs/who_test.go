package jobs

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/skitzo2000/espdns/controller/internal/actionlog"
)

// Who names the logged-in user for a job started over the API, and the job's params go
// into its record and the action log.
func TestWhoAndArgs(t *testing.T) {
	r, dir, _ := newRunner(t, newKinds())
	r.Who = func(*http.Request) string { return "admin" }
	mux := http.NewServeMux()
	r.Routes(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	resp := post(t, srv.URL+"/api/jobs", `{"kind": "lines", "params": [ "a",  "b" ]}`)
	var j Job
	json.NewDecoder(resp.Body).Decode(&j)
	resp.Body.Close()
	if j.Who != "admin" || len(j.Args) != 1 || j.Args[0] != `["a","b"]` {
		t.Fatalf("%+v", j)
	}
	waitEnd(t, r, j.ID)
	es, _ := actionlog.Tail(dir, 0)
	if len(es) != 2 || es[0].Who != "admin" || es[0].Source != "controller" || len(es[0].Args) != 1 || es[0].Args[0] != `["a","b"]` {
		t.Fatalf("%+v", es)
	}
	if argsOf(json.RawMessage(`{}`)) != nil || argsOf(nil) != nil || argsOf(json.RawMessage(`null`)) != nil {
		t.Error("empty params logged")
	}
}
