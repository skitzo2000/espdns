package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/skitzo2000/espdns/controller/internal/actionlog"
	"github.com/skitzo2000/espdns/controller/internal/auth"
	"github.com/skitzo2000/espdns/controller/internal/keys"
	"github.com/skitzo2000/espdns/controller/internal/settings"
)

// setupEnv is a controller with no password and no settings: a fresh install. Nothing in
// it reaches a node or a primary.
type setupEnv struct {
	t      *testing.T
	h      http.Handler
	dir    string
	cookie string
	tok    string
	listed [][]string // what each save told the node list
}

func newSetupEnv(t *testing.T, opts ...func(*server)) *setupEnv {
	e := &setupEnv{t: t}
	e.h, _ = testServer(t, false, append([]func(*server){func(s *server) {
		e.dir = s.dataDir
		s.listed = func(n []string) { e.listed = append(e.listed, n) }
	}}, opts...)...)
	return e
}

// do sends a request for pattern with body, from this machine, in the session if there is one.
func (e *setupEnv) do(pattern, body string) (int, map[string]any) {
	e.t.Helper()
	r := fromHere(pattern, body)
	if e.cookie != "" {
		withSession(r, e.cookie, e.tok)
	}
	w := serve(e.h, r)
	var out map[string]any
	json.Unmarshal(w.Body.Bytes(), &out)
	if strings.Contains(w.Body.String(), setupToken) {
		e.t.Errorf("%s: the token in the reply: %s", pattern, w.Body)
	}
	if out == nil {
		out = map[string]any{"raw": w.Body.String()}
	}
	return w.Code, out
}

// firstPassword sets the first password and keeps the session it logs in.
func (e *setupEnv) firstPassword() {
	e.t.Helper()
	r := fromHere("POST /api/setup/password", `{"password":"`+testPassword+`"}`)
	w := serve(e.h, r)
	if w.Code != http.StatusOK {
		e.t.Fatalf("first password: %d %s", w.Code, w.Body)
	}
	var reply struct{ Token string }
	json.Unmarshal(w.Body.Bytes(), &reply)
	for _, c := range w.Result().Cookies() {
		if c.Name == auth.CookieName(r.Host) {
			e.cookie = c.Value
		}
	}
	e.tok = reply.Token
	if e.cookie == "" || e.tok == "" {
		e.t.Fatalf("first password: no session: %s", w.Body)
	}
}

// fromHere is request(pattern) with body, from a client on this machine.
func fromHere(pattern, body string) *http.Request {
	r := request(pattern)
	r.RemoteAddr = "127.0.0.1:40000"
	r.Body = io.NopCloser(strings.NewReader(body))
	return r
}

const setupToken = "first-run-token-0123456789"

// steps is /api/setup's steps as name: done.
func steps(out map[string]any) map[string]bool {
	m := map[string]bool{}
	for _, s := range out["steps"].([]any) {
		s := s.(map[string]any)
		m[s["step"].(string)] = s["done"].(bool)
	}
	return m
}

// A fresh install, set up from the browser: first_run until there is a password or a
// settings file; the password (from this machine, logged in at once); the zone primary
// with its token (never echoed); two nodes; each step then done.
func TestFirstRun(t *testing.T) {
	e := newSetupEnv(t)
	code, out := e.do("GET /api/setup", "")
	if code != http.StatusOK || out["first_run"] != true || out["password_set"] != false || out["settings_saved"] != false {
		t.Fatalf("fresh: %d %v", code, out)
	}
	for step, done := range steps(out) {
		if done {
			t.Errorf("fresh: %s done", step)
		}
	}
	// Read-only until the password: the settings are read, not saved.
	if code, out := e.do("GET /api/settings", ""); code != http.StatusOK || out["exists"] != false || out["version"] != "" {
		t.Fatalf("settings, fresh: %d %v", code, out)
	}
	if code, _ := e.do("POST /api/settings", `{"settings": {}, "version": ""}`); code != http.StatusForbidden {
		t.Fatalf("settings saved without a password: %d", code)
	}

	e.firstPassword()
	code, out = e.do("GET /api/setup", "")
	if code != http.StatusOK || out["first_run"] != false || !steps(out)["password"] {
		t.Fatalf("after the password: %d %v", code, out)
	}
	// The zone primary, by its API, with its token; the file made (version "").
	code, out = e.do("POST /api/settings", `{"settings": {"primary": {"kind": "technitium", "url": "https://192.0.2.254:53443"}},
		"version": "", "primary_token": "`+setupToken+`"}`)
	if code != http.StatusOK || out["exists"] != true || out["version"] == "" {
		t.Fatalf("primary: %d %v", code, out)
	}
	if tok := out["primary_token"].(map[string]any); tok["set"] != true {
		t.Fatalf("token: %v", tok)
	}
	if st := out["primary_state"].(map[string]any); st["by_hand"] != false || st["kind"] != "technitium" {
		t.Fatalf("primary state: %v", st)
	}
	if got, err := (keys.DataTokenSource{DataDir: e.dir}).Token(); got != setupToken || err != nil {
		t.Fatal("token file:", err)
	}
	if fi, _ := os.Stat(keys.TokenPath(e.dir)); fi.Mode().Perm() != 0o600 {
		t.Fatal("token mode", fi.Mode())
	}
	// Two nodes, the first the canary: on the version just read.
	v := out["version"].(string)
	code, out = e.do("POST /api/settings", `{"settings": {"nodes": ["192.0.2.53", "192.0.2.52"], "canary": "192.0.2.52",
		"no_dhcp": ["192.0.2.0/24"], "dns_peers": ["192.0.2.254"],
		"primary": {"kind": "technitium", "url": "https://192.0.2.254:53443"}}, "version": "`+v+`"}`)
	if code != http.StatusOK {
		t.Fatalf("nodes: %d %v", code, out)
	}
	s, err := settings.Load(settings.Path(e.dir))
	if err != nil || !slices.Equal(s.Nodes, []string{"192.0.2.53", "192.0.2.52"}) || s.Canary != "192.0.2.52" || s.ZonePrimary().Kind != "technitium" {
		t.Fatal(s, err)
	}
	if len(e.listed) != 2 || !slices.Equal(e.listed[1], s.Nodes) {
		t.Fatalf("node list told %v", e.listed)
	}
	// The token kept: a save without one leaves it.
	if got, _ := (keys.DataTokenSource{DataDir: e.dir}).Token(); got != setupToken {
		t.Fatal("the token went with a save that didn't name it")
	}
	code, out = e.do("GET /api/setup", "")
	want := map[string]bool{"password": true, "release_key": false, "primary": true, "first_node": true, "second_node": true}
	if code != http.StatusOK || out["nodes"] != 2.0 || out["primary_token"] != true || !mapsEqual(steps(out), want) {
		t.Fatalf("set up: %d %v", code, out)
	}
	// The first run's password is refused from now on, and the password stays.
	if code, _ := e.do("POST /api/setup/password", `{"password":"another password!"}`); code != http.StatusConflict {
		t.Fatalf("first password again: %d", code)
	}
	// In the action log: what changed, never the token.
	es, _ := actionlog.Tail(e.dir, 10)
	var args []string
	for _, a := range es {
		if a.Action == "settings" {
			args = append(args, strings.Join(a.Args, ","))
		}
	}
	if !slices.Equal(args, []string{"primary,primary token set", "nodes,dns_peers,canary,no_dhcp"}) {
		t.Fatalf("action log: %q", args)
	}
	b, _ := os.ReadFile(actionlog.Path(e.dir))
	if strings.Contains(string(b), setupToken) {
		t.Fatal("the token in the action log")
	}
}

func mapsEqual(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
}

// Every refusal says which field, and changes nothing: neither settings.json nor the token.
func TestSettingsRefused(t *testing.T) {
	e := newSetupEnv(t)
	e.firstPassword()
	code, out := e.do("POST /api/settings", `{"settings": {"nodes": ["192.0.2.53"], "primary": {"kind": "manual"}}, "version": ""}`)
	if code != http.StatusOK {
		t.Fatal(code, out)
	}
	v := out["version"].(string)
	before, _ := os.ReadFile(settings.Path(e.dir))
	for body, field := range map[string]string{
		`{"settings": {"nodes": ["192.0.2.53"], "canary": "192.0.2.9"}, "version": "V"}`:                       "canary",
		`{"settings": {"nodes": ["192.0.2.53", "192.0.2.53"]}, "version": "V"}`:                                "nodes",
		`{"settings": {"no_dhcp": ["192.0.2.1/24"]}, "version": "V"}`:                                          "no_dhcp",
		`{"settings": {"dns_peers": ["192.0.2.254:"]}, "version": "V"}`:                                        "dns_peers",
		`{"settings": {"primary": {"kind": "technitium"}}, "version": "V"}`:                                    "primary",
		`{"settings": {"primary": {"kind": "bind9"}}, "version": "V"}`:                                         "primary",
		`{"settings": {"nodez": []}, "version": "V"}`:                                                          "settings",
		`{"settings": null, "version": "V"}`:                                                                   "settings",
		`{"version": "V"}`:                                                                                     "settings",
		`{"settings": {}}`:                                                                                     "version",
		`{"settings": {"primary": {"kind": "manual"}}, "version": "V", "primary_token": "` + setupToken + `"}`: "primary_token",
		`{"settings": {}, "version": "V", "primary_token": "` + setupToken + `"}`:                              "primary_token",
		`{"settings": {"primary": {"kind": "technitium", "url": "https://192.0.2.254:53443"}}, "version": "V", "primary_token": "short"}`: "primary_token",
		`{"settings": {"primary": {"kind": "technitium", "url": "https://192.0.2.254:53443"}}, "version": "V", "primary_token": "` +
			setupToken + `", "remove_primary_token": true}`: "primary_token",
	} {
		code, out := e.do("POST /api/settings", strings.ReplaceAll(body, `"V"`, `"`+v+`"`))
		if code != http.StatusBadRequest || out["field"] != field {
			t.Errorf("%s: %d %v, want field %s", body, code, out, field)
		}
	}
	// Not JSON at all, or a field the request doesn't have.
	for _, body := range []string{`{"settings": {}, "version": "", "token": "x"}`, `[`} {
		if code, _ := e.do("POST /api/settings", body); code != http.StatusBadRequest {
			t.Errorf("%s: %d", body, code)
		}
	}
	if after, _ := os.ReadFile(settings.Path(e.dir)); string(after) != string(before) {
		t.Fatal("a refused save changed settings.json")
	}
	if _, err := os.Stat(keys.TokenPath(e.dir)); err == nil {
		t.Fatal("a refused save wrote a token")
	}
	if len(e.listed) != 1 {
		t.Fatal("a refused save told the node list:", e.listed)
	}
}

// An edit on a version that is no longer the file's (an adoption added a node meanwhile) is
// refused (409), its token not written; read again, it saves.
func TestSettingsConflict(t *testing.T) {
	e := newSetupEnv(t)
	e.firstPassword()
	_, out := e.do("POST /api/settings", `{"settings": {"nodes": ["192.0.2.53"]}, "version": ""}`)
	v := out["version"].(string)
	if _, err := settings.AddNode(settings.Path(e.dir), "192.0.2.52"); err != nil {
		t.Fatal(err)
	}
	body := `{"settings": {"nodes": ["192.0.2.53"], "primary": {"kind": "technitium", "url": "https://192.0.2.254:53443"}},
		"version": "%s", "primary_token": "` + setupToken + `"}`
	if code, out := e.do("POST /api/settings", strings.Replace(body, "%s", v, 1)); code != http.StatusConflict {
		t.Fatalf("stale: %d %v", code, out)
	}
	if _, err := os.Stat(keys.TokenPath(e.dir)); err == nil {
		t.Fatal("a refused save wrote its token")
	}
	if s, _ := settings.Load(settings.Path(e.dir)); len(s.Nodes) != 2 {
		t.Fatal("the adoption's node lost:", s.Nodes)
	}
	_, out = e.do("GET /api/settings", "")
	form := out["settings"].(map[string]any)
	if n := form["nodes"].([]any); len(n) != 2 || form["canary"] != "" || form["primary"] != nil || len(form["dns_peers"].([]any)) != 0 {
		t.Fatalf("form: %v", form)
	}
	if code, out := e.do("POST /api/settings", strings.Replace(body, "%s", out["version"].(string), 1)); code != http.StatusOK {
		t.Fatalf("on the version read: %d %v", code, out)
	}
}

// The token removed (the primary changed by hand from then on); the kinds offered.
func TestSettingsPrimaryToken(t *testing.T) {
	e := newSetupEnv(t)
	e.firstPassword()
	_, out := e.do("POST /api/settings", `{"settings": {"primary": {"kind": "technitium", "url": "https://192.0.2.254:53443"}},
		"version": "", "primary_token": "`+setupToken+`"}`)
	var kinds []string
	for _, k := range out["primary_kinds"].([]any) {
		k := k.(map[string]any)
		kinds = append(kinds, k["kind"].(string))
		if k["kind"] == "technitium" && (k["api"] != true || k["example"] == "") {
			t.Errorf("technitium: %v", k)
		}
	}
	if !slices.Contains(kinds, "manual") || !slices.Contains(kinds, "technitium") {
		t.Fatalf("kinds: %v", kinds)
	}
	code, out := e.do("POST /api/settings", `{"settings": {"primary": {"kind": "manual"}}, "version": "`+out["version"].(string)+`",
		"remove_primary_token": true}`)
	if code != http.StatusOK {
		t.Fatal(code, out)
	}
	if out["primary_token"].(map[string]any)["set"] != false {
		t.Fatalf("token after removal: %v", out["primary_token"])
	}
	if st := out["primary_state"].(map[string]any); st["by_hand"] != true || st["kind"] != "manual" {
		t.Fatalf("state: %v", st)
	}
	if _, err := os.Stat(keys.TokenPath(e.dir)); err == nil {
		t.Fatal("token file still there")
	}
	// A technitium primary without its token: saved, changed by hand until there is one.
	code, out = e.do("POST /api/settings", `{"settings": {"primary": {"kind": "technitium", "url": "https://192.0.2.254:53443"}},
		"version": "`+out["version"].(string)+`"}`)
	if st := out["primary_state"].(map[string]any); code != http.StatusOK || st["by_hand"] != true || !strings.Contains(st["why"].(string), "token") {
		t.Fatalf("no token: %d %v", code, out)
	}
}

// A settings.json that doesn't parse (edited by hand): the form says why and gives its
// version, so the browser can replace it whole; /api/setup says it too.
func TestSettingsUnreadable(t *testing.T) {
	e := newSetupEnv(t)
	e.firstPassword()
	os.WriteFile(settings.Path(e.dir), []byte(`{"nodez": ["192.0.2.53"]}`), 0o600)
	code, out := e.do("GET /api/settings", "")
	if code != http.StatusOK || out["exists"] != true || out["version"] == "" || !strings.Contains(out["error"].(string), "unknown field") {
		t.Fatalf("%d %v", code, out)
	}
	if _, out := e.do("GET /api/setup", ""); out["settings_saved"] != true || out["settings_error"] == nil {
		t.Fatalf("setup: %v", out)
	}
	if code, out := e.do("POST /api/settings", `{"settings": {"nodes": ["192.0.2.53"]}, "version": "`+out["version"].(string)+`"}`); code != http.StatusOK || out["error"] != nil {
		t.Fatalf("replaced: %d %v", code, out)
	}
}

// The token kept goes only to the primary it was saved for: a save that moves the primary
// to another address (or kind with an API) without giving the token again, or removing it,
// is refused and changes nothing, so a session can't send the token somewhere else.
func TestSettingsTokenStaysWithItsPrimary(t *testing.T) {
	e := newSetupEnv(t)
	e.firstPassword()
	_, out := e.do("POST /api/settings", `{"settings": {"primary": {"kind": "technitium", "url": "https://192.0.2.254:53443"}},
		"version": "", "primary_token": "`+setupToken+`"}`)
	v := out["version"].(string)
	before, _ := os.ReadFile(settings.Path(e.dir))
	moved := func(v, extra string) string {
		return `{"settings": {"primary": {"kind": "technitium", "url": "https://198.51.100.7:53443"}}, "version": "` + v + `"` + extra + `}`
	}
	code, out := e.do("POST /api/settings", moved(v, ""))
	if code != http.StatusBadRequest || out["field"] != "primary_token" {
		t.Fatalf("moved with the token kept: %d %v", code, out)
	}
	if after, _ := os.ReadFile(settings.Path(e.dir)); string(after) != string(before) {
		t.Fatal("the refused move changed settings.json")
	}
	if got, _ := (keys.DataTokenSource{DataDir: e.dir}).Token(); got != setupToken {
		t.Fatal("the refused move changed the token")
	}
	// The same primary, other fields changed: the token stays, no need to give it.
	code, out = e.do("POST /api/settings", `{"settings": {"nodes": ["192.0.2.53"], "primary": {"kind": "technitium", "url": "https://192.0.2.254:53443"}},
		"version": "`+v+`"}`)
	if code != http.StatusOK {
		t.Fatalf("same primary: %d %v", code, out)
	}
	v = out["version"].(string)
	// Given again: moved.
	code, out = e.do("POST /api/settings", moved(v, `, "primary_token": "`+setupToken+`"`))
	if code != http.StatusOK {
		t.Fatalf("moved with the token given: %d %v", code, out)
	}
	// Or removed: moved, changed by hand until a token is given.
	v = out["version"].(string)
	code, out = e.do("POST /api/settings", `{"settings": {"primary": {"kind": "technitium", "url": "https://192.0.2.254:53443"}},
		"version": "`+v+`", "remove_primary_token": true}`)
	if code != http.StatusOK || out["primary_token"].(map[string]any)["set"] != false {
		t.Fatalf("moved with the token removed: %d %v", code, out)
	}
}

// A save with a new token for another primary that fails to write settings.json leaves no
// token at all: never the new token beside the old primary, nor the old token beside the
// new one. The primary is changed by hand until a save goes through.
func TestSettingsTokenFailedSave(t *testing.T) {
	// The write of settings.json fails where SaveIf would write it: the version checked and
	// the old token taken away (before), the file not yet written, after never run. (Not by
	// file modes: run as root, as CI's Go job is, a read-only directory is still written.)
	failWrite := false
	e := newSetupEnv(t, func(s *server) {
		s.saveSettings = func(path, version string, st settings.Settings, before, after func() error) error {
			return settings.SaveIf(path, version, st, func() error {
				if err := before(); err != nil {
					return err
				}
				if failWrite {
					return errors.New("settings.json: no space left on device")
				}
				return nil
			}, after)
		}
	})
	e.firstPassword()
	_, out := e.do("POST /api/settings", `{"settings": {"primary": {"kind": "technitium", "url": "https://192.0.2.254:53443"}},
		"version": "", "primary_token": "`+setupToken+`"}`)
	v := out["version"].(string)
	before, _ := os.ReadFile(settings.Path(e.dir))
	failWrite = true
	code, out := e.do("POST /api/settings", `{"settings": {"primary": {"kind": "technitium", "url": "https://198.51.100.7:53443"}},
		"version": "`+v+`", "primary_token": "other-token-0123456789"}`)
	if code != http.StatusInternalServerError {
		t.Fatalf("unwritable: %d %v", code, out)
	}
	if after, _ := os.ReadFile(settings.Path(e.dir)); string(after) != string(before) {
		t.Fatal("settings.json changed")
	}
	if _, err := (keys.DataTokenSource{DataDir: e.dir}).Token(); !errors.Is(err, keys.ErrNoToken) {
		t.Fatal("a token left after the failed save:", err)
	}
}
