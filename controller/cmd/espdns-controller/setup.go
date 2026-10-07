package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"slices"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/actionlog"
	"github.com/skitzo2000/espdns/controller/internal/auth"
	"github.com/skitzo2000/espdns/controller/internal/keys"
	"github.com/skitzo2000/espdns/controller/internal/primary"
	"github.com/skitzo2000/espdns/controller/internal/settings"
)

// The first run and the controller's settings from the browser (docs/plan.md, The GUI
// redesign: easy to stand up, no hand-edited config files). The first run's password is
// auth's (POST /api/setup/password: only while none is set, only from this machine); the
// rest is here:
//
//	GET  /api/setup      what is set up: the password, settings.json, the release key, the
//	                     zone primary and its token, the nodes; first_run while there is
//	                     neither a password nor settings.json; the first run's steps
//	GET  /api/settings   settings.json as the form edits it (every field, empty ones too), its
//	                     version, the zone primary's kinds and whether its token is set (never
//	                     the token)
//	POST /api/settings   {"settings": {...}, "version", "primary_token", "remove_primary_token"}:
//	                     settings.json replaced whole if still the version read; the token
//	                     written (or removed) with it; the form again. The zone primary's
//	                     pinned certificate (cert_sha256) is kept or taken away here, never
//	                     set: it is set by confirming it (primarycert.go)
//
// The GETs are open as the other reads are while no password is set (the first run reads
// them before one is); with a password they need a login. The POST needs a login. Nothing
// here goes to a node: settings.json is the controller's and the CLI's, and a change applies
// at once (the nodes listed are polled from the next poll; a job or the CLI reads the file
// when it starts), with no restart and no pending change.

type setupServer struct {
	dataDir string
	auth    *auth.Auth
	key     keys.Source
	// listed, if set, hears settings.json's nodes after a save, so they are polled at once
	// (otherwise within the 10 s the controller reads the file again).
	listed func([]string)
	// saveIf, if set, stands in for settings.SaveIf (a test fails the write with it).
	saveIf func(path, version string, s settings.Settings, before, after func() error) error
}

func (s setupServer) routes(mux *routes) {
	mux.HandleFunc("GET /api/setup", s.setup)
	mux.HandleFunc("GET /api/settings", s.get)
	mux.HandleFunc("POST /api/settings", needLogin("changing the settings needs", s.save))
}

// A first-run step, in the order the browser walks them; done when what it sets up is
// there. Optional ones may be skipped.
type setupStep struct {
	Step     string `json:"step"`
	Done     bool   `json:"done"`
	Optional bool   `json:"optional,omitempty"`
}

func (s setupServer) setup(w http.ResponseWriter, r *http.Request) {
	pwSet, pwErr := s.auth.State()
	st, _, exists, err := settings.Read(settings.Path(s.dataDir))
	_, keyErr := s.key.Key()
	_, tokErr := keys.DataTokenSource{DataDir: s.dataDir}.Token()
	out := map[string]any{
		"first_run":      !pwSet && !exists,
		"password_set":   pwSet,
		"settings_saved": exists,
		"release_key":    keyErr == nil,
		"primary":        st.ZonePrimary().Kind,
		"primary_token":  tokErr == nil,
		"nodes":          len(st.Nodes),
		"steps": []setupStep{
			{Step: "password", Done: pwSet && pwErr == nil},
			{Step: "release_key", Done: keyErr == nil},
			{Step: "primary", Done: st.Primary != nil, Optional: true},
			{Step: "first_node", Done: len(st.Nodes) >= 1},
			{Step: "second_node", Done: len(st.Nodes) >= 2},
		},
	}
	if pwErr != nil {
		out["password_error"] = pwErr.Error()
	}
	if err != nil {
		out["settings_error"] = err.Error()
	}
	writeJSON(w, out)
}

// settingsForm is settings.json with every field, an empty one as [] or "" (primary null):
// what the form shows and sends back.
type settingsForm struct {
	Nodes        []string        `json:"nodes"`
	DNSPeers     []string        `json:"dns_peers"`
	DNSPeerZones []string        `json:"dns_peer_zones"`
	Canary       string          `json:"canary"`
	NoDHCP       []string        `json:"no_dhcp"`
	Primary      *primary.Config `json:"primary"`
	// InternalSources: the internal allowlist for blocklist URL sources
	InternalSources []string `json:"internal_sources"`
}

func formOf(s settings.Settings) settingsForm {
	nz := func(v []string) []string {
		if v == nil {
			return []string{}
		}
		return v
	}
	return settingsForm{Nodes: nz(s.Nodes), DNSPeers: nz(s.DNSPeers), DNSPeerZones: nz(s.DNSPeerZones),
		Canary: s.Canary, NoDHCP: nz(s.NoDHCP), Primary: s.Primary, InternalSources: nz(s.InternalSources)}
}

// primaryKind is a kind of zone primary the form offers.
type primaryKind struct {
	Kind    string `json:"kind"`
	Name    string `json:"name"`
	API     bool   `json:"api"`               // driven over its API, with an address and a token
	Example string `json:"example,omitempty"` // an API address, for the form's hint
}

func (s setupServer) view() (map[string]any, error) {
	st, version, exists, err := settings.Read(settings.Path(s.dataDir))
	out := map[string]any{"settings": formOf(st), "version": version, "exists": exists}
	if err != nil {
		if !exists && version == "" {
			return nil, err // not there and not readable: nothing to show
		}
		out["error"] = err.Error() // shown, and replaced whole by the next save
	}
	var kinds []primaryKind
	for _, k := range primary.Kinds() {
		d, _ := primary.Lookup(k)
		kinds = append(kinds, primaryKind{Kind: d.Kind, Name: d.Name, API: d.API, Example: d.Example})
	}
	tok := map[string]any{"set": false}
	t, terr := keys.DataTokenSource{DataDir: s.dataDir}.Token()
	switch {
	case terr == nil:
		tok["set"] = true
	case !errors.Is(terr, keys.ErrNoToken):
		tok["error"] = terr.Error() // there but not usable (its mode, its owner): never the token
	}
	// Whether the primary is reached from here or changed by hand, and why: from the
	// settings and the token only, nothing is asked of it (GET /api/primary reads its lists).
	zp := st.ZonePrimary()
	if zp.IsZero() {
		zp.Kind = primary.KindManual
	}
	ready := map[string]any{"kind": zp.Kind, "api": zp.URL, "by_hand": true}
	if zp.CertSHA256 != "" {
		ready["cert_sha256"] = zp.CertSHA256
	}
	if p, err := primary.Open(zp, t, primary.Options{}); err != nil {
		ready["why"] = err.Error()
	} else if why := primary.Why(p); why != "" {
		ready["why"] = why
	} else {
		ready["by_hand"] = false
	}
	out["primary_kinds"], out["primary_token"], out["primary_state"] = kinds, tok, ready
	return out, nil
}

func (s setupServer) get(w http.ResponseWriter, r *http.Request) {
	v, err := s.view()
	if err != nil {
		httpErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, v)
}

// fieldErr answers a refused field: 400, the error and the field's name.
func fieldErr(w http.ResponseWriter, field string, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(map[string]string{"error": err.Error(), "field": field})
}

func (s setupServer) save(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Settings           json.RawMessage `json:"settings"`
		Version            *string         `json:"version"`
		PrimaryToken       string          `json:"primary_token"`
		RemovePrimaryToken bool            `json:"remove_primary_token"`
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10))
	d.DisallowUnknownFields()
	if err := d.Decode(&body); err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	switch {
	case body.Version == nil:
		fieldErr(w, "version", errors.New(`the version read (GET /api/settings "version"; "" while there is no file)`))
		return
	case len(bytes.TrimSpace(body.Settings)) == 0 || bytes.Equal(bytes.TrimSpace(body.Settings), []byte("null")):
		fieldErr(w, "settings", errors.New("the whole settings, as GET /api/settings has them"))
		return
	}
	st, err := settings.Parse(body.Settings)
	if err != nil {
		var fe *settings.FieldError
		if errors.As(err, &fe) {
			fieldErr(w, fe.Field, err)
		} else {
			fieldErr(w, "settings", err)
		}
		return
	}
	// A plain http address is let through in a settings.json already written (the primary
	// paused), never saved here.
	if st.Primary != nil {
		if err := st.Primary.Check(); err != nil {
			fieldErr(w, "primary", err)
			return
		}
	}
	zp := st.ZonePrimary()
	d2, _ := primary.Lookup(zp.Kind)
	var tok string
	switch {
	case body.PrimaryToken != "" && body.RemovePrimaryToken:
		fieldErr(w, "primary_token", errors.New("a token to set, or the token removed: not both"))
		return
	case body.PrimaryToken != "" && zp.IsZero():
		fieldErr(w, "primary_token", fmt.Errorf("no zone primary to use the token with: set \"primary\" (%v take a token)", primary.APIKinds()))
		return
	case body.PrimaryToken != "" && !d2.API:
		fieldErr(w, "primary_token", fmt.Errorf("a zone primary of kind %s takes no token (only %v, over their API)", zp.Kind, primary.APIKinds()))
		return
	case body.PrimaryToken != "":
		if tok, err = keys.ParseToken("primary_token", []byte(body.PrimaryToken)); err != nil {
			fieldErr(w, "primary_token", err)
			return
		}
	}
	path := settings.Path(s.dataDir)
	var old settings.Settings
	save := settings.SaveIf
	if s.saveIf != nil {
		save = s.saveIf
	}
	err = save(path, *body.Version, st, func() error {
		// The file as it is now (the version checked, the writes held off): what changed.
		old, _, _, _ = settings.Read(path)
		// A pin is set by confirming the certificate the primary presents, never by a save:
		// one may only be kept, for the same primary, or taken away. Checked first, whether a
		// token is given or removed or not: a save with a token sets no pin either.
		if pin := zp.CertSHA256; pin != "" && (pin != old.ZonePrimary().CertSHA256 || !old.ZonePrimary().SameTarget(zp)) {
			why := "it is set by confirming the certificate the primary presents (GET, then POST /api/primary/certificate)"
			if pin == old.ZonePrimary().CertSHA256 {
				why = "it is the certificate of " + old.ZonePrimary().URL + ": leave it out, then confirm the new primary's certificate"
			}
			return &settings.FieldError{Field: "primary", Err: fmt.Errorf(`"cert_sha256" can't be set here: %s`, why)}
		}
		// A token given or removed: the old one goes first, and a new one is written only
		// once the settings it is for are (after). A save that fails halfway leaves no
		// token, never one beside a primary it wasn't given for.
		if tok != "" || body.RemovePrimaryToken {
			return keys.RemoveToken(keys.TokenPath(s.dataDir))
		}
		// The token kept goes only to the primary it was saved for: one moved to another
		// kind or address with it would be sent there, so the save must give it again (who
		// moves it shows they hold it) or remove it.
		if _, terr := (keys.DataTokenSource{DataDir: s.dataDir}).Token(); d2.API && !errors.Is(terr, keys.ErrNoToken) &&
			!old.ZonePrimary().SameTarget(zp) {
			return &settings.FieldError{Field: "primary_token", Err: fmt.Errorf(
				"the saved token is for %s, not %s: give it again (primary_token), or remove it", primaryName(old.ZonePrimary()), zp)}
		}
		return nil
	}, func() error {
		if tok == "" {
			return nil
		}
		if _, err := keys.ImportDataToken(s.dataDir, tok, true); err != nil {
			return fmt.Errorf("settings.json saved, but not the zone primary's token (give it again): %w", err)
		}
		return nil
	})
	var fe *settings.FieldError
	switch {
	case errors.As(err, &fe):
		fieldErr(w, fe.Field, err)
		return
	case errors.Is(err, settings.ErrChanged):
		httpErr(w, http.StatusConflict, err)
		return
	case err != nil:
		httpErr(w, http.StatusInternalServerError, err)
		return
	}
	what := changedFields(old, st)
	switch {
	case tok != "":
		what = append(what, "primary token set")
	case body.RemovePrimaryToken:
		what = append(what, "primary token removed")
	}
	user := auth.User(r.Context())
	log.Printf("settings: saved by %s: %v", user, what)
	if err := actionlog.Append(s.dataDir, actionlog.Entry{Event: "save", ID: "settings-" + time.Now().UTC().Format("20060102-150405"),
		Source: "controller", Who: user, Action: "settings", Args: what, Result: "ok"}); err != nil {
		log.Printf("settings: saved, but not in the action log: %v", err)
	}
	if s.listed != nil {
		s.listed(st.Nodes)
	}
	s.get(w, r)
}

// primaryName is a zone primary as an error names it: none set is "none".
func primaryName(c primary.Config) string {
	if c.IsZero() {
		return "none"
	}
	return c.String()
}

// changedFields names the fields of settings.json that differ (never their values: the
// action log says what changed, the file says to what).
func changedFields(a, b settings.Settings) []string {
	var out []string
	for _, f := range []struct {
		name string
		same bool
	}{
		{"nodes", slices.Equal(a.Nodes, b.Nodes)},
		{"dns_peers", slices.Equal(a.DNSPeers, b.DNSPeers)},
		{"dns_peer_zones", slices.Equal(a.DNSPeerZones, b.DNSPeerZones)},
		{"canary", a.Canary == b.Canary},
		{"no_dhcp", slices.Equal(a.NoDHCP, b.NoDHCP)},
		{"primary", a.ZonePrimary() == b.ZonePrimary() && (a.Primary == nil) == (b.Primary == nil)},
		{"internal_sources", slices.Equal(a.InternalSources, b.InternalSources)},
	} {
		if !f.same {
			out = append(out, f.name)
		}
	}
	if out == nil {
		out = []string{"nothing changed"}
	}
	return out
}
