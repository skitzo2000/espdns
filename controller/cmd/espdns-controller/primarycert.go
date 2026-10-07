package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/actionlog"
	"github.com/skitzo2000/espdns/controller/internal/auth"
	"github.com/skitzo2000/espdns/controller/internal/primary"
	"github.com/skitzo2000/espdns/controller/internal/settings"
)

// The zone primary's certificate: the confirm step that pins a self-signed one
// (internal/primary, tls.go; the CLI's espdns primary cert|pin|unpin does the same).
//
//	GET    /api/primary/certificate  the certificate the primary in settings.json presents
//	                                 now (read in a TLS handshake: nothing else is sent, no
//	                                 token), its fingerprint, whether the system's roots
//	                                 trust it, and the pin
//	POST   /api/primary/certificate  {"sha256": "<the fingerprint shown>"}: pinned, if the
//	                                 primary still presents that certificate (409 if not)
//	DELETE /api/primary/certificate  the pin taken away
//
// All need a login (the changes, from this machine, as every change).
type primaryCertServer struct {
	dataDir string
	// presented reads the certificate (primary.Presented; a test's stand-in).
	presented func(ctx context.Context, url string) (primary.CertInfo, error)
}

func (p primaryCertServer) routes(mux *routes) {
	mux.HandleFunc("GET /api/primary/certificate", needLogin("the zone primary's certificate needs", p.get))
	mux.HandleFunc("POST /api/primary/certificate", needLogin("pinning the zone primary's certificate needs", p.pin))
	mux.HandleFunc("DELETE /api/primary/certificate", needLogin("unpinning the zone primary's certificate needs", p.unpin))
}

// api is the zone primary's API address in settings.json, or why there is none to read a
// certificate from.
func (p primaryCertServer) api() (primary.Config, error) {
	s, err := settings.Load(settings.Path(p.dataDir))
	if err != nil {
		return primary.Config{}, err
	}
	zp := s.ZonePrimary()
	if zp.URL == "" {
		return zp, errors.New(`settings.json names no zone primary reached over an API ("primary": {"kind", "url"})`)
	}
	if zp.PlainHTTP() {
		return zp, fmt.Errorf("%w (save its https address in the settings, then confirm the certificate it presents)", primary.ErrPlainHTTP)
	}
	return zp, nil
}

func (p primaryCertServer) read(ctx context.Context, url string) (primary.CertInfo, error) {
	if p.presented != nil {
		return p.presented(ctx, url)
	}
	return primary.Presented(ctx, url)
}

func (p primaryCertServer) get(w http.ResponseWriter, r *http.Request) {
	zp, err := p.api()
	if err != nil {
		httpErr(w, http.StatusConflict, err)
		return
	}
	info, err := p.read(r.Context(), zp.URL)
	if err != nil {
		httpErr(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, map[string]any{"url": zp.URL, "presented": info, "pinned": zp.CertSHA256,
		"matches": zp.CertSHA256 != "" && zp.CertSHA256 == info.SHA256})
}

func (p primaryCertServer) pin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		SHA256 string `json:"sha256"`
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10))
	d.DisallowUnknownFields()
	if err := d.Decode(&body); err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	fp, err := primary.ParseFingerprint(body.SHA256)
	if err != nil {
		fieldErr(w, "sha256", fmt.Errorf("%v: the fingerprint GET /api/primary/certificate shows, once checked on the primary", err))
		return
	}
	zp, err := p.api()
	if err != nil {
		httpErr(w, http.StatusConflict, err)
		return
	}
	// Confirmed against what the primary presents now: the certificate shown and checked
	// is the one pinned, not whatever is there by the time this is sent.
	info, err := p.read(r.Context(), zp.URL)
	if err != nil {
		httpErr(w, http.StatusBadGateway, err)
		return
	}
	if info.SHA256 != fp {
		httpErr(w, http.StatusConflict, fmt.Errorf("the zone primary at %s now presents SHA-256 %s, not %s: "+
			"nothing pinned; read it again (GET /api/primary/certificate) and check it on the primary", zp.URL, info.SHA256, fp))
		return
	}
	p.save(w, r, zp.URL, fp, "pin", info)
}

func (p primaryCertServer) unpin(w http.ResponseWriter, r *http.Request) {
	zp, err := p.api()
	if err != nil {
		httpErr(w, http.StatusConflict, err)
		return
	}
	p.save(w, r, zp.URL, "", "unpin", primary.CertInfo{})
}

func (p primaryCertServer) save(w http.ResponseWriter, r *http.Request, url, fp, what string, info primary.CertInfo) {
	switch err := settings.SetPrimaryPin(settings.Path(p.dataDir), url, fp); {
	case errors.Is(err, settings.ErrNoPrimaryAPI):
		httpErr(w, http.StatusConflict, fmt.Errorf("settings.json's zone primary changed meanwhile (no longer %s): nothing pinned", url))
		return
	case err != nil:
		httpErr(w, http.StatusInternalServerError, err)
		return
	}
	user := auth.User(r.Context())
	args := []string{url}
	if fp != "" {
		args = append(args, "sha256 "+fp)
	}
	log.Printf("zone primary: certificate %s by %s: %v", what, user, args)
	if err := actionlog.Append(p.dataDir, actionlog.Entry{Event: "save", ID: "primary-cert-" + time.Now().UTC().Format("20060102-150405"),
		Source: "controller", Who: user, Action: "primary-cert-" + what, Args: args, Result: "ok"}); err != nil {
		log.Printf("zone primary: certificate %s, but not in the action log: %v", what, err)
	}
	out := map[string]any{"url": url, "pinned": fp}
	if fp != "" {
		out["presented"], out["matches"] = info, true
	}
	writeJSON(w, out)
}
