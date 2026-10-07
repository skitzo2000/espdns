package main

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/secfile"
)

// healthcheck asks the controller listening on listen for its dashboard (GET /) and says
// whether it answered: the container's health check (compose.yaml), which has no shell or
// curl in the distroless image, so it is this binary run with -healthcheck.
func healthcheck(listen string, timeout time.Duration) error {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return fmt.Errorf("-listen %s: %v", listen, err)
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	c := &http.Client{Timeout: timeout}
	resp, err := c.Get("http://" + net.JoinHostPort(host, port) + "/")
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("GET /: %s", resp.Status)
	}
	return nil
}

// writable says whether the controller can write in its data directory: a file made there
// and removed. Without it the controller would start and then fail at its first write (a
// login, a job record, the action log), so it refuses to start instead. In a container the
// usual cause is the user it runs as (compose.yaml: ESPDNS_UID/ESPDNS_GID in .env) not owning
// the directory mounted at /data, or that directory made by docker, as root.
func writable(dir string) error {
	f, err := os.CreateTemp(dir, ".write-check-*")
	if err != nil {
		return fmt.Errorf("data directory %s is not writable by uid %d gid %d: %v", dir, os.Getuid(), os.Getgid(), err)
	}
	name := f.Name()
	f.Close()
	return os.Remove(name)
}

// prepareData makes the data directory if missing (0700), refuses one the controller can't
// write in (writable), and takes group's and others' access away from what is in it
// (secfile.Tighten: directories 0700, files 0600, as the controller writes them; a data
// directory from before was 0755 with files 0644), after removing the backups a controller
// stopped mid-send left in .tmp (clearTmp). What it changed, and what it couldn't
// (another user's file), is logged, not fatal: the controller works either way.
func prepareData(dir string, logf func(format string, args ...any)) error {
	if err := secfile.MkdirAll(dir); err != nil {
		return fmt.Errorf("data directory: %v", err)
	}
	if err := writable(dir); err != nil {
		return err
	}
	clearTmp(dir, logf)
	changed, err := secfile.Tighten(dir)
	if n := len(changed); n > 0 {
		const shown = 5
		names := changed[:min(n, shown)]
		more := ""
		if n > shown {
			more = fmt.Sprintf(" and %d more", n-shown)
		}
		logf("data directory: %d open to group or others, made the controller user's only (directories 0700, files 0600): %s%s",
			n, strings.Join(names, ", "), more)
	}
	if err != nil {
		logf("data directory: not all of it could be made the controller user's only: %v", err)
	}
	return nil
}

// clearTmp removes the backups the Backup page left in <data>/.tmp (TmpDir) when the
// controller stopped while one was written or sent (killed at its memory limit, a restart):
// each is as big as the lists, and nothing else removes them. Only those, and only files.
func clearTmp(dir string, logf func(format string, args ...any)) {
	tmp := filepath.Join(dir, TmpDir)
	ents, err := os.ReadDir(tmp)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			logf("data directory: %s: %v", tmp, err)
		}
		return
	}
	for _, e := range ents {
		if ok, _ := filepath.Match(tmpBackup, e.Name()); !ok || !e.Type().IsRegular() {
			continue
		}
		if err := os.Remove(filepath.Join(tmp, e.Name())); err != nil {
			logf("data directory: a backup left from before: %v", err)
			continue
		}
		logf("data directory: removed %s, a backup left from before (the controller stopped while it was sent)", e.Name())
	}
}
