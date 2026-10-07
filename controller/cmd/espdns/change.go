package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/actionlog"
	"github.com/skitzo2000/espdns/controller/internal/fleet"
	"github.com/skitzo2000/espdns/controller/internal/fleetlock"
	"github.com/skitzo2000/espdns/controller/internal/settings"
)

// defaultData is the controller's data directory as `make run` uses it, from controller/.
const defaultData = "data"

// dataFlag is -data: the directory the CLI shares with the controller (internal/settings,
// internal/fleetlock, internal/actionlog).
func dataFlag(fs *flag.FlagSet) *string {
	return fs.String("data", defaultData, "the controller's data directory (/data in Docker): its settings.json, "+
		"the fleet lock and the action log")
}

// settingsPath is -settings if given, else the data directory's settings.json.
func settingsPath(path, dataDir string) string {
	if path != "" {
		return path
	}
	return settings.Path(dataDir)
}

// begin starts a change to the nodes: it takes the fleet lock in dataDir (failing at once
// if the controller or another espdns has it) and writes the change's start to the action
// log. end(err) writes its result and lets the lock go. ctx is cancelled by Ctrl-C or
// SIGTERM, which stops the change at once, as killing the CLI did; a second Ctrl-C quits.
// A dry run changes nothing: it takes no lock and isn't logged.
func begin(dataDir, cmd string, args []string, dry bool) (ctx context.Context, end func(error), err error) {
	ctx, cancel := context.WithCancel(context.Background())
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		select {
		case s := <-sig:
			log.Printf("%v: stopping now (again to quit at once)", s)
			signal.Stop(sig)
			cancel()
		case <-done:
		}
	}()
	stop := func() {
		close(done)
		signal.Stop(sig)
		cancel()
	}
	if dry {
		return ctx, func(error) { stop() }, nil
	}
	if fi, err := os.Stat(dataDir); err != nil || !fi.IsDir() {
		stop()
		if err == nil {
			err = errors.New("not a directory")
		}
		return nil, nil, fmt.Errorf("-data %s: %v: the data directory shared with the controller, for the fleet lock "+
			"and the action log (make it before you start the controller: docs/getting-started.md, step 5)", dataDir, err)
	}
	h := fleetlock.Self("espdns "+cmd, strings.Join(args, " "))
	who := h.User
	if h.Host != "" {
		who += "@" + h.Host
	}
	b := make([]byte, 4)
	rand.Read(b)
	entry := actionlog.Entry{ID: "cli-" + time.Now().UTC().Format("20060102-150405") + "-" + hex.EncodeToString(b),
		Source: "cli", Who: who, Action: cmd, Args: args}
	lk, err := fleetlock.Acquire(fleetlock.Path(dataDir), h)
	if err != nil {
		stop()
		if errors.Is(err, fleetlock.ErrLocked) {
			entry.Event, entry.Result, entry.Error = "refused", "failed", err.Error()
			if lerr := actionlog.Append(dataDir, entry); lerr != nil {
				log.Printf("action log: %v", lerr)
			}
		}
		return nil, nil, err
	}
	entry.Event = "start"
	if err := actionlog.Append(dataDir, entry); err != nil {
		lk.Release()
		stop()
		return nil, nil, fmt.Errorf("action log: %w", err)
	}
	t0 := time.Now()
	return ctx, func(err error) {
		entry.Event, entry.Time, entry.Duration = "end", time.Time{}, time.Since(t0).Seconds()
		switch {
		case err == nil:
			entry.Result = "ok"
		case ctx.Err() != nil || errors.Is(err, fleet.ErrStopped):
			entry.Result, entry.Error = "stopped", err.Error()
		default:
			entry.Result, entry.Error = "failed", err.Error()
		}
		if lerr := actionlog.Append(dataDir, entry); lerr != nil {
			log.Printf("action log: %v", lerr)
		}
		lk.Release()
		stop()
	}, nil
}
