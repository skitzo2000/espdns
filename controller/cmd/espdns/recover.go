package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/fleet"
	"github.com/skitzo2000/espdns/controller/internal/recovery"
)

// espdns recover -data /data [-host a,b] [-mdns 3s] [-add-to-settings] [-dry-run]
//
// Rebuilds what it can of a data directory from the nodes, without a backup
// (internal/recovery): the release key must be imported first (espdns key import). It only
// reads the nodes (/status, /health), writes settings.json if there is none (the nodes in
// service that trust the key), pins each node listed there to its address (internal/pins),
// writes each node's /status into recovered/<time>/, and says per node what is here for its
// config and zones and what can't come back.
func cmdRecover(args []string) error {
	fs := flag.NewFlagSet("recover", flag.ExitOnError)
	dataDir := dataFlag(fs)
	hosts := fs.String("host", "", "node addresses to read besides those found over mDNS and in settings.json, comma-separated")
	mdns := fs.Duration("mdns", 3*time.Second, "how long to browse mDNS for nodes (0: only -host and settings.json)")
	add := fs.Bool("add-to-settings", false, "add the nodes found to a settings.json that is there already")
	dry := fs.Bool("dry-run", false, "read the nodes and say what would be written; write nothing")
	fs.Parse(args)
	if fi, err := os.Stat(*dataDir); err != nil || !fi.IsDir() {
		return fmt.Errorf("-data %s: not a directory", *dataDir)
	}
	var hs []string
	for _, h := range strings.Split(*hosts, ",") {
		if h = strings.TrimSpace(h); h != "" {
			hs = append(hs, h)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	r, err := recovery.Run(ctx, &fleet.Client{}, recovery.Options{DataDir: *dataDir, Hosts: hs, MDNS: *mdns, AddToSettings: *add, DryRun: *dry})
	if r.Fingerprint != "" {
		fmt.Printf("release key %s; %d node(s) read\n", r.Fingerprint, len(r.Nodes))
	}
	for _, n := range r.Nodes {
		fmt.Printf("\n%s (%s)", n.Addr, n.Source)
		if n.Error != "" {
			fmt.Printf(": %s\n", n.Error)
			continue
		}
		fmt.Printf(": %s, %s on %s, firmware %s; adopted %v, trusts the key %v, in settings.json %v\n", n.ID, n.Board, n.Image,
			n.Version, n.Adopted, n.Trusts, n.Listed)
		if n.Pinned {
			fmt.Printf("  pinned: releases are signed for node %s at %s\n", n.ID, n.Addr)
		}
		for _, z := range n.Hosted {
			fmt.Printf("  hosted %s serial %d, %d records: %s\n", z.Name, z.Serial, z.Records, z.File)
		}
		if len(n.Secondary) > 0 {
			fmt.Printf("  secondary zones: %s\n", strings.Join(n.Secondary, ", "))
		}
		for _, note := range n.Notes {
			fmt.Printf("  - %s\n", note)
		}
	}
	if r.Settings != "" {
		fmt.Printf("\nsettings: %s\n", r.Settings)
	}
	if r.Dir != "" {
		fmt.Printf("each node's /status and this report: %s\n", r.Dir)
	}
	if err != nil {
		return err
	}
	fmt.Println("\nnot recovered from the nodes (the firmware returns none of it):")
	for _, s := range r.NotRecovered {
		fmt.Printf("  - %s\n", s)
	}
	if *mdns > 0 {
		fmt.Println("\na node found only over mDNS is any host that says so: check the nodes listed are yours before a change")
	}
	return nil
}
