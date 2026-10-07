package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/configs"
	"github.com/skitzo2000/espdns/controller/internal/fleet"
	"github.com/skitzo2000/espdns/controller/internal/memplan"
	"github.com/skitzo2000/espdns/controller/internal/nodecfg"
	"github.com/skitzo2000/espdns/controller/internal/nodes"
	"github.com/skitzo2000/espdns/controller/internal/release"
	"github.com/skitzo2000/espdns/controller/internal/settings"
)

// espdns config -host 192.0.2.53 -file node.json [-check] [-confirm=false] [-reboot]
//
// A config that applies only at a boot (address, Wi-Fi network, zones) leaves the node
// with a reboot pending: the node waits for the controller. With -reboot this reboots it
// once another node or DNS peer answers (as espdns reboot; -peer, -dns-peer, -allow-single,
// -force) and, for a new address, confirms it there. Firmware from before reboots by itself.
func cmdConfig(args []string) (err error) {
	fs := flag.NewFlagSet("config", flag.ExitOnError)
	host, key, recovery := pushFlags(fs)
	file := fs.String("file", "", "the node config (JSON; format in controller/internal/nodecfg)")
	check := fs.Bool("check", false, "only check the file and print the payload (with -host: and the checks for that node, read only)")
	board := fs.String("board", "", "with -check: also check the memory plan on this catalog board (as a node on it does)")
	catalog := fs.String("catalog", defaultCatalog, "the board catalog (boards/), for -board")
	confirm := fs.Bool("confirm", true, "after a change of address, reach the node on it so it keeps the config")
	var peers hostList
	fs.Var(&peers, "peer", "another node clients use, for the rule before a reboot (comma-separated or repeat)")
	reboot := fs.Bool("reboot", false, "if the config waits for a reboot, reboot the node now (coordinated) and confirm it")
	allowSingle := fs.Bool("allow-single", false, "reboot the node even if it is the only one answering")
	force := fs.Bool("force", false, "reboot the node while another node is unhealthy (one must still answer)")
	dataDir := dataFlag(fs)
	settingsFile := fs.String("settings", "", "the settings file (default: settings.json in -data): its \"dns_peers\" (none if missing)")
	dnsPeers := addDNSPeerFlags(fs)
	fs.Parse(args)
	if *file == "" {
		return errors.New("need -file")
	}
	// A bare file name is the data directory's config of that name (internal/configs).
	*file = configs.Resolve(*dataDir, *file)
	if *check {
		if err := checkConfig(os.Stdout, *file, *board, *catalog); err != nil || *host == "" {
			return err
		}
		// -check -host: the checks for that node too, as a push makes them (read only).
		spec, err := configs.LoadSpec(*host, *file)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		fc := &fleet.Client{}
		st, err := fc.Status(ctx, *host)
		if err != nil {
			return err
		}
		if err := nodeChecks(ctx, fc, spec, st, settingsPath(*settingsFile, *dataDir), peers, *catalog); err != nil {
			return err
		}
		fmt.Printf("%s: %s takes it (its address checked: no DHCP where there is none, a new address free)\n", *file, *host)
		return nil
	}
	if err := needHost(*host); err != nil {
		return err
	}
	spec, err := configs.LoadSpec(*host, *file)
	if err != nil {
		return err
	}
	c, payload := spec.Config, spec.Payload
	p, err := pusher(*key, *recovery, *dataDir)
	if err != nil {
		return err
	}
	var dp []fleet.DNSPeer
	if *reboot {
		if dp, err = dnsPeers.peers(settingsPath(*settingsFile, *dataDir)); err != nil {
			return err
		}
	}
	ctx, end, err := begin(*dataDir, "config", args, false)
	if err != nil {
		return err
	}
	defer func() { end(err) }()
	fc := &fleet.Client{Pusher: p, Poll: 2 * time.Second, Logf: log.Printf}
	st, err := fc.Status(ctx, *host)
	if err != nil {
		return err
	}
	if err := nodeChecks(ctx, fc, spec, st, settingsPath(*settingsFile, *dataDir), peers, *catalog); err != nil {
		return err
	}
	r, err := p.PushRelease(ctx, *host, release.Config, payload)
	if err != nil {
		return err
	}
	fmt.Printf("%s: %s\n", *host, r.Reply)
	// For the controller's editor: the config the node took, and its seq (internal/configs).
	if err := configs.RecordPushed(*dataDir, configs.Pushed{NodeID: r.Before.NodeID, Host: *host,
		File: filepath.Base(*file), Seq: r.Seq, Payload: payload, By: "cli"}); err != nil {
		log.Printf("not recorded as the config %s runs: %v", *host, err)
	}
	pending, reasons := fc.RebootPending(ctx, *host, r.Node)
	trial := onTrial(r.Node, pending, reasons, c, *host)
	if pending {
		if !*reboot {
			fmt.Printf("%s waits for a reboot (%s): run this again with -reboot, or espdns reboot -host %s\n",
				*host, strings.Join(reasons, ", "), *host)
			if trial {
				fmt.Println("it comes up on trial on its new network: only -reboot confirms it there")
			}
			return nil
		}
		plan := fleet.Plan{Peers: peers, DNSPeers: dp, AllowSingle: *allowSingle, Force: *force}
		if !trial {
			return single(fc.Reboot(ctx, plan, *host, true))
		}
		if err := fc.RebootNow(ctx, plan, *host, true); err != nil {
			return single(err)
		}
	}
	if !trial {
		return nil
	}
	// The node reboots onto its new address, and keeps the config only if it is reached there.
	// Addresses, not the node's .local name: the static binary can't resolve those.
	locate := func(context.Context) []string { return []string{*host} }
	where := *host
	if a, ok := c.StaticAddr(); ok {
		where = a.String()
		locate = func(context.Context) []string { return []string{where} }
	} else if id := r.Before.NodeID; id != "" {
		// On DHCP the new address is the lease's: the same one if the router reserves it,
		// else whatever mDNS finds for the node's ID.
		where = *host + ", else its address over mDNS"
		locate = func(ctx context.Context) []string {
			hosts := []string{*host}
			if a, err := nodes.Find(ctx, id, 3*time.Second); err == nil && a != *host {
				hosts = append(hosts, a)
			}
			return hosts
		}
	}
	if !*confirm {
		fmt.Printf("not confirming: query %s within %v or it goes back to its previous config\n", where, fleet.TrialWindow)
		return nil
	}
	fmt.Printf("waiting for %s on %s ...\n", *host, where)
	cs, at, err := fc.ConfirmConfig(ctx, locate, r.Before.NodeID, r.Seq, fleet.TrialWindow+30*time.Second)
	if err != nil {
		return err
	}
	fmt.Printf("%s: config seq %d confirmed (%s address)\n", at, cs.Seq, cs.Address)
	return nil
}

// nodeChecks are the checks a config gets for the node it goes to, whose /status is st, as
// the controller's Configs page and its push make them (internal/configs): what a config
// rollout refuses (Refusal: the memory plan, firmware too old for it, a zone both hosted and
// forwarded) and its address (AddressRefusal: no DHCP on a network in settings.json's
// no_dhcp; a move onto no address another node or a DNS peer is known by, in settings.json
// or -peer, nor one something answers on, asked as adoption asks it).
func nodeChecks(ctx context.Context, fc *fleet.Client, spec configs.Spec, st release.NodeStatus, settingsFile string,
	peers []string, catalog string) error {
	if err := spec.Refusal(st, catalog); err != nil {
		return fmt.Errorf("%s: %w", spec.Host, err)
	}
	s, err := settings.Load(settingsFile)
	if err != nil {
		return err
	}
	return spec.AddressRefusal(configs.Addressing{Settings: s, Known: peers, Free: func(addr string) error {
		return fc.AddressFree(ctx, addr, st.NodeID, st.Net.MAC)
	}}, &st)
}

// onTrial says whether the config comes up on trial on a new network at the node's next
// boot (internal/configs, OnTrial: the controller's push confirms a moved node the same way).
func onTrial(reply release.Reply, pending bool, reasons []string, c *nodecfg.Config, host string) bool {
	return configs.OnTrial(reply, pending, reasons, c, host)
}

// defaultCatalog is the board catalog in the controller's image (Dockerfile); from a
// checkout, -catalog ../boards.
const defaultCatalog = "/catalog"

// checkConfig is espdns config -check: the file checked as the node checks it, its
// payload, and with a board, its memory plan there. The controller's editor runs the same
// checks (internal/configs).
func checkConfig(w io.Writer, file, board, catalog string) error {
	spec, err := configs.LoadSpec("", file)
	if err != nil {
		return err
	}
	if board != "" {
		b, err := configs.CatalogBoard(catalog, board)
		if err != nil {
			return err
		}
		p, err := configs.BoardPlan(spec.Config, board, b)
		if err != nil {
			if b.PSRAMMB == nil {
				return err
			}
			return fmt.Errorf("%s on %s: memory plan: %w", file, board, err)
		}
		fmt.Fprintf(w, "%s on %s: memory plan fits: %d of %d KB internal RAM, %d of %d KB PSRAM\n", file, board,
			p.Total[memplan.Internal]/1024, p.Capacity[memplan.Internal]/1024, p.Total[memplan.PSRAM]/1024,
			p.Capacity[memplan.PSRAM]/1024)
	}
	fmt.Fprintf(w, "%s: ok, %d bytes\n%s\n", file, len(spec.Payload), spec.Payload)
	return nil
}
