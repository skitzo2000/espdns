package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/fleet"
	"github.com/skitzo2000/espdns/controller/internal/pins"
	"github.com/skitzo2000/espdns/controller/internal/release"
)

// espdns pin -data /data                                     (the nodes pinned, and their seqs)
// espdns pin -data /data -host 192.0.2.53 -node 30:ed:a0:00:00:01
//
// Releases are signed only for the node ID pinned to an address (internal/pins), never for
// the one a /status gives. Adoption pins a node, and espdns recover the nodes it lists; pin
// is for the rest: a node adopted before pins, or a replaced board at an adopted node's
// address. The node must answer at -host as -node: its ID is read off its label, the Adopt
// page or espdns discover, and the /status here only checks it is the one named.
func cmdPin(args []string) (err error) {
	fs := flag.NewFlagSet("pin", flag.ExitOnError)
	dataDir := dataFlag(fs)
	host := fs.String("host", "", "the node's address (without it: list the nodes pinned)")
	node := fs.String("node", "", "the node's ID (its chip MAC), which must answer at -host")
	fs.Parse(args)
	l := pins.Open(*dataDir)
	if *host == "" {
		if *node != "" {
			return errors.New("-node goes with -host")
		}
		return printPins(l)
	}
	if *node == "" {
		return errors.New("need -node: the ID of the node at -host (espdns discover, or its label)")
	}
	ctx, end, err := begin(*dataDir, "pin", args, false)
	if err != nil {
		return err
	}
	defer func() { end(err) }()
	replaced, err := pinNode(ctx, l, &fleet.Client{}, *host, *node)
	if err != nil {
		return err
	}
	fmt.Printf("%s: node %s pinned\n", *host, strings.ToLower(*node))
	if replaced != "" {
		fmt.Printf("(node %s, pinned there before, is pinned to no address now)\n", replaced)
	}
	return nil
}

// pinNode pins node to host once the node at host answers as it.
func pinNode(ctx context.Context, l *pins.Ledger, c *fleet.Client, host, node string) (string, error) {
	if _, err := release.ParseMAC(node); err != nil {
		return "", err
	}
	tctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	st, err := c.Status(tctx, host)
	if err != nil {
		return "", fmt.Errorf("the node at %s: %w", host, err)
	}
	if !strings.EqualFold(st.NodeID, node) {
		return "", fmt.Errorf("%s answers as node %q, not %s: not pinned", host, st.NodeID, node)
	}
	return l.Pin(node, host)
}

func printPins(l *pins.Ledger) error {
	rs, err := l.List()
	if err != nil {
		return err
	}
	if len(rs) == 0 {
		fmt.Println("no node is pinned: adopt them, or pin each node in service (espdns pin -host <address> -node <its ID>)")
		return nil
	}
	for _, r := range rs {
		addr := r.Addr
		if addr == "" {
			addr = "(no address)"
		}
		var seqs []string
		for _, k := range []release.Kind{release.Firmware, release.Config, release.Zones, release.Blocklist,
			release.Overrides, release.Control} {
			if s := r.Seq[k.String()]; s > 0 {
				seqs = append(seqs, fmt.Sprintf("%s %d", k, s))
			}
		}
		last := "none yet"
		if len(seqs) > 0 {
			last = strings.Join(seqs, ", ")
		}
		fmt.Printf("%-15s %s pinned %s; last signed: %s\n", addr, r.ID, r.Pinned.Local().Format(time.DateTime), last)
	}
	return nil
}
