package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/skitzo2000/espdns/controller/internal/adoption"
	"github.com/skitzo2000/espdns/controller/internal/fleet"
	"github.com/skitzo2000/espdns/controller/internal/keys"
	"github.com/skitzo2000/espdns/controller/internal/primary"
)

// espdns adopt -host <address> | -node <id>  [-address 192.0.2.52/24 [-gateway ...] | -address dhcp]
//
//	[-config configs/<name>.json] [-name ...] [-reserved] [-identify 30s] [-add-to-settings]
//	[-primary-kind technitium -primary-url https://primary:53443 [-primary-token-file token] | -primary-done] [-dry-run]
//
// Adoption and addressing (docs/design.md): the node is found on the static address it has
// (its board's default, the one it was flashed with, or its config's; no DHCP lease), and
// that address, or a new one, goes into its node config. The address comes from -address,
// else the config file's network, else what the node runs on now. A new address is kept only
// once the node is reached there. "dhcp" is for a network with a DHCP server (never
// one in settings.json's no_dhcp): the node's address must then be reserved there (-reserved).
//
// The zone primary (internal/primary) is settings.json's "primary" unless -primary-kind and
// -primary-url say otherwise.
//
// The flags make an adoption.Request, which the controller's Adopt page makes too
// (adoption.Web): both are built and run by internal/adoption.
func cmdAdopt(args []string) (err error) {
	req, o, tf, err := adoptRequest(args)
	if err != nil {
		return err
	}
	ctx, end, err := begin(*o.data, "adopt", args, *o.dryRun)
	if err != nil {
		return err
	}
	defer func() { end(err) }()
	c, err := adoptClient(o)
	if err != nil {
		return err
	}
	b, err := adoption.Build(ctx, c, req, cliToken(tf, *o.data), log.Printf)
	if err != nil {
		return err
	}
	if fi, err := os.Stdin.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 {
		b.Adopt.AskReserved = func(addr, mac string) bool {
			return confirmPrompt(fmt.Sprintf("Is %s reserved for MAC %s in the DHCP server?", addr, mac))
		}
	}
	_, err = adoption.Run(ctx, c, b, "cli", log.Printf)
	switch {
	case errors.Is(err, fleet.ErrReservation):
		return fmt.Errorf("%w (-reserved)", err)
	case errors.Is(err, fleet.ErrManual):
		how := ""
		if d, _ := primary.Lookup(b.PrimaryKind); d.API {
			how = fmt.Sprintf(`; or let the controller make them: "primary": {"kind": %q, "url": ...} in settings.json and the token `+
				"(from the environment, or espdns primary import: docs/reference/cli.md#primary)", b.PrimaryKind)
		}
		return fmt.Errorf("%w (%s): once they are made, run it again with -primary-done%s",
			err, b.PrimaryWhy, how)
	}
	return single(err)
}

// adoptClient is the client adopt runs with (a test reaches its fake network through it).
var adoptClient = func(o *fleetOpts) (*fleet.Client, error) { return o.client() }

// tokenFrom is where the CLI's adopt takes the zone primary's token from, besides the data
// directory: -primary-token-file, and -primary-token-env.
type tokenFrom struct{ file, env string }

// adoptRequest reads espdns adopt's flags into the request internal/adoption builds the
// adoption from: the controller's Adopt page makes the same request (adoption.Web).
func adoptRequest(args []string) (adoption.Request, *fleetOpts, tokenFrom, error) {
	fs := flag.NewFlagSet("adopt", flag.ExitOnError)
	o := addFleetFlags(fs)
	host := fs.String("host", "", "the node's address now (the one it was flashed with, or see espdns discover)")
	node := fs.String("node", "", "the node's ID (its MAC, from espdns discover): found over mDNS without -host, else checked")
	address := fs.String("address", "", "its static address with the prefix length (192.0.2.52/24), or dhcp on a network "+
		"with a DHCP server, never one in settings.json's no_dhcp (default: the config's, else the one it runs on now)")
	gateway := fs.String("gateway", "", "the gateway (default: the config's, else the node's now)")
	cfgFile := fs.String("config", "", "the node's config (JSON, controller/internal/nodecfg; a bare file name is the data directory's configs/<name>); its network is set from the address")
	name := fs.String("name", "", "the node's name (default: the config's)")
	reserved := fs.Bool("reserved", false, "with dhcp: the node's address is reserved for its MAC in the DHCP server "+
		"(without it, adopt asks, or stops after saying what to reserve)")
	identify := fs.Duration("identify", 0, "flicker the node's LED this long first, to match it to the board in your hand")
	pKind := fs.String("primary-kind", "", "the zone primary's kind, one of "+strings.Join(primary.Kinds(), ", ")+
		" (manual: any primary, its lists changed by hand; the others over their API) (default: settings \"primary\", else manual)")
	pURL := fs.String("primary-url", "", "the zone primary's API (technitium: https://<host>:53443): the node is allowed to transfer "+
		"its secondary zones there (default: settings \"primary\" \"url\")")
	pToken := fs.String("primary-token-file", "", "file holding the zone primary's API token (default $ESPDNS_PRIMARY_TOKEN, "+
		"else -primary-token-env's, else the data directory's keys/primary.token)")
	pEnv := fs.String("primary-token-env", "", "an environment variable holding the token (the Makefile's PRIMARY_TOKEN_ENV)")
	pDone := fs.Bool("primary-done", false, "the zone primary isn't changed from here (manual, or no API or token): the changes "+
		"adopt names (each zone's transfer and NOTIFY lists) are made by hand on it already")
	addSettings := fs.Bool("add-to-settings", false, "once adopted, add the node's address to settings.json (the nodes rollouts count and change)")
	wait := fs.Duration("wait", adoption.DefaultWait, "how long to wait for the node on its new address")
	catalog := fs.String("catalog", defaultCatalog, "the board catalog, for the config's memory plan on a node from before the plan")
	checks := checkFlags(fs)
	fs.Parse(args)
	tf := tokenFrom{file: *pToken, env: *pEnv}
	return adoption.Request{Host: *host, Node: *node, Address: *address, Gateway: *gateway, Config: *cfgFile, Name: *name,
		Reserved: *reserved, Identify: *identify, PrimaryKind: *pKind, PrimaryURL: *pURL,
		PrimaryDone: *pDone, AddToSettings: *addSettings, Wait: *wait, Catalog: *catalog, Checks: checks(),
		DataDir: *o.data, Settings: *o.settings, MDNS: *o.mdns, Peers: o.peers, DNSPeers: o.dnsPeers.addrs,
		DNSPeerZones: o.dnsPeers.zones, NoDNSPeers: *o.dnsPeers.none, AllowSingle: *o.allowSingle, Force: *o.force,
		DryRun: *o.dryRun}, o, tf, nil
}

// cliToken is the zone primary token the CLI uses: the file named, else the environment (as
// a password manager gives it), else the controller's copy in the data directory; "" if none.
func cliToken(tf tokenFrom, dataDir string) adoption.Token {
	return func() (string, error) {
		t, err := primaryToken(tf.file, tf.env)
		if err != nil || t != "" {
			return t, err
		}
		t, err = keys.DataTokenSource{DataDir: dataDir}.Token()
		if errors.Is(err, keys.ErrNoToken) {
			return "", nil
		}
		return t, err
	}
}
