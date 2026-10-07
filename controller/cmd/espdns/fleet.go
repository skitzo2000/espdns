package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/configs"
	"github.com/skitzo2000/espdns/controller/internal/fleet"
	"github.com/skitzo2000/espdns/controller/internal/release"
	"github.com/skitzo2000/espdns/controller/internal/rolling"
)

// hostList is a flag of addresses: comma-separated, repeatable.
type hostList []string

func (l *hostList) String() string { return strings.Join(*l, ",") }
func (l *hostList) Set(s string) error {
	for _, h := range strings.Split(s, ",") {
		if h = strings.TrimSpace(h); h != "" && !slices.Contains(*l, h) {
			*l = append(*l, h)
		}
	}
	return nil
}

// fleetOpts are the flags the commands that work on several nodes share.
type fleetOpts struct {
	key         *string
	recovery    *bool
	peers       hostList
	settings    *string
	data        *string
	mdns        *time.Duration
	allowSingle *bool
	force       *bool
	dryRun      *bool
	dnsPeers    *dnsPeerOpts
	poll        time.Duration
}

// dnsPeerOpts are the flags for DNS peers: resolvers clients use besides the nodes.
type dnsPeerOpts struct {
	addrs, zones hostList
	none         *bool
}

func addDNSPeerFlags(fs *flag.FlagSet) *dnsPeerOpts {
	d := &dnsPeerOpts{}
	fs.Var(&d.addrs, "dns-peer", "a resolver clients use besides the nodes (the zone primary, 192.0.2.254, or addr:port): counts as one answering peer while it resolves a forwarded name and answers the zones' SOA authoritatively, checked right before each change or reboot; repeat (default: settings \"dns_peers\")")
	fs.Var(&d.zones, "dns-peer-zone", "a zone the DNS peers must answer for (default: settings \"dns_peer_zones\", else the node's secondary zones); repeat")
	d.none = fs.Bool("no-dns-peers", false, "ignore the settings' \"dns_peers\"")
	return d
}

// peers are the DNS peers: the flags', else the settings file's.
func (d *dnsPeerOpts) peers(settingsPath string) ([]fleet.DNSPeer, error) {
	return rolling.DNSPeers(rolling.Request{Settings: settingsPath, DNSPeers: d.addrs, DNSPeerZones: d.zones,
		NoDNSPeers: *d.none}, log.Printf)
}

func addFleetFlags(fs *flag.FlagSet) *fleetOpts {
	o := &fleetOpts{poll: time.Second}
	o.key = fs.String("key", defaultKey, "release signing key: a PEM file, or - to read it (PEM or base64) from standard input")
	o.recovery = fs.Bool("recovery", false, "sign with the offline recovery key (key slot 1; -key defaults to "+recoveryKey+")")
	fs.Var(&o.peers, "peer", "another node clients use (address; comma-separated or repeat): counts for the last-healthy-node rule, never changed")
	o.data = dataFlag(fs)
	o.settings = fs.String("settings", "", "the settings file (default: settings.json in -data): its \"nodes\" count as peers, its \"dns_peers\" as DNS peers (none if missing)")
	o.mdns = fs.Duration("mdns", 3*time.Second, "browse mDNS this long for the other nodes (0: don't)")
	o.allowSingle = fs.Bool("allow-single", false, "go ahead when the node is the only one: clients get no DNS while it reboots")
	o.force = fs.Bool("force", false, "start a change that may reboot a node while another node is unhealthy (one must still answer)")
	o.dryRun = fs.Bool("dry-run", false, "check the nodes and the rule for each; push nothing")
	o.dnsPeers = addDNSPeerFlags(fs)
	return o
}

// client is a fleet client signing with the key; in a dry run, without one if it can't be read.
func (o *fleetOpts) client() (*fleet.Client, error) {
	c := &fleet.Client{Poll: o.poll, Logf: log.Printf}
	p, err := pusher(*o.key, *o.recovery, *o.data)
	switch {
	case err == nil:
		c.Pusher = p
	case *o.dryRun:
		log.Printf("no release key (%v): a dry run goes on without one", err)
	default:
		return nil, err
	}
	return c, nil
}

// settingsPath is the settings file the commands read.
func (o *fleetOpts) settingsPath() string { return settingsPath(*o.settings, *o.data) }

// known is every node the CLI can find: mDNS (a failed browse is only a warning) and the
// settings list.
func (o *fleetOpts) known(ctx context.Context, c *fleet.Client) ([]fleet.Node, error) {
	return rolling.Known(ctx, c, rolling.Request{DataDir: *o.data, Settings: *o.settings, MDNS: *o.mdns, Peers: o.peers}, log.Printf)
}

// plan is the plan for changing targets, with every other known node answering as a peer.
func (o *fleetOpts) plan(ctx context.Context, c *fleet.Client, targets []string) (fleet.Plan, error) {
	p := fleet.Plan{Targets: targets, AllowSingle: *o.allowSingle, Force: *o.force, DryRun: *o.dryRun}
	var err error
	if p.DNSPeers, err = o.dnsPeers.peers(o.settingsPath()); err != nil {
		return p, err
	}
	ns, err := o.known(ctx, c)
	if err != nil {
		return p, err
	}
	c.Count(ctx, &p, ns, o.peers)
	return p, nil
}

// espdns discover [-mdns 5s] [-settings ...] [-peer ...] [-json]
func cmdDiscover(args []string) error {
	fs := flag.NewFlagSet("discover", flag.ExitOnError)
	o := addFleetFlags(fs)
	asJSON := fs.Bool("json", false, "print JSON")
	fs.Parse(args)
	if !isSet(fs, "mdns") {
		*o.mdns = 5 * time.Second
	}
	c := &fleet.Client{Logf: log.Printf}
	ns, err := o.known(context.Background(), c)
	if err != nil {
		return err
	}
	if *asJSON {
		return printJSON(ns)
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ADDRESS\tNODE\tMAC\tBOARD\tIMAGE\tFIRMWARE\tNET\tADDRESSING\tSTATE\tFOUND")
	for _, n := range ns {
		if n.Status == nil {
			fmt.Fprintf(w, "%s\t\t\t\t\t\t\t\t%s\t%s\n", n.Addr, n.Error, n.Source)
			continue
		}
		st := n.Status
		addressing := "?"
		if st.Config != nil {
			addressing = st.Config.Address
			if st.Config.AddressFrom != "" {
				addressing += " (" + st.Config.AddressFrom + ")"
			}
			if st.Config.Source != "node" {
				addressing += ", not adopted"
			}
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", n.Addr, st.NodeID, st.Net.MAC, st.Board, st.Image,
			st.Version+" "+st.ElfSHA256, st.Net.Kind, addressing, state(n), n.Source)
	}
	return w.Flush()
}

func state(n fleet.Node) string {
	if n.Health == nil {
		return n.Error
	}
	s := n.Health.State
	if len(n.Health.Reasons) > 0 {
		s += " (" + strings.Join(n.Health.Reasons, ", ") + ")"
	}
	if n.Status != nil && n.Status.Reboot != nil && n.Status.Reboot.Pending {
		s += ", reboot pending (" + strings.Join(n.Status.Reboot.Reasons, ", ") + ")"
	}
	return s
}

func isSet(fs *flag.FlagSet, name string) bool {
	set := false
	fs.Visit(func(f *flag.Flag) { set = set || f.Name == name })
	return set
}

func printJSON(v any) error {
	e := json.NewEncoder(os.Stdout)
	e.SetIndent("", "  ")
	return e.Encode(v)
}

// espdns status [-host a,b | -all] [-json]
func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	o := addFleetFlags(fs)
	var hosts hostList
	fs.Var(&hosts, "host", "node address (comma-separated or repeat)")
	all := fs.Bool("all", false, "every node found over mDNS or listed in -settings")
	asJSON := fs.Bool("json", false, "print JSON")
	fs.Parse(args)
	ctx := context.Background()
	c := &fleet.Client{Logf: log.Printf}
	var ns []fleet.Node
	switch {
	case *all:
		var err error
		if ns, err = o.known(ctx, c); err != nil {
			return err
		}
	case len(hosts) > 0:
		for _, h := range hosts {
			n := fleet.Node{Addr: h, Source: "flag"}
			c.Fill(ctx, &n)
			ns = append(ns, n)
		}
	default:
		return errors.New("need -host or -all")
	}
	if *asJSON {
		return printJSON(ns)
	}
	for i, n := range ns {
		if i > 0 {
			fmt.Println()
		}
		printNode(n)
	}
	return nil
}

func printNode(n fleet.Node) {
	fmt.Printf("%s: %s\n", n.Addr, state(n))
	st := n.Status
	if st == nil {
		return
	}
	fmt.Printf("  node %s (%s), MAC %s, %s, link %v\n", st.NodeID, st.Net.Hostname, st.Net.MAC, st.Net.Kind, st.Net.Link)
	fmt.Printf("  board %s, chip image %s\n", st.Board, st.Image)
	fmt.Printf("  firmware %s %s built %s, elf %s, %s (%s)\n", st.Project, st.Version, st.Built, st.ElfSHA256, st.Slot, st.OTAState)
	fmt.Printf("  up %s, boot %d ms\n", time.Duration(st.UptimeS)*time.Second, st.BootMS)
	if st.Config != nil {
		fmt.Printf("  config: %s seq %d, %s address, storage %s", st.Config.Source, st.Config.Seq, st.Config.Address, st.Config.Storage)
		if st.Config.Trial {
			fmt.Print(", on trial")
		}
		if st.Config.Error != "" {
			fmt.Printf(", error: %s", st.Config.Error)
		}
		fmt.Println()
	}
	if h := n.Health; h != nil {
		for _, s := range []struct {
			name string
			s    *fleet.Stored
		}{{"blocklist", h.Blocklist}, {"overrides", h.Overrides}, {"hosted zones", h.Zones}} {
			if s.s != nil && s.s.State != "off" {
				fmt.Printf("  %s: %s seq %d\n", s.name, s.s.State, s.s.Seq)
			}
		}
	}
	if len(st.Zones) > 0 {
		var z []string
		for _, s := range st.Zones {
			z = append(z, s.Name)
		}
		fmt.Printf("  secondary zones: %s\n", strings.Join(z, ", "))
	}
	if len(st.Seq) > 0 {
		var s []string
		for _, k := range []string{"firmware", "config", "zones", "blocklist", "overrides", "control"} {
			if v, ok := st.Seq[k]; ok {
				s = append(s, fmt.Sprintf("%s %d", k, v))
			}
		}
		fmt.Printf("  seq: %s\n", strings.Join(s, ", "))
	}
}

// checkFlags are the DNS checks after each node is changed.
func checkFlags(fs *flag.FlagSet) func() rolling.Checks {
	var local, fwd, blocked hostList
	fs.Var(&local, "check-local", "a name the node answers from its own zones (default: each zone's SOA); repeat")
	fs.Var(&fwd, "check-forward", "a forwarded name that must resolve (default example.com); repeat")
	fs.Var(&blocked, "check-blocked", "a name the blocklist must block (checked while it is on); repeat")
	must := fs.String("must-resolve", "", "file of names that must resolve, one per line")
	off := fs.Bool("no-dns-checks", false, "only check that the node answers DNS")
	return func() rolling.Checks {
		return rolling.Checks{Local: local, Forward: fwd, Blocked: blocked, MustResolve: *must, Off: *off}
	}
}

// rolloutRequest reads espdns rollout's flags into the request internal/rolling builds the
// plan and the change from: the controller's Push page makes the same request (rolling.Web).
func rolloutRequest(args []string) (rolling.Request, *fleetOpts, error) {
	fs := flag.NewFlagSet("rollout", flag.ExitOnError)
	o := addFleetFlags(fs)
	kindName := fs.String("kind", "", "what to roll out: firmware, config, zones, blocklist or overrides")
	var hosts, images, cfgArgs, zoneFiles, allowDeg hostList
	fs.Var(&hosts, "host", "nodes to change (comma-separated or repeat), in order")
	all := fs.Bool("all", false, "change every node found over mDNS or listed in -settings")
	canary := fs.String("canary", "", "the node to change first (default: settings.json's \"canary\" if it is one of them, else the first)")
	soak := fs.Duration("soak", rolling.DefaultSoak, "how long each changed node runs, checked again, before the next starts")
	fs.Var(&allowDeg, "allow-degraded", "a degraded reason accepted after the change (besides those the node had); repeat")
	fs.Var(&images, "image", "firmware: a chip image directory (with image.json and app.bin), or name=app.bin; repeat per chip image")
	board := fs.String("board", "", "firmware, for a node from before board definitions: the board a transitional -image name=app.bin was built for")
	reinstall := fs.Bool("reinstall", false, "firmware: push to nodes that already run the build")
	fs.Var(&cfgArgs, "config", "config: host=file per node (or one file with one -host); a bare file name is the data directory's configs/<name>")
	fs.Var(&zoneFiles, "zone", "zones: a zone master file, <zone>.zone or origin=path (comma-separated or repeat)")
	empty := fs.Bool("empty", false, "zones: remove every hosted zone")
	file := fs.String("file", "", "blocklist or overrides: the file from espdns blocklist")
	catalog := fs.String("catalog", defaultCatalog, "config: the board catalog, for the memory plan of a node on firmware from before it")
	checks := checkFlags(fs)
	fs.Parse(args)
	kind, err := release.ParseKind(*kindName)
	if err != nil || kind == release.Control {
		return rolling.Request{}, o, errors.New("need -kind firmware, config, zones, blocklist or overrides")
	}
	return rolling.Request{Kind: kind, Hosts: hosts, All: *all, Canary: *canary, Soak: *soak, AllowDegraded: allowDeg,
		Images: images, Board: *board, Reinstall: *reinstall, Configs: cfgArgs, Catalog: *catalog, Zones: zoneFiles,
		EmptyZones: *empty, File: *file, Checks: checks(),
		DataDir: *o.data, Settings: *o.settings, MDNS: *o.mdns, Peers: o.peers, DNSPeers: o.dnsPeers.addrs,
		DNSPeerZones: o.dnsPeers.zones, NoDNSPeers: *o.dnsPeers.none, AllowSingle: *o.allowSingle, Force: *o.force,
		DryRun: *o.dryRun}, o, nil
}

// espdns rollout -kind firmware|config|zones|blocklist|overrides (-host a,b | -all) ...
func cmdRollout(args []string) (err error) {
	req, o, err := rolloutRequest(args)
	if err != nil {
		return err
	}
	ctx, end, err := begin(*o.data, "rollout", args, *o.dryRun)
	if err != nil {
		return err
	}
	defer func() { end(err) }()
	c, err := o.client()
	if err != nil {
		return err
	}
	b, err := rolling.Build(ctx, c, req, log.Printf)
	if err != nil {
		return err
	}
	p := b.Plan
	log.Printf("rolling out %s to %s", req.Kind, strings.Join(p.Order(), ", then "))
	res, err := c.Rollout(ctx, p, b.Change)
	err = single(err)
	rolling.Report(log.Printf, p, res)
	if req.Kind == release.Config && !p.DryRun {
		rolling.RecordPushed(ctx, c, *o.data, b.Specs, res.Done, "cli", log.Printf)
	}
	if req.Kind == release.Zones && !p.DryRun {
		rolling.RecordZones(ctx, c, req, res.Done, "cli", log.Printf)
	}
	return err
}

// configPayloads is rolling.ConfigPayloads: each node's config, checked.
func configPayloads(specs, hosts []string, catalog, dataDir string) (func(context.Context, string, release.NodeStatus) ([]byte, error), []configs.Spec, error) {
	return rolling.ConfigPayloads(specs, hosts, catalog, dataDir)
}

// espdns reboot -host <node> [-if-pending] [-peer ...] [-allow-single] [-force] [-dry-run]
func cmdReboot(args []string) (err error) {
	fs := flag.NewFlagSet("reboot", flag.ExitOnError)
	o := addFleetFlags(fs)
	host := fs.String("host", "", "the node to reboot")
	ifPending := fs.Bool("if-pending", false, "only if a release it took waits for a reboot")
	checks := checkFlags(fs)
	fs.Parse(args)
	if *host == "" {
		return errors.New("need -host")
	}
	ctx, end, err := begin(*o.data, "reboot", args, *o.dryRun)
	if err != nil {
		return err
	}
	defer func() { end(err) }()
	c, err := o.client()
	if err != nil {
		return err
	}
	p, err := o.plan(ctx, c, []string{*host})
	if err != nil {
		return err
	}
	if p.Checks, err = checks().Make(); err != nil {
		return err
	}
	return single(c.Reboot(ctx, p, *host, *ifPending))
}

// single names the flag that lets a change go ahead on the only node.
func single(err error) error {
	if errors.Is(err, fleet.ErrSingle) {
		return fmt.Errorf("%w (-allow-single to go ahead anyway, or -peer the other nodes, or -dns-peer a resolver clients also use)", err)
	}
	return err
}

// confirmPrompt asks a yes/no question on the terminal.
func confirmPrompt(q string) bool {
	fmt.Fprintf(os.Stderr, "%s [y/N] ", q)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "y")
}
