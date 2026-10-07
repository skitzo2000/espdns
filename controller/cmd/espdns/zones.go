package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/skitzo2000/espdns/controller/internal/nodecfg"
	"github.com/skitzo2000/espdns/controller/internal/release"
	"github.com/skitzo2000/espdns/controller/internal/rolling"
	"github.com/skitzo2000/espdns/controller/internal/zonefiles"
	"github.com/skitzo2000/espdns/controller/internal/zones"
)

// espdns zones -zone home.example.zone [-zone origin=path ...] [-config node.json]
//
//	[-check] [-out bundle.bin] [-empty] [-host ...]
//
// Reads the hosted zones (RFC 1035 master files, one per zone), checks them as the node
// will, and pushes them as one REL_ZONES release, which replaces every hosted zone the node
// had. The node applies it live.
func cmdZones(args []string) (err error) {
	fs := flag.NewFlagSet("zones", flag.ExitOnError)
	host, key, recovery := pushFlags(fs)
	var files listFlag
	fs.Var(&files, "zone", "a zone's master file, named <zone>.zone, or origin=path; repeat")
	cfgFile := fs.String("config", "", "the node's config: refuse a zone that is also one of its secondary or forward zones")
	check := fs.Bool("check", false, "only check the zones (against -limit-kb) and say what they hold")
	limitKB := fs.Int("limit-kb", zones.DefaultLimitKB, "with -check or -out: the node's memory.hosted_zones_kb (a push reads it from the node)")
	out := fs.String("out", "", "write the payload to this file instead of pushing it")
	empty := fs.Bool("empty", false, "push no zones: removes every hosted zone from the node")
	dataDir := dataFlag(fs)
	fs.Parse(args)
	if len(files) == 0 && !*empty {
		return errors.New("need -zone (or -empty to remove every hosted zone)")
	}
	if len(files) > 0 && *empty {
		return errors.New("-empty takes no -zone")
	}
	set := &zones.Set{}
	for _, f := range files {
		z, err := zones.LoadFile(f)
		if err != nil {
			return err
		}
		set.Zones = append(set.Zones, z)
	}
	var cfg *nodecfg.Config
	if *cfgFile != "" {
		b, err := os.ReadFile(*cfgFile)
		if err != nil {
			return err
		}
		if cfg, err = nodecfg.Parse(b); err != nil {
			return fmt.Errorf("%s: %w", *cfgFile, err)
		}
	}
	// The checks the controller's zone editor makes too (zones.Check); a push checks the
	// bundle against the limit the node reports.
	limit := -1
	if *check || *out != "" {
		limit = *limitKB
	}
	ck, err := zones.Check(set, cfg, limit)
	for _, l := range ck.Lines {
		fmt.Println(l)
	}
	if err != nil {
		return err
	}
	if *check || *out != "" {
		if *out != "" {
			return os.WriteFile(*out, ck.Payload, 0o644)
		}
		return nil
	}
	if err := needHost(*host); err != nil {
		return err
	}
	p, err := pusher(*key, *recovery, *dataDir)
	if err != nil {
		return err
	}
	ctx, end, err := begin(*dataDir, "zones", args, false)
	if err != nil {
		return err
	}
	defer func() { end(err) }()
	payload, note, err := zonesPayload(ctx, p, *host, set)
	if err != nil {
		return err
	}
	if note != "" {
		fmt.Printf("%s: %s\n", *host, note)
	}
	reply, err := p.Push(ctx, *host, release.Zones, payload)
	if err != nil {
		return err
	}
	fmt.Printf("%s: %s\n", *host, reply)
	recordZones(ctx, p, *dataDir, *host, files)
	return nil
}

// recordZones keeps the set as the zones the node serves now, for the controller's zone
// editor (internal/zonefiles, Pushed). Only said if it fails.
func recordZones(ctx context.Context, p *release.Pusher, dataDir, host string, files []string) {
	hashes, err := zonefiles.PushedFiles(files, os.ReadFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: not recorded as the zones it serves: %v\n", host, err)
		return
	}
	st, err := p.Status(ctx, host)
	if err == nil && st.Hosted == nil {
		err = errors.New("no hosted zones in its /status")
	}
	if err == nil {
		err = zonefiles.RecordPushed(dataDir, zonefiles.Pushed{NodeID: st.NodeID, Host: host, Seq: st.Hosted.Seq, Files: hashes, By: "cli"})
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: not recorded as the zones it serves: %v\n", host, err)
	}
}

// zonesPayload is the bundle for the node at host, checked against its memory limit and its
// secondary and forward zones as its /status reports them (zones.Set.Payload, as a rollout
// checks it), and what
// it stops serving (rolling.ZonesNote, "" for nothing).
func zonesPayload(ctx context.Context, p *release.Pusher, host string, set *zones.Set) ([]byte, string, error) {
	st, err := p.Status(ctx, host)
	if err != nil {
		return nil, "", err
	}
	b, err := set.Payload(host, st)
	if err != nil {
		return nil, "", err
	}
	return b, rolling.ZonesNote(set)(host, st), nil
}
