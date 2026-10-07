// espdns is the command line side of the controller: it finds nodes, adopts them, builds
// blocklists, checks node configs and hosted zones, and pushes signed releases to nodes,
// one at a time across the fleet (docs/design.md, Principles, Blocking, Signed releases,
// Adoption and addressing, Answering). Run from controller/, where the release key is
// ../firmware/secrets/release.pem, or with it on standard input (-key -, as the Docker runs
// in docs/rollout.md pass it) or in $ESPDNS_RELEASE_KEY (secrets.go). The fleet work is
// internal/fleet.
//
//	espdns discover                                (mDNS and data/settings.json's nodes)
//	espdns status -all                             (-host a,b for some; -json)
//	espdns adopt -host 192.0.2.52 -config configs/node2.json \
//	    [-address 192.0.2.60/24] [-primary-kind technitium -primary-url https://192.0.2.254:53443] [-primary-done] \
//	    [-add-to-settings] [-dry-run]
//	espdns rollout -kind firmware -all -image data/firmware/images/esp32p4-rev1 -image ... [-dry-run]
//	espdns rollout -kind blocklist -all -file list.bin -check-blocked doubleclick.net -must-resolve must.txt
//	espdns rollout -kind config -config 192.0.2.53=node1.json -config 192.0.2.52=...
//	espdns rollout -kind zones -all -zone home.example.zone
//	espdns reboot -host 192.0.2.53           (only with another node answering)
//
//	espdns blocklist -list adblock:pro.txt -list hosts:hosts.txt -allow domains:ok.txt \
//	    -popular top-1m.csv -must-resolve must.txt -out list.bin
//	espdns blocklist -list rpz:https://feeds.example/rpz.zone -out list.bin   (-max-change 20; -accept-change)
//	espdns blocklist -list hosts:http://192.0.2.10/hosts.txt -internal 192.0.2.10 -out list.bin   (a list server inside)
//	espdns blocklist -list wildcard:deny.txt -allow wildcard:allow.txt -xor 0 -out overrides.bin
//	espdns push -host 192.0.2.53 -kind blocklist -file list.bin
//	espdns push -host 192.0.2.53 -kind overrides -file overrides.bin
//	espdns pause -host 192.0.2.53 -for 30m     (-for 0 resumes)
//	espdns identify -host 192.0.2.53 -for 30s (flickers the node's LED; -for 0 stops)
//	espdns flush -host 192.0.2.53             (drops the node's cached answers)
//	espdns revert -host 192.0.2.53 -kind blocklist   (back to the older list the node keeps; -kind overrides, zones)
//	espdns metrics -host 192.0.2.53           (its /metrics, summed up; -raw as sent, -json parsed)
//	espdns querylog -host 192.0.2.53 [-follow] (its query log: what it holds, then what comes)
//	espdns config -host 192.0.2.53 -file node.json   (-check: only check the file)
//	espdns zones -host 192.0.2.53 -zone home.example.zone   (-check: only check them)
//	espdns key import -data /data -key - -pub release.pub   (the controller's release key, from standard input)
//	espdns key status -data /data
//	espdns primary import -data /data              (the controller's zone primary API token, from standard input)
//	espdns primary cert -data /data                (the certificate the zone primary presents; pin -sha256 <it>, unpin)
//	espdns passwd -data /data                      (the controller's login)
//	espdns backup -data /data -out backup.age      (the data directory, encrypted; the passphrase asked)
//	espdns restore -data /new -in backup.age [-dry-run]   (into an empty data directory)
//	espdns recover -data /data [-host a,b]         (without a backup: settings.json from the nodes)
//	espdns pin -data /data -host 192.0.2.53 -node 30:ed:a0:00:00:01   (sign for that node there; no -host: list)
//	espdns version                                 (this build's version, the repository's VERSION)
//	espdns release build -version 0.0.1 -images dir -catalog /catalog -out dist   (a release's files, unsigned)
//	espdns release sign -dir dist -pub /keys/release.pub < release.pem            (signs its SHA256SUMS)
//	espdns release verify -dir dist -pub /keys/release.pub
//	espdns release import -dir dist -pub /keys/release.pub -data /data            (its chip images, once verified)
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/blocklist"
	"github.com/skitzo2000/espdns/controller/internal/pins"
	"github.com/skitzo2000/espdns/controller/internal/release"
	"github.com/skitzo2000/espdns/controller/internal/version"
)

type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(s string) error { *l = append(*l, s); return nil }

func usage() {
	fmt.Fprintf(os.Stderr, "usage: espdns discover|status|adopt|rollout|reboot|blocklist|push|config|zones|pause|identify|flush|revert|metrics|querylog|key|primary|passwd|backup|restore|recover|pin|release|version [flags]; "+
		"espdns <command> -h for its flags\n")
	os.Exit(2)
}

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		usage()
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "discover":
		err = cmdDiscover(args)
	case "status":
		err = cmdStatus(args)
	case "adopt":
		err = cmdAdopt(args)
	case "rollout":
		err = cmdRollout(args)
	case "reboot":
		err = cmdReboot(args)
	case "blocklist":
		err = cmdBlocklist(args)
	case "push":
		err = cmdPush(args)
	case "config":
		err = cmdConfig(args)
	case "zones":
		err = cmdZones(args)
	case "key":
		err = cmdKey(args)
	case "primary":
		err = cmdPrimary(cmd, args)
	case "passwd":
		err = cmdPasswd(args)
	case "backup":
		err = cmdBackup(args)
	case "restore":
		err = cmdRestore(args)
	case "recover":
		err = cmdRecover(args)
	case "pin":
		err = cmdPin(args)
	case "pause", "identify", "flush", "revert":
		err = cmdControl(cmd, args)
	case "metrics":
		err = cmdMetrics(args)
	case "querylog":
		err = cmdQueryLog(args)
	case "release":
		err = cmdRelease(args, os.Stdin, os.Stdout)
	case "version":
		err = cmdVersion(os.Stdout, args)
	default:
		usage()
	}
	if err != nil {
		log.Fatalf("espdns %s: %v", cmd, err)
	}
}

// cmdVersion says this build's version (internal/version).
func cmdVersion(w io.Writer, args []string) error {
	fs := flag.NewFlagSet("version", flag.ExitOnError)
	fs.Parse(args)
	if fs.NArg() > 0 {
		return fmt.Errorf("takes no arguments (got %q)", fs.Args())
	}
	_, err := fmt.Fprintln(w, version.Version)
	return err
}

// pushFlags are the flags every command that pushes shares.
func pushFlags(fs *flag.FlagSet) (host, key *string, recovery *bool) {
	host = fs.String("host", "", "the node's address (required: there is no default node)")
	key = fs.String("key", defaultKey, "release signing key: a PEM file, or - to read it (PEM or base64) from standard input")
	recovery = fs.Bool("recovery", false, "sign with the offline recovery key (key slot 1; -key defaults to "+recoveryKey+")")
	return
}

// needHost refuses a push with no -host: there is no default node.
func needHost(host string) error {
	if host == "" {
		return errors.New("need -host: the node's address")
	}
	return nil
}

const (
	defaultKey  = "../firmware/secrets/release.pem"
	recoveryKey = "../firmware/secrets/recovery.pem"
)

// pusher signs with the key (the recovery key, with recovery), for the nodes pinned in the
// data directory's record (internal/pins), with the seqs it records.
func pusher(key string, recovery bool, dataDir string) (*release.Pusher, error) {
	if recovery && key == defaultKey {
		key = recoveryKey // as tools/ota_push.py --recovery
	}
	k, err := loadReleaseKey(key, recovery)
	if err != nil {
		return nil, err
	}
	p := &release.Pusher{Key: k, KeyID: release.KeyRelease, Pins: pins.Open(dataDir)}
	if recovery {
		p.KeyID = release.KeyRecovery
	}
	return p, nil
}

func cmdPush(args []string) (err error) {
	fs := flag.NewFlagSet("push", flag.ExitOnError)
	host, key, recovery := pushFlags(fs)
	dataDir := dataFlag(fs)
	kind := fs.String("kind", "blocklist", "release kind: blocklist or overrides")
	file := fs.String("file", "", "the payload (from espdns blocklist)")
	fs.Parse(args)
	if err := needHost(*host); err != nil {
		return err
	}
	k, err := release.ParseKind(*kind)
	if err != nil {
		return err
	}
	if k != release.Blocklist && k != release.Overrides {
		return fmt.Errorf("push takes blocklist or overrides (firmware: espdns rollout -kind firmware; config: espdns config; zones: espdns zones; " +
			"control: espdns pause, identify, flush or revert)")
	}
	if *file == "" {
		return fmt.Errorf("need -file")
	}
	payload, err := os.ReadFile(*file)
	if err != nil {
		return err
	}
	if len(payload) < 8 || string(payload[:8]) != blocklist.FileMagic {
		return fmt.Errorf("%s is not a blocklist file", *file)
	}
	p, err := pusher(*key, *recovery, *dataDir)
	if err != nil {
		return err
	}
	ctx, end, err := begin(*dataDir, "push", args, false)
	if err != nil {
		return err
	}
	defer func() { end(err) }()
	reply, err := p.Push(ctx, *host, k, payload)
	if err != nil {
		return err
	}
	fmt.Printf("%s: %s\n", *host, reply)
	return nil
}

// controlPayload is the Control release a control command sends; d is its -for, kind its
// -kind (revert).
func controlPayload(cmd string, d time.Duration, kind string) ([]byte, error) {
	switch cmd {
	case "pause":
		if d < 0 || d > release.PauseMax {
			return nil, fmt.Errorf("-for %v: 0 (resume) to %v (a week)", d, release.PauseMax)
		}
		return release.PausePayload(d), nil
	case "identify":
		return release.IdentifyPayload(d), nil
	case "flush":
		return release.FlushPayload(), nil
	case "revert":
		k, err := release.ParseKind(kind)
		if err != nil {
			return nil, err
		}
		return release.RevertPayload(k)
	}
	return nil, fmt.Errorf("unknown control command %q", cmd)
}

// controlPusher signs control command cmd: identify also for a node not adopted yet (its LED
// flickers, nothing more: release.Pusher.Unadopted), the others for a pinned node alone.
func controlPusher(cmd, key string, recovery bool, dataDir string) (*release.Pusher, error) {
	p, err := pusher(key, recovery, dataDir)
	if err != nil {
		return nil, err
	}
	p.Unadopted = cmd == "identify"
	return p, nil
}

// cmdControl sends a control release: pause blocking, identify (the LED), flush the cache,
// revert the blocklist, overrides or hosted zones. All apply live; the node keeps none of
// them across a reboot but a revert, which holds until a newer one is pushed (a revert whose
// list only fits once the one in use is gone applies at the next reboot: reboot pending).
func cmdControl(cmd string, args []string) (err error) {
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	host, key, recovery := pushFlags(fs)
	dataDir := dataFlag(fs)
	d := new(time.Duration)
	kind := new(string)
	switch cmd {
	case "pause":
		d = fs.Duration("for", 5*time.Minute, "how long blocking stays off (at most 168h, a week); 0 resumes it")
	case "identify":
		d = fs.Duration("for", 30*time.Second, "how long the LED flickers (at most 1h); 0 stops it")
	case "revert":
		kind = fs.String("kind", "blocklist", "what goes back to the older copy the node keeps: blocklist, overrides or zones")
	}
	fs.Parse(args)
	if err := needHost(*host); err != nil {
		return err
	}
	payload, err := controlPayload(cmd, *d, *kind)
	if err != nil {
		return err
	}
	p, err := controlPusher(cmd, *key, *recovery, *dataDir)
	if err != nil {
		return err
	}
	ctx, end, err := begin(*dataDir, cmd, args, false)
	if err != nil {
		return err
	}
	defer func() { end(err) }()
	reply, err := p.Push(ctx, *host, release.Control, payload)
	if err != nil {
		return err
	}
	fmt.Printf("%s: %s\n", *host, reply)
	return nil
}
