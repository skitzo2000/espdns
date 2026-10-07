package nodesettings

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/skitzo2000/espdns/controller/internal/nodecfg"
)

// timezones.json is the form's time zones: a zone's name (the tz database's) and the POSIX
// TZ string a node takes for it, the footer of the zone's TZif file in Go's
// lib/time/zoneinfo.zip. A node keeps only the POSIX rule, so a zone whose rule changes
// later is edited here.
//
//go:embed timezones.json
var timezonesJSON []byte

// Zone is one of the form's time zones.
type Zone struct {
	Name string `json:"name"`
	TZ   string `json:"tz"`
}

// TimeZones are the form's time zones, in the file's order.
var TimeZones = func() []Zone {
	var zs []Zone
	if err := json.Unmarshal(timezonesJSON, &zs); err != nil {
		panic("nodesettings: timezones.json: " + err.Error())
	}
	return zs
}()

// ZoneName is the first of TimeZones with the POSIX TZ string tz ("" if none).
func ZoneName(tz string) string {
	for _, z := range TimeZones {
		if z.TZ == tz {
			return z.Name
		}
	}
	return ""
}

// PosixTZ is the POSIX TZ string for s: a name from TimeZones, or a POSIX TZ string as it
// is, checked as the node checks it. A name with '/' that TimeZones doesn't have is refused:
// it would pass as a POSIX string's shape and mean something else on the node.
func PosixTZ(s string) (string, error) {
	s = strings.TrimSpace(s)
	for _, z := range TimeZones {
		if strings.EqualFold(z.Name, s) {
			return z.TZ, nil
		}
	}
	if strings.Contains(s, "/") && !strings.ContainsAny(s, ",<") {
		return "", fmt.Errorf("time.tz: %q is not a time zone this controller knows: pick one, or give a POSIX TZ string, as EST5EDT,M3.2.0,M11.1.0", s)
	}
	c := nodecfg.Config{Time: &nodecfg.Time{TZ: s}}
	if s == "" {
		return "", fmt.Errorf("time.tz: give a time zone, or reset it")
	}
	if err := c.Validate(); err != nil {
		return "", err
	}
	return s, nil
}
