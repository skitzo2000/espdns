// Package nodesettings is a node's settings as a form (the node page's Settings, docs/plan.md,
// The GUI redesign): the few settings a person changes, read from the node's config
// (internal/configs) and what the node reports, and an edit of them made into a new config,
// checked with the node's own rules (internal/nodecfg).
//
// The form's fields and the config keys they are:
//
//	name        "name"
//	network     "network": {"address", "gateway"} ("dhcp" for a network with a DHCP server)
//	forwarders  "forwarders" (upstream DNS, in order; [] turns forwarding off)
//	tz          "time": {"tz"} (a POSIX TZ string; a name from TimeZones is made one)
//	blocking    "blocking": {"enabled"}
//	querylog    "querylog": {"enabled", "client"}
//
// Every other key of the config is kept as it is: an edit changes only what it names. A
// field in an edit's Reset goes back to the board's or the firmware's value (its key left
// out of the config).
package nodesettings

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/skitzo2000/espdns/controller/internal/configs"
	"github.com/skitzo2000/espdns/controller/internal/nodecfg"
	"github.com/skitzo2000/espdns/controller/internal/release"
)

// Fields are the form's fields, in the page's order.
var Fields = []string{"name", "network", "forwarders", "tz", "blocking", "querylog"}

// Words are the fields as a person reads them, for a change's summary.
var Words = map[string]string{"name": "name", "network": "address", "forwarders": "upstream DNS", "tz": "time zone",
	"blocking": "blocking", "querylog": "query log"}

// Applies is how a change of each field reaches the node: "live", or "restart" (the node
// takes it at its next boot, which the controller makes only while another node answers).
// It is the firmware's (nodecfg.Compare: the address waits for a reboot, the rest is live);
// a test holds the two together.
var Applies = map[string]string{"name": "live", "network": "restart", "forwarders": "live", "tz": "live",
	"blocking": "live", "querylog": "live"}

// From says where a field's value comes from.
const (
	FromConfig  = "config"  // the node's config sets it
	FromNode    = "node"    // the node reports it (the board's or the firmware's value)
	FromDefault = "default" // the firmware's default, as nodecfg documents it
	FromUnknown = "unknown" // the board's or the firmware's, which only the node knows and doesn't report
)

// Field is one field of the form: its value, where it comes from, and how a change applies.
type Field[T any] struct {
	Value   T      `json:"value"`
	From    string `json:"from"`
	Applies string `json:"applies"`
}

// TimeZone is the tz field's value: the POSIX TZ string, and its name when TimeZones has it.
type TimeZone struct {
	TZ   string `json:"tz"`
	Name string `json:"name,omitempty"`
}

// QueryLog is the querylog field's value.
type QueryLog struct {
	Enabled bool   `json:"enabled"`
	Client  string `json:"client"` // nodecfg.QueryLogClients
}

// Form is a node's settings as the form shows them.
type Form struct {
	Name       Field[string]           `json:"name"`
	Network    Field[*nodecfg.Network] `json:"network"`
	Forwarders Field[[]string]         `json:"forwarders"`
	TZ         Field[TimeZone]         `json:"tz"`
	Blocking   Field[bool]             `json:"blocking"`
	QueryLog   Field[QueryLog]         `json:"querylog"`
}

// Read is the form for a node whose config is c (nil: none, the board's and firmware's
// settings) and whose last /status is st (nil: not read): each field from the config where
// it sets it, else from what the node reports, else the firmware's default where nodecfg
// says it.
func Read(c *nodecfg.Config, st *release.NodeStatus) Form {
	if c == nil {
		c = &nodecfg.Config{}
	}
	var f Form
	f.Name = Field[string]{From: FromUnknown}
	switch {
	case c.Name != "":
		f.Name = Field[string]{Value: c.Name, From: FromConfig}
	case st != nil && st.Config != nil && st.Config.Name != "":
		f.Name = Field[string]{Value: st.Config.Name, From: FromNode}
	}
	f.Network = Field[*nodecfg.Network]{From: FromUnknown}
	switch {
	case c.Network != nil:
		n := *c.Network
		f.Network = Field[*nodecfg.Network]{Value: &n, From: FromConfig}
	case st != nil && configs.RunningNetwork(*st) != nil:
		f.Network = Field[*nodecfg.Network]{Value: configs.RunningNetwork(*st), From: FromNode}
	}
	f.Forwarders = Field[[]string]{From: FromUnknown}
	if c.Forwarders != nil {
		f.Forwarders = Field[[]string]{Value: slices.Clone(*c.Forwarders), From: FromConfig}
	}
	f.TZ = Field[TimeZone]{From: FromUnknown}
	if c.Time != nil && c.Time.TZ != "" {
		f.TZ = Field[TimeZone]{Value: TimeZone{TZ: c.Time.TZ, Name: ZoneName(c.Time.TZ)}, From: FromConfig}
	}
	// Blocking and the query log are on unless the config says off (nodecfg).
	f.Blocking = Field[bool]{Value: true, From: FromDefault}
	switch {
	case c.Blocking != nil && c.Blocking.Enabled != nil:
		f.Blocking = Field[bool]{Value: *c.Blocking.Enabled, From: FromConfig}
	case st != nil && st.Services != nil:
		i := slices.IndexFunc(st.Services, func(s release.ServiceStatus) bool { return s.Name == "blocking" })
		f.Blocking = Field[bool]{Value: i >= 0 && st.Services[i].State != "off", From: FromNode}
	}
	f.QueryLog = Field[QueryLog]{Value: QueryLog{Enabled: true, Client: "full"}, From: FromDefault}
	if st != nil && st.QueryLog != nil {
		f.QueryLog = Field[QueryLog]{Value: QueryLog{Enabled: st.QueryLog.Enabled, Client: st.QueryLog.Client}, From: FromNode}
		if f.QueryLog.Value.Client == "" {
			f.QueryLog.Value.Client = "full"
		}
	}
	if q := c.QueryLog; q != nil {
		f.QueryLog.From = FromConfig
		if q.Enabled != nil {
			f.QueryLog.Value.Enabled = *q.Enabled
		}
		if q.Client != "" {
			f.QueryLog.Value.Client = q.Client
		}
	}
	f.Name.Applies, f.Network.Applies, f.Forwarders.Applies = Applies["name"], Applies["network"], Applies["forwarders"]
	f.TZ.Applies, f.Blocking.Applies, f.QueryLog.Applies = Applies["tz"], Applies["blocking"], Applies["querylog"]
	return f
}

// QueryLogEdit changes the query log: either part, or both.
type QueryLogEdit struct {
	Enabled *bool   `json:"enabled,omitempty"`
	Client  *string `json:"client,omitempty"`
}

// Edit is a change of the form: the fields it gives are set, the fields in Reset go back to
// the board's or the firmware's value; the rest stay as they are.
type Edit struct {
	Name       *string          `json:"name,omitempty"`
	Network    *nodecfg.Network `json:"network,omitempty"`
	Forwarders *[]string        `json:"forwarders,omitempty"`
	TZ         *string          `json:"tz,omitempty"` // a POSIX TZ string, or a name from TimeZones
	Blocking   *bool            `json:"blocking,omitempty"`
	QueryLog   *QueryLogEdit    `json:"querylog,omitempty"`
	Reset      []string         `json:"reset,omitempty"`
}

// FieldError is an edit refused, with the form field it is about.
type FieldError struct {
	Field string
	Err   error
}

func (e *FieldError) Error() string { return e.Err.Error() }
func (e *FieldError) Unwrap() error { return e.Err }

func fieldErr(field string, err error) error { return &FieldError{Field: field, Err: err} }

// Clone is a deep copy of a config.
func Clone(c *nodecfg.Config) *nodecfg.Config {
	out := &nodecfg.Config{}
	if c == nil {
		return out
	}
	b, err := json.Marshal(c)
	if err != nil {
		panic(err) // a Config always marshals
	}
	if err := json.Unmarshal(b, out); err != nil {
		panic(err)
	}
	return out
}

// set is whether the edit gives the field.
func (e Edit) set(field string) bool {
	switch field {
	case "name":
		return e.Name != nil
	case "network":
		return e.Network != nil
	case "forwarders":
		return e.Forwarders != nil
	case "tz":
		return e.TZ != nil
	case "blocking":
		return e.Blocking != nil
	case "querylog":
		return e.QueryLog != nil
	}
	return false
}

// Apply makes the config the edit gives from base (nil: an empty one): base is left as it
// is. Each field is checked as the node checks it (nodecfg.Validate); a refusal is a
// *FieldError naming the field. An edit that gives nothing is refused.
func Apply(base *nodecfg.Config, e Edit) (*nodecfg.Config, error) {
	c := Clone(base)
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("the config edited doesn't pass the node's checks: %w", err)
	}
	some := len(e.Reset) > 0
	for _, f := range e.Reset {
		if !slices.Contains(Fields, f) {
			return nil, fieldErr(f, fmt.Errorf("reset: no field %q (%s)", f, strings.Join(Fields, ", ")))
		}
		if e.set(f) {
			return nil, fieldErr(f, fmt.Errorf("%s: both set and reset", f))
		}
	}
	for _, f := range Fields {
		if !e.set(f) && !slices.Contains(e.Reset, f) {
			continue
		}
		some = true
		if err := e.apply(c, f, slices.Contains(e.Reset, f)); err != nil {
			return nil, fieldErr(f, err)
		}
		if err := c.Validate(); err != nil {
			return nil, fieldErr(f, err)
		}
	}
	if !some {
		return nil, errors.New("the edit changes nothing: give a field, or one in \"reset\"")
	}
	if _, err := c.Payload(); err != nil {
		return nil, err
	}
	return c, nil
}

// apply sets (or resets) one field of c.
func (e Edit) apply(c *nodecfg.Config, field string, reset bool) error {
	switch field {
	case "name":
		if reset {
			c.Name = ""
			return nil
		}
		n := strings.TrimSpace(*e.Name)
		if n == "" {
			return errors.New(`name: give one, or reset it to the board's`)
		}
		c.Name = n
	case "network":
		if reset {
			c.Network = nil
			return nil
		}
		n := nodecfg.Network{Address: strings.TrimSpace(e.Network.Address), Gateway: strings.TrimSpace(e.Network.Gateway)}
		if err := n.Check(); err != nil {
			return err
		}
		c.Network = &n
	case "forwarders":
		if reset {
			c.Forwarders = nil
			return nil
		}
		fs := []string{}
		for _, f := range *e.Forwarders {
			fs = append(fs, strings.TrimSpace(f))
		}
		c.Forwarders = &fs
	case "tz":
		if c.Time == nil {
			c.Time = &nodecfg.Time{}
		}
		if reset {
			c.Time.TZ = ""
		} else {
			tz, err := PosixTZ(*e.TZ)
			if err != nil {
				return err
			}
			c.Time.TZ = tz
		}
		if c.Time.TZ == "" && c.Time.NTP == nil {
			c.Time = nil
		}
	case "blocking":
		if c.Blocking == nil {
			c.Blocking = &nodecfg.Blocking{}
		}
		if reset {
			c.Blocking.Enabled = nil
		} else {
			on := *e.Blocking
			c.Blocking.Enabled = &on
		}
		if *c.Blocking == (nodecfg.Blocking{}) {
			c.Blocking = nil
		}
	case "querylog":
		if reset {
			c.QueryLog = nil
			return nil
		}
		if e.QueryLog.Enabled == nil && e.QueryLog.Client == nil {
			return errors.New(`querylog: give "enabled", "client" or both`)
		}
		if c.QueryLog == nil {
			c.QueryLog = &nodecfg.QueryLog{}
		}
		if e.QueryLog.Enabled != nil {
			on := *e.QueryLog.Enabled
			c.QueryLog.Enabled = &on
		}
		if e.QueryLog.Client != nil {
			c.QueryLog.Client = *e.QueryLog.Client
			if c.QueryLog.Client == "" {
				return errors.New(`querylog.client: "full", "subnet" or "hidden"`)
			}
		}
	}
	return nil
}

// Changed are the form's fields that differ between two configs, in the form's order.
func Changed(a, b *nodecfg.Config) []string {
	if a == nil {
		a = &nodecfg.Config{}
	}
	if b == nil {
		b = &nodecfg.Config{}
	}
	fa, fb := Read(a, nil), Read(b, nil)
	var out []string
	for _, f := range Fields {
		x, _ := json.Marshal(fieldOf(fa, f))
		y, _ := json.Marshal(fieldOf(fb, f))
		if string(x) != string(y) {
			out = append(out, f)
		}
	}
	return out
}

func fieldOf(f Form, name string) any {
	switch name {
	case "name":
		return f.Name
	case "network":
		return f.Network
	case "forwarders":
		return f.Forwarders
	case "tz":
		return f.TZ
	case "blocking":
		return f.Blocking
	case "querylog":
		return f.QueryLog
	}
	return nil
}

// Restart says, in a word, whether a change waits for a restart of the node: "no", "yes",
// or "maybe" (unless the board's or the firmware's value is the same; the node says).
func Restart(ch nodecfg.Change) string {
	switch {
	case len(ch.Reboot) > 0:
		return "yes"
	case len(ch.Maybe) > 0:
		return "maybe"
	}
	return "no"
}

// Effect says in words what a change does on the node called node.
func Effect(node string, ch nodecfg.Change) string {
	switch Restart(ch) {
	case "yes":
		return node + " restarts to take it, for a few seconds; the controller restarts it only while another node answers"
	case "maybe":
		return node + " may restart to take it, unless its board already has the same value; " +
			"the controller restarts it only while another node answers"
	}
	return "Applies live: DNS keeps answering"
}

// Summary is a change in words: "dns2: upstream DNS, time zone".
func Summary(node string, fields []string) string {
	var w []string
	for _, f := range fields {
		w = append(w, Words[f])
	}
	return node + ": " + strings.Join(w, ", ")
}
