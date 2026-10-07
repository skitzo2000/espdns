package fleet

// Observability (docs/design.md, Observability): a node's GET /metrics (Prometheus text,
// parsed here) and GET /querylog (its query log, read with a cursor). The CLI's espdns
// metrics and espdns querylog use these, and the controller's dashboard will.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/release"
)

// ErrNotSupported is a node whose firmware has no such endpoint (404): from before /metrics
// and the query log.
var ErrNotSupported = errors.New("not supported by the node's firmware (update it)")

// Most a /metrics or /querylog reply may be; a node's are far smaller.
const observeMax = 8 << 20

// fetch reads path from the node: its body, or ErrNotSupported for a 404.
func (c *Client) fetch(ctx context.Context, host, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+host+path, nil)
	if err != nil {
		return nil, err
	}
	hc := c.http()
	if c.HTTP == nil {
		// A long query log page from a small node takes longer than /status's 3 s.
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, observeMax))
	if err != nil {
		return nil, fmt.Errorf("%s%s: %w", host, path, err)
	}
	switch resp.StatusCode {
	case http.StatusOK:
		return body, nil
	case http.StatusNotFound:
		return nil, fmt.Errorf("%s%s: %w", host, path, ErrNotSupported)
	default:
		return nil, fmt.Errorf("%s%s: %s: %s", host, path, resp.Status, strings.TrimSpace(string(body)))
	}
}

// ---- /metrics ----

// Sample is one line of the exposition: a name, its labels and its value.
type Sample struct {
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels,omitempty"`
	Value  float64           `json:"value"`
}

// Family is a metric with its help, type (counter, gauge, histogram, untyped) and samples,
// a histogram's _bucket, _sum and _count among them.
type Family struct {
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	Help    string   `json:"help"`
	Samples []Sample `json:"samples"`
}

// Metrics is a node's /metrics: the text as it came, and parsed, in its order.
type Metrics struct {
	Text     string   `json:"-"`
	Families []Family `json:"families"`
}

// Metrics reads the node's /metrics. ErrNotSupported (errors.Is) for firmware from before it.
func (c *Client) Metrics(ctx context.Context, host string) (Metrics, error) {
	b, err := c.fetch(ctx, host, "/metrics")
	if err != nil {
		return Metrics{}, err
	}
	m, err := ParseMetrics(string(b))
	if err != nil {
		return m, fmt.Errorf("%s/metrics: %w", host, err)
	}
	return m, nil
}

// ParseMetrics reads the Prometheus text exposition format (0.0.4).
func ParseMetrics(text string) (Metrics, error) {
	m := Metrics{Text: text}
	index := map[string]int{} // family name: its index
	family := func(name string) *Family {
		if i, ok := index[name]; ok {
			return &m.Families[i]
		}
		index[name] = len(m.Families)
		m.Families = append(m.Families, Family{Name: name, Type: "untyped"})
		return &m.Families[len(m.Families)-1]
	}
	for n, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			f := strings.Fields(line)
			if len(f) >= 3 && (f[1] == "HELP" || f[1] == "TYPE") {
				fam := family(f[2])
				rest := strings.TrimPrefix(strings.TrimPrefix(line[1:], " "), f[1])
				rest = strings.TrimPrefix(strings.TrimPrefix(rest, " "), f[2])
				rest = strings.TrimPrefix(rest, " ")
				if f[1] == "HELP" {
					fam.Help = strings.NewReplacer(`\\`, `\`, `\n`, "\n").Replace(rest)
				} else {
					fam.Type = strings.TrimSpace(rest)
				}
			}
			continue
		}
		s, err := parseSample(line)
		if err != nil {
			return m, fmt.Errorf("line %d: %w", n+1, err)
		}
		name := s.Name
		for _, suffix := range []string{"_bucket", "_sum", "_count"} {
			base := strings.TrimSuffix(s.Name, suffix)
			if i, ok := index[base]; ok && base != s.Name &&
				(m.Families[i].Type == "histogram" || m.Families[i].Type == "summary") {
				name = base
			}
		}
		fam := family(name)
		fam.Samples = append(fam.Samples, s)
	}
	return m, nil
}

func parseSample(line string) (Sample, error) {
	s := Sample{}
	i := strings.IndexAny(line, "{ ")
	if i <= 0 {
		return s, fmt.Errorf("no value: %q", line)
	}
	s.Name = line[:i]
	rest := line[i:]
	if rest[0] == '{' {
		s.Labels = map[string]string{}
		rest = rest[1:]
		for {
			rest = strings.TrimLeft(rest, " ,")
			if strings.HasPrefix(rest, "}") {
				rest = rest[1:]
				break
			}
			eq := strings.Index(rest, "=\"")
			if eq <= 0 {
				return s, fmt.Errorf("bad labels: %q", line)
			}
			key := strings.TrimSpace(rest[:eq])
			rest = rest[eq+2:]
			var v strings.Builder
			closed := false
			for j := 0; j < len(rest); j++ {
				ch := rest[j]
				if ch == '\\' && j+1 < len(rest) {
					j++
					switch rest[j] {
					case 'n':
						v.WriteByte('\n')
					default:
						v.WriteByte(rest[j])
					}
					continue
				}
				if ch == '"' {
					rest = rest[j+1:]
					closed = true
					break
				}
				v.WriteByte(ch)
			}
			if !closed {
				return s, fmt.Errorf("unterminated label value: %q", line)
			}
			s.Labels[key] = v.String()
		}
	}
	f := strings.Fields(rest)
	if len(f) < 1 || len(f) > 2 {
		return s, fmt.Errorf("bad value: %q", line)
	}
	v, err := parseValue(f[0])
	if err != nil {
		return s, fmt.Errorf("bad value: %q", line)
	}
	s.Value = v
	return s, nil
}

func parseValue(s string) (float64, error) {
	switch s {
	case "+Inf", "Inf":
		return math.Inf(1), nil
	case "-Inf":
		return math.Inf(-1), nil
	case "NaN":
		return math.NaN(), nil
	}
	return strconv.ParseFloat(s, 64)
}

// Family is the family named, or nil.
func (m Metrics) Family(name string) *Family {
	for i := range m.Families {
		if m.Families[i].Name == name {
			return &m.Families[i]
		}
	}
	return nil
}

// match says whether s is named name and has every label in kv (pairs: key, value).
func match(s Sample, name string, kv []string) bool {
	if s.Name != name {
		return false
	}
	for i := 0; i+1 < len(kv); i += 2 {
		if s.Labels[kv[i]] != kv[i+1] {
			return false
		}
	}
	return true
}

// Value is the first sample named name with the labels kv (pairs: "result", "cache", ...).
func (m Metrics) Value(name string, kv ...string) (float64, bool) {
	for _, f := range m.Families {
		for _, s := range f.Samples {
			if match(s, name, kv) {
				return s.Value, true
			}
		}
	}
	return 0, false
}

// Sum adds every sample named name with the labels kv.
func (m Metrics) Sum(name string, kv ...string) float64 {
	t := 0.0
	for _, f := range m.Families {
		for _, s := range f.Samples {
			if match(s, name, kv) {
				t += s.Value
			}
		}
	}
	return t
}

// ByLabel is each sample named name with the labels kv, by the value of its label key.
func (m Metrics) ByLabel(name, key string, kv ...string) map[string]float64 {
	out := map[string]float64{}
	for _, f := range m.Families {
		for _, s := range f.Samples {
			if match(s, name, kv) {
				out[s.Labels[key]] += s.Value
			}
		}
	}
	return out
}

// Quantile estimates the q-quantile (0-1) of histogram name (its _bucket samples with the
// labels kv) as Prometheus' histogram_quantile does: linearly within the bucket it falls in.
// False with no observations.
func (m Metrics) Quantile(name string, q float64, kv ...string) (float64, bool) {
	type bucket struct{ le, n float64 }
	var bs []bucket
	for _, f := range m.Families {
		for _, s := range f.Samples {
			if match(s, name+"_bucket", kv) {
				le, err := parseValue(s.Labels["le"])
				if err == nil {
					bs = append(bs, bucket{le, s.Value})
				}
			}
		}
	}
	sort.Slice(bs, func(i, j int) bool { return bs[i].le < bs[j].le })
	if len(bs) == 0 || bs[len(bs)-1].n == 0 {
		return 0, false
	}
	rank := q * bs[len(bs)-1].n
	lo, below := 0.0, 0.0
	for _, b := range bs {
		if b.n >= rank {
			if math.IsInf(b.le, 1) {
				return lo, true // past the last bound: the last bound, as Prometheus says
			}
			if b.n == below {
				return b.le, true
			}
			return lo + (b.le-lo)*(rank-below)/(b.n-below), true
		}
		lo, below = b.le, b.n
	}
	return lo, true
}

// ---- /querylog ----

// QueryLog reads the node's query log after cursor (0: everything it holds), at most limit
// entries (0: the node's default, 100). ErrNotSupported for firmware from before it.
func (c *Client) QueryLog(ctx context.Context, host string, cursor uint64, limit int) (release.QueryLogPage, error) {
	var p release.QueryLogPage
	q := url.Values{"cursor": {strconv.FormatUint(cursor, 10)}}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(min(limit, release.QueryLogLimit)))
	}
	b, err := c.fetch(ctx, host, "/querylog?"+q.Encode())
	if err != nil {
		return p, err
	}
	if err := json.Unmarshal(b, &p); err != nil {
		return p, fmt.Errorf("%s/querylog: %w", host, err)
	}
	return p, nil
}

// QueryLogCursor is a reader's place in one node's query log: the boot it read in and the
// last seq it has. The zero value reads from the oldest entry held.
type QueryLogCursor struct {
	BootID string `json:"boot_id"`
	Seq    uint64 `json:"seq"`
}

// ReadQueryLog reads the page after cur and moves cur past it. restarted: the node booted
// since cur's page (its seqs started over), so this page is read from its oldest entry and
// what it logged before the boot is gone; the page's Lost and Reset say the rest.
func (c *Client) ReadQueryLog(ctx context.Context, host string, cur *QueryLogCursor, limit int) (p release.QueryLogPage, restarted bool, err error) {
	p, err = c.QueryLog(ctx, host, cur.Seq, limit)
	if err != nil {
		return p, false, err
	}
	if cur.BootID != "" && p.BootID != cur.BootID {
		restarted = true
		if p, err = c.QueryLog(ctx, host, 0, limit); err != nil {
			return p, true, err
		}
	}
	cur.BootID, cur.Seq = p.BootID, p.Next
	return p, restarted, nil
}
