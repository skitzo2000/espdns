package blocklist

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// names writes a domains list of n names (ads<i>.example.com) and returns its path.
func names(t *testing.T, dir, file string, n int) string {
	t.Helper()
	var b strings.Builder
	for i := range n {
		fmt.Fprintf(&b, "ads%d.example.com\n", i)
	}
	p := filepath.Join(dir, file)
	if err := os.WriteFile(p, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func domains(path string) Source { return Source{Kind: Domains, Path: path} }

func TestRunSizeChange(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "list.bin")
	big := names(t, dir, "big.txt", 1000)
	run := func(src string, accept bool) (*Result, error) {
		return Run(context.Background(), Request{Sources: []Source{domains(src)}, XorBits: 10, Out: out, AcceptChange: accept})
	}

	// No previous build: any size
	r, err := run(big, false)
	if err != nil || !r.Written || r.Change.Previous != "" || r.Change.New.Blocked != 1000 {
		t.Fatalf("first build: %+v, %v", r, err)
	}
	first, _ := os.ReadFile(out)

	// The same again: within the limits
	r, err = run(big, false)
	if err != nil || !r.Written || r.Change.Previous != out || r.Change.Old.Blocked != 1000 || len(r.Change.Over) != 0 {
		t.Fatalf("same build: %+v, %v", r.Change, err)
	}
	first, _ = os.ReadFile(out)

	// Down to 600 (-40%): refused, the file left as it was
	small := names(t, dir, "small.txt", 600)
	r, err = run(small, false)
	var sce *SizeChangeError
	if !errors.As(err, &sce) || !r.Change.Refused || r.Written {
		t.Fatalf("40%% smaller: %+v, %v", r.Change, err)
	}
	for _, want := range []string{"blocked 1000 → 600 (-40.0%)", "20%", out, "-accept-change"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q doesn't say %q", err, want)
		}
	}
	if now, _ := os.ReadFile(out); !bytes.Equal(now, first) {
		t.Error("a refused build replaced the file")
	}

	// Accepted once
	r, err = run(small, true)
	if err != nil || !r.Written || !r.Change.Accepted || r.Change.New.Blocked != 600 {
		t.Fatalf("accepted: %+v, %v", r.Change, err)
	}
	// and then the new size is the one compared with
	if r, err = run(small, false); err != nil || len(r.Change.Over) != 0 {
		t.Fatalf("after accepting: %+v, %v", r.Change, err)
	}

	// 15% up (90 entries): within the default 20%; over -max-change 10 with a floor of 50
	more := names(t, dir, "more.txt", 690)
	if r, err = Run(context.Background(), Request{Sources: []Source{domains(more)}, XorBits: 10, Out: out, MaxChange: ptr(10.0), MinChange: ptr(50)}); !errors.As(err, &sce) {
		t.Fatalf("15%% with a 10%% limit: %+v, %v", r.Change, err)
	}
	if r, err = run(more, false); err != nil {
		t.Fatalf("15%% with the default: %+v, %v", r.Change, err)
	}
}

// A change of MinChange entries or fewer is taken whatever its percentage (an overrides
// file of a few names), unless the floor is off.
func TestRunMinChange(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "overrides.bin")
	req := Request{Sources: []Source{domains(names(t, dir, "a.txt", 5))}, Out: out}
	if _, err := Run(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	req.Sources = []Source{domains(names(t, dir, "b.txt", 9))}
	if r, err := Run(context.Background(), req); err != nil || len(r.Change.Over) != 0 {
		t.Fatalf("5 → 9 entries: %+v, %v", r.Change, err)
	}
	req.Sources, req.MinChange = []Source{domains(names(t, dir, "c.txt", 3))}, ptr(0)
	var sce *SizeChangeError
	if _, err := Run(context.Background(), req); !errors.As(err, &sce) {
		t.Fatalf("9 → 3 with no floor: %v", err)
	}
}

// Another build to compare with (-previous); one that isn't a list is not replaced unless
// accepted; no Out writes nothing.
func TestRunPrevious(t *testing.T) {
	dir := t.TempDir()
	prev := filepath.Join(dir, "prev.bin")
	big, small := names(t, dir, "big.txt", 1000), names(t, dir, "small.txt", 500)
	if _, err := Run(context.Background(), Request{Sources: []Source{domains(big)}, Out: prev}); err != nil {
		t.Fatal(err)
	}
	r, err := Run(context.Background(), Request{Sources: []Source{domains(small)}, Previous: prev})
	var sce *SizeChangeError
	if !errors.As(err, &sce) || r.Change.Previous != prev || r.Written {
		t.Fatalf("against -previous: %+v, %v", r.Change, err)
	}
	if r, err = Run(context.Background(), Request{Sources: []Source{domains(small)}}); err != nil || r.Written {
		t.Fatalf("no Out: %+v, %v", r, err)
	}

	junk := filepath.Join(dir, "junk.bin")
	os.WriteFile(junk, []byte("not a list"), 0o644)
	if _, err := Run(context.Background(), Request{Sources: []Source{domains(small)}, Out: junk}); err == nil ||
		!strings.Contains(err.Error(), "not a blocklist file") {
		t.Fatalf("over a file that isn't a list: %v", err)
	}
	if b, _ := os.ReadFile(junk); string(b) != "not a list" {
		t.Fatal("replaced a file that isn't a list")
	}
	if r, err := Run(context.Background(), Request{Sources: []Source{domains(small)}, Out: junk, AcceptChange: true}); err != nil || !r.Written {
		t.Fatalf("accepted over it: %+v, %v", r, err)
	}
}

// Bytes are compared only between builds of the same widths.
func TestCheckSizeBytes(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "list.bin")
	src := domains(names(t, dir, "l.txt", 1000))
	if _, err := Run(context.Background(), Request{Sources: []Source{src}, XorBits: 10, Out: out}); err != nil {
		t.Fatal(err)
	}
	// Without the xor filter the file is much smaller, but the entries are the same
	if r, err := Run(context.Background(), Request{Sources: []Source{src}, Out: out}); err != nil || len(r.Change.Over) != 0 {
		t.Fatalf("xor 10 → 0: %+v, %v", r.Change, err)
	}
	old := Size{Blocked: 1000, Bytes: 4000, Bits: 44}
	b := make([]byte, FileHeader)
	copy(b, FileMagic)
	b[8], b[9] = FileVersion, 44
	b[32] = 0xe8 // 1000 hashes in the exact table
	b[33] = 0x03
	b = append(b, make([]byte, old.Bytes-FileHeader)...)
	p := filepath.Join(dir, "old.bin")
	os.WriteFile(p, b, 0o644)
	sc, err := CheckSize(p, Size{Blocked: 1150, Bytes: 6000, Bits: 44}, DefaultMaxChange, DefaultMinChange, false)
	if err != nil || !sc.Refused || len(sc.Over) != 1 || !strings.HasPrefix(sc.Over[0], "bytes 4000 → 6000 (+50.0%)") {
		t.Fatalf("bytes +50%%: %+v, %v", sc, err)
	}
}

func TestRunSources(t *testing.T) {
	feed, err := os.ReadFile("testdata/feed.rpz")
	if err != nil {
		t.Fatal(err)
	}
	srv, fetch := serveTLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/feed.rpz" {
			http.NotFound(w, r)
			return
		}
		w.Write(feed)
	}))
	dir := t.TempDir()
	allow := filepath.Join(dir, "allow.txt")
	os.WriteFile(allow, []byte("tracker.example.net\n"), 0o644)

	req := Request{Fetch: fetch}
	for _, spec := range []string{"rpz:" + srv.URL + "/feed.rpz"} {
		s, err := ParseSource(spec, false)
		if err != nil {
			t.Fatal(err)
		}
		req.Sources = append(req.Sources, s)
	}
	s, _ := ParseSource("domains:"+allow, true)
	req.Sources = append(req.Sources, s)
	r, err := Run(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Sources) != 2 || r.Sources[0].Source != "rpz:"+srv.URL+"/feed.rpz" || r.Sources[0].RPZ == nil ||
		r.Sources[0].RPZ.LocalData != 4 || r.Sources[0].Entries != 8 || !r.Sources[1].Allow {
		t.Fatalf("sources: %+v", r.Sources)
	}
	// tracker.example.net: blocked by the feed, allowed by the allowlist (overruled)
	if r.Compile.Overruled != 1 || r.AllowedExact != 2 || r.AllowedSuffix != 1 {
		t.Errorf("compile: %+v, allowed %d exact %d suffix", r.Compile, r.AllowedExact, r.AllowedSuffix)
	}

	if _, err := ParseSource("rpz", false); err == nil {
		t.Error("a spec without a path taken")
	}
	if _, err := ParseSource("zone:x.txt", false); err == nil {
		t.Error("an unknown kind taken")
	}
	missing, _ := ParseSource("rpz:"+srv.URL+"/none.rpz", false)
	if _, err := Run(context.Background(), Request{Sources: []Source{missing}, Fetch: fetch}); err == nil || !strings.Contains(err.Error(), "404") {
		t.Errorf("a 404: %v", err)
	}
}

// A source fetched is cut at maxFetch and refused; a redirect to a file is not followed;
// a cancelled context stops the fetch.
func TestRunFetchLimits(t *testing.T) {
	body := strings.Repeat("ads.example.com\n", 1<<16) // 1 MiB
	srv, fetch := serveTLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/file":
			http.Redirect(w, r, "file:///etc/passwd", http.StatusFound)
		default:
			w.Write([]byte(body))
		}
	}))
	old := maxFetch
	defer func() { maxFetch = old }()

	maxFetch = 1 << 20
	if _, err := Run(context.Background(), Request{Sources: []Source{domains(srv.URL + "/list")}, Fetch: fetch}); err != nil {
		t.Fatalf("exactly the limit: %v", err)
	}
	maxFetch = 1<<20 - 1
	if _, err := Run(context.Background(), Request{Sources: []Source{domains(srv.URL + "/list")}, Fetch: fetch}); err == nil ||
		!strings.Contains(err.Error(), "more than") {
		t.Fatalf("over the limit: %v", err)
	}
	maxFetch = old
	if _, err := Run(context.Background(), Request{Sources: []Source{domains(srv.URL + "/file")}, Fetch: fetch}); err == nil {
		t.Fatal("followed a redirect to a file")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Run(ctx, Request{Sources: []Source{domains(srv.URL + "/list")}, Fetch: fetch}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled: %v", err)
	}
	// Stopped while it read local files or built (neither looks): nothing written.
	dir := t.TempDir()
	out := filepath.Join(dir, "list.bin")
	res, err := Run(ctx, Request{Sources: []Source{domains(names(t, dir, "a.txt", 10))}, Out: out})
	if !errors.Is(err, context.Canceled) || res.Written {
		t.Fatalf("cancelled before the write: %v", err)
	}
	if _, err := os.Stat(out); err == nil {
		t.Fatal("written though cancelled")
	}
}

// A previous build named and not there is an error, not a first build; a NaN limit is no
// limit and is refused.
func TestRunPreviousMissing(t *testing.T) {
	dir := t.TempDir()
	src := domains(names(t, dir, "l.txt", 10))
	out := filepath.Join(dir, "list.bin")
	r, err := Run(context.Background(), Request{Sources: []Source{src}, Out: out, Previous: filepath.Join(dir, "typo.bin")})
	if err == nil || !errors.Is(err, os.ErrNotExist) || r.Written {
		t.Fatalf("missing -previous: %+v, %v", r, err)
	}
	if _, err := os.Stat(out); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("wrote the list with the previous build missing")
	}
	for _, l := range []struct {
		mx float64
		mn int
	}{{math.NaN(), 0}, {-1, 0}, {math.Inf(1), 0}, {20, -1}} {
		if _, err := CheckSize("", Size{}, l.mx, l.mn, false); err == nil {
			t.Errorf("limits %v%%, %d taken", l.mx, l.mn)
		}
	}
	if _, err := Run(context.Background(), Request{Sources: []Source{src}, MinChange: ptr(-1)}); err == nil ||
		!strings.Contains(err.Error(), "floor") {
		t.Errorf("a negative floor: %v", err)
	}
}

// A limit of 0 refuses any change; an unset limit is the default (20%, a floor of 100).
func TestRunZeroLimits(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "list.bin")
	a, b := names(t, dir, "a.txt", 1000), names(t, dir, "b.txt", 1001)
	run := func(src string, mx *float64, mn *int) error {
		_, err := Run(context.Background(), Request{Sources: []Source{domains(src)}, Out: out, MaxChange: mx, MinChange: mn})
		return err
	}
	if err := run(a, nil, nil); err != nil {
		t.Fatal(err)
	}
	if mx, mn := Limits(nil, nil); mx != DefaultMaxChange || mn != DefaultMinChange {
		t.Errorf("unset limits: %v%%, %d", mx, mn)
	}
	var sce *SizeChangeError
	if err := run(b, ptr(0.0), ptr(0)); !errors.As(err, &sce) {
		t.Fatalf("one entry more with both limits 0: %v", err)
	}
	if err := run(a, ptr(0.0), ptr(0)); err != nil {
		t.Fatalf("the same build with both limits 0: %v", err)
	}
	// max 0 alone refuses any change too: the floor (default or given) doesn't apply
	for _, mn := range []*int{nil, ptr(500)} {
		if err := run(b, ptr(0.0), mn); !errors.As(err, &sce) || sce.Change.MinChange != 0 {
			t.Fatalf("one entry more with max 0, floor %v: %v", mn, err)
		}
	}
	// unset: the defaults take one entry (0.1%) either way
	if err := run(b, nil, nil); err != nil {
		t.Fatalf("one entry more with the defaults: %v", err)
	}
	if err := run(a, nil, nil); err != nil {
		t.Fatalf("one entry less with the defaults: %v", err)
	}
}

func ptr[T any](v T) *T { return &v }

// A Request's sources travel as JSON (a page's form) with their kind by name.
func TestSourceJSON(t *testing.T) {
	b, err := json.Marshal(Source{Kind: RPZ, Path: "https://feeds.example/rpz.zone", Allow: true})
	if err != nil || string(b) != `{"kind":"rpz","path":"https://feeds.example/rpz.zone","allow":true}` {
		t.Fatalf("marshal: %s, %v", b, err)
	}
	var s Source
	if err := json.Unmarshal(b, &s); err != nil || s.Kind != RPZ || !s.Allow {
		t.Fatalf("unmarshal: %+v, %v", s, err)
	}
	if err := json.Unmarshal([]byte(`{"kind":"zone","path":"x"}`), &s); err == nil {
		t.Fatal("an unknown kind taken")
	}
}

// serveTLS is an https test server on loopback, and the Fetch that trusts its certificate
// and lets a fetch connect to it (and only it) although it isn't a public address.
func serveTLS(t *testing.T, h http.Handler) (*httptest.Server, *Fetch) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	return srv, &Fetch{TLS: srv.Client().Transport.(*http.Transport).TLSClientConfig,
		Allow: []netip.AddrPort{netip.MustParseAddrPort(srv.Listener.Addr().String())}}
}

// A source URL is https: plain http, its host not on the internal allowlist, is refused as
// it is fetched, before anything is sent, saying how to allow a server inside; a redirect
// to anything but https is refused (naming only the target's host: its query may hold a
// key). https to https is followed.
func TestRunHTTPSOnly(t *testing.T) {
	for _, spec := range []string{"domains:http://lists.example/l.txt?key=secret", "domains:https://lists.example/l.txt"} {
		if _, err := ParseSource(spec, false); err != nil {
			t.Errorf("%s: %v", spec, err)
		}
	}
	asked := false
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { asked = true }))
	defer plain.Close()
	for _, internal := range [][]string{nil, {"localhost"}, {"192.0.2.1"}} {
		if _, err := Run(context.Background(), Request{Sources: []Source{domains(plain.URL + "/l.txt")}, Internal: internal}); err == nil ||
			!strings.Contains(err.Error(), "plain http is refused") || !strings.Contains(err.Error(), "internal_sources") || asked {
			t.Errorf("plain http fetched (internal %v): %v (asked %v)", internal, err, asked)
		}
	}

	list := []byte("ads.example.com\n")
	var tlsURL string
	srv, fetch := serveTLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/down":
			http.Redirect(w, r, plain.URL+"/list?key=secret", http.StatusFound)
		case "/hop":
			http.Redirect(w, r, tlsURL+"/down", http.StatusMovedPermanently)
		case "/up":
			http.Redirect(w, r, tlsURL+"/list", http.StatusFound)
		case "/loop":
			http.Redirect(w, r, tlsURL+"/loop", http.StatusFound)
		default:
			w.Write(list)
		}
	}))
	tlsURL = srv.URL
	run := func(u string) error {
		_, err := Run(context.Background(), Request{Sources: []Source{domains(u)}, Fetch: fetch})
		return err
	}
	if err := run(srv.URL + "/up"); err != nil {
		t.Errorf("https to https: %v", err)
	}
	for _, u := range []string{srv.URL + "/down", srv.URL + "/hop"} {
		err := run(u)
		if err == nil || !strings.Contains(err.Error(), "refused a redirect to http://") || !strings.Contains(err.Error(), "https only") || asked {
			t.Errorf("%s: %v", u, err)
		} else if strings.Contains(err.Error(), "secret") {
			t.Errorf("the refusal names the target's query: %v", err)
		}
	}
	if err := run(srv.URL + "/loop"); err == nil || !strings.Contains(err.Error(), "redirects") {
		t.Errorf("a redirect loop: %v", err)
	}
}

// A fetch connects to public addresses only, each checked as it is connected to: a source
// on loopback is refused (by name too: the address it resolves to is checked, not the
// name), and a redirect from an allowed server to another inside address is refused.
func TestRunPublicOnly(t *testing.T) {
	list := []byte("ads.example.com\n")
	other, _ := serveTLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(list) }))
	srv, fetch := serveTLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/inside" {
			http.Redirect(w, r, other.URL+"/list", http.StatusFound)
			return
		}
		w.Write(list)
	}))
	run := func(u string, f *Fetch) error {
		_, err := Run(context.Background(), Request{Sources: []Source{domains(u)}, Fetch: f})
		return err
	}
	if err := run(srv.URL+"/list", fetch); err != nil {
		t.Fatalf("the allowed server: %v", err)
	}
	// Trusted but not allowed: refused for its address alone.
	trustOnly := &Fetch{TLS: fetch.TLS}
	_, port, _ := strings.Cut(strings.TrimPrefix(srv.URL, "https://"), ":")
	for _, u := range []string{srv.URL + "/list", "https://localhost:" + port + "/list"} {
		if err := run(u, trustOnly); err == nil || !strings.Contains(err.Error(), "not a public address") {
			t.Errorf("%s: %v", u, err)
		}
	}
	if err := run(srv.URL+"/inside", fetch); err == nil || !strings.Contains(err.Error(), "not a public address") {
		t.Errorf("a redirect to another inside address: %v", err)
	}
}

// A list server inside, its host on the internal allowlist: fetched over plain http or
// https at its inside address, by its address or its name, and only from that host: a
// redirect to another host (inside or not) or down to plain http is refused, another name
// for the same address isn't allowed by it (as a name rebound to an inside address isn't),
// and a public source's redirect into the allowed host is refused.
func TestRunInternal(t *testing.T) {
	list := []byte("ads.example.com\n")
	asked := false
	var plainURL string
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { asked = true; w.Write(list) }))
	t.Cleanup(other.Close)
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/elsewhere": // the same address, by another name
			http.Redirect(w, r, strings.Replace(other.URL, "127.0.0.1", "localhost", 1)+"/list", http.StatusFound)
		case "/other": // another server, by the allowed address
			http.Redirect(w, r, other.URL+"/list", http.StatusFound)
		case "/self":
			http.Redirect(w, r, plainURL+"/list", http.StatusFound)
		default:
			w.Write(list)
		}
	}))
	t.Cleanup(plain.Close)
	plainURL = plain.URL
	_, port, _ := strings.Cut(strings.TrimPrefix(plain.URL, "http://"), ":")
	run := func(u string, internal []string, f *Fetch) error {
		_, err := Run(context.Background(), Request{Sources: []Source{domains(u)}, Internal: internal, Fetch: f})
		return err
	}
	for _, c := range []struct {
		url      string
		internal []string
	}{
		{plain.URL + "/list", []string{"127.0.0.1"}},
		{plain.URL + "/self", []string{"192.0.2.9", "127.0.0.1"}},
		{"http://localhost:" + port + "/list", []string{"LOCALHOST."}},
	} {
		if err := run(c.url, c.internal, nil); err != nil {
			t.Errorf("%s (internal %v): %v", c.url, c.internal, err)
		}
	}
	// The allowed host only: by another name it is any other source, refused at its inside
	// address (the address it resolves to is checked, as a name rebound to one is)
	tlsSrv, fetch := serveTLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/in" {
			http.Redirect(w, r, plainURL+"/list", http.StatusFound)
			return
		}
		if r.URL.Path == "/away" {
			http.Redirect(w, r, strings.Replace(plainURL, "127.0.0.1", "localhost", 1)+"/list", http.StatusFound)
			return
		}
		if r.URL.Path == "/down" {
			http.Redirect(w, r, plainURL+"/list", http.StatusFound)
			return
		}
		w.Write(list)
	}))
	_, tport, _ := strings.Cut(strings.TrimPrefix(tlsSrv.URL, "https://"), ":")
	trustOnly := &Fetch{TLS: fetch.TLS}
	if err := run("https://localhost:"+tport+"/list", []string{"127.0.0.1"}, trustOnly); err == nil ||
		!strings.Contains(err.Error(), "not a public address") || !strings.Contains(err.Error(), "internal_sources") {
		t.Errorf("another name for an allowed address: %v", err)
	}
	// https to the allowed host, at its inside address, without the test's own allowance
	if err := run(tlsSrv.URL+"/list", []string{"127.0.0.1"}, trustOnly); err != nil {
		t.Errorf("https inside: %v", err)
	}
	for _, c := range []struct{ path, want string }{
		{"/elsewhere", "its own host only"},
		{"/other", ""}, // same host (127.0.0.1), another port: still that host, allowed
	} {
		err := run(plain.URL+c.path, []string{"127.0.0.1"}, nil)
		if c.want == "" {
			if err != nil {
				t.Errorf("%s: %v", c.path, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", c.path, err)
		}
	}
	asked = false
	// To another host, allowed itself: refused; https down to plain http on the allowed host
	if err := run(tlsSrv.URL+"/away", []string{"localhost", "127.0.0.1"}, trustOnly); err == nil ||
		!strings.Contains(err.Error(), "own host only") {
		t.Errorf("a redirect to another allowed host: %v", err)
	}
	if err := run(tlsSrv.URL+"/down", []string{"127.0.0.1"}, trustOnly); err == nil ||
		!strings.Contains(err.Error(), "downgrade") {
		t.Errorf("a downgrade on the allowed host: %v", err)
	}
	// A public source (the test's allowance) redirected into the allowed host: refused
	if err := run(tlsSrv.URL+"/in", []string{"192.0.2.9"}, fetch); err == nil || !strings.Contains(err.Error(), "https only") {
		t.Errorf("a public source's redirect inside: %v", err)
	}
	if asked {
		t.Error("the other server was asked")
	}
}

// The internal allowlist's hosts: an address or a name, nothing else; the same host in any
// of its forms.
func TestInternalHosts(t *testing.T) {
	for h, ok := range map[string]bool{
		"lists.example": true, "LISTS.example.": true, "192.0.2.7": true, "2001:db8::7": true, "a-b.c": true, "x": true,
		"": false, "http://lists.example": false, "lists.example:8080": false, "*.example": false, "lists.example/l": false,
		"-a.example": false, "a..b": false, "[2001:db8::7]": false, "fe80::1%eth0": false, "lists example": false,
		strings.Repeat("a", 64) + ".example": false,
	} {
		if err := CheckHost(h); (err == nil) != ok {
			t.Errorf("%q: %v", h, err)
		}
	}
	for _, c := range []struct {
		a, b string
		same bool
	}{
		{"lists.example", "LISTS.EXAMPLE.", true}, {"192.0.2.7", "::ffff:192.0.2.7", true}, {"[2001:db8::7]", "2001:db8:0::7", true},
		{"lists.example", "other.example", false}, {"192.0.2.7", "192.0.2.8", false}, {"localhost", "127.0.0.1", false},
		{"", "", false},
	} {
		if SameHost(c.a, c.b) != c.same {
			t.Errorf("%s %s: same %v", c.a, c.b, !c.same)
		}
	}
	if !InternalHost("Lists.Example", []string{"192.0.2.1", "lists.example"}) || InternalHost("lists.example", nil) {
		t.Fatal("InternalHost")
	}
}

func TestPublicAddr(t *testing.T) {
	for a, public := range map[string]bool{
		"8.8.8.8": true, "1.1.1.1": true, "2606:4700::1111": true, "93.184.215.14": true,
		"127.0.0.1": false, "127.9.9.9": false, "::1": false, "0.0.0.0": false, "::": false,
		"fd00::1":         false,
		"169.254.169.254": false, "fe80::1": false, "224.0.0.251": false, "ff02::fb": false,
		"255.255.255.255": false, "240.0.0.1": false,
		"0.1.2.3": false, "198.18.0.1": false, "192.0.0.8": false, "fec0::1": false,
		"::ffff:127.0.0.1": false, "::ffff:8.8.8.8": true,
		"::127.0.0.1": false, "::ffff:0:a00:1": false, "64:ff9b:1::a00:1": false,
		"64:ff9b::7f00:1": false, "64:ff9b::a00:1": false, "64:ff9b::a9fe:a9fe": false, "64:ff9b::808:808": true,
		"2002:7f00:1::1": false, "2002:a00:1::1": false, "2002:808:808::1": true,
	} {
		err := publicAddr(netip.MustParseAddr(a))
		if (err == nil) != public {
			t.Errorf("%s: public %v, got %v", a, public, err)
		}
	}
	// The private (RFC 1918) and shared (RFC 6598) ranges' edges, built rather than written
	// as literals: CI refuses those in a test's text
	for _, a := range []netip.Addr{
		netip.AddrFrom4([4]byte{10, 1, 2, 3}), netip.AddrFrom16(netip.AddrFrom4([4]byte{10, 0, 0, 1}).As16()),
		netip.AddrFrom4([4]byte{172, 16, 0, 1}), netip.AddrFrom4([4]byte{172, 31, 255, 255}),
		netip.AddrFrom4([4]byte{192, 168, 1, 10}),
		netip.AddrFrom4([4]byte{100, 64, 0, 1}), netip.AddrFrom4([4]byte{100, 127, 255, 254}),
	} {
		if err := publicAddr(a); err == nil {
			t.Errorf("%s: public", a)
		}
	}
}

// The check is of size (the header's counts and the bytes): both limits 0 refuse any change
// in size, but a build of as many other names is the same size and taken.
func TestRunZeroLimitsSizeOnly(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "list.bin")
	a := names(t, dir, "a.txt", 1000)
	var b strings.Builder
	for i := range 1000 {
		fmt.Fprintf(&b, "other%d.example.net\n", i)
	}
	other := filepath.Join(dir, "other.txt")
	os.WriteFile(other, []byte(b.String()), 0o644)
	zero, none := 0.0, 0
	for _, src := range []string{a, other} {
		if _, err := Run(context.Background(), Request{Sources: []Source{domains(src)}, Out: out, MaxChange: &zero, MinChange: &none}); err != nil {
			t.Fatalf("%s: %v", src, err)
		}
	}
}
