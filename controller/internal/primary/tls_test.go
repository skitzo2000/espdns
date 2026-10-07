package primary

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/faketech"
)

const testToken = "0123456789abcdef-test-token"

// selfSigned is a certificate as a primary makes its own: self-signed, not a CA, naming
// dnsNames and ips, valid from notBefore for a year.
func selfSigned(t *testing.T, dnsNames []string, ips []net.IP, notBefore time.Time) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "primary"},
		NotBefore: notBefore, NotAfter: notBefore.Add(365 * 24 * time.Hour), DNSNames: dnsNames, IPAddresses: ips,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// fakePrimary is the fake Technitium over https with cert (httptest's own when nil), on
// loopback.
func fakePrimary(t *testing.T, cert *tls.Certificate) (*httptest.Server, *faketech.Server) {
	t.Helper()
	fake := faketech.New(testToken, "home.example")
	srv := httptest.NewUnstartedServer(fake)
	if cert != nil {
		srv.TLS = &tls.Config{Certificates: []tls.Certificate{*cert}}
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, fake
}

// A primary with its own (self-signed) certificate: not pinned, it is refused with the
// fingerprint it presents and nothing is sent; pinned, it is reached, whatever name its
// certificate carries (here one that doesn't name the address it is reached at).
func TestPinSelfSigned(t *testing.T) {
	cert := selfSigned(t, []string{"primary.example"}, nil, time.Now().Add(-time.Hour))
	srv, fake := fakePrimary(t, &cert)
	fp := Fingerprint(cert.Leaf)

	p, err := Open(Config{Kind: KindTechnitium, URL: srv.URL}, testToken, Options{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.Lists(context.Background(), "home.example")
	var ce *CertError
	if !errors.As(err, &ce) || ce.Presented != fp || ce.Pinned != "" || !strings.Contains(err.Error(), "doesn't trust") ||
		!strings.Contains(err.Error(), fp) || !strings.Contains(err.Error(), "pin it") || strings.Contains(err.Error(), testToken) {
		t.Fatalf("unpinned: %v", err)
	}
	if len(fake.Calls()) != 0 {
		t.Fatal("sent to an unverified primary:", fake.Calls())
	}

	p, _ = Open(Config{Kind: KindTechnitium, URL: srv.URL, CertSHA256: fp}, testToken, Options{})
	for i := 0; i < 2; i++ { // the second over the certificate learnt
		if l, err := p.Lists(context.Background(), "home.example"); err != nil || l.Zone != "home.example" {
			t.Fatalf("pinned: %+v %v", l, err)
		}
	}
	if err := p.Allow(context.Background(), "home.example", "192.0.2.60"); err != nil {
		t.Fatal(err)
	}
}

// A primary that presents another certificate than the one pinned is refused, with both
// fingerprints and what to do, before anything is sent: at the first connection, and after
// a certificate seen before was changed.
func TestPinChangedRefused(t *testing.T) {
	old := selfSigned(t, nil, []net.IP{net.IPv4(127, 0, 0, 1)}, time.Now().Add(-time.Hour))
	cur := selfSigned(t, nil, []net.IP{net.IPv4(127, 0, 0, 1)}, time.Now().Add(-time.Hour))
	srv, fake := fakePrimary(t, &cur)
	p, _ := Open(Config{Kind: KindTechnitium, URL: srv.URL, CertSHA256: Fingerprint(old.Leaf)}, testToken, Options{})
	_, err := p.Lists(context.Background(), "home.example")
	var ce *CertError
	if !errors.As(err, &ce) || ce.Pinned != Fingerprint(old.Leaf) || ce.Presented != Fingerprint(cur.Leaf) ||
		!strings.Contains(err.Error(), "other than the one pinned") || !strings.Contains(err.Error(), "pin it again") {
		t.Fatalf("%v", err)
	}
	if len(fake.Calls()) != 0 {
		t.Fatal("sent:", fake.Calls())
	}

	// Pinned and reached, then the primary's certificate changes under it
	srv2, fake2 := fakePrimary(t, &old)
	p, _ = Open(Config{Kind: KindTechnitium, URL: srv2.URL, CertSHA256: Fingerprint(old.Leaf)}, testToken, Options{})
	if _, err := p.Lists(context.Background(), "home.example"); err != nil {
		t.Fatal(err)
	}
	n := len(fake2.Calls())
	srv2.TLS.Certificates = []tls.Certificate{cur}
	srv2.CloseClientConnections()
	_, err = p.Lists(context.Background(), "home.example")
	if !errors.As(err, &ce) || ce.Presented != Fingerprint(cur.Leaf) {
		t.Fatalf("after the change: %v", err)
	}
	if len(fake2.Calls()) != n {
		t.Fatal("sent after the change:", fake2.Calls())
	}
}

// A certificate the system's roots verify needs no pin; pinned, it must still be the one
// pinned.
func TestTrustedCertificate(t *testing.T) {
	srv, _ := fakePrimary(t, nil) // httptest's certificate, for 127.0.0.1
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	systemRoots = roots
	t.Cleanup(func() { systemRoots = nil })
	p, _ := Open(Config{Kind: KindTechnitium, URL: srv.URL}, testToken, Options{})
	if _, err := p.Lists(context.Background(), "home.example"); err != nil {
		t.Fatal(err)
	}
	p, _ = Open(Config{Kind: KindTechnitium, URL: srv.URL, CertSHA256: Fingerprint(srv.Certificate())}, testToken, Options{})
	if _, err := p.Lists(context.Background(), "home.example"); err != nil {
		t.Fatal(err)
	}
	other := strings.Repeat("0", 64)
	p, _ = Open(Config{Kind: KindTechnitium, URL: srv.URL, CertSHA256: other}, testToken, Options{})
	var ce *CertError
	if _, err := p.Lists(context.Background(), "home.example"); !errors.As(err, &ce) || ce.Pinned != other {
		t.Fatal(err)
	}
	info, err := Presented(context.Background(), srv.URL)
	if err != nil || !info.Trusted || info.SHA256 != Fingerprint(srv.Certificate()) {
		t.Fatal(info, err)
	}
}

// A pinned certificate that has expired is refused, saying so.
func TestPinExpired(t *testing.T) {
	cert := selfSigned(t, []string{"primary.example"}, nil, time.Now().Add(-2*365*24*time.Hour))
	srv, fake := fakePrimary(t, &cert)
	p, _ := Open(Config{Kind: KindTechnitium, URL: srv.URL, CertSHA256: Fingerprint(cert.Leaf)}, testToken, Options{})
	if _, err := p.Lists(context.Background(), "home.example"); err == nil || !strings.Contains(err.Error(), "doesn't verify") ||
		!strings.Contains(err.Error(), "expired") {
		t.Fatal(err)
	}
	if len(fake.Calls()) != 0 {
		t.Fatal("sent:", fake.Calls())
	}
}

// Presented reads the certificate a primary presents in the handshake alone (no request):
// its fingerprint, names and dates, not trusted and why.
func TestPresented(t *testing.T) {
	cert := selfSigned(t, []string{"primary.example"}, []net.IP{net.IPv4(192, 0, 2, 254)}, time.Now().Add(-time.Hour))
	srv, fake := fakePrimary(t, &cert)
	info, err := Presented(context.Background(), srv.URL)
	if err != nil || info.SHA256 != Fingerprint(cert.Leaf) || info.Trusted || info.Untrusted == "" ||
		strings.Join(info.Names, ",") != "primary.example,192.0.2.254" || info.Subject != "CN=primary" || info.NotAfter.IsZero() {
		t.Fatalf("%+v %v", info, err)
	}
	if len(fake.Calls()) != 0 {
		t.Fatal("a request was sent:", fake.Calls())
	}
	if _, err := Presented(context.Background(), "http://192.0.2.254:5380"); err == nil {
		t.Fatal("plain http read")
	}
}

// Fingerprints as people copy them; the pin only in its own form.
func TestParseFingerprint(t *testing.T) {
	want := strings.Repeat("ab", 32)
	for _, in := range []string{want, strings.ToUpper(want), strings.TrimSuffix(strings.Repeat("AB:", 32), ":"), " " + want + " "} {
		if got, err := ParseFingerprint(in); err != nil || got != want {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
	for _, in := range []string{"", "ab", strings.Repeat("zz", 32), strings.Repeat("ab", 33)} {
		if _, err := ParseFingerprint(in); err == nil {
			t.Errorf("%q taken", in)
		}
	}
	if checkPin(want) != nil || checkPin(strings.ToUpper(want)) == nil {
		t.Fatal("the pin's form")
	}
}

// nameIn: the address itself when the certificate names it, else a name it carries.
func TestNameIn(t *testing.T) {
	c := selfSigned(t, []string{"*.example"}, nil, time.Now()).Leaf
	if n := nameIn(c, "127.0.0.1"); n != "pinned.example" {
		t.Fatal(n)
	}
	c = selfSigned(t, nil, []net.IP{net.IPv4(192, 0, 2, 1)}, time.Now()).Leaf
	if n := nameIn(c, "192.0.2.1"); n != "192.0.2.1" {
		t.Fatal(n)
	}
	if n := nameIn(c, "127.0.0.1"); n != "192.0.2.1" {
		t.Fatal(n)
	}
	if n := nameIn(selfSigned(t, nil, nil, time.Now()).Leaf, "127.0.0.1"); n != "" {
		t.Fatal(n)
	}
}
