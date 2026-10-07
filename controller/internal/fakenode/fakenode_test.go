package fakenode

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The fake node checks Host as the firmware does (firmware/main/httpguard.h): the
// controller addresses nodes by IP, which passes; a page rebound to the node's address
// (DNS rebinding) sends its own name, which is refused.
func TestHostCheck(t *testing.T) {
	n := New("espdns-0a0b0c", [6]byte{2, 0, 0, 0, 0, 1}, "esp32p4", "p4-ip101", nil)
	srv := httptest.NewServer(n)
	defer srv.Close()
	n.Addr = strings.TrimPrefix(srv.URL, "http://")
	host, _, _ := strings.Cut(n.Addr, ":")
	for _, c := range []struct {
		host string
		want int
	}{
		{"", http.StatusOK}, // the URL's own host:port, as the controller sends it
		{host, http.StatusOK},
		{host + ":80", http.StatusOK},
		{"espdns-0a0b0c.local", http.StatusOK},
		{"ESPDNS-0A0B0C.local.", http.StatusOK},
		{"evil.example", http.StatusMisdirectedRequest},
		{"evil.example:80", http.StatusMisdirectedRequest},
		{host + ".evil.example", http.StatusMisdirectedRequest},
		{"[::1]", http.StatusMisdirectedRequest},
	} {
		for _, path := range []string{"/status", "/health"} {
			req, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
			if c.host != "" {
				req.Host = c.host
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != c.want {
				t.Errorf("Host %q %s: %d, want %d", c.host, path, resp.StatusCode, c.want)
			}
		}
	}
	// Its configured name, once a config names it
	n.Do(func(n *Node) { n.cfg.Name = "dns-a.example.com" })
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/status", nil)
	req.Host = "dns-a.example.com"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("configured name: %d", resp.StatusCode)
	}
}
