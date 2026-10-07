package fakenode

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"
)

// Lan is fake nodes on made-up addresses (203.0.113.52), each served on loopback and reached
// at the address it is on now: a node that moves (a config with a new address, then a
// reboot) answers on its new address from then on, as on a real network. Others are other
// hosts answering HTTP on an address (a web server, to find an address taken).
type Lan struct {
	Net
	mu      sync.Mutex
	servers map[*Node]*httptest.Server
	others  map[string]string // address: loopback host:port
}

// NewLan is an empty fake network.
func NewLan() *Lan {
	return &Lan{servers: map[*Node]*httptest.Server{}, others: map[string]string{}}
}

// Add serves n (its Addr is the made-up address it is on).
func (l *Lan) Add(n *Node) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.Net = append(l.Net, n)
	l.servers[n] = httptest.NewServer(n)
}

// Other puts something else answering HTTP on addr: h.
func (l *Lan) Other(addr string, h http.Handler) {
	s := httptest.NewServer(h)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.others[addr] = strings.TrimPrefix(s.URL, "http://")
	l.servers[&Node{}] = s
}

// Close stops every server.
func (l *Lan) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, s := range l.servers {
		s.Close()
	}
}

// HTTP is a client that reaches each address as it is now: the node there, another host
// put there, or nothing (no route, as an address no one is on).
func (l *Lan) HTTP() *http.Client {
	return &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			l.mu.Lock()
			to := l.others[host]
			if n := l.At(host); n != nil {
				to = strings.TrimPrefix(l.servers[n].URL, "http://")
			}
			l.mu.Unlock()
			if to == "" {
				return nil, errors.New("fake lan: no route to " + host)
			}
			return (&net.Dialer{}).DialContext(ctx, network, to)
		}}}
}
