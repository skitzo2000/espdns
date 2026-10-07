package nodes

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// Run browses mDNS only when asked: without it, only the listed addresses are polled and
// nothing else goes on the network (the browser tests' controller, make e2e).
func TestRunBrowsesOnlyWithMDNS(t *testing.T) {
	for _, mdns := range []bool{false, true} {
		r := New(nil)
		var browsed atomic.Int32
		r.browse = func(context.Context) { browsed.Add(1) }
		polled := make(chan struct{}, 1)
		r.OnPoll(func([]Node) {
			select {
			case polled <- struct{}{}:
			default:
			}
		})
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { r.Run(ctx, mdns); close(done) }()
		<-polled
		if mdns {
			deadline := time.Now().Add(5 * time.Second)
			for browsed.Load() == 0 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
		} else {
			time.Sleep(50 * time.Millisecond)
		}
		cancel()
		<-done
		if got := browsed.Load(); (got > 0) != mdns {
			t.Errorf("mdns %v: browsed %d times", mdns, got)
		}
	}
}
