package fleet

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/release"
)

// TrialWindow is how long a node waits on a new address to be reached (firmware
// SETTINGS_TRIAL_S) before it goes back to its previous config.
const TrialWindow = 90 * time.Second

// ConfirmConfig waits up to wait for the node (id, if given) to come back with config seq
// on one of the addresses locate gives, sends it DNS queries there until it confirms the
// trial, and returns its config status and the address it answered on. The node's pin
// (internal/pins) moves there with it.
func (c *Client) ConfirmConfig(ctx context.Context, locate func(context.Context) []string, id string,
	seq uint64, wait time.Duration) (*release.ConfigStatus, string, error) {
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	var last string
	for {
		st, host, err := c.Locate(ctx, locate(ctx), id)
		switch {
		case err != nil:
			last = err.Error()
		case st.Config == nil:
			return nil, "", fmt.Errorf("%s: no config in /status", host)
		case st.Config.Seq != seq:
			last = fmt.Sprintf("%s: running config seq %d (%s)", host, st.Config.Seq, st.Config.Error)
			if st.Config.Error != "" && strings.Contains(st.Config.Error, fmt.Sprint(seq)) {
				return nil, "", fmt.Errorf("%s: %s", host, st.Config.Error)
			}
		case !st.Config.Trial:
			if err := c.movePin(id, host); err != nil {
				return nil, "", err
			}
			return st.Config, host, nil
		default:
			last = host + ": on trial"
			if err := c.Answers(ctx, host); err != nil {
				last += "; DNS query: " + err.Error()
			} else {
				c.logf("%s answered DNS", host)
			}
		}
		if sleep(ctx, c.poll()) != nil {
			return nil, "", fmt.Errorf("the node didn't confirm config seq %d (%s): it goes back to its previous config", seq, last)
		}
	}
}

// Locate returns the /status of the first of hosts that answers as node id (any node if id
// is empty), and that host.
func (c *Client) Locate(ctx context.Context, hosts []string, id string) (release.NodeStatus, string, error) {
	var errs []string
	for _, h := range hosts {
		tctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		st, err := c.Status(tctx, h)
		cancel()
		switch {
		case err != nil:
			errs = append(errs, err.Error())
		case id != "" && !strings.EqualFold(st.NodeID, id):
			errs = append(errs, fmt.Sprintf("%s is node %s, not %s", h, st.NodeID, id))
		default:
			return st, h, nil
		}
	}
	return release.NodeStatus{}, "", errors.New(strings.Join(errs, "; "))
}

// movePin moves node id's pin to host, where a config it took moved it; nothing without an
// ID or a record (a dry run's client).
func (c *Client) movePin(id, host string) error {
	if id == "" || c.Pusher == nil || c.Pusher.Pins == nil {
		return nil
	}
	old, err := c.Pusher.Pins.Pinned(host)
	if err == nil && strings.EqualFold(old, id) {
		return nil
	}
	replaced, err := c.Pusher.Pins.Pin(id, host)
	if err != nil {
		return fmt.Errorf("node %s confirmed on %s, but not pinned there: %w", id, host, err)
	}
	c.logf("node %s pinned to %s now", id, host)
	if replaced != "" {
		c.logf("(node %s, pinned there before, is pinned to no address now)", replaced)
	}
	return nil
}
