package backup

import (
	"context"
	"errors"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/fleetlock"
)

// Lock takes dataDir's fleet lock for a backup, so no job or CLI change writes while it
// reads (settings.json, the pushed records, the action log). While another holds it (a
// rollout, a job), it tries again every second for up to wait, calling waiting once with
// who has it; then it fails with fleetlock's error naming them. wait 0 fails at once.
func Lock(ctx context.Context, dataDir, who string, wait time.Duration, waiting func(fleetlock.Holder)) (*fleetlock.Lock, error) {
	deadline := time.Now().Add(wait)
	told := false
	for {
		lk, err := fleetlock.Acquire(fleetlock.Path(dataDir), fleetlock.Self(who, "reading the data directory"))
		var le *fleetlock.LockedError
		if err == nil || !errors.As(err, &le) || !time.Now().Before(deadline) {
			return lk, err
		}
		if !told && waiting != nil {
			waiting(le.Holder)
			told = true
		}
		select {
		case <-ctx.Done():
			return nil, err
		case <-time.After(min(time.Second, time.Until(deadline))):
		}
	}
}
