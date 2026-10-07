//go:build !unix

package fleetlock

import (
	"errors"
	"os"
)

var errBusy = errors.New("held by another")

// The controller and the CLI run on Linux (in Docker); elsewhere there is no fleet lock.
func tryLock(*os.File) error { return errors.New("no fleet lock on this system") }
func unlock(*os.File) error  { return nil }
