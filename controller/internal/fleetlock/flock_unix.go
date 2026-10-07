//go:build unix

package fleetlock

import (
	"errors"
	"os"
	"syscall"
)

var errBusy = errors.New("held by another")

// tryLock takes an exclusive flock on f without waiting: errBusy if another open file has it.
func tryLock(f *os.File) error {
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		switch {
		case err == nil:
			return nil
		case errors.Is(err, syscall.EINTR):
			continue
		case errors.Is(err, syscall.EWOULDBLOCK):
			return errBusy
		}
		return err
	}
}

func unlock(f *os.File) error { return syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }
