//go:build unix

package secfile

import (
	"io/fs"
	"syscall"
)

const noFollow = syscall.O_NOFOLLOW

func owner(fi fs.FileInfo) (int, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(st.Uid), true
}

func inode(fi fs.FileInfo) uint64 {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0
	}
	return uint64(st.Ino)
}

// nonBlock: Tighten opens what it changes, and opening a FIFO put in a file's place must not
// wait for a writer.
const nonBlock = syscall.O_NONBLOCK
