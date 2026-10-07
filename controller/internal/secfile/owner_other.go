//go:build !unix

package secfile

import "io/fs"

const noFollow = 0

// The controller runs on Linux; elsewhere only the mode is checked.
func owner(fs.FileInfo) (int, bool) { return 0, false }

func inode(fs.FileInfo) uint64 { return 0 }

const nonBlock = 0
