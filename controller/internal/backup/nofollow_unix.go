//go:build unix

package backup

import "syscall"

const noFollow = syscall.O_NOFOLLOW
