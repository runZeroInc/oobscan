//go:build !windows

package engine

import "syscall"

// raiseFileLimit bumps RLIMIT_NOFILE toward the largest value the OS will
// accept, so a high worker count doesn't exhaust file descriptors. Ported from
// sshamble. Best-effort: failure is silently ignored.
func raiseFileLimit() {
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		return
	}
	for _, l := range []uint64{999999, 99999, 49999, 32766, 9999, 4999, 2048} {
		lim.Max = l
		lim.Cur = l
		if syscall.Setrlimit(syscall.RLIMIT_NOFILE, &lim) == nil {
			return
		}
	}
}
