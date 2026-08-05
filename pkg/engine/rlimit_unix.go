//go:build !windows

package engine

import "syscall"

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
