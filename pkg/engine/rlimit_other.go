//go:build windows

package engine

// raiseFileLimit is a no-op on platforms without RLIMIT_NOFILE.
func raiseFileLimit() {}
