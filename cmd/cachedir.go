package cmd

import (
	"os"
	"path/filepath"
)

// userCacheDir returns the per-user cache root, "$HOME/.cache".
//
// This deliberately does not use os.UserCacheDir, which on macOS resolves to
// ~/Library/Caches instead of the ~/.cache tree the rest of the toolchain
// (sshamble, badkeys, hashcat, runzero) already shares.
//
// Falls back to the running binary's directory when HOME is unset or invalid.
func userCacheDir() string {
	base := os.Getenv("HOME")
	if st, err := os.Stat(base); base == "" || err != nil || !st.IsDir() {
		base = executableDir()
	}
	return filepath.Join(base, ".cache")
}

// executableDir returns the absolute directory holding the running binary,
// falling back to the working directory if the path cannot be resolved.
func executableDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	abs, err := filepath.Abs(exe)
	if err != nil {
		return filepath.Dir(exe)
	}
	return filepath.Dir(abs)
}
