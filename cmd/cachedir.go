package cmd

import (
	"os"
	"path/filepath"
)

func userCacheDir() string {
	base := os.Getenv("HOME")
	if st, err := os.Stat(base); base == "" || err != nil || !st.IsDir() {
		base = executableDir()
	}
	return filepath.Join(base, ".cache")
}

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
