package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUserCacheDirUsesHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	if got, want := userCacheDir(), filepath.Join(home, ".cache"); got != want {
		t.Fatalf("userCacheDir() = %q, want %q", got, want)
	}
}

// A missing or unset HOME must not yield a bare relative path: the potfile would
// then follow the process's working directory and a resumed run would silently
// miss every previously cracked hash.
func TestUserCacheDirFallsBackWhenHomeUnusable(t *testing.T) {
	exeDir := executableDir()
	if exeDir == "." {
		t.Skip("executable path unavailable")
	}
	cases := map[string]string{
		"unset":   "",
		"missing": filepath.Join(t.TempDir(), "no-such-dir"),
		"notADir": "",
	}
	f := filepath.Join(t.TempDir(), "home-is-a-file")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	cases["notADir"] = f

	want := filepath.Join(exeDir, ".cache")
	for name, home := range cases {
		t.Run(name, func(t *testing.T) {
			t.Setenv("HOME", home)
			if got := userCacheDir(); got != want {
				t.Fatalf("userCacheDir() = %q, want %q", got, want)
			}
		})
	}
}

// The potfile must land under ~/.cache (not macOS's ~/Library/Caches) so one
// potfile is shared across platforms and with the rest of the toolchain.
func TestDefaultPotfilePathUnderDotCache(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	got := defaultPotfilePath()
	if want := filepath.Join(home, ".cache", "oobscan", "oobscan.pot"); got != want {
		t.Fatalf("defaultPotfilePath() = %q, want %q", got, want)
	}
	if strings.Contains(got, "Library/Caches") {
		t.Errorf("defaultPotfilePath() = %q, must not use the macOS cache dir", got)
	}
}
