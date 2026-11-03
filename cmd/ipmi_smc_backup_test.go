package cmd

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/runZeroInc/oobscan/pkg/ipmi"
)

func TestSMCRestoreShellRejectsUnauthenticatedFallback(t *testing.T) {
	previous := smcPayloadHost
	t.Cleanup(func() { smcPayloadHost = previous })
	for _, member := range []string{ipmi.SMCShellHostnameDHCPName, " " + ipmi.SMCShellHostnameDHCPName + " "} {
		smcPayloadHost = member
		_, err := runIPMISMCRestoreShell(context.Background(), nil, nil)
		if err == nil || !strings.Contains(err.Error(), "unauthenticated Telnet fallback is disabled") {
			t.Fatalf("member %q: expected refusal before session access, got %v", member, err)
		}
	}
}

func TestLoadOrCreateSMCShellClientCertConcurrent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "smcrestore-shell.pem")

	const n = 24
	var wg sync.WaitGroup
	fingerprints := make([]string, n)
	created := make([]bool, n)
	errs := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cert, wasCreated, err := loadOrCreateSMCShellClientCert(path)
			errs[i] = err
			created[i] = wasCreated
			if err == nil {
				fingerprints[i] = cert.Fingerprint
			}
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	want := fingerprints[0]
	if want == "" {
		t.Fatal("empty fingerprint")
	}
	for i, fp := range fingerprints {
		if fp != want {
			t.Errorf("call %d: fingerprint %q != %q - concurrent callers disagree on the identity", i, fp, want)
		}
	}
	createdCount := 0
	for _, c := range created {
		if c {
			createdCount++
		}
	}
	if createdCount != 1 {
		t.Errorf("exactly one caller should have generated the cert, got %d", createdCount)
	}

	// The lock file must not be left behind.
	if _, err := os.Stat(path + ".lock"); !os.IsNotExist(err) {
		t.Errorf("lock file %s.lock was not cleaned up (stat err: %v)", path, err)
	}

	// A fresh call afterward must reuse the same cert, not mint another.
	cert, wasCreated, err := loadOrCreateSMCShellClientCert(path)
	if err != nil {
		t.Fatalf("post-concurrency call: %v", err)
	}
	if wasCreated {
		t.Errorf("post-concurrency call should have reused the cached cert")
	}
	if cert.Fingerprint != want {
		t.Errorf("post-concurrency fingerprint %q != %q", cert.Fingerprint, want)
	}
}

func TestAcquireSMCShellCertLockRemovesStaleLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "smcrestore-shell.pem")
	lockPath := path + ".lock"
	if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
		t.Fatalf("seeding stale lock: %v", err)
	}
	stale := time.Now().Add(-2 * smcShellCertLockStale)
	if err := os.Chtimes(lockPath, stale, stale); err != nil {
		t.Fatalf("backdating lock mtime: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		unlock, err := acquireSMCShellCertLock(path)
		if err == nil {
			unlock()
		}
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("acquiring lock after a stale one should succeed promptly, got: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("acquireSMCShellCertLock did not return promptly for a stale lock; it should be removed rather than waited out")
	}
}

func TestLoadOrCreateSMCShellClientCertRejectsUnusableExisting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "smcrestore-shell.pem")
	if err := os.WriteFile(path, []byte("not a cert"), 0o600); err != nil {
		t.Fatalf("seeding garbage file: %v", err)
	}
	if _, _, err := loadOrCreateSMCShellClientCert(path); err == nil {
		t.Error("expected an error for an existing-but-unusable cert file, not silent regeneration")
	}
}
