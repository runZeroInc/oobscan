package httpscan

import (
	"fmt"
	"sync"
	"testing"
)

// TestRegexCacheConcurrent exercises the memoized regex helpers from many
// goroutines at once, which is how the endpoint sweep reaches them. With a bare
// map cache this is a `fatal error: concurrent map writes` (and a data race under
// -race), which kills the whole scan process rather than one target.
func TestRegexCacheConcurrent(t *testing.T) {
	var wg sync.WaitGroup
	for i := range 64 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := range 64 {
				key := fmt.Sprintf("k%d", (i*7+j)%32)
				if re := jsonKeyRE(key); re == nil {
					t.Error("nil json regex")
				}
				if re := xmlTagRE(key); re == nil {
					t.Error("nil xml regex")
				}
			}
		}(i)
	}
	wg.Wait()
	// Same key must yield the identical cached regex, not a fresh compile each
	// call: LoadOrStore, not Store, is what guarantees one shared instance.
	jsonA, jsonB := jsonKeyRE("k1"), jsonKeyRE("k1")
	if jsonA != jsonB {
		t.Error("jsonKeyRE did not share one compiled regex per key")
	}
	xmlA, xmlB := xmlTagRE("k1"), xmlTagRE("k1")
	if xmlA != xmlB {
		t.Error("xmlTagRE did not share one compiled regex per key")
	}
}
