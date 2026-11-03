package convert

import (
	"encoding/json"
	"runtime"
	"sync"

	"github.com/runZeroInc/oobscan/pkg/scanfile"
)

// This file holds the parallel transform pipeline. Redaction and the runZero
// projection are CPU-bound and per-record independent, so they parallelize across a
// worker pool; the only shared mutable is the Redactor's mapping table, which is
// mutex-guarded (see redact.go). Output is written back in input order so the file
// stays stable and diffable.
//
// The audit must not run on this path: it is stateful and order-sensitive, so a
// --quality run stays on the serial path in convert.go.

// resolveWorkers picks the pool size: the requested count, or the CPU count.
func resolveWorkers(requested int) int {
	if requested > 0 {
		return requested
	}
	if n := runtime.NumCPU(); n > 1 {
		return n
	}
	return 1
}

// producer yields owned records in input order. It calls submit exactly once
// per source record, passing a closure that materializes a fresh, caller-owned
// *scanfile.Record (or nil to skip the record). Deferring materialization into
// the closure lets the expensive decode/projection run on the worker, not the
// producer goroutine. It returns the source stats and the first read error.
type producer func(submit func(make func() *scanfile.Record)) (sourceStats, error)

// parallelJob is one unit of work with its input-order sequence number.
type parallelJob struct {
	seq  int
	make func() *scanfile.Record
}

// parallelResult is a finished job: an encoded NDJSON line, or a skip.
type parallelResult struct {
	seq  int
	line []byte
	skip bool
}

// runParallel drives prod through the worker pool, redacting (when redactor is
// non-nil) and writing results in input order. It returns the source stats and
// the number of records written.
func runParallel(prod producer, w *scanfile.Writer, redactor *Redactor, workers int, progress func(int)) (sourceStats, int, error) {
	workers = resolveWorkers(workers)
	jobs := make(chan parallelJob, workers*8)
	results := make(chan parallelResult, workers*8)

	var (
		errMu    sync.Mutex
		firstErr error
	)
	setErr := func(err error) {
		if err == nil {
			return
		}
		errMu.Lock()
		if firstErr == nil {
			firstErr = err
		}
		errMu.Unlock()
	}

	// Workers: materialize, migrate, redact, marshal.
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for j := range jobs {
				rec := j.make()
				if rec == nil {
					results <- parallelResult{seq: j.seq, skip: true}
					continue
				}
				rec.Migrate()
				if redactor != nil {
					redactor.Record(rec)
				}
				line, err := scanfile.MarshalRecord(rec)
				if err != nil {
					setErr(err)
					results <- parallelResult{seq: j.seq, skip: true}
					continue
				}
				results <- parallelResult{seq: j.seq, line: line}
			}
		})
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	// Writer: reassemble input order and write. Only this goroutine touches w,
	// so no lock is needed around the writes.
	written := 0
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		pending := map[int]parallelResult{}
		next := 0
		flush := func(res parallelResult) {
			pending[res.seq] = res
			for {
				r, ok := pending[next]
				if !ok {
					return
				}
				delete(pending, next)
				next++
				if !r.skip && w != nil {
					if err := w.WriteLine(r.line); err != nil {
						setErr(err)
					} else {
						written++
					}
				}
				if progress != nil {
					progress(next)
				}
			}
		}
		for res := range results {
			flush(res)
		}
	}()

	// Producer runs on this goroutine, feeding jobs in input order.
	seq := 0
	ss, ferr := prod(func(make func() *scanfile.Record) {
		jobs <- parallelJob{seq: seq, make: make}
		seq++
	})
	close(jobs)
	<-writerDone

	setErr(ferr)
	return ss, written, firstErr
}

// producerFor returns the input producer for a format.
func producerFor(format Format, path string) producer {
	switch format {
	case FormatRZSQL:
		return func(submit func(func() *scanfile.Record)) (sourceStats, error) {
			return streamRZSQL(path, func(h *rzHost) error {
				submit(func() *scanfile.Record { return h.record() })
				return nil
			})
		}
	case FormatRZServices:
		return func(submit func(func() *scanfile.Record)) (sourceStats, error) {
			return streamRZServices(path, func(h *rzHost) error {
				submit(func() *scanfile.Record { return h.record() })
				return nil
			})
		}
	default:
		return nativeProducer(path)
	}
}

// nativeProducer streams an oobscan NDJSON file, submitting a decode closure per
// line. The reader validates and skips malformed lines; the worker re-decodes
// the raw line into a record it owns (the reader reuses its buffer), which also
// spreads the JSON decode across the pool. The redundant reader-side decode is
// dwarfed by the redaction the worker then does.
func nativeProducer(path string) producer {
	return func(submit func(func() *scanfile.Record)) (sourceStats, error) {
		r, err := scanfile.Open(path)
		if err != nil {
			return sourceStats{}, err
		}
		defer r.Close()
		for r.Next() {
			line := append([]byte(nil), r.Raw()...) // copy: Raw is reused on Next
			submit(func() *scanfile.Record {
				var rec scanfile.Record
				if json.Unmarshal(line, &rec) != nil {
					return nil
				}
				return &rec
			})
		}
		return sourceStats{Read: r.Total(), Skipped: r.Skipped()}, r.Err()
	}
}
