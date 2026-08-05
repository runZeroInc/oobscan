package convert

import (
	"encoding/json"
	"runtime"
	"sync"

	"github.com/runZeroInc/oobscan/pkg/scanfile"
)

func resolveWorkers(requested int) int {
	if requested > 0 {
		return requested
	}
	if n := runtime.NumCPU(); n > 1 {
		return n
	}
	return 1
}

type producer func(submit func(make func() *scanfile.Record)) (sourceStats, error)

type parallelJob struct {
	seq  int
	make func() *scanfile.Record
}

type parallelResult struct {
	seq  int
	line []byte
	skip bool
}

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

func nativeProducer(path string) producer {
	return func(submit func(func() *scanfile.Record)) (sourceStats, error) {
		r, err := scanfile.Open(path)
		if err != nil {
			return sourceStats{}, err
		}
		defer r.Close()
		for r.Next() {
			line := append([]byte(nil), r.Raw()...)
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
