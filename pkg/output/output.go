package output

import (
	"io"
	"os"

	"github.com/runZeroInc/oobscan/pkg/engine"
)

// Options configures New.
type Options struct {
	Fancy   io.Writer // human findings + summary (default os.Stdout)
	Errors  io.Writer // diagnostics + panics (default os.Stderr)
	Records io.Writer // NDJSON sink (the --output file)
	Total   int       // number of targets (reserved for progress reporting)
	NoColor bool      // disable ANSI styling
	Verbose bool      // include verbose-only lines such as id.final summaries
}

// New builds the emitter. There is a single emitter: it always renders the
// human ("fancy") output to Fancy and diagnostics to Errors, and additionally
// streams machine NDJSON to Records. The three streams are independent, so
// `oobscan scan --output out.jsonl` shows the fancy
// scan on the terminal while out.jsonl stays pure NDJSON.
func New(o Options) engine.Emitter {
	if o.Fancy == nil {
		o.Fancy = os.Stdout
	}
	if o.Errors == nil {
		o.Errors = os.Stderr
	}
	return newTTYEmitterTo(o.Fancy, o.Errors, o.Records, o.NoColor, o.Verbose)
}
