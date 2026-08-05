package output

import (
	"io"
	"os"

	"github.com/runZeroInc/oobscan/pkg/engine"
)

type Options struct {
	Fancy   io.Writer
	Errors  io.Writer
	Records io.Writer
	Total   int
	NoColor bool
	Verbose bool
}

func New(o Options) engine.Emitter {
	if o.Fancy == nil {
		o.Fancy = os.Stdout
	}
	if o.Errors == nil {
		o.Errors = os.Stderr
	}
	return newTTYEmitterTo(o.Fancy, o.Errors, o.Records, o.NoColor, o.Verbose)
}
