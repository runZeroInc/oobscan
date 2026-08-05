package ipmi

import (
	"context"
	"fmt"
)

type progressReporter func(string)

type progressContextKey struct{}

func WithCommandProgress(ctx context.Context, fn func(string)) context.Context {
	if fn == nil {
		return ctx
	}
	return context.WithValue(ctx, progressContextKey{}, progressReporter(fn))
}

func reportCommandProgress(ctx context.Context, format string, args ...any) {
	if ctx == nil {
		return
	}
	v := ctx.Value(progressContextKey{})
	if v == nil {
		return
	}
	reporter, ok := v.(progressReporter)
	if !ok || reporter == nil {
		return
	}
	reporter(fmt.Sprintf(format, args...))
}
