//go:build windows

package timeout

import (
	"context"
	"time"
)

// Run calls fn with a timeout context. On Windows, Enter-to-skip is not
// supported; only the timeout applies.
func Run(ctx context.Context, d time.Duration, fn func(context.Context) ([]byte, error)) Result {
	childCtx, cancel := context.WithTimeout(ctx, d)
	defer cancel()

	secret, err := fn(childCtx)
	if err != nil {
		if childCtx.Err() == context.DeadlineExceeded && ctx.Err() == nil {
			return Result{Err: err, SkipReason: SkippedTimeout}
		}
		return Result{Err: err}
	}
	return Result{Secret: secret}
}
