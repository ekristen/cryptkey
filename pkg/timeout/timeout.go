//go:build !windows

// Package timeout provides a context-based timeout wrapper with Enter-to-skip
// and Escape/Ctrl+C support via /dev/tty for hardware provider derivation.
package timeout

import (
	"context"
	"os"
	"sync"
	"syscall"
	"time"

	"golang.org/x/term"
)

// SkipReason indicates why a provider was skipped.
type SkipReason int

const (
	NotSkipped     SkipReason = iota
	SkippedTimeout            // deadline exceeded
	SkippedUser               // user pressed Enter/Escape to skip
)

// Result holds the outcome of a timeout-wrapped provider call.
type Result struct {
	Secret     []byte
	Err        error
	SkipReason SkipReason
}

// Run calls fn with a context that cancels after the given timeout or when
// the user presses Enter/Escape on /dev/tty. Ctrl+C sends SIGINT to quit.
// Returns the result and the skip reason.
//
// When the context is canceled (timeout, skip, or interrupt), Run returns
// immediately without waiting for fn to complete. The goroutine running fn
// will eventually finish when the underlying call returns.
func Run(ctx context.Context, d time.Duration, fn func(context.Context) ([]byte, error)) Result {
	childCtx, cancel := context.WithTimeout(ctx, d)
	defer cancel()

	// Start keypress listener on /dev/tty
	listener := newEnterListener(cancel)

	// Run the provider in a goroutine
	type provResult struct {
		secret []byte
		err    error
	}
	ch := make(chan provResult, 1)
	go func() {
		secret, err := fn(childCtx)
		ch <- provResult{secret, err}
	}()

	// Wait for either the provider to finish or cancellation
	select {
	case r := <-ch:
		listener.stop()
		if r.err == nil {
			return Result{Secret: r.secret}
		}
		return Result{Err: r.err}

	case <-childCtx.Done():
		// Context canceled — don't block waiting for fn to return.
		// The goroutine will finish on its own when the C call completes.
		listener.stop()

		if ctx.Err() != nil {
			// Parent context canceled (e.g., SIGINT) — not a skip
			return Result{Err: childCtx.Err()}
		}
		if childCtx.Err() == context.DeadlineExceeded {
			return Result{Err: childCtx.Err(), SkipReason: SkippedTimeout}
		}
		return Result{Err: childCtx.Err(), SkipReason: SkippedUser}
	}
}

// enterListener watches for keypress on /dev/tty:
//   - Enter or Escape: cancel the child context (skip provider)
//   - Ctrl+C: send SIGINT to quit the process
type enterListener struct {
	tty      *os.File
	oldState *term.State
	cancel   context.CancelFunc
	once     sync.Once
}

func newEnterListener(cancel context.CancelFunc) *enterListener {
	el := &enterListener{cancel: cancel}

	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return el
	}
	el.tty = tty

	fd := int(tty.Fd()) //nolint:gosec
	oldState, err := term.GetState(fd)
	if err != nil {
		tty.Close()
		el.tty = nil
		return el
	}
	el.oldState = oldState

	if _, err := term.MakeRaw(fd); err != nil {
		tty.Close()
		el.tty = nil
		return el
	}

	go el.listen()
	return el
}

func (el *enterListener) listen() {
	if el.tty == nil {
		return
	}

	buf := make([]byte, 1)
	for {
		n, err := el.tty.Read(buf)
		if err != nil {
			// tty was closed by stop() — exit cleanly
			return
		}
		if n != 1 {
			continue
		}
		switch buf[0] {
		case '\r', '\n', 0x1b: // Enter or Escape — skip this provider
			el.cancel()
			return
		case 0x03: // Ctrl+C — interrupt the whole process
			el.stop()
			_ = syscall.Kill(syscall.Getpid(), syscall.SIGINT)
			return
		}
	}
}

// stop closes the tty to unblock the listener goroutine and restores
// the terminal to its original state.
func (el *enterListener) stop() {
	el.once.Do(func() {
		if el.tty != nil {
			// Close the fd to unblock the Read in listen()
			el.tty.Close()
		}

		// Restore terminal state using a fresh fd
		if el.oldState != nil {
			if tty2, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
				_ = term.Restore(int(tty2.Fd()), el.oldState) //nolint:gosec
				tty2.Close()
			}
		}
	})
}
