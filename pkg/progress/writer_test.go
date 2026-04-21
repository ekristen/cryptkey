package progress

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The writer tests focus on behaviors that are easy to get subtly wrong
// and silently ship: ANSI/color gating, in-place vs committed lines,
// line-clearing on transition, and the quiet/non-interactive fallbacks.
// Raw-mode prompt flows (PromptPassword, readTTYEdit) need /dev/tty and
// are exercised by manual runs + the sub-model tests in pkg/tui.

// newTestWriter returns a Writer that writes into a bytes.Buffer so tests
// can inspect the exact output. Tests pick isTTY and quiet; noTUI is
// always false here because its effect collapses into !isTTY for the
// code paths these tests care about, and dedicated TestNewSetsInteractive
// below covers the noTUI matrix.
func newTestWriter(isTTY, quiet bool) (*Writer, *bytes.Buffer) {
	var buf bytes.Buffer
	return New(&buf, isTTY, false, quiet), &buf
}

// --- Construction ---

func TestNewSetsInteractiveOnlyWhenAllFlagsAllow(t *testing.T) {
	cases := []struct {
		isTTY, noTUI, quiet bool
		wantInteractive     bool
	}{
		{true, false, false, true},   // real terminal, TUI on, not quiet
		{false, false, false, false}, // not a terminal
		{true, true, false, false},   // --no-tui
		{true, false, true, false},   // --quiet
		{false, true, true, false},   // all off
	}
	for _, tc := range cases {
		w := New(&bytes.Buffer{}, tc.isTTY, tc.noTUI, tc.quiet)
		assert.Equalf(t, tc.wantInteractive, w.interactive,
			"isTTY=%v noTUI=%v quiet=%v", tc.isTTY, tc.noTUI, tc.quiet)
		assert.Equalf(t, tc.wantInteractive, w.color,
			"color tracks interactive: isTTY=%v noTUI=%v quiet=%v", tc.isTTY, tc.noTUI, tc.quiet)
	}
}

// --- Emit ---

func TestEmitSucceededInteractiveHasColorAndCheck(t *testing.T) {
	w, buf := newTestWriter(true, false)
	w.Emit(Event{Provider: "fido2", ID: "yk-1", Status: StatusSucceeded})
	got := buf.String()
	assert.Contains(t, got, "fido2")
	assert.Contains(t, got, "✓")
	assert.Contains(t, got, "\033[32m", "interactive should include green ANSI")
	assert.True(t, strings.HasSuffix(got, "\n"), "committed status must end with newline")
}

func TestEmitSucceededNonInteractiveDropsColor(t *testing.T) {
	w, buf := newTestWriter(false, false)
	w.Emit(Event{Provider: "fido2", Status: StatusSucceeded})
	got := buf.String()
	assert.Contains(t, got, "✓")
	assert.NotContains(t, got, "\033[", "non-interactive must not emit ANSI")
}

func TestEmitFailedNonEmptyMessageIncluded(t *testing.T) {
	w, buf := newTestWriter(false, false)
	w.Emit(Event{Provider: "fido2", Status: StatusFailed, Message: "pin invalid"})
	assert.Contains(t, buf.String(), "failed: pin invalid")
}

func TestEmitSkippedDefaultReason(t *testing.T) {
	w, buf := newTestWriter(false, false)
	w.Emit(Event{Provider: "sshkey", Status: StatusSkipped})
	assert.Contains(t, buf.String(), "skipped (skipped)")
}

func TestEmitWaitingInteractiveOmitsNewline(t *testing.T) {
	// StatusWaiting is the only status that leaves the cursor mid-line
	// in interactive mode, so a countdown can overwrite it via \r. If
	// this accidentally starts ending with \n, the countdown stacks.
	w, buf := newTestWriter(true, false)
	w.Emit(Event{Provider: "fido2", Status: StatusWaiting, Message: "touch"})
	got := buf.String()
	assert.Contains(t, got, "touch")
	assert.False(t, strings.HasSuffix(got, "\n"), "interactive waiting must not terminate line")
}

func TestEmitWaitingNonInteractiveCommitsLine(t *testing.T) {
	// Non-interactive flow has no \r overwrite path, so we commit the
	// line or the next write runs on against it.
	w, buf := newTestWriter(false, false)
	w.Emit(Event{Provider: "fido2", Status: StatusWaiting, Message: "touch"})
	assert.True(t, strings.HasSuffix(buf.String(), "\n"))
}

func TestEmitQuietSuppressesAllStatuses(t *testing.T) {
	w, buf := newTestWriter(true, true)
	w.Emit(Event{Provider: "fido2", Status: StatusSucceeded})
	w.Emit(Event{Provider: "fido2", Status: StatusFailed, Message: "nope"})
	w.Emit(Event{Provider: "fido2", Status: StatusSkipped, Message: "x"})
	w.Emit(Event{Provider: "fido2", Status: StatusWaiting, Message: "x"})
	assert.Empty(t, buf.String())
}

// --- Clear-transient-on-commit ---
//
// Succeeded / Failed / Skipped are committed statuses that must clear any
// pending transient line first in interactive mode. Without this, a
// waiting line like "» fido2 touch..." followed by a success would render
// as "» fido2 touch...» fido2 ✓" on one smashed line.

func TestSucceededClearsTransientInInteractiveMode(t *testing.T) {
	w, buf := newTestWriter(true, false)
	w.Emit(Event{Provider: "fido2", Status: StatusWaiting, Message: "touch"})
	w.Emit(Event{Provider: "fido2", Status: StatusSucceeded})
	got := buf.String()
	// "\r\033[2K" must appear before the final success line.
	clearIdx := strings.Index(got, "\r\033[2K")
	assert.NotEqual(t, -1, clearIdx, "interactive commit must include line-clear ANSI")
	assert.Contains(t, got, "✓")
}

func TestSucceededNoClearWhenNonInteractive(t *testing.T) {
	w, buf := newTestWriter(false, false)
	w.Emit(Event{Provider: "fido2", Status: StatusWaiting, Message: "x"})
	w.Emit(Event{Provider: "fido2", Status: StatusSucceeded})
	assert.NotContains(t, buf.String(), "\r\033[2K", "non-interactive must not emit line-clear")
}

// --- Countdown ---

func TestCountdownInteractiveOverwritesViaCR(t *testing.T) {
	w, buf := newTestWriter(true, false)
	w.Countdown("fido2", "waiting for touch...", "", 12*time.Second)
	got := buf.String()
	assert.True(t, strings.HasPrefix(got, "\r\033[2K"), "countdown must start with line-clear ANSI to overwrite")
	assert.Contains(t, got, "(12s)")
	assert.NotContains(t, got, "\n", "countdown stays on its line")
}

func TestCountdownNoOpWhenNotInteractive(t *testing.T) {
	w, buf := newTestWriter(false, false)
	w.Countdown("fido2", "waiting for touch...", "", 5*time.Second)
	assert.Empty(t, buf.String(), "countdown must not render in non-interactive mode")
}

func TestCountdownNoOpWhenQuiet(t *testing.T) {
	w, buf := newTestWriter(true, true)
	w.Countdown("fido2", "waiting for touch...", "", 5*time.Second)
	assert.Empty(t, buf.String())
}

// --- Info ---

func TestInfoInteractiveClearsPriorTransient(t *testing.T) {
	w, buf := newTestWriter(true, false)
	w.Emit(Event{Provider: "fido2", Status: StatusWaiting, Message: "x"})
	buf.Reset()
	w.Info("some message")
	got := buf.String()
	assert.True(t, strings.HasPrefix(got, "\r\033[2K"), "Info must clear line before writing")
	assert.Contains(t, got, "some message\n")
}

func TestInfoNonInteractiveJustWritesLine(t *testing.T) {
	w, buf := newTestWriter(false, false)
	w.Info("hello")
	assert.Equal(t, "hello\n", buf.String())
}

func TestInfoQuietSuppressed(t *testing.T) {
	w, buf := newTestWriter(true, true)
	w.Info("hello")
	assert.Empty(t, buf.String())
}

// --- Link ---

func TestLinkInteractiveRendersURLDim(t *testing.T) {
	w, buf := newTestWriter(true, false)
	w.Link("Opening browser: ", "http://localhost:4242/")
	got := buf.String()
	assert.Contains(t, got, "Opening browser: ")
	assert.Contains(t, got, "http://localhost:4242/")
	assert.Contains(t, got, "\033[90m", "URL should be rendered in dim (gray) ANSI")
}

func TestLinkNonInteractivePlain(t *testing.T) {
	w, buf := newTestWriter(false, false)
	w.Link("Opening browser: ", "http://localhost:4242/")
	got := buf.String()
	assert.Contains(t, got, "Opening browser: http://localhost:4242/")
	assert.NotContains(t, got, "\033[", "non-interactive must not emit ANSI")
}

// --- FinishLine ---

func TestFinishLineOnlyActsInInteractive(t *testing.T) {
	w, buf := newTestWriter(true, false)
	w.FinishLine()
	assert.Equal(t, "\r\033[2K", buf.String())

	w2, buf2 := newTestWriter(false, false)
	w2.FinishLine()
	assert.Empty(t, buf2.String())

	w3, buf3 := newTestWriter(true, true)
	w3.FinishLine()
	assert.Empty(t, buf3.String(), "quiet should not emit line clears")
}

// --- Fatal ---

func TestFatalBypassesQuiet(t *testing.T) {
	w, buf := newTestWriter(true, true)
	w.Fatal("can't open /dev/tty")
	assert.Contains(t, buf.String(), "error: can't open /dev/tty")
}

// --- Starting ---

func TestStartingCommitsWithProviderBullet(t *testing.T) {
	w, buf := newTestWriter(true, false)
	w.Starting("passphrase", "pass-2", "enrolling")
	got := buf.String()
	// Committed line: provider bullet + dim detail.
	assert.True(t, strings.HasPrefix(got, "» passphrase"), "should start with the bullet-prefixed provider label")
	assert.Contains(t, got, "enrolling (pass-2)")
	assert.True(t, strings.HasSuffix(got, "\n"))
}

func TestStartingOmitsIDParensWhenEmpty(t *testing.T) {
	w, buf := newTestWriter(false, false)
	w.Starting("tpm", "", "unlocking")
	assert.Contains(t, buf.String(), "unlocking")
	assert.NotContains(t, buf.String(), "(")
}

func TestStartingQuietSuppressed(t *testing.T) {
	w, buf := newTestWriter(true, true)
	w.Starting("passphrase", "pass-1", "enrolling")
	assert.Empty(t, buf.String())
}

// --- Provider label formatting ---

func TestProviderLabelIsPaddedToFixedWidth(t *testing.T) {
	// The providerWidth constant is meant to keep the column after the
	// label aligned. If someone shortens it, old logs misalign.
	w, buf := newTestWriter(false, false)
	w.Emit(Event{Provider: "a", Status: StatusSucceeded})
	got := buf.String()
	// Expect at least providerWidth spaces between "a" and the ✓.
	require.Contains(t, got, "a")
	aIdx := strings.Index(got, "a")
	checkIdx := strings.Index(got, "✓")
	require.Greater(t, checkIdx, aIdx)
	gap := checkIdx - aIdx
	assert.GreaterOrEqualf(t, gap, providerWidth, "label column must be at least providerWidth=%d chars wide", providerWidth)
}

// --- Concurrency safety ---

func TestEmitIsConcurrencySafe(t *testing.T) {
	// pw.mu exists for a reason: multiple provider goroutines can emit
	// events simultaneously during enrollment. If the mutex is removed
	// the -race build catches it here.
	w, _ := newTestWriter(false, false)
	done := make(chan struct{})
	for range 10 {
		go func() {
			for range 20 {
				w.Emit(Event{Provider: "p", Status: StatusSucceeded})
				w.Info("msg")
			}
			done <- struct{}{}
		}()
	}
	for range 10 {
		<-done
	}
}
