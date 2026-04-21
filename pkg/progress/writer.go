package progress

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"golang.org/x/term"

	"github.com/ekristen/cryptkey/pkg/provider"
)

const providerWidth = 14

// echoMode controls how keystrokes are rendered during interactive prompts.
type echoMode int

const (
	echoMask  echoMode = iota // each char shows as '•'
	echoPlain                 // literal echo
)

const maskChar = "•"

// Writer formats and emits progress lines to an io.Writer (typically stderr).
type Writer struct {
	w           io.Writer
	color       bool
	quiet       bool
	interactive bool
	mu          sync.Mutex
}

// New creates a Writer.
//
// isTTY indicates whether the writer's target is a terminal.
// noTUI, if true, forces plain-line output even on a TTY (script mode).
// quiet suppresses all non-fatal output.
//
// When both isTTY and !noTUI are true, the Writer renders colors,
// in-place countdowns, and raw-mode inline prompts. Otherwise it falls
// back to plain stdin reads and line-based output.
func New(w io.Writer, isTTY, noTUI, quiet bool) *Writer {
	interactive := isTTY && !noTUI && !quiet
	return &Writer{
		w:           w,
		color:       interactive,
		quiet:       quiet,
		interactive: interactive,
	}
}

// Emit writes a progress event as a single line. In interactive mode the
// committed statuses (Succeeded / Failed / Skipped) clear any pending
// transient line with \r\033[2K first, so they don't visually collide with
// a Waiting event or countdown that lacked a trailing newline.
func (pw *Writer) Emit(e Event) {
	if pw.quiet {
		return
	}

	pw.mu.Lock()
	defer pw.mu.Unlock()

	label := fmt.Sprintf("%-*s", providerWidth, e.Provider)

	switch e.Status {
	case StatusSucceeded:
		pw.clearTransient()
		pw.writef("» %s %s\n", label, pw.green("✓"))
	case StatusWaiting:
		msg := e.Message
		if msg == "" {
			msg = "waiting..."
		}
		if pw.interactive {
			// No newline — countdown and final status will overwrite via \r
			pw.writef("» %s %s", label, pw.yellow(msg))
		} else {
			pw.writef("» %s %s\n", label, msg)
		}
	case StatusSkipped:
		reason := e.Message
		if reason == "" {
			reason = "skipped"
		}
		pw.clearTransient()
		pw.writef("» %s %s\n", label, pw.dim("skipped ("+reason+")"))
	case StatusFailed:
		reason := e.Message
		if reason == "" {
			reason = "unknown error"
		}
		pw.clearTransient()
		pw.writef("» %s %s\n", label, pw.red("failed: "+reason))
	case StatusRunning:
		// Running is transient; typically not emitted as a final line
	}
}

// Starting emits a committed "starting" line for a provider. Used by flows
// (rekey's enroll phase, for example) that kick off a provider operation
// the provider itself may annotate with direct stderr writes. Committing
// the line immediately means those provider writes don't smear into our
// formatted prefix.
func (pw *Writer) Starting(providerName, id, msg string) {
	if pw.quiet {
		return
	}
	pw.mu.Lock()
	defer pw.mu.Unlock()

	label := fmt.Sprintf("%-*s", providerWidth, providerName)
	detail := msg
	if id != "" {
		detail = fmt.Sprintf("%s (%s)", msg, id)
	}
	pw.writef("» %s %s\n", label, pw.dim(detail))
}

// clearTransient clears the current line in interactive mode so a committed
// line can be written cleanly on top of it. Caller must hold pw.mu.
func (pw *Writer) clearTransient() {
	if pw.interactive {
		pw.writef("\r\033[2K")
	}
}

// Countdown overwrites the current line with a provider-specific waiting
// message followed by the remaining seconds. When detail is non-empty it
// is embedded inline next to the message with an arrow separator
// ("waiting for browser → http://localhost:N/") so the actionable text
// is obvious without the user having to scan to the edge of the terminal.
// The hint ("esc skip • ctrl+c quit") is kept when it fits, dropped when
// the line would overflow. No-op when the output isn't interactive.
func (pw *Writer) Countdown(providerName, waitingMsg, detail string, remaining time.Duration) {
	if !pw.interactive {
		return
	}

	pw.mu.Lock()
	defer pw.mu.Unlock()

	label := fmt.Sprintf("%-*s", providerWidth, providerName)
	secs := int(remaining.Seconds())
	hint := "esc skip • ctrl+c quit"
	termW := pw.terminalWidth()

	// Compose the message body. When a detail is present (e.g. passkey's
	// fallback URL) embed it inline with an arrow so it reads as part of
	// the instruction: "waiting for browser → <url>".
	msgPlain := waitingMsg
	msgStyled := pw.yellow(waitingMsg)
	if detail != "" {
		msgPlain = fmt.Sprintf("%s → %s", waitingMsg, detail)
		msgStyled = pw.yellow(waitingMsg) + " " + pw.dim("→ "+detail)
	}

	// Try with hint; fall back to dropping it when the line would wrap.
	fullPlain := fmt.Sprintf("» %s %s (%ds) %s", label, msgPlain, secs, hint)
	if len(fullPlain) <= termW {
		pw.writef("\r\033[2K» %s %s %s %s", label, msgStyled,
			pw.yellow(fmt.Sprintf("(%ds)", secs)), pw.dim(hint))
		return
	}

	tersePlain := fmt.Sprintf("» %s %s (%ds)", label, msgPlain, secs)
	if len(tersePlain) <= termW {
		pw.writef("\r\033[2K» %s %s %s", label, msgStyled,
			pw.yellow(fmt.Sprintf("(%ds)", secs)))
		return
	}

	// Truly too narrow even for the terse form — drop the detail so the
	// countdown stays readable. Detail re-appears on resize next tick.
	pw.writef("\r\033[2K» %s %s %s", label, pw.yellow(waitingMsg),
		pw.yellow(fmt.Sprintf("(%ds)", secs)))
}

// terminalWidth returns the current terminal column count on pw.w's fd,
// or 80 as a safe default if stderr isn't a TTY / ioctl fails.
func (pw *Writer) terminalWidth() int {
	type fder interface{ Fd() uintptr }
	f, ok := pw.w.(fder)
	if !ok {
		return 80
	}
	w, _, err := term.GetSize(int(f.Fd())) //nolint:gosec // Fd() fits in int on every supported platform
	if err != nil || w <= 0 {
		return 80
	}
	return w
}

// Info writes a message on its own line, clearing any in-progress countdown
// line first so the output doesn't collide. The countdown ticker will
// re-paint on its next tick.
func (pw *Writer) Info(msg string) {
	if pw.quiet {
		return
	}

	pw.mu.Lock()
	defer pw.mu.Unlock()

	if pw.interactive {
		pw.writef("\r\033[2K")
	}
	pw.writef("%s\n", msg)
}

// Link writes a labeled URL where the URL portion is rendered in dim
// styling on interactive terminals.
func (pw *Writer) Link(prefix, url string) {
	if pw.quiet {
		return
	}

	pw.mu.Lock()
	defer pw.mu.Unlock()

	if pw.interactive {
		pw.writef("\r\033[2K")
	}
	pw.writef("%s%s\n", prefix, pw.dim(url))
}

// FinishLine clears the current in-place line and moves to a new line,
// so the next Emit starts clean. Call after a waiting/countdown sequence.
func (pw *Writer) FinishLine() {
	if !pw.interactive {
		return
	}

	pw.mu.Lock()
	defer pw.mu.Unlock()

	pw.writef("\r\033[2K")
}

// Fatal writes an error message regardless of quiet mode.
func (pw *Writer) Fatal(msg string) {
	pw.mu.Lock()
	defer pw.mu.Unlock()

	pw.writef("%s\n", pw.red("error: "+msg))
}

// PromptPassword prompts for a secret with masked bullets.
// hint is rendered in dim text next to the label (e.g. "esc to skip")
// and may be empty.
func (pw *Writer) PromptPassword(providerType, label, hint string) (string, error) {
	return pw.prompt(providerType, label, hint, echoMask)
}

// PromptLine prompts for a plain echoed line (e.g. a file path).
func (pw *Writer) PromptLine(providerType, label, hint string) (string, error) {
	return pw.prompt(providerType, label, hint, echoPlain)
}

func (pw *Writer) prompt(providerType, label, hint string, mode echoMode) (string, error) {
	promptPrefix := pw.buildPromptPrefix(providerType, label, hint)

	if !pw.interactive {
		return pw.promptPlain(promptPrefix, mode)
	}

	pw.mu.Lock()
	pw.writef("%s", promptPrefix)
	pw.mu.Unlock()

	result, err := readTTYEdit(promptPrefix, mode)

	// Move cursor up and clear the prompt line so the next Emit overwrites it.
	// Happens on every exit path (success, skip, interrupt) so we don't leave
	// a dangling prompt sitting above the subsequent status event.
	pw.mu.Lock()
	pw.writef("\033[A\r\033[2K")
	pw.mu.Unlock()

	if err != nil {
		return "", err
	}
	return string(result), nil
}

func (pw *Writer) buildPromptPrefix(providerType, label, hint string) string {
	hintStr := ""
	if hint != "" {
		hintStr = " " + pw.dim("("+hint+")")
	}
	return fmt.Sprintf("» %-*s %s%s: ", providerWidth, providerType, label, hintStr)
}

// promptPlain reads from /dev/tty when available (so secrets never touch
// stdin redirected from a file), falling back to os.Stdin otherwise.
// Used for --no-tui and non-TTY invocations.
func (pw *Writer) promptPlain(promptPrefix string, mode echoMode) (string, error) {
	pw.mu.Lock()
	pw.writef("%s", promptPrefix)
	pw.mu.Unlock()

	// Try /dev/tty first — even when stderr isn't a TTY, the user's
	// terminal may still be reachable directly.
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err == nil {
		defer tty.Close()
		if mode == echoMask {
			pass, rerr := term.ReadPassword(int(tty.Fd())) //nolint:gosec // Fd() fits in int
			pw.mu.Lock()
			pw.writef("\n")
			pw.mu.Unlock()
			if rerr != nil {
				return "", rerr
			}
			return string(pass), nil
		}
		reader := bufio.NewReader(tty)
		line, rerr := reader.ReadString('\n')
		if rerr != nil && line == "" {
			return "", rerr
		}
		return strings.TrimRight(line, "\r\n"), nil
	}

	// No /dev/tty: read a line from stdin plain. This is the CI / piped
	// case; we can't mask anyway since there's no terminal to suppress echo.
	reader := bufio.NewReader(os.Stdin)
	line, rerr := reader.ReadString('\n')
	if rerr != nil && line == "" {
		return "", rerr
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// editAction enumerates cursor / buffer operations parsed from escape
// sequences during inline editing.
type editAction int

const (
	actionNone editAction = iota
	actionLeft
	actionRight
	actionHome
	actionEnd
	actionDelete
	actionSkip // standalone Escape
)

// readTTYEdit reads a line from /dev/tty in raw mode with inline editing
// (backspace, left/right, home/end, delete) and the requested echo mode.
//
//nolint:gocyclo,funlen // key-dispatch switch; splitting it hurts readability
func readTTYEdit(promptPrefix string, mode echoMode) ([]byte, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/tty: %w", err)
	}
	defer tty.Close()

	fd := int(tty.Fd()) //nolint:gosec
	oldState, err := term.GetState(fd)
	if err != nil {
		return nil, fmt.Errorf("get terminal state: %w", err)
	}
	if _, err := term.MakeRaw(fd); err != nil {
		return nil, fmt.Errorf("set raw mode: %w", err)
	}
	defer func() { _ = term.Restore(fd, oldState) }()

	var buf []byte
	cursor := 0
	b := make([]byte, 1)

	for {
		n, err := tty.Read(b)
		if err != nil {
			fmt.Fprint(tty, "\r\n")
			return nil, err
		}
		if n == 0 {
			continue
		}

		switch b[0] {
		case '\r', '\n':
			fmt.Fprint(tty, "\r\n")
			return buf, nil
		case 0x03: // Ctrl-C
			fmt.Fprint(tty, "\r\n")
			// MakeRaw disables ISIG, so the kernel does not translate 0x03
			// into SIGINT for us. Raise SIGINT explicitly so the outer
			// signal handler (wrangler) cancels the derive context on the
			// first press — otherwise Ctrl-C only aborts this prompt and
			// the loop immediately prompts the next provider, forcing the
			// user to mash Ctrl-C N times to bail out of a multi-provider
			// profile.
			_ = syscall.Kill(syscall.Getpid(), syscall.SIGINT)
			return nil, errors.New("interrupted")
		case 0x01: // Ctrl-A
			cursor = 0
			redrawLine(tty, promptPrefix, buf, cursor, mode)
		case 0x05: // Ctrl-E
			cursor = len(buf)
			redrawLine(tty, promptPrefix, buf, cursor, mode)
		case 0x15: // Ctrl-U: clear line
			buf = buf[:0]
			cursor = 0
			redrawLine(tty, promptPrefix, buf, cursor, mode)
		case 0x1b: // Escape or escape sequence
			// In masked-echo mode (password / PIN / recovery-code prompts)
			// cursor-editing actions are invisible: every char renders as a
			// bullet, so left/right/home/end movement produces no visible
			// feedback. Worse, if a stale byte happens to be queued behind
			// the ESC (slow terminal, prior raw-mode handoff), parseEscape-
			// Sequence can read ESC+byte as actionRight/Left and *silently*
			// consume the press — the user mashes ESC repeatedly thinking
			// it's broken. Treat any ESC in masked mode as a skip; editing
			// ergonomics don't exist here to preserve.
			if mode == echoMask {
				// Drain any follow-up bytes belonging to this sequence so
				// they don't leak into the next read.
				_, _ = readEscapeSeqBytes(tty)
				fmt.Fprint(tty, "\r\n")
				return nil, provider.ErrSkipped
			}
			action := parseEscapeSequence(tty)
			switch action {
			case actionSkip:
				fmt.Fprint(tty, "\r\n")
				return nil, provider.ErrSkipped
			case actionLeft:
				if cursor > 0 {
					cursor--
					redrawLine(tty, promptPrefix, buf, cursor, mode)
				}
			case actionRight:
				if cursor < len(buf) {
					cursor++
					redrawLine(tty, promptPrefix, buf, cursor, mode)
				}
			case actionHome:
				cursor = 0
				redrawLine(tty, promptPrefix, buf, cursor, mode)
			case actionEnd:
				cursor = len(buf)
				redrawLine(tty, promptPrefix, buf, cursor, mode)
			case actionDelete:
				if cursor < len(buf) {
					buf = append(buf[:cursor], buf[cursor+1:]...)
					redrawLine(tty, promptPrefix, buf, cursor, mode)
				}
			case actionNone:
				// Unknown ESC-sequence in echoPlain mode — treat as skip.
				// A user who pressed ESC wants to move on; silently
				// ignoring leaves them staring at an unresponsive prompt.
				fmt.Fprint(tty, "\r\n")
				return nil, provider.ErrSkipped
			}
		case 0x7F, 0x08: // Backspace
			if cursor > 0 {
				buf = append(buf[:cursor-1], buf[cursor:]...)
				cursor--
				redrawLine(tty, promptPrefix, buf, cursor, mode)
			}
		default:
			if b[0] >= 0x20 && b[0] < 0x7F {
				// Insert at cursor position. Use a pre-sized slice to avoid
				// aliasing issues when cursor < len(buf).
				next := make([]byte, 0, len(buf)+1)
				next = append(next, buf[:cursor]...)
				next = append(next, b[0])
				next = append(next, buf[cursor:]...)
				buf = next
				cursor++
				redrawLine(tty, promptPrefix, buf, cursor, mode)
			}
		}
	}
}

// redrawLine repaints the prompt line after a buffer/cursor edit.
// \r returns to column 0, \033[2K clears, then we reprint the prompt and
// the display form of the buffer (literal or masked), and finally reposition
// the cursor if it isn't at end-of-line.
func redrawLine(tty *os.File, promptPrefix string, buf []byte, cursor int, mode echoMode) {
	fmt.Fprint(tty, "\r\033[2K")
	fmt.Fprint(tty, promptPrefix)
	switch mode {
	case echoMask:
		fmt.Fprint(tty, strings.Repeat(maskChar, len(buf)))
	case echoPlain:
		fmt.Fprint(tty, string(buf))
	}
	if back := len(buf) - cursor; back > 0 {
		fmt.Fprintf(tty, "\033[%dD", back)
	}
}

// parseEscapeSequence interprets bytes that follow a 0x1b. Returns the
// parsed editor action, or actionSkip when the Escape was standalone.
// Unknown sequences return actionNone so the main loop ignores them.
func parseEscapeSequence(tty *os.File) editAction {
	seq, ok := readEscapeSeqBytes(tty)
	if !ok {
		return actionSkip
	}

	// Common CSI sequences: ESC [ X
	if len(seq) >= 2 && seq[0] == '[' {
		switch seq[1] {
		case 'A', 'B': // up/down — not used for editing
			return actionNone
		case 'C':
			return actionRight
		case 'D':
			return actionLeft
		case 'H':
			return actionHome
		case 'F':
			return actionEnd
		case '3':
			if len(seq) >= 3 && seq[2] == '~' {
				return actionDelete
			}
		case '1', '7':
			return actionHome
		case '4', '8':
			return actionEnd
		}
	}
	return actionNone
}

// readEscapeSeqBytes polls for bytes queued after a 0x1b within a short
// window and returns them. Returns ok=false when no bytes arrive, meaning
// the previous 0x1b was a standalone Escape keypress.
func readEscapeSeqBytes(tty *os.File) ([]byte, bool) {
	fd := int(tty.Fd()) //nolint:gosec
	var all []byte
	var scratch [16]byte
	for {
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}} //nolint:gosec
		n, err := unix.Poll(fds, 30)                               // 30ms window
		if err != nil || n == 0 {
			if len(all) == 0 {
				return nil, false
			}
			return all, true
		}
		r, err := tty.Read(scratch[:])
		if err != nil || r == 0 {
			if len(all) == 0 {
				return nil, false
			}
			return all, true
		}
		all = append(all, scratch[:r]...)
		// Bound accumulation in pathological cases.
		if len(all) >= 16 {
			return all, true
		}
	}
}

func (pw *Writer) writef(format string, args ...any) {
	fmt.Fprintf(pw.w, format, args...)
}

func (pw *Writer) green(s string) string {
	if pw.color {
		return "\033[32m" + s + "\033[0m"
	}
	return s
}

func (pw *Writer) yellow(s string) string {
	if pw.color {
		return "\033[33m" + s + "\033[0m"
	}
	return s
}

func (pw *Writer) red(s string) string {
	if pw.color {
		return "\033[31m" + s + "\033[0m"
	}
	return s
}

func (pw *Writer) dim(s string) string {
	if pw.color {
		return "\033[90m" + s + "\033[0m"
	}
	return s
}
