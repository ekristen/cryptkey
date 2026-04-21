package tui

import (
	"strings"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
)

// appendProgress appends msg to log, skipping empty strings and deduping
// against the previous entry so a provider re-emitting the same status
// doesn't pile up. Returns the new slice; callers assign back:
//
//	m.progressLog = appendProgress(m.progressLog, msg)
func appendProgress(log []string, msg string) []string {
	if msg == "" {
		return log
	}
	if n := len(log); n > 0 && log[n-1] == msg {
		return log
	}
	return append(log, msg)
}

// listenProgress returns a tea.Cmd that reads the next message from ch and
// wraps it in a component-specific tea.Msg type. When ch is closed the
// command returns nil (no message), letting the caller tree unwind naturally.
//
// The ~string constraint lets each component pass its own string-backed
// progress-msg type (e.g. type fido2ProgressMsg string).
func listenProgress[T ~string](ch chan string, wrap func(string) T) tea.Cmd {
	return func() tea.Msg {
		msg, ok := <-ch
		if !ok {
			return nil
		}
		return wrap(msg)
	}
}

// newPasswordInput builds a textinput configured for masked secret entry —
// password echo mode, bullet echo char, and the given character limit.
// Caller is responsible for calling Focus() on the addressable local before
// embedding the result in a model struct (focus set on the value copy would
// be lost when the struct is returned by value).
func newPasswordInput(charLimit int) textinput.Model {
	ti := textinput.New()
	ti.EchoMode = textinput.EchoPassword
	ti.EchoCharacter = '•'
	ti.CharLimit = charLimit
	return ti
}

// renderProgressChecklist writes a shared checklist view for in-flight
// background work: completed steps dim with a ✓, the active (last) step
// highlighted with a leading bullet. When the log is empty, a generic
// "Working..." placeholder is rendered.
func renderProgressChecklist(b *strings.Builder, log []string) {
	if len(log) == 0 {
		b.WriteString(highlightStyle.Render("Working..."))
		b.WriteString("\n")
		return
	}
	last := len(log) - 1
	for i, step := range log {
		if i < last {
			b.WriteString(successStyle.Render("  ✓ "))
			b.WriteString(dimStyle.Render(step))
		} else {
			b.WriteString(highlightStyle.Render("  • "))
			b.WriteString(highlightStyle.Render(step))
		}
		b.WriteString("\n")
	}
}
