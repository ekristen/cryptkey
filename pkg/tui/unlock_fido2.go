package tui

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"

	libfido2 "github.com/keys-pub/go-libfido2"

	"github.com/ekristen/cryptkey/pkg/provider"
)

// unlockFIDO2 is the derive-time sub-model for the fido2 provider.
// Flow: PIN entry (skipped when uv=discouraged) → touch with progress
// → done. PIN retry is handled at the TUI layer by re-rendering the
// PIN entry screen after a wrong-PIN error; the provider's own retry
// loop is short-circuited to a single attempt via a stubbed
// CtxPromptPassword that always reports ErrSkipped, otherwise the
// provider would fall back to /dev/tty and collide with bubbletea.
type unlockFIDO2 struct {
	ctx      context.Context
	provider provider.Provider
	id       string
	params   map[string]string

	state       unlockFIDO2State
	input       textinput.Model
	pin         string
	pinAttempts int
	progressCh  chan string
	progressLog []string
	errorMsg    string

	secret []byte
	err    error
}

type unlockFIDO2State int

const (
	unlockFIDO2StatePINEntry unlockFIDO2State = iota
	unlockFIDO2StateDeriving
	unlockFIDO2StateDone
	unlockFIDO2StateSkipped
)

type unlockFIDO2CompletedMsg struct {
	secret []byte
	err    error
}

type unlockFIDO2ProgressMsg string

const unlockMaxPINAttempts = 3

func newUnlockFIDO2(ctx context.Context, p provider.Provider, id string, params map[string]string) unlockFIDO2 {
	ti := newPasswordInput(64)
	// Focus the addressable local now (only when uv !=  discouraged).
	// See unlockPassphrase for why this can't be in Init.
	if params["uv"] != uvDiscouraged {
		ti.Focus()
	}
	return unlockFIDO2{
		ctx:      ctx,
		provider: p,
		id:       id,
		params:   params,
		state:    unlockFIDO2StatePINEntry,
		input:    ti,
	}
}

// Init emits the cursor-blink command when PIN entry is active; the focus
// bit itself is already set by the constructor.
func (m unlockFIDO2) Init() tea.Cmd {
	if m.params["uv"] == uvDiscouraged {
		return nil
	}
	return textinput.Blink
}

//nolint:dupl // mirror of unlockPIV.Update — distinct concrete types
func (m unlockFIDO2) Update(msg tea.Msg) (unlockFIDO2, tea.Cmd) {
	switch msg := msg.(type) {
	case unlockFIDO2CompletedMsg:
		return m.handleDeriveCompleted(msg)
	case unlockFIDO2ProgressMsg:
		m.progressLog = appendProgress(m.progressLog, string(msg))
		if m.progressCh != nil {
			return m, listenProgress(m.progressCh, func(s string) unlockFIDO2ProgressMsg { return unlockFIDO2ProgressMsg(s) })
		}
		return m, nil
	case tea.KeyMsg:
		if m.state == unlockFIDO2StatePINEntry {
			return m.handlePINEntry(msg)
		}
	}
	if m.state == unlockFIDO2StatePINEntry {
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m unlockFIDO2) handlePINEntry(msg tea.KeyMsg) (unlockFIDO2, tea.Cmd) {
	switch msg.String() {
	case keyEnter:
		m.pin = m.input.Value()
		m.input.SetValue("")
		m.input.Blur()
		if m.params["uv"] == uvRequired && m.pin == "" {
			m.errorMsg = "PIN is required"
			return m, m.input.Focus()
		}
		m.errorMsg = ""
		return m.startDerive()
	case keyEscape:
		m.input.SetValue("")
		m.input.Blur()
		m.state = unlockFIDO2StateSkipped
		return m, nil
	default:
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		return m, cmd
	}
}

// startDerive kicks off the background provider.Derive. The stubbed
// CtxPromptPassword intercepts the provider's retry path so wrong-PIN
// errors bubble up immediately; the TUI handles retry itself.
func (m unlockFIDO2) startDerive() (unlockFIDO2, tea.Cmd) {
	m.state = unlockFIDO2StateDeriving
	m.progressLog = nil

	ctx := context.WithValue(m.ctx, provider.CtxSilent, true)
	if m.pin != "" {
		ctx = context.WithValue(ctx, provider.CtxFIDO2PIN, m.pin)
	} else {
		// An empty PIN is a legitimate answer for uv=preferred ("proceed
		// without PIN"). Seed the key so fido2.PreDerive sees it and does
		// not prompt on /dev/tty.
		ctx = context.WithValue(ctx, provider.CtxFIDO2PIN, "")
	}

	// Short-circuit the provider's built-in PIN retry: it would otherwise
	// fall back to /dev/tty when CtxPromptPassword is absent, clobbering
	// the alt-screen. Returning ErrSkipped from the stub makes the
	// provider's retry loop emit ErrSkipped back to us after the first
	// wrong PIN; we detect that and re-prompt at the TUI level.
	ctx = context.WithValue(ctx, provider.CtxPromptPassword,
		func(_, _, _ string) (string, error) {
			return "", provider.ErrSkipped
		})

	progressCh := make(chan string, 4)
	m.progressCh = progressCh
	ctx = context.WithValue(ctx, provider.CtxProgressFunc, func(msg string) {
		progressCh <- msg
	})

	p := m.provider
	params := m.params
	deriveCmd := func() tea.Msg {
		secret, err := p.Derive(ctx, params)
		close(progressCh)
		return unlockFIDO2CompletedMsg{secret: secret, err: err}
	}
	return m, tea.Batch(deriveCmd, listenProgress(progressCh, func(s string) unlockFIDO2ProgressMsg { return unlockFIDO2ProgressMsg(s) }))
}

//nolint:dupl // mirror of unlockPIV.handleCompleted — distinct concrete types
func (m unlockFIDO2) handleDeriveCompleted(msg unlockFIDO2CompletedMsg) (unlockFIDO2, tea.Cmd) {
	m.progressCh = nil

	if msg.err != nil {
		// Wrong-PIN errors surface either as provider.ErrSkipped (our
		// retry stub ran) or as a wrapped libfido2.ErrPinInvalid (the
		// final attempt in the provider's retry loop). In either case
		// we re-prompt in the TUI, up to unlockMaxPINAttempts.
		if isRetryablePINError(msg.err) && m.pinAttempts+1 < unlockMaxPINAttempts {
			m.pinAttempts++
			m.errorMsg = fmt.Sprintf("wrong PIN — attempt %d/%d, esc to skip",
				m.pinAttempts+1, unlockMaxPINAttempts)
			m.state = unlockFIDO2StatePINEntry
			m.input.SetValue("")
			return m, m.input.Focus()
		}
		// Not a retryable PIN error, or we've burned through our attempts.
		m.err = msg.err
		m.state = unlockFIDO2StateDone
		return m, nil
	}

	m.secret = msg.secret
	m.state = unlockFIDO2StateDone
	return m, nil
}

// isRetryablePINError reports whether err looks like a wrong-PIN response
// from either libfido2 directly or via our retry-stub's ErrSkipped bounce.
func isRetryablePINError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, libfido2.ErrPinInvalid) {
		return true
	}
	if errors.Is(err, provider.ErrSkipped) {
		return true
	}
	return false
}

func (m unlockFIDO2) View() string {
	var b strings.Builder
	switch m.state {
	case unlockFIDO2StatePINEntry:
		fmt.Fprintf(&b, "FIDO2 PIN for %s: %s\n", highlightStyle.Render(m.id), m.input.View())
		b.WriteString("\n")
		if m.errorMsg != "" {
			b.WriteString(errorStyle.Render(m.errorMsg))
			b.WriteString("\n")
		} else {
			b.WriteString(dimStyle.Render("enter to continue • esc to skip"))
		}
	case unlockFIDO2StateDeriving:
		renderProgressChecklist(&b, m.progressLog)
	case unlockFIDO2StateDone, unlockFIDO2StateSkipped:
		// Parent unmounts once Done() is true.
	}
	return b.String()
}

func (m unlockFIDO2) Done() bool {
	return m.state == unlockFIDO2StateDone || m.state == unlockFIDO2StateSkipped
}

func (m unlockFIDO2) Skipped() bool {
	return m.state == unlockFIDO2StateSkipped
}

func (m unlockFIDO2) Secret() ([]byte, error) {
	return m.secret, m.err
}
