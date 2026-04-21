package tui

import (
	"context"
	"fmt"
	"strings"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"

	"github.com/ekristen/cryptkey/pkg/provider"
)

// unlockPIV is the derive-time sub-model for the piv provider.
// Flow: PIN entry (empty means "default PIN 123456") → touch with
// progress → done. Mirrors unlockFIDO2 structurally: pre-seed the
// provider's CtxPIVPIN + CtxPIVSerial so it doesn't fall back to
// /dev/tty, and disable its retry path so wrong-PIN errors come back
// immediately for us to re-prompt in-TUI.
type unlockPIV struct {
	ctx      context.Context
	provider provider.Provider
	id       string
	params   map[string]string

	state       unlockPIVState
	input       textinput.Model
	pin         string
	pinAttempts int
	progressCh  chan string
	progressLog []string
	errorMsg    string

	secret []byte
	err    error
}

type unlockPIVState int

const (
	unlockPIVStatePINEntry unlockPIVState = iota
	unlockPIVStateDeriving
	unlockPIVStateDone
	unlockPIVStateSkipped
)

type unlockPIVCompletedMsg struct {
	secret []byte
	err    error
}

type unlockPIVProgressMsg string

func newUnlockPIV(ctx context.Context, p provider.Provider, id string, params map[string]string) unlockPIV {
	ti := newPasswordInput(64)
	// Focus the addressable local; see unlockPassphrase for why.
	ti.Focus()
	return unlockPIV{
		ctx:      ctx,
		provider: p,
		id:       id,
		params:   params,
		state:    unlockPIVStatePINEntry,
		input:    ti,
	}
}

func (m unlockPIV) Init() tea.Cmd { return textinput.Blink }

//nolint:dupl // mirror of unlockFIDO2.Update — distinct concrete types
func (m unlockPIV) Update(msg tea.Msg) (unlockPIV, tea.Cmd) {
	switch msg := msg.(type) {
	case unlockPIVCompletedMsg:
		return m.handleCompleted(msg)
	case unlockPIVProgressMsg:
		m.progressLog = appendProgress(m.progressLog, string(msg))
		if m.progressCh != nil {
			return m, listenProgress(m.progressCh, func(s string) unlockPIVProgressMsg { return unlockPIVProgressMsg(s) })
		}
		return m, nil
	case tea.KeyMsg:
		if m.state == unlockPIVStatePINEntry {
			return m.handlePINEntry(msg)
		}
	}
	if m.state == unlockPIVStatePINEntry {
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		return m, cmd
	}
	return m, nil
}

//nolint:dupl // mirror of enrollPIV.handlePINEntry — distinct phase/state
func (m unlockPIV) handlePINEntry(msg tea.KeyMsg) (unlockPIV, tea.Cmd) {
	switch msg.String() {
	case keyEnter:
		m.pin = m.input.Value()
		m.input.SetValue("")
		m.input.Blur()
		m.errorMsg = ""
		return m.startDerive()
	case keyEscape:
		m.input.SetValue("")
		m.input.Blur()
		m.state = unlockPIVStateSkipped
		return m, nil
	default:
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		return m, cmd
	}
}

func (m unlockPIV) startDerive() (unlockPIV, tea.Cmd) {
	m.state = unlockPIVStateDeriving
	m.progressLog = nil

	ctx := context.WithValue(m.ctx, provider.CtxSilent, true)
	// Always set the PIN key — even when empty — so the provider treats
	// "use default PIN" as a pre-collected answer and does not fall back
	// to prompting on /dev/tty.
	ctx = context.WithValue(ctx, provider.CtxPIVPIN, m.pin)
	if serial := m.params["serial"]; serial != "" {
		ctx = context.WithValue(ctx, provider.CtxPIVSerial, serial)
	}

	// Same short-circuit trick as unlockFIDO2: a stubbed CtxPromptPassword
	// that always returns ErrSkipped prevents the provider from falling
	// through to a /dev/tty prompt on a wrong PIN. The TUI handles retry
	// itself by bouncing back to the PIN-entry state.
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
		return unlockPIVCompletedMsg{secret: secret, err: err}
	}
	return m, tea.Batch(deriveCmd, listenProgress(progressCh, func(s string) unlockPIVProgressMsg { return unlockPIVProgressMsg(s) }))
}

//nolint:dupl // mirror of unlockFIDO2.handleDeriveCompleted — distinct concrete types
func (m unlockPIV) handleCompleted(msg unlockPIVCompletedMsg) (unlockPIV, tea.Cmd) {
	m.progressCh = nil
	if msg.err != nil {
		if isRetryablePINError(msg.err) && m.pinAttempts+1 < unlockMaxPINAttempts {
			m.pinAttempts++
			m.errorMsg = fmt.Sprintf("wrong PIN — attempt %d/%d, esc to skip",
				m.pinAttempts+1, unlockMaxPINAttempts)
			m.state = unlockPIVStatePINEntry
			m.input.SetValue("")
			return m, m.input.Focus()
		}
		m.err = msg.err
		m.state = unlockPIVStateDone
		return m, nil
	}
	m.secret = msg.secret
	m.state = unlockPIVStateDone
	return m, nil
}

func (m unlockPIV) View() string {
	var b strings.Builder
	switch m.state {
	case unlockPIVStatePINEntry:
		fmt.Fprintf(&b, "PIV PIN for %s: %s\n", highlightStyle.Render(m.id), m.input.View())
		b.WriteString("\n")
		if m.errorMsg != "" {
			b.WriteString(errorStyle.Render(m.errorMsg))
			b.WriteString("\n")
		} else {
			b.WriteString(dimStyle.Render("enter to continue (empty = default 123456) • esc to skip"))
		}
	case unlockPIVStateDeriving:
		renderProgressChecklist(&b, m.progressLog)
	case unlockPIVStateDone, unlockPIVStateSkipped:
		// Parent unmounts once Done() is true.
	}
	return b.String()
}

func (m unlockPIV) Done() bool {
	return m.state == unlockPIVStateDone || m.state == unlockPIVStateSkipped
}

func (m unlockPIV) Skipped() bool {
	return m.state == unlockPIVStateSkipped
}

func (m unlockPIV) Secret() ([]byte, error) {
	return m.secret, m.err
}
