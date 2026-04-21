package tui

import (
	"context"
	"fmt"
	"strings"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"

	"github.com/ekristen/cryptkey/pkg/crypto"
	"github.com/ekristen/cryptkey/pkg/provider"
)

// unlockRecovery is the unlock sub-model for the recovery-code provider.
// Shape: single masked entry (the recovery code), enter → provider.Derive,
// secret returned. No confirm — the user is asserting a known code.
//
// Mirrors unlockPassphrase structurally; the difference is that the
// provider consumes the code via CtxPassphrase (recovery reuses that key
// internally) and runs its own Argon2 derivation.
type unlockRecovery struct {
	ctx      context.Context
	provider provider.Provider
	params   map[string]string
	id       string

	state    unlockRecoveryState
	input    textinput.Model
	errorMsg string

	secret []byte
	err    error
}

type unlockRecoveryState int

const (
	unlockRecoveryStateEntry unlockRecoveryState = iota
	unlockRecoveryStateDeriving
	unlockRecoveryStateDone
	unlockRecoveryStateSkipped
)

type unlockRecoveryCompletedMsg struct {
	secret []byte
	err    error
}

func newUnlockRecovery(ctx context.Context, p provider.Provider, id string, params map[string]string) unlockRecovery {
	ti := newPasswordInput(128)
	// Focus the addressable local before returning; see the note on
	// unlockPassphrase for why this can't live inside a value-receiver
	// Init.
	ti.Focus()
	return unlockRecovery{
		ctx:      ctx,
		provider: p,
		params:   params,
		id:       id,
		state:    unlockRecoveryStateEntry,
		input:    ti,
	}
}

func (m unlockRecovery) Init() tea.Cmd { return textinput.Blink }

//nolint:dupl // mirror of unlockPassphrase.Update — same shape, distinct concrete types
func (m unlockRecovery) Update(msg tea.Msg) (unlockRecovery, tea.Cmd) {
	switch msg := msg.(type) {
	case unlockRecoveryCompletedMsg:
		m.secret = msg.secret
		m.err = msg.err
		m.state = unlockRecoveryStateDone
		return m, nil
	case tea.KeyMsg:
		if m.state == unlockRecoveryStateEntry {
			return m.handleEntry(msg)
		}
	}
	if m.state == unlockRecoveryStateEntry {
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m unlockRecovery) handleEntry(msg tea.KeyMsg) (unlockRecovery, tea.Cmd) {
	switch msg.String() {
	case keyEnter:
		val := m.input.Value()
		if val == "" {
			m.errorMsg = "recovery code cannot be empty"
			return m, nil
		}
		code := []byte(val)
		m.input.SetValue("")
		m.input.Blur()
		m.errorMsg = ""
		m.state = unlockRecoveryStateDeriving
		cmd := m.runDerive(code)
		return m, cmd
	case keyEscape:
		m.input.SetValue("")
		m.input.Blur()
		m.state = unlockRecoveryStateSkipped
		return m, nil
	default:
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		return m, cmd
	}
}

// runDerive returns a tea.Cmd that invokes the provider's Derive with the
// code on context. The byte copy is wiped by the provider once Argon2
// finishes.
func (m unlockRecovery) runDerive(code []byte) tea.Cmd {
	ctx := context.WithValue(m.ctx, provider.CtxPassphrase, code)
	ctx = context.WithValue(ctx, provider.CtxSilent, true)
	p := m.provider
	params := m.params
	return func() tea.Msg {
		secret, err := p.Derive(ctx, params)
		crypto.WipeBytes(code)
		return unlockRecoveryCompletedMsg{secret: secret, err: err}
	}
}

func (m unlockRecovery) View() string {
	var b strings.Builder
	switch m.state {
	case unlockRecoveryStateEntry:
		fmt.Fprintf(&b, "Recovery code for %s: %s\n", highlightStyle.Render(m.id), m.input.View())
		b.WriteString("\n")
		b.WriteString(dimStyle.Render("enter to unlock • esc to skip"))
	case unlockRecoveryStateDeriving:
		b.WriteString("Deriving with Argon2id (this may take a moment)...\n")
	case unlockRecoveryStateDone, unlockRecoveryStateSkipped:
		// Parent unmounts once Done() is true.
	}
	if m.errorMsg != "" {
		fmt.Fprintf(&b, "\n%s\n", errorStyle.Render(m.errorMsg))
	}
	return b.String()
}

func (m unlockRecovery) Done() bool {
	return m.state == unlockRecoveryStateDone || m.state == unlockRecoveryStateSkipped
}

func (m unlockRecovery) Skipped() bool {
	return m.state == unlockRecoveryStateSkipped
}

func (m unlockRecovery) Secret() ([]byte, error) {
	return m.secret, m.err
}
