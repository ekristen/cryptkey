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

// unlockPassphrase is the derive-time counterpart to enrollPassphrase: a
// single-field masked entry, submit → provider.Derive, returns the 32-byte
// secret or a skip/error. No confirm step (user is asserting a known
// passphrase, not committing to a new one).
//
// Shared between rekey's unlock phase and its fill-in phase for kept
// passphrase providers.
type unlockPassphrase struct {
	ctx      context.Context
	provider provider.Provider
	params   map[string]string
	id       string // used only for display

	state    unlockPassphraseState
	input    textinput.Model
	errorMsg string

	secret []byte
	err    error
}

type unlockPassphraseState int

const (
	unlockPassphraseStateEntry unlockPassphraseState = iota
	unlockPassphraseStateDeriving
	unlockPassphraseStateDone
	unlockPassphraseStateSkipped
)

// unlockPassphraseCompletedMsg is emitted when the derive goroutine finishes.
type unlockPassphraseCompletedMsg struct {
	secret []byte
	err    error
}

// newUnlockPassphrase builds the sub-model. params are the provider config
// params (salt, argon_time, …). id is the profile-provider ID, used for
// display only.
func newUnlockPassphrase(ctx context.Context, p provider.Provider, id string, params map[string]string) unlockPassphrase {
	ti := newPasswordInput(256)
	// Focus must be set on the addressable local `ti` — not inside a
	// value-receiver Init — so the stored struct carries focus=true.
	// Otherwise textinput.Update early-returns on the unfocused copy and
	// no keystrokes land.
	ti.Focus()
	return unlockPassphrase{
		ctx:      ctx,
		provider: p,
		params:   params,
		id:       id,
		state:    unlockPassphraseStateEntry,
		input:    ti,
	}
}

// Init returns the cursor-blink command. Focus itself is applied in the
// constructor above — see the comment there.
func (m unlockPassphrase) Init() tea.Cmd { return textinput.Blink }

//nolint:dupl // mirror of unlockRecovery.Update — same shape, distinct concrete types
func (m unlockPassphrase) Update(msg tea.Msg) (unlockPassphrase, tea.Cmd) {
	switch msg := msg.(type) {
	case unlockPassphraseCompletedMsg:
		m.secret = msg.secret
		m.err = msg.err
		m.state = unlockPassphraseStateDone
		return m, nil
	case tea.KeyMsg:
		if m.state == unlockPassphraseStateEntry {
			return m.handleEntry(msg)
		}
	}
	if m.state == unlockPassphraseStateEntry {
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m unlockPassphrase) handleEntry(msg tea.KeyMsg) (unlockPassphrase, tea.Cmd) {
	switch msg.String() {
	case keyEnter:
		val := m.input.Value()
		if val == "" {
			m.errorMsg = errPassphraseEmpty.Error()
			return m, nil
		}
		pass := []byte(val)
		m.input.SetValue("")
		m.input.Blur()
		m.errorMsg = ""
		m.state = unlockPassphraseStateDeriving
		cmd := m.runDerive(pass)
		return m, cmd
	case keyEscape:
		m.input.SetValue("")
		m.input.Blur()
		m.state = unlockPassphraseStateSkipped
		return m, nil
	default:
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		return m, cmd
	}
}

// runDerive returns a tea.Cmd that invokes the provider's Derive with the
// given passphrase in context. The passphrase copy inside ctx is wiped by
// the provider once Argon2 finishes.
func (m unlockPassphrase) runDerive(passphrase []byte) tea.Cmd {
	ctx := context.WithValue(m.ctx, provider.CtxPassphrase, passphrase)
	ctx = context.WithValue(ctx, provider.CtxSilent, true)
	p := m.provider
	params := m.params
	return func() tea.Msg {
		secret, err := p.Derive(ctx, params)
		crypto.WipeBytes(passphrase)
		return unlockPassphraseCompletedMsg{secret: secret, err: err}
	}
}

func (m unlockPassphrase) View() string {
	var b strings.Builder
	switch m.state {
	case unlockPassphraseStateEntry:
		fmt.Fprintf(&b, "Passphrase for %s: %s\n", highlightStyle.Render(m.id), m.input.View())
		b.WriteString("\n")
		b.WriteString(dimStyle.Render("enter to unlock • esc to skip"))
	case unlockPassphraseStateDeriving:
		fmt.Fprintf(&b, "Deriving with Argon2id (this may take a moment)...")
		b.WriteString("\n")
	case unlockPassphraseStateDone, unlockPassphraseStateSkipped:
		// Parent unmounts once Done() is true.
	}
	if m.errorMsg != "" {
		fmt.Fprintf(&b, "\n%s\n", errorStyle.Render(m.errorMsg))
	}
	return b.String()
}

func (m unlockPassphrase) Done() bool {
	return m.state == unlockPassphraseStateDone || m.state == unlockPassphraseStateSkipped
}

// Skipped reports whether the user pressed esc instead of providing a
// passphrase. Distinct from an error — the share simply won't be recovered
// from this provider.
func (m unlockPassphrase) Skipped() bool {
	return m.state == unlockPassphraseStateSkipped
}

// Secret returns the 32-byte derived secret and any error. Only meaningful
// when Done() returns true and Skipped() returns false.
func (m unlockPassphrase) Secret() ([]byte, error) {
	return m.secret, m.err
}
