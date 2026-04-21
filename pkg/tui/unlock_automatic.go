package tui

import (
	"context"
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/ekristen/cryptkey/pkg/provider"
)

// unlockAutomatic is the unlock sub-model for providers whose Derive
// takes no interactive input — TPM (sealed to the host's TPM state) and
// SSH agent (signs a challenge with an already-loaded key). The sub-model
// shows a single-line status while Derive runs in a goroutine, then
// reports the secret back to the parent.
//
// Shared between tpm and ssh-agent: both are zero-input from the user's
// perspective at derive time, so there's no need for a distinct state
// machine per type.
type unlockAutomatic struct {
	ctx      context.Context
	provider provider.Provider
	id       string
	params   map[string]string
	label    string // e.g. "Unlocking with TPM..." / "Signing with SSH agent..."

	state    unlockAutomaticState
	errorMsg string

	secret []byte
	err    error
}

type unlockAutomaticState int

const (
	unlockAutomaticStateDeriving unlockAutomaticState = iota
	unlockAutomaticStateDone
	unlockAutomaticStateSkipped
)

// unlockAutomaticCompletedMsg is emitted when Derive finishes.
type unlockAutomaticCompletedMsg struct {
	secret []byte
	err    error
}

func newUnlockAutomatic(ctx context.Context, p provider.Provider, id string, params map[string]string, label string) unlockAutomatic {
	return unlockAutomatic{
		ctx:      ctx,
		provider: p,
		id:       id,
		params:   params,
		label:    label,
		state:    unlockAutomaticStateDeriving,
	}
}

func (m unlockAutomatic) Init() tea.Cmd {
	ctx := context.WithValue(m.ctx, provider.CtxSilent, true)
	p := m.provider
	params := m.params
	return func() tea.Msg {
		secret, err := p.Derive(ctx, params)
		return unlockAutomaticCompletedMsg{secret: secret, err: err}
	}
}

func (m unlockAutomatic) Update(msg tea.Msg) (unlockAutomatic, tea.Cmd) {
	if completed, ok := msg.(unlockAutomaticCompletedMsg); ok {
		m.secret = completed.secret
		m.err = completed.err
		m.state = unlockAutomaticStateDone
		return m, nil
	}
	return m, nil
}

func (m unlockAutomatic) View() string {
	var b strings.Builder
	switch m.state {
	case unlockAutomaticStateDeriving:
		b.WriteString(highlightStyle.Render(m.label))
		b.WriteString("\n")
	case unlockAutomaticStateDone, unlockAutomaticStateSkipped:
		// Parent unmounts once Done() is true.
	}
	if m.errorMsg != "" {
		fmt.Fprintf(&b, "\n%s\n", errorStyle.Render(m.errorMsg))
	}
	return b.String()
}

func (m unlockAutomatic) Done() bool {
	return m.state == unlockAutomaticStateDone || m.state == unlockAutomaticStateSkipped
}

// Skipped is always false for automatic providers — there's no skip gesture
// during hardware-free sync derivation. Provided for interface symmetry
// with the interactive unlock sub-models.
func (m unlockAutomatic) Skipped() bool { return false }

func (m unlockAutomatic) Secret() ([]byte, error) {
	return m.secret, m.err
}
