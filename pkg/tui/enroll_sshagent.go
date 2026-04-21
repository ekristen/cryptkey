package tui

import (
	"context"
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/ekristen/cryptkey/pkg/enrollment"
	"github.com/ekristen/cryptkey/pkg/provider"
	"github.com/ekristen/cryptkey/pkg/provider/sshagent"
)

// enrollSSHAgent is a self-contained sub-model: scan for ed25519 keys in the
// running agent → select (when >1) → sign → done.
type enrollSSHAgent struct {
	ctx      context.Context
	provider provider.Provider
	id       string
	options  map[string]string

	state    sshAgentState
	keys     []sshagent.AgentKeyInfo
	cur      int
	errorMsg string

	result *enrollment.Enrollment
	err    error
}

type sshAgentState int

const (
	sshAgentStateScanning sshAgentState = iota
	sshAgentStateSelect
	sshAgentStateEnrolling
	sshAgentStateDone
	sshAgentStateCanceled
)

// agentKeysMsg is returned by the agent key scan command.
type agentKeysMsg struct {
	keys []sshagent.AgentKeyInfo
	err  error
}

// sshAgentEnrollCompletedMsg is emitted when the background enroll finishes.
type sshAgentEnrollCompletedMsg struct {
	result *enrollment.Enrollment
	err    error
}

// scanAgentKeys returns a tea.Cmd that lists SSH agent keys.
func scanAgentKeys() tea.Msg {
	keys, err := sshagent.ListEd25519Keys()
	return agentKeysMsg{keys: keys, err: err}
}

func newEnrollSSHAgent(ctx context.Context, p provider.Provider, id string, options map[string]string) enrollSSHAgent {
	return enrollSSHAgent{
		ctx:      ctx,
		provider: p,
		id:       id,
		options:  options,
		state:    sshAgentStateScanning,
	}
}

func (m enrollSSHAgent) Init() tea.Cmd { return scanAgentKeys }

func (m enrollSSHAgent) Update(msg tea.Msg) (enrollSSHAgent, tea.Cmd) {
	switch msg := msg.(type) {
	case agentKeysMsg:
		return m.handleKeys(msg)
	case sshAgentEnrollCompletedMsg:
		m.result = msg.result
		m.err = msg.err
		m.state = sshAgentStateDone
		return m, nil
	case tea.KeyMsg:
		if m.state == sshAgentStateSelect {
			return m.handleSelect(msg.String())
		}
	}
	return m, nil
}

//nolint:dupl // structurally similar to enrollFIDO2.handleDevices but on a different type
func (m enrollSSHAgent) handleKeys(msg agentKeysMsg) (enrollSSHAgent, tea.Cmd) {
	if msg.err != nil {
		m.errorMsg = msg.err.Error()
		m.state = sshAgentStateCanceled
		return m, nil
	}
	if len(msg.keys) == 0 {
		m.errorMsg = "No Ed25519 keys found in SSH agent"
		m.state = sshAgentStateCanceled
		return m, nil
	}
	m.keys = msg.keys
	if len(msg.keys) == 1 {
		m.cur = 0
		return m.startEnroll()
	}
	m.state = sshAgentStateSelect
	return m, nil
}

func (m enrollSSHAgent) handleSelect(key string) (enrollSSHAgent, tea.Cmd) {
	switch key {
	case keyUp, "k":
		if m.cur > 0 {
			m.cur--
		}
	case keyDown, "j":
		if m.cur < len(m.keys)-1 {
			m.cur++
		}
	case keyEnter:
		return m.startEnroll()
	case keyEscape:
		m.state = sshAgentStateCanceled
	}
	return m, nil
}

func (m enrollSSHAgent) startEnroll() (enrollSSHAgent, tea.Cmd) {
	m.state = sshAgentStateEnrolling
	selected := m.keys[m.cur]

	ctx := provider.WithEnrollOptions(m.ctx, m.options)
	ctx = context.WithValue(ctx, provider.CtxSilent, true)
	ctx = context.WithValue(ctx, provider.CtxSSHAgentKeyFingerprint, selected.Fingerprint)

	p := m.provider
	id := m.id
	return m, func() tea.Msg {
		res, err := enrollment.EnrollProvider(ctx, p, id)
		return sshAgentEnrollCompletedMsg{result: res, err: err}
	}
}

func (m enrollSSHAgent) View() string {
	var b strings.Builder
	switch m.state {
	case sshAgentStateScanning:
		b.WriteString(highlightStyle.Render("Listing SSH agent keys..."))
		b.WriteString("\n")
	case sshAgentStateSelect:
		b.WriteString("Select Ed25519 key from SSH agent:\n\n")
		for i, k := range m.keys {
			cursor := indentTwo
			style := dimStyle
			if i == m.cur {
				cursor = highlightStyle.Render("> ")
				style = highlightStyle
			}
			label := k.Fingerprint
			if k.Comment != "" {
				label = fmt.Sprintf("%s %s", k.Fingerprint, k.Comment)
			}
			fmt.Fprintf(&b, "%s%s\n", cursor, style.Render(label))
		}
		b.WriteString("\n")
		b.WriteString(dimStyle.Render("↑/↓ navigate • enter select • esc cancel"))
	case sshAgentStateEnrolling:
		b.WriteString(highlightStyle.Render("Signing with SSH agent..."))
		b.WriteString("\n")
	case sshAgentStateDone, sshAgentStateCanceled:
		// Parent unmounts once Done() is true.
	}
	if m.errorMsg != "" {
		fmt.Fprintf(&b, "\n%s\n", errorStyle.Render(m.errorMsg))
	}
	return b.String()
}

func (m enrollSSHAgent) Done() bool {
	return m.state == sshAgentStateDone || m.state == sshAgentStateCanceled
}

func (m enrollSSHAgent) Canceled() bool {
	return m.state == sshAgentStateCanceled
}

func (m enrollSSHAgent) Result() (*enrollment.Enrollment, error) {
	return m.result, m.err
}
