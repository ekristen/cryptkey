package tui

import (
	"context"
	"fmt"
	"strings"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"

	"github.com/ekristen/cryptkey/pkg/crypto"
	"github.com/ekristen/cryptkey/pkg/provider"
	"github.com/ekristen/cryptkey/pkg/provider/sshkey"
)

// unlockSSHKey is the derive-time sub-model for the sshkey provider.
// Flow: edit the stored key path (or accept default) → probe the file
// for encryption → if encrypted, ask for the passphrase → run
// provider.Derive → return secret.
//
// Pre-populates CtxSSHKeyPath and (when needed) CtxSSHKeyPassphrase on
// the derive ctx so the provider doesn't fall back to /dev/tty prompts,
// which would collide with bubbletea's alt-screen.
type unlockSSHKey struct {
	ctx      context.Context
	provider provider.Provider
	params   map[string]string
	id       string

	state   unlockSSHKeyState
	pathBuf string
	passInp textinput.Model

	errorMsg string

	secret []byte
	err    error
}

type unlockSSHKeyState int

const (
	unlockSSHKeyStatePath unlockSSHKeyState = iota
	unlockSSHKeyStateProbing
	unlockSSHKeyStatePass
	unlockSSHKeyStateDeriving
	unlockSSHKeyStateDone
	unlockSSHKeyStateSkipped
)

type unlockSSHKeyProbeMsg struct {
	needsPass bool
	err       error
}

type unlockSSHKeyCompletedMsg struct {
	secret []byte
	err    error
}

func newUnlockSSHKey(ctx context.Context, p provider.Provider, id string, params map[string]string) unlockSSHKey {
	// Use the stored path as the default; the user can edit.
	path := params["path"]
	if path == "" {
		path = "~/.ssh/id_ed25519"
	}
	return unlockSSHKey{
		ctx:      ctx,
		provider: p,
		params:   params,
		id:       id,
		state:    unlockSSHKeyStatePath,
		pathBuf:  path,
		passInp:  newPasswordInput(256),
	}
}

func (m unlockSSHKey) Init() tea.Cmd { return nil }

//nolint:dupl // shape intentionally mirrors enrollSSHKey.Update; distinct types
func (m unlockSSHKey) Update(msg tea.Msg) (unlockSSHKey, tea.Cmd) {
	switch msg := msg.(type) {
	case unlockSSHKeyProbeMsg:
		return m.handleProbe(msg)
	case unlockSSHKeyCompletedMsg:
		m.secret = msg.secret
		m.err = msg.err
		m.state = unlockSSHKeyStateDone
		return m, nil
	case tea.KeyMsg:
		switch m.state {
		case unlockSSHKeyStatePath:
			return m.handlePath(msg.String())
		case unlockSSHKeyStatePass:
			return m.handlePass(msg)
		}
	}
	if m.state == unlockSSHKeyStatePass {
		var cmd tea.Cmd
		m.passInp, cmd = m.passInp.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m unlockSSHKey) handlePath(key string) (unlockSSHKey, tea.Cmd) {
	switch key {
	case keyEnter:
		m.state = unlockSSHKeyStateProbing
		path := m.pathBuf
		return m, func() tea.Msg {
			needs, err := sshkey.ProbeKeyFile(path)
			return unlockSSHKeyProbeMsg{needsPass: needs, err: err}
		}
	case keyEscape:
		m.state = unlockSSHKeyStateSkipped
		return m, nil
	case keyBackspace:
		if m.pathBuf != "" {
			m.pathBuf = m.pathBuf[:len(m.pathBuf)-1]
		}
	default:
		if len(key) == 1 {
			m.pathBuf += key
		}
	}
	return m, nil
}

func (m unlockSSHKey) handleProbe(msg unlockSSHKeyProbeMsg) (unlockSSHKey, tea.Cmd) {
	if msg.err != nil {
		m.errorMsg = msg.err.Error()
		m.state = unlockSSHKeyStatePath
		return m, nil
	}
	if msg.needsPass {
		m.state = unlockSSHKeyStatePass
		m.passInp.SetValue("")
		return m, m.passInp.Focus()
	}
	return m.startDerive(nil)
}

//nolint:dupl // shape intentionally mirrors enrollSSHKey.handlePassphrase; distinct types
func (m unlockSSHKey) handlePass(msg tea.KeyMsg) (unlockSSHKey, tea.Cmd) {
	switch msg.String() {
	case keyEnter:
		val := m.passInp.Value()
		if val == "" {
			m.errorMsg = errPassphraseEmpty.Error()
			return m, nil
		}
		pass := []byte(val)
		m.passInp.SetValue("")
		m.passInp.Blur()
		m.errorMsg = ""
		return m.startDerive(pass)
	case keyEscape:
		m.passInp.SetValue("")
		m.passInp.Blur()
		m.state = unlockSSHKeyStateSkipped
		return m, nil
	default:
		var cmd tea.Cmd
		m.passInp, cmd = m.passInp.Update(msg)
		return m, cmd
	}
}

func (m unlockSSHKey) startDerive(passphrase []byte) (unlockSSHKey, tea.Cmd) {
	m.state = unlockSSHKeyStateDeriving
	ctx := context.WithValue(m.ctx, provider.CtxSilent, true)
	ctx = context.WithValue(ctx, provider.CtxSSHKeyPath, m.pathBuf)
	if passphrase != nil {
		ctx = context.WithValue(ctx, provider.CtxSSHKeyPassphrase, passphrase)
	}
	p := m.provider
	params := m.params
	return m, func() tea.Msg {
		secret, err := p.Derive(ctx, params)
		if passphrase != nil {
			crypto.WipeBytes(passphrase)
		}
		return unlockSSHKeyCompletedMsg{secret: secret, err: err}
	}
}

func (m unlockSSHKey) View() string {
	var b strings.Builder
	switch m.state {
	case unlockSSHKeyStatePath:
		fmt.Fprintf(&b, "SSH key path for %s:\n\n", highlightStyle.Render(m.id))
		b.WriteString(promptStyle.Render("> "))
		b.WriteString(m.pathBuf)
		b.WriteString(highlightStyle.Render("█"))
		b.WriteString("\n\n")
		b.WriteString(dimStyle.Render("enter to continue • esc to skip"))
	case unlockSSHKeyStateProbing:
		b.WriteString(highlightStyle.Render("Checking SSH key..."))
		b.WriteString("\n")
	case unlockSSHKeyStatePass:
		fmt.Fprintf(&b, "Passphrase for %s: %s\n", highlightStyle.Render(m.pathBuf), m.passInp.View())
		b.WriteString("\n")
		b.WriteString(dimStyle.Render("enter to unlock • esc to skip"))
	case unlockSSHKeyStateDeriving:
		b.WriteString(highlightStyle.Render("Deriving from SSH key..."))
		b.WriteString("\n")
	case unlockSSHKeyStateDone, unlockSSHKeyStateSkipped:
		// Parent unmounts once Done() is true.
	}
	if m.errorMsg != "" {
		fmt.Fprintf(&b, "\n%s\n", errorStyle.Render(m.errorMsg))
	}
	return b.String()
}

func (m unlockSSHKey) Done() bool {
	return m.state == unlockSSHKeyStateDone || m.state == unlockSSHKeyStateSkipped
}

func (m unlockSSHKey) Skipped() bool {
	return m.state == unlockSSHKeyStateSkipped
}

func (m unlockSSHKey) Secret() ([]byte, error) {
	return m.secret, m.err
}
