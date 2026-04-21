package tui

import (
	"context"
	"fmt"
	"strings"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"

	"github.com/ekristen/cryptkey/pkg/crypto"
	"github.com/ekristen/cryptkey/pkg/enrollment"
	"github.com/ekristen/cryptkey/pkg/provider"
	"github.com/ekristen/cryptkey/pkg/provider/sshkey"
)

// enrollSSHKey is a self-contained sub-model for ssh-key enrollment: user
// types the key path → we probe whether it's encrypted → if so, ask for
// the passphrase → background enroll → done.
type enrollSSHKey struct {
	ctx      context.Context
	provider provider.Provider
	id       string
	options  map[string]string

	state    sshKeyState
	pathBuf  string
	passInp  textinput.Model
	errorMsg string

	result *enrollment.Enrollment
	err    error
}

type sshKeyState int

const (
	sshKeyStatePathInput sshKeyState = iota
	sshKeyStateProbing
	sshKeyStatePassphrase
	sshKeyStateEnrolling
	sshKeyStateDone
	sshKeyStateCanceled
)

// sshKeyProbeMsg is returned after probing an SSH key file.
type sshKeyProbeMsg struct {
	needsPassphrase bool
	err             error
}

// sshKeyEnrollCompletedMsg is emitted when the background enroll finishes.
type sshKeyEnrollCompletedMsg struct {
	result *enrollment.Enrollment
	err    error
}

func newEnrollSSHKey(ctx context.Context, p provider.Provider, id string, options map[string]string) enrollSSHKey {
	return enrollSSHKey{
		ctx:      ctx,
		provider: p,
		id:       id,
		options:  options,
		state:    sshKeyStatePathInput,
		pathBuf:  "~/.ssh/id_ed25519",
		passInp:  newPasswordInput(256),
	}
}

func (m enrollSSHKey) Init() tea.Cmd { return nil }

//nolint:dupl // mirror of unlockSSHKey.Update — distinct concrete types
func (m enrollSSHKey) Update(msg tea.Msg) (enrollSSHKey, tea.Cmd) {
	switch msg := msg.(type) {
	case sshKeyProbeMsg:
		return m.handleProbe(msg)
	case sshKeyEnrollCompletedMsg:
		m.result = msg.result
		m.err = msg.err
		m.state = sshKeyStateDone
		return m, nil
	case tea.KeyMsg:
		switch m.state {
		case sshKeyStatePathInput:
			return m.handlePathInput(msg.String())
		case sshKeyStatePassphrase:
			return m.handlePassphrase(msg)
		}
	}
	if m.state == sshKeyStatePassphrase {
		var cmd tea.Cmd
		m.passInp, cmd = m.passInp.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m enrollSSHKey) handlePathInput(key string) (enrollSSHKey, tea.Cmd) {
	switch key {
	case keyEnter:
		path := m.pathBuf
		if path == "" {
			path = "~/.ssh/id_ed25519"
			m.pathBuf = path
		}
		m.state = sshKeyStateProbing
		return m, func() tea.Msg {
			needsPass, err := sshkey.ProbeKeyFile(path)
			return sshKeyProbeMsg{needsPassphrase: needsPass, err: err}
		}
	case keyEscape:
		m.state = sshKeyStateCanceled
		return m, nil
	case keyBackspace:
		if m.pathBuf != "" {
			m.pathBuf = m.pathBuf[:len(m.pathBuf)-1]
		}
		return m, nil
	default:
		if len(key) == 1 {
			m.pathBuf += key
		}
		return m, nil
	}
}

func (m enrollSSHKey) handleProbe(msg sshKeyProbeMsg) (enrollSSHKey, tea.Cmd) {
	if msg.err != nil {
		m.errorMsg = msg.err.Error()
		m.state = sshKeyStatePathInput
		return m, nil
	}
	if msg.needsPassphrase {
		m.state = sshKeyStatePassphrase
		m.passInp.SetValue("")
		return m, m.passInp.Focus()
	}
	return m.startEnroll(nil)
}

//nolint:dupl // mirror of unlockSSHKey.handlePassphrase — distinct phase/state
func (m enrollSSHKey) handlePassphrase(msg tea.KeyMsg) (enrollSSHKey, tea.Cmd) {
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
		return m.startEnroll(pass)
	case keyEscape:
		m.passInp.SetValue("")
		m.passInp.Blur()
		m.state = sshKeyStatePathInput
		return m, nil
	default:
		var cmd tea.Cmd
		m.passInp, cmd = m.passInp.Update(msg)
		return m, cmd
	}
}

func (m enrollSSHKey) startEnroll(passphrase []byte) (enrollSSHKey, tea.Cmd) {
	m.state = sshKeyStateEnrolling

	ctx := provider.WithEnrollOptions(m.ctx, m.options)
	ctx = context.WithValue(ctx, provider.CtxSilent, true)
	ctx = context.WithValue(ctx, provider.CtxSSHKeyPath, m.pathBuf)
	if passphrase != nil {
		ctx = context.WithValue(ctx, provider.CtxSSHKeyPassphrase, passphrase)
	}

	p := m.provider
	id := m.id
	return m, func() tea.Msg {
		res, err := enrollment.EnrollProvider(ctx, p, id)
		// Passphrase is wiped inside the sshkey provider after use; wipe the
		// outer copy too.
		if passphrase != nil {
			crypto.WipeBytes(passphrase)
		}
		return sshKeyEnrollCompletedMsg{result: res, err: err}
	}
}

func (m enrollSSHKey) View() string {
	var b strings.Builder
	switch m.state {
	case sshKeyStatePathInput:
		b.WriteString("SSH key file path:\n\n")
		b.WriteString(promptStyle.Render("> "))
		if m.pathBuf == "" {
			b.WriteString(dimStyle.Render("~/.ssh/id_ed25519"))
		} else {
			b.WriteString(m.pathBuf)
		}
		b.WriteString(dimStyle.Render("█"))
		b.WriteString("\n\n")
		b.WriteString(dimStyle.Render("enter continue • esc cancel"))
	case sshKeyStateProbing:
		b.WriteString(highlightStyle.Render("Checking SSH key..."))
		b.WriteString("\n")
	case sshKeyStatePassphrase:
		fmt.Fprintf(&b, "Enter passphrase for %s:\n\n", highlightStyle.Render(m.pathBuf))
		b.WriteString(promptStyle.Render("> "))
		b.WriteString(m.passInp.View())
		b.WriteString("\n\n")
		b.WriteString(dimStyle.Render("enter continue • esc back"))
	case sshKeyStateEnrolling:
		b.WriteString(highlightStyle.Render("Enrolling SSH key..."))
		b.WriteString("\n")
	case sshKeyStateDone, sshKeyStateCanceled:
		// Parent unmounts once Done() is true.
	}
	if m.errorMsg != "" {
		fmt.Fprintf(&b, "\n%s\n", errorStyle.Render(m.errorMsg))
	}
	return b.String()
}

func (m enrollSSHKey) Done() bool {
	return m.state == sshKeyStateDone || m.state == sshKeyStateCanceled
}

func (m enrollSSHKey) Canceled() bool {
	return m.state == sshKeyStateCanceled
}

func (m enrollSSHKey) Result() (*enrollment.Enrollment, error) {
	return m.result, m.err
}
