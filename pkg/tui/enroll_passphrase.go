package tui

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"

	"github.com/ekristen/cryptkey/pkg/crypto"
	"github.com/ekristen/cryptkey/pkg/enrollment"
	"github.com/ekristen/cryptkey/pkg/provider"
	"github.com/ekristen/cryptkey/pkg/provider/passphrase"
)

var (
	errPassphraseEmpty    = errors.New("passphrase cannot be empty")
	errPassphraseMismatch = errors.New("passphrases do not match")
)

// enrollPassphrase is a self-contained bubbletea sub-model that walks a user
// through enrolling a passphrase provider: entry → confirm → (weak warn?) →
// background enroll → done. Parent models (init.Model today, rekey.AppModel
// later) compose it — routing key messages to its Update, rendering its View
// in their own layout, and observing Done() / Result().
//
// The component owns the real enrollment.EnrollProvider call so it can
// display an "enrolling" status while Argon2 chews on the passphrase.
type enrollPassphrase struct {
	ctx      context.Context
	provider provider.Provider
	id       string
	options  map[string]string // enroll-option values (argon_time, …)

	state    passphraseState
	input    textinput.Model
	captured []byte // first entry held across confirm step

	strength passphrase.Strength // updated live during entry

	result *enrollment.Enrollment
	err    error
}

type passphraseState int

const (
	passphraseStateEntry passphraseState = iota
	passphraseStateConfirm
	passphraseStateWeakWarn
	passphraseStateEnrolling
	passphraseStateDone
	passphraseStateCanceled
)

// enrollPassphraseCompletedMsg is emitted by the background enroll goroutine.
// Parents must route it back to the child's Update method.
type enrollPassphraseCompletedMsg struct {
	result *enrollment.Enrollment
	err    error
}

// newEnrollPassphrase builds a passphrase enroll component. options are the
// provider's enroll-option values (e.g. argon_time, argon_memory) which are
// layered onto the ctx before the background Enroll call.
func newEnrollPassphrase(ctx context.Context, p provider.Provider, id string, options map[string]string) enrollPassphrase {
	ti := newPasswordInput(256)
	// Focus must be applied here (on the addressable local) — not inside a
	// value-receiver Init, whose mutations are lost to the caller's copy.
	ti.Focus()
	return enrollPassphrase{
		ctx:      ctx,
		provider: p,
		id:       id,
		options:  options,
		state:    passphraseStateEntry,
		input:    ti,
	}
}

func (m enrollPassphrase) Init() tea.Cmd { return textinput.Blink }

func (m enrollPassphrase) Update(msg tea.Msg) (enrollPassphrase, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch m.state {
		case passphraseStateEntry:
			return m.handleEntry(msg)
		case passphraseStateConfirm:
			return m.handleConfirm(msg)
		case passphraseStateWeakWarn:
			return m.handleWeakWarn(msg)
		}
	case enrollPassphraseCompletedMsg:
		m.result = msg.result
		m.err = msg.err
		m.state = passphraseStateDone
		return m, nil
	}

	// Forward other messages (cursor blink, etc.) to the textinput while
	// one of the editable states is active.
	if m.state == passphraseStateEntry || m.state == passphraseStateConfirm {
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		if m.state == passphraseStateEntry {
			m.strength = passphrase.ScorePassphrase([]byte(m.input.Value()))
		}
		return m, cmd
	}
	return m, nil
}

func (m enrollPassphrase) handleEntry(msg tea.KeyMsg) (enrollPassphrase, tea.Cmd) {
	switch msg.String() {
	case keyEnter:
		val := m.input.Value()
		if val == "" {
			m.err = errPassphraseEmpty
			return m, nil
		}
		m.captured = []byte(val)
		m.strength = passphrase.ScorePassphrase(m.captured)
		m.input.SetValue("")
		m.err = nil
		m.state = passphraseStateConfirm
		return m, nil
	case keyEscape:
		m.wipe()
		m.state = passphraseStateCanceled
		return m, nil
	default:
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		m.strength = passphrase.ScorePassphrase([]byte(m.input.Value()))
		return m, cmd
	}
}

func (m enrollPassphrase) handleConfirm(msg tea.KeyMsg) (enrollPassphrase, tea.Cmd) {
	switch msg.String() {
	case keyEnter:
		val := []byte(m.input.Value())
		match := len(val) == len(m.captured) && subtle.ConstantTimeCompare(val, m.captured) == 1
		crypto.WipeBytes(val)
		if !match {
			m.err = errPassphraseMismatch
			m.input.SetValue("")
			m.state = passphraseStateEntry
			crypto.WipeBytes(m.captured)
			m.captured = nil
			return m, nil
		}
		m.err = nil
		m.input.SetValue("")
		m.input.Blur()
		// If the captured passphrase is below the recommended strength,
		// route to an explicit confirmation screen before proceeding.
		if m.strength.IsWeak() {
			m.state = passphraseStateWeakWarn
			return m, nil
		}
		m.state = passphraseStateEnrolling
		// Split so runEnroll's mutations (clearing captured) are visible in
		// the returned copy. `return m, m.runEnroll()` would snapshot m
		// before runEnroll mutated it.
		cmd := m.runEnroll()
		return m, cmd
	case keyEscape:
		m.input.SetValue("")
		crypto.WipeBytes(m.captured)
		m.captured = nil
		m.err = nil
		m.state = passphraseStateEntry
		return m, m.input.Focus()
	default:
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		return m, cmd
	}
}

func (m enrollPassphrase) handleWeakWarn(msg tea.KeyMsg) (enrollPassphrase, tea.Cmd) {
	switch msg.String() {
	case "y", "Y":
		m.state = passphraseStateEnrolling
		cmd := m.runEnroll()
		return m, cmd
	case "n", "N", keyEscape, keyEnter:
		// Go back and let the user enter a different passphrase.
		crypto.WipeBytes(m.captured)
		m.captured = nil
		m.strength = passphrase.Strength{}
		m.state = passphraseStateEntry
		m.err = nil
		return m, m.input.Focus()
	}
	return m, nil
}

// runEnroll returns a tea.Cmd that performs the real enrollment in the
// background. The captured passphrase is moved onto the context and
// cleared from the component; the Argon2 derive inside Enroll wipes its
// own copy once done.
func (m *enrollPassphrase) runEnroll() tea.Cmd {
	pass := m.captured
	m.captured = nil

	ctx := provider.WithEnrollOptions(m.ctx, m.options)
	ctx = context.WithValue(ctx, provider.CtxSilent, true)
	ctx = context.WithValue(ctx, provider.CtxPassphrase, pass)

	p := m.provider
	id := m.id
	return func() tea.Msg {
		res, err := enrollment.EnrollProvider(ctx, p, id)
		return enrollPassphraseCompletedMsg{result: res, err: err}
	}
}

// wipe zeroes any in-progress captured bytes. Safe to call multiple times.
func (m *enrollPassphrase) wipe() {
	crypto.WipeBytes(m.captured)
	m.captured = nil
	m.input.SetValue("")
	m.err = nil
	m.strength = passphrase.Strength{}
}

// View renders the component's own content — just the prompt line plus any
// error message. Parent is responsible for the surrounding chrome (title,
// enrolled list, help bar).
func (m enrollPassphrase) View() string {
	var b strings.Builder
	switch m.state {
	case passphraseStateEntry:
		fmt.Fprintf(&b, "Enter passphrase: %s\n", m.input.View())
		b.WriteString(renderStrengthLine(m.strength, len(m.input.Value())))
		b.WriteString("\n")
		b.WriteString(dimStyle.Render("enter to continue • esc to cancel"))
	case passphraseStateConfirm:
		fmt.Fprintf(&b, "Confirm passphrase: %s\n", m.input.View())
		b.WriteString("\n")
		b.WriteString(dimStyle.Render("enter to continue • esc to re-enter"))
	case passphraseStateWeakWarn:
		fmt.Fprintf(&b, "%s\n\n", errorStyle.Render("Weak passphrase"))
		fmt.Fprintf(&b, "  Strength: %s (~%s to crack offline)\n",
			m.strength.Label(), m.strength.CrackDisplay)
		b.WriteString("\n")
		b.WriteString(dimStyle.Render("  If this provider alone can meet the profile's threshold,\n"))
		b.WriteString(dimStyle.Render("  an attacker who gets the profile file can brute force it.\n"))
		b.WriteString(dimStyle.Render("  Mixing a weak passphrase with a stronger provider is fine;\n"))
		b.WriteString(dimStyle.Render("  using it alone is not recommended.\n"))
		b.WriteString("\n")
		b.WriteString("Proceed with this passphrase anyway? ")
		b.WriteString(dimStyle.Render("[y/N]"))
	case passphraseStateEnrolling:
		fmt.Fprintf(&b, "Deriving key for %q (Argon2id — this may take a moment)...\n", m.id)
	case passphraseStateDone, passphraseStateCanceled:
		// Parent unmounts us once Done() returns true; nothing to render.
	}
	if m.err != nil {
		fmt.Fprintf(&b, "\n%s\n", errorStyle.Render(m.err.Error()))
	}
	return b.String()
}

// renderStrengthLine produces the dim-styled inline strength feedback shown
// under the entry prompt. Returns a leading space + styled label, or "" if
// the input is empty (don't show "weak" while the user has only typed one
// character — that's just noise).
func renderStrengthLine(s passphrase.Strength, typedLen int) string {
	if typedLen == 0 {
		return ""
	}
	var label string
	if s.IsWeak() {
		label = errorStyle.Render(fmt.Sprintf("strength: %s", s.Label()))
	} else {
		label = successStyle.Render(fmt.Sprintf("strength: %s", s.Label()))
	}
	return " " + label
}

// Done reports whether the component has settled — either successfully
// enrolled, failed, or was canceled by the user.
func (m enrollPassphrase) Done() bool {
	return m.state == passphraseStateDone || m.state == passphraseStateCanceled
}

// Canceled reports whether the user escaped out of the flow.
func (m enrollPassphrase) Canceled() bool {
	return m.state == passphraseStateCanceled
}

// Result returns the completed enrollment. Only valid after Done() returns
// true and Canceled() returns false. If the background enrollment failed,
// err is non-nil.
func (m enrollPassphrase) Result() (*enrollment.Enrollment, error) {
	return m.result, m.err
}
