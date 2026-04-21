package tui

import (
	"context"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/stretchr/testify/assert"

	"github.com/ekristen/cryptkey/pkg/provider"
	_ "github.com/ekristen/cryptkey/pkg/provider/passphrase"
)

// keyRune builds a synthetic KeyPressMsg for a single printable character.
func keyRune(r rune) tea.KeyPressMsg {
	return tea.KeyPressMsg{Code: r, Text: string(r)}
}

// Verify that unlockPassphrase actually accepts typed characters after the
// constructor-focus fix. Pre-regression, this would have failed because
// textinput.Update's `if !focus { return m, nil }` gate would drop the
// keystroke on the floor.
func TestUnlockPassphraseCapturesInput(t *testing.T) {
	p, ok := provider.Get("passphrase")
	if !ok {
		t.Fatal("passphrase provider not registered")
	}

	m := newUnlockPassphrase(context.Background(), p, "pass-1", nil)
	assert.True(t, m.input.Focused(), "constructor must focus the input")

	// Type "ab"
	m, _ = m.Update(keyRune('a'))
	m, _ = m.Update(keyRune('b'))
	assert.Equal(t, "ab", m.input.Value(), "two characters should have landed in the input")
}

// Same check for unlockFIDO2: make sure PIN entry catches keystrokes.
func TestUnlockFIDO2CapturesPIN(t *testing.T) {
	p, ok := provider.Get("passphrase") // any provider; we're only testing input plumbing
	if !ok {
		t.Fatal("passphrase provider not registered")
	}

	m := newUnlockFIDO2(context.Background(), p, "fido2-1", map[string]string{"uv": "preferred"})
	assert.True(t, m.input.Focused(), "constructor must focus the PIN input when uv != discouraged")

	m, _ = m.Update(keyRune('1'))
	m, _ = m.Update(keyRune('2'))
	m, _ = m.Update(keyRune('3'))
	m, _ = m.Update(keyRune('4'))
	assert.Equal(t, "1234", m.input.Value(), "PIN characters should land in the input")
}
