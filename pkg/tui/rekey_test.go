package tui

import (
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ekristen/cryptkey/pkg/config"

	// Register at least one provider so RekeyModel.providers isn't empty.
	_ "github.com/ekristen/cryptkey/pkg/provider/passphrase"
)

func sampleProfile() *config.Profile {
	return &config.Profile{
		Version:   1,
		Name:      "sample",
		Threshold: 2,
		Providers: []config.ProviderConfig{
			{Type: "passphrase", ID: "pass-1"},
			{Type: "passphrase", ID: "pass-2"},
			{Type: "passphrase", ID: "pass-3"},
		},
	}
}

// press feeds a key into the model and returns the next state. The string
// names mirror the keys our TUI matches on (e.g. "up", "space", "enter").
// We synthesize a tea.KeyPressMsg directly since the test never goes through
// a real tea.Program.
func press(t *testing.T, m RekeyModel, key string) RekeyModel {
	t.Helper()
	var msg tea.KeyPressMsg
	switch key {
	case "up":
		msg = tea.KeyPressMsg{Code: tea.KeyUp}
	case "down":
		msg = tea.KeyPressMsg{Code: tea.KeyDown}
	case "left":
		msg = tea.KeyPressMsg{Code: tea.KeyLeft}
	case "right":
		msg = tea.KeyPressMsg{Code: tea.KeyRight}
	case "enter":
		msg = tea.KeyPressMsg{Code: tea.KeyEnter}
	case "esc":
		msg = tea.KeyPressMsg{Code: tea.KeyEscape}
	case " ", "space":
		msg = tea.KeyPressMsg{Code: tea.KeySpace}
	default:
		// Single rune like "a", "k", "x".
		msg = tea.KeyPressMsg{Code: rune(key[0]), Text: key}
	}
	next, _ := m.Update(msg)
	rm, ok := next.(RekeyModel)
	require.True(t, ok)
	return rm
}

func TestRekeyTUIInitialState(t *testing.T) {
	p := sampleProfile()
	m := NewRekey("sample", p)
	assert.Len(t, m.entries, 3)
	assert.Equal(t, 2, m.threshold)
	for _, e := range m.entries {
		assert.True(t, e.kept, "all entries kept by default")
		assert.False(t, e.isAdd)
	}
}

func TestRekeyTUIToggleRemoveAndPlan(t *testing.T) {
	p := sampleProfile()
	m := NewRekey("sample", p)

	// Move to second entry, toggle off, confirm.
	m = press(t, m, "down")
	m = press(t, m, " ")
	assert.False(t, m.entries[1].kept, "space toggles off the focused entry")

	m = press(t, m, "enter")
	require.Equal(t, rekeyStateDone, m.state)

	plan := m.Plan()
	assert.Equal(t, 2, plan.Threshold)
	assert.ElementsMatch(t, []string{"passphrase:pass-1", "passphrase:pass-3"}, plan.Keep)
	assert.ElementsMatch(t, []string{"passphrase:pass-2"}, plan.Remove)
	assert.Empty(t, plan.Add)
}

func TestRekeyTUIThresholdBounds(t *testing.T) {
	p := sampleProfile()
	m := NewRekey("sample", p)

	// Move cursor onto the threshold row (last index = len(entries)).
	for range m.entries {
		m = press(t, m, "down")
	}
	require.True(t, m.rowIsThreshold())

	// Right increases, capped at provider count (3 here).
	m = press(t, m, "right")
	assert.Equal(t, 3, m.threshold)
	m = press(t, m, "right")
	assert.Equal(t, 3, m.threshold, "threshold capped at provider count")

	// Left decreases, floor of 2.
	m = press(t, m, "left")
	assert.Equal(t, 2, m.threshold)
	m = press(t, m, "left")
	assert.Equal(t, 2, m.threshold, "threshold floor is 2")
}

func TestRekeyTUIInvalidPlanBlocksConfirm(t *testing.T) {
	p := sampleProfile()
	m := NewRekey("sample", p)

	// Remove two of three providers → 1 kept, threshold 2 → invalid.
	m = press(t, m, " ") // toggle pass-1 off
	m = press(t, m, "down")
	m = press(t, m, " ") // toggle pass-2 off
	m = press(t, m, "enter")
	assert.Equal(t, rekeyStateReview, m.state, "invalid plan must NOT advance to done")
	assert.NotEmpty(t, m.err, "validation error should be surfaced")
}

func TestRekeyTUIAddProviderFlow(t *testing.T) {
	p := sampleProfile()
	m := NewRekey("sample", p)

	m = press(t, m, "a")
	require.Equal(t, rekeyStateAddType, m.state)

	// First provider in the list (alphabetical via provider.All) — accept it.
	m = press(t, m, "enter")
	require.Equal(t, rekeyStateReview, m.state)
	require.Len(t, m.entries, 4)
	assert.True(t, m.entries[3].isAdd, "queued add appended at the end")

	m = press(t, m, "enter")
	plan := m.Plan()
	assert.Len(t, plan.Add, 1)
	assert.NotEmpty(t, plan.Add[0])
}

func TestRekeyTUIRemoveQueuedAdd(t *testing.T) {
	p := sampleProfile()
	m := NewRekey("sample", p)

	m = press(t, m, "a")
	m = press(t, m, "enter") // queue an add → 4 entries
	require.Len(t, m.entries, 4)

	// Cursor is on the queued add (last entry). Space removes it.
	m = press(t, m, " ")
	assert.Len(t, m.entries, 3, "space on a queued add removes it")
}

func TestRekeyTUICancelEsc(t *testing.T) {
	p := sampleProfile()
	m := NewRekey("sample", p)
	m = press(t, m, "esc")
	assert.True(t, m.Canceled())
}
