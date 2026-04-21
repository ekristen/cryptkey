package tui

import (
	"context"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ekristen/cryptkey/pkg/config"
	"github.com/ekristen/cryptkey/pkg/enrollment"
	"github.com/ekristen/cryptkey/pkg/provider"
	_ "github.com/ekristen/cryptkey/pkg/provider/passphrase"
)

// These tests drive RekeyAppModel's state machine through synthetic key
// and completion messages. They don't spin up a real tea.Program — the
// point is to assert phase transitions, sub-model selection, error
// propagation, and cancel handling, all in-process. The focus bug we
// spent a commit fixing is exactly the class of regression these pin
// down: if a phase fails to route messages into the active sub-model,
// or if a sub-model swaps in under the wrong state, these go red.

// --- Helpers ---

const testCommonPass = "hunter2-test-pass"

// synthPass creates a signed profile on disk with len(ids) passphrase
// providers, all enrolled with testCommonPass. Isolated under
// XDG_CONFIG_HOME = t.TempDir() so it doesn't touch real state.
//
//nolint:unparam // threshold is an intentional parameter; future tests may vary it
func synthPass(t *testing.T, name string, threshold int, ids []string) *config.Profile {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	p, ok := provider.Get("passphrase")
	require.True(t, ok)

	enrolls := make([]enrollment.Enrollment, len(ids))
	for i, id := range ids {
		ctx := context.WithValue(context.Background(), provider.CtxPassphrase, []byte(testCommonPass))
		e, err := enrollment.EnrollProvider(ctx, p, id)
		require.NoError(t, err)
		enrolls[i] = *e
	}
	require.NoError(t, enrollment.BuildProfile(name, threshold, enrolls))

	profile, err := config.Load(name)
	require.NoError(t, err)
	return profile
}

// key builds a synthetic key press from a short name. Uses the existing
// keyEnter / keyLeft / keyRight constants for names that already have
// them; names without constants ("space", "up", "down", "esc") are
// literal strings local to this helper.
func key(s string) tea.KeyPressMsg {
	switch s {
	case keyEnter:
		return tea.KeyPressMsg{Code: tea.KeyEnter}
	case keyEscape:
		return tea.KeyPressMsg{Code: tea.KeyEscape}
	case "space", " ":
		return tea.KeyPressMsg{Code: tea.KeySpace}
	case keyUp:
		return tea.KeyPressMsg{Code: tea.KeyUp}
	case keyDown:
		return tea.KeyPressMsg{Code: tea.KeyDown}
	case keyRight:
		return tea.KeyPressMsg{Code: tea.KeyRight}
	case keyLeft:
		return tea.KeyPressMsg{Code: tea.KeyLeft}
	default:
		return tea.KeyPressMsg{Code: rune(s[0]), Text: s}
	}
}

// step feeds a single message into the app model and returns the updated
// app + any tea.Cmd the model returned. We cast back to RekeyAppModel
// since Update returns tea.Model for the outer interface.
func step(t *testing.T, m RekeyAppModel, msg tea.Msg) (RekeyAppModel, tea.Cmd) {
	t.Helper()
	next, cmd := m.Update(msg)
	appNext, ok := next.(RekeyAppModel)
	require.Truef(t, ok, "Update must return RekeyAppModel, got %T", next)
	return appNext, cmd
}

// runCmd runs a tea.Cmd if it's non-nil and returns the resulting message.
// Sub-commands that return nil or batches are unwrapped best-effort; the
// tests that care feed the resulting msg back into step().
func runCmd(cmd tea.Cmd) tea.Msg {
	if cmd == nil {
		return nil
	}
	return cmd()
}

// typeString feeds each character of s into the model one at a time.
func typeString(t *testing.T, m RekeyAppModel, s string) RekeyAppModel {
	t.Helper()
	for _, r := range s {
		m, _ = step(t, m, tea.KeyPressMsg{Code: r, Text: string(r)})
	}
	return m
}

// --- Init / plan phase ---

func TestAppStartsInPlanState(t *testing.T) {
	profile := synthPass(t, "app-init", 2, []string{"pass-1", "pass-2"})
	m := NewRekeyApp(context.Background(), "app-init", profile)
	assert.Equal(t, rekeyAppPlan, m.state)
	assert.False(t, m.quitting)
}

func TestAppCtrlCAtPlanCancels(t *testing.T) {
	profile := synthPass(t, "app-ctrlc", 2, []string{"pass-1", "pass-2"})
	m := NewRekeyApp(context.Background(), "app-ctrlc", profile)
	// Real terminals send ctrl+c as Code='c' + Mod=ModCtrl with Text
	// empty — ultraviolet's String() falls through to Keystroke() for
	// empty Text, producing "ctrl+c". If Text were set to "c", String()
	// would short-circuit to "c" and our AppModel wouldn't recognize it.
	m, _ = step(t, m, tea.KeyPressMsg{Code: 'c', Mod: tea.ModCtrl})
	assert.Equal(t, RekeyAppExitCanceled, m.Exit())
	assert.True(t, m.quitting)
}

func TestAppEscAtPlanCancels(t *testing.T) {
	profile := synthPass(t, "app-esc", 2, []string{"pass-1", "pass-2"})
	m := NewRekeyApp(context.Background(), "app-esc", profile)
	m, _ = step(t, m, key("esc"))
	assert.Equal(t, RekeyAppExitCanceled, m.Exit())
}

// TestPlanConfirmTransitionsToUnlock confirms the review screen via enter
// and expects the state to advance to rekeyAppUnlock with a live
// passphrase sub-model ready to accept input.
func TestPlanConfirmTransitionsToUnlock(t *testing.T) {
	profile := synthPass(t, "app-plan-unlock", 2, []string{"pass-1", "pass-2"})
	m := NewRekeyApp(context.Background(), "app-plan-unlock", profile)

	// No plan edits — just confirm on the review screen. Enter should
	// advance past plan into unlock.
	m, _ = step(t, m, key("enter"))

	assert.Equal(t, rekeyAppUnlock, m.state)
	require.NotNil(t, m.passUnlock, "first provider is passphrase → passUnlock should be active")
	assert.Equal(t, 0, m.unlockIdx)
}

// --- Phase routing / sub-model selection ---

// Every registered provider type in the test profile should get the
// right sub-model activated when startCurrentUnlock fires on it.
func TestUnlockSelectsCorrectChildPerProvider(t *testing.T) {
	// Two-passphrase profile so we can observe the second iteration
	// after the first completes.
	profile := synthPass(t, "app-child-select", 2, []string{"pass-1", "pass-2"})
	m := NewRekeyApp(context.Background(), "app-child-select", profile)
	m, _ = step(t, m, key("enter")) // confirm plan → unlock

	// First provider (passphrase) → passUnlock set, others nil.
	assert.NotNil(t, m.passUnlock)
	assert.Nil(t, m.autoUnlock)
	assert.Nil(t, m.recoveryUnlock)
	assert.Nil(t, m.fido2Unlock)
	assert.Nil(t, m.pivUnlock)
}

// --- Unlock passphrase round-trip ---
//
// Feeds the first passphrase, processes the derive completion, checks
// the master key is reconstructed once threshold is met.

func TestUnlockPassphraseHappyPath(t *testing.T) {
	profile := synthPass(t, "app-unlock-happy", 2, []string{"pass-1", "pass-2"})
	m := NewRekeyApp(context.Background(), "app-unlock-happy", profile)
	m, _ = step(t, m, key("enter")) // confirm plan
	require.Equal(t, rekeyAppUnlock, m.state)

	// Type the passphrase for provider #1 and press enter.
	m = typeString(t, m, testCommonPass)
	require.NotNil(t, m.passUnlock, "still in passphrase entry")
	m, cmd := step(t, m, key("enter"))
	// After enter the child transitions to Deriving and returns a
	// derive cmd. Run it to get the completion msg; feed it back.
	require.NotNil(t, cmd, "enter must queue a derive cmd")
	m, _ = step(t, m, runCmd(cmd))

	// The first provider is done; startCurrentUnlock advanced to the
	// second. Active child is still passUnlock (for pass-2) but with
	// state reset to entry.
	require.Equal(t, rekeyAppUnlock, m.state)
	require.NotNil(t, m.passUnlock)
	assert.Equal(t, 1, m.unlockIdx, "should have moved onto the second provider")
	assert.Len(t, m.secrets, 1, "one secret collected so far")

	// Second passphrase.
	m = typeString(t, m, testCommonPass)
	m, cmd = step(t, m, key("enter"))
	require.NotNil(t, cmd)
	m, _ = step(t, m, runCmd(cmd))

	// Threshold hit → afterUnlockLoop → masterKey should be populated,
	// and since there are no kept-but-unsatisfied providers, we advance
	// either to Write or Enroll. With no adds the state should be Done
	// after the write happens synchronously.
	assert.Equal(t, rekeyAppDone, m.state, "no adds + threshold met → immediate Done")
	assert.Equal(t, RekeyAppExitSuccess, m.Exit())
	assert.Empty(t, m.secrets, "secrets wiped after successful write")
}

// --- Wrong passphrase ---

func TestUnlockWrongPassphraseSkipsNotAborts(t *testing.T) {
	profile := synthPass(t, "app-wrong-pass", 2, []string{"pass-1", "pass-2"})
	m := NewRekeyApp(context.Background(), "app-wrong-pass", profile)
	m, _ = step(t, m, key("enter"))

	// Wrong passphrase on provider #1 — Argon2 derives *a* secret, but it
	// doesn't match what was stored, so DecryptShare fails. The orchestrator
	// should treat this as a skip and move on, not abort.
	m = typeString(t, m, "nope-nope-nope")
	m, cmd := step(t, m, key("enter"))
	m, _ = step(t, m, runCmd(cmd))

	require.Equal(t, rekeyAppUnlock, m.state, "wrong pass for one provider must not abort the whole flow")
	assert.Equal(t, 1, m.unlockIdx, "should have advanced to provider #2")
	assert.Empty(t, m.secrets, "no valid secret collected yet")

	// Wrong again on #2 — both providers exhausted without reaching
	// threshold → afterUnlockLoop fails with a clear message.
	m = typeString(t, m, "also-wrong")
	m, cmd = step(t, m, key("enter"))
	m, _ = step(t, m, runCmd(cmd))

	assert.Equal(t, rekeyAppError, m.state)
	assert.Equal(t, RekeyAppExitError, m.Exit())
	require.Error(t, m.Err())
	assert.Contains(t, m.Err().Error(), "could not reconstruct master key",
		"final error should say threshold not met, not provider-specific")
}

// --- Skip via esc during unlock + fill-in ---

// Skipping a provider during unlock is legitimate — the provider is still
// kept in the new profile, its secret is needed to re-encrypt the rewritten
// share, so after threshold is met via other providers the flow transitions
// to a fill-in phase that asks for the skipped provider's secret.
func TestUnlockEscSkipsProviderThenFillInCollectsIt(t *testing.T) {
	profile := synthPass(t, "app-esc-skip", 2, []string{"pass-1", "pass-2", "pass-3"})
	m := NewRekeyApp(context.Background(), "app-esc-skip", profile)
	m, _ = step(t, m, key("enter"))

	// Esc on the first passphrase — sub-model returns Skipped. The
	// orchestrator advances to provider #2.
	m, _ = step(t, m, key("esc"))
	require.Equal(t, rekeyAppUnlock, m.state)
	assert.Equal(t, 1, m.unlockIdx)
	assert.Empty(t, m.secrets, "no secret collected yet — skip honored")

	// Provide correct passphrases for 2 and 3 to meet threshold.
	m = typeString(t, m, testCommonPass)
	m, cmd := step(t, m, key("enter"))
	m, _ = step(t, m, runCmd(cmd))
	m = typeString(t, m, testCommonPass)
	m, cmd = step(t, m, key("enter"))
	m, _ = step(t, m, runCmd(cmd))

	// Threshold met, but pass-1 was skipped and it's still kept, so we
	// transition to the fill-in phase to collect its secret.
	require.Equal(t, rekeyAppFill, m.state)
	require.NotNil(t, m.passUnlock, "fill-in should have a live passphrase sub-model for pass-1")

	// Provide pass-1's passphrase in the fill-in phase.
	m = typeString(t, m, testCommonPass)
	m, cmd = step(t, m, key("enter"))
	m, _ = step(t, m, runCmd(cmd))

	assert.Equal(t, rekeyAppDone, m.state)
	assert.Equal(t, RekeyAppExitSuccess, m.Exit())
}

// --- tuiUnlockSupported ---
//
// Pure function; cheap to pin down every branch.

func TestTUIUnlockSupportedMatrix(t *testing.T) {
	cases := map[string]bool{
		"passphrase": true,
		"tpm":        true,
		"ssh-agent":  true,
		"recovery":   true,
		"sshkey":     true,
		"fido2":      true,
		"piv":        true,
		"passkey":    false, // browser flow — no unlock sub-model yet
		"unknown":    false,
	}
	for providerType, want := range cases {
		assert.Equalf(t, want, tuiUnlockSupported(providerType),
			"tuiUnlockSupported(%q)", providerType)
	}
}

// --- Plan resolution helper ---

func TestResolveKeptFromPlanRespectsRemove(t *testing.T) {
	p := &config.Profile{
		Providers: []config.ProviderConfig{
			{Type: "passphrase", ID: "a"},
			{Type: "passphrase", ID: "b"},
			{Type: "passphrase", ID: "c"},
		},
	}
	keep, err := resolveKeptFromPlan(p, RekeyPlan{Remove: []string{"passphrase:b"}})
	require.NoError(t, err)
	assert.Len(t, keep, 2)
	assert.Equal(t, "a", keep[0].ID)
	assert.Equal(t, "c", keep[1].ID)
}

func TestResolveKeptFromPlanExplicitKeepIsFilter(t *testing.T) {
	p := &config.Profile{
		Providers: []config.ProviderConfig{
			{Type: "passphrase", ID: "a"},
			{Type: "passphrase", ID: "b"},
			{Type: "passphrase", ID: "c"},
		},
	}
	keep, err := resolveKeptFromPlan(p, RekeyPlan{Keep: []string{"passphrase:a", "passphrase:c"}})
	require.NoError(t, err)
	assert.Len(t, keep, 2)
	ids := []string{keep[0].ID, keep[1].ID}
	assert.ElementsMatch(t, []string{"a", "c"}, ids)
}

func TestResolveKeptFromPlanRejectsUnknownName(t *testing.T) {
	p := &config.Profile{
		Providers: []config.ProviderConfig{{Type: "passphrase", ID: "a"}},
	}
	_, err := resolveKeptFromPlan(p, RekeyPlan{Remove: []string{"passphrase:nope"}})
	require.Error(t, err)

	_, err = resolveKeptFromPlan(p, RekeyPlan{Keep: []string{"passphrase:missing"}})
	require.Error(t, err)
}

// parseSpec is tiny and local; pin it down too so changing the delimiter
// (":" → "/") is a caught-in-review edit.
func TestParseSpec(t *testing.T) {
	typ, id := parseSpec("passphrase:pass-2")
	assert.Equal(t, "passphrase", typ)
	assert.Equal(t, "pass-2", id)

	typ, id = parseSpec("fido2")
	assert.Equal(t, "fido2", typ)
	assert.Empty(t, id)

	typ, id = parseSpec("passphrase:")
	assert.Equal(t, "passphrase", typ)
	assert.Empty(t, id)
}
