package tui

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/ekristen/cryptkey/pkg/config"
	"github.com/ekristen/cryptkey/pkg/crypto"
	"github.com/ekristen/cryptkey/pkg/crypto/shamir"
	"github.com/ekristen/cryptkey/pkg/enrollment"
	"github.com/ekristen/cryptkey/pkg/provider"
)

// rekeyAppState tracks the top-level phase of a full-TUI rekey.
type rekeyAppState int

const (
	rekeyAppPlan     rekeyAppState = iota // running the planning RekeyModel
	rekeyAppUnlock                        // iterating the current profile's providers
	rekeyAppFill                          // deriving kept providers not yet unlocked
	rekeyAppEnroll                        // enrolling new providers from plan.Add
	rekeyAppWrite                         // writing the new profile
	rekeyAppDone                          // success — new profile saved
	rekeyAppCanceled                      // user canceled before a write happened
	rekeyAppFallback                      // TUI can't handle this profile — caller runs CLI flow
	rekeyAppError                         // fatal error
)

// RekeyAppExit is what the parent command needs after RekeyAppModel finishes.
type RekeyAppExit int

const (
	RekeyAppExitSuccess     RekeyAppExit = iota // new profile written
	RekeyAppExitCanceled                        // user dismissed without writing
	RekeyAppExitFallbackCLI                     // unsupported provider for TUI unlock; run CLI flow with Plan
	RekeyAppExitError                           // something blew up; see Err()
)

// RekeyAppModel is the top-level bubbletea model for rekey. It owns the
// full lifecycle: plan → unlock → fill-in → enroll → write. Provider
// interactions compose the enroll*/unlock* sub-models. Unsupported
// providers (for example, FIDO2 in the unlock phase — its sub-model
// isn't written yet) cause the model to exit with
// RekeyAppExitFallbackCLI so the rekey command can run the tested
// line-based flow instead.
type RekeyAppModel struct {
	profileName string
	profile     *config.Profile
	ctx         context.Context

	state rekeyAppState
	err   error
	exit  RekeyAppExit

	// Plan phase
	plan     RekeyModel
	resolved RekeyPlan
	keepList []config.ProviderConfig

	// Unlock phase. At most one of the *Unlock pointers is non-nil at a
	// time; which one is set is driven by the current provider's type.
	unlockIdx      int
	passUnlock     *unlockPassphrase
	autoUnlock     *unlockAutomatic // for tpm + ssh-agent (no interactive input)
	recoveryUnlock *unlockRecovery
	sshKeyUnlock   *unlockSSHKey
	fido2Unlock    *unlockFIDO2
	pivUnlock      *unlockPIV
	secrets        map[string][]byte
	shares         [][]byte
	masterKey      []byte

	// Fill-in phase
	fillMissing []config.ProviderConfig
	fillIdx     int

	// Enroll phase
	addIdx      int
	addSpecs    []string
	newEnrolls  []enrollment.Enrollment
	passEnroll  *enrollPassphrase
	fido2Enroll *enrollFIDO2
	sshAgentE   *enrollSSHAgent
	sshKeyE     *enrollSSHKey
	pivE        *enrollPIV

	// Results shown on the done screen
	writtenPath string
	quitting    bool
}

// NewRekeyApp constructs the top-level rekey TUI model.
func NewRekeyApp(ctx context.Context, profileName string, profile *config.Profile) RekeyAppModel {
	return RekeyAppModel{
		profileName: profileName,
		profile:     profile,
		ctx:         ctx,
		state:       rekeyAppPlan,
		plan:        NewRekey(profileName, profile),
		secrets:     make(map[string][]byte),
	}
}

func (m RekeyAppModel) Init() tea.Cmd { return m.plan.Init() }

// Exit is the post-run signal the command should branch on.
func (m RekeyAppModel) Exit() RekeyAppExit { return m.exit }

// Err returns any fatal error. Valid when Exit() == RekeyAppExitError.
func (m RekeyAppModel) Err() error { return m.err }

// Plan returns the resolved plan from the planning phase. Useful when
// Exit() == RekeyAppExitFallbackCLI so the command can run the CLI flow
// with the same plan the user confirmed.
func (m RekeyAppModel) Plan() RekeyPlan { return m.resolved }

func (m RekeyAppModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if km, ok := msg.(tea.KeyMsg); ok && km.String() == keyCtrlC {
		m.quitting = true
		m.exit = RekeyAppExitCanceled
		return m, tea.Quit
	}

	switch m.state {
	case rekeyAppPlan:
		return m.updatePlan(msg)
	case rekeyAppUnlock:
		return m.updateUnlock(msg)
	case rekeyAppFill:
		return m.updateFill(msg)
	case rekeyAppEnroll:
		return m.updateEnroll(msg)
	case rekeyAppDone, rekeyAppCanceled, rekeyAppError, rekeyAppFallback:
		if km, ok := msg.(tea.KeyMsg); ok {
			if km.String() == "enter" || km.String() == "q" {
				m.quitting = true
				return m, tea.Quit
			}
		}
	}
	return m, nil
}

// --- Plan phase ---

func (m RekeyAppModel) updatePlan(msg tea.Msg) (tea.Model, tea.Cmd) {
	plan, cmd := m.plan.Update(msg)
	m.plan = plan.(RekeyModel)

	if m.plan.Canceled() {
		m.exit = RekeyAppExitCanceled
		m.state = rekeyAppCanceled
		return m, tea.Quit
	}
	if m.plan.state != rekeyStateDone {
		return m, cmd
	}

	m.resolved = m.plan.Plan()

	// Figure out the kept set.
	keep, err := resolveKeptFromPlan(m.profile, m.resolved)
	if err != nil {
		m.err = err
		m.exit = RekeyAppExitError
		m.state = rekeyAppError
		return m, tea.Quit
	}
	m.keepList = keep

	// If any existing provider isn't supported by a TUI unlock component
	// yet, bail out and let the CLI flow run. The user still gets the
	// planning TUI; the rest falls back to the tested line-based path.
	for _, pc := range m.profile.Providers {
		if !tuiUnlockSupported(pc.Type) {
			m.exit = RekeyAppExitFallbackCLI
			m.state = rekeyAppFallback
			return m, tea.Quit
		}
	}

	return m.beginUnlock()
}

// Provider type / key literal constants, extracted to satisfy goconst.
// typeRecovery and typeFIDO2 live in styles.go and are reused here.
const (
	typePassphrase = "passphrase"
	typeSSHKey     = "sshkey"
	typeSSHAgent   = "ssh-agent"
	typeTPM        = "tpm"
	typePIV        = "piv"
	keyCtrlC       = "ctrl+c"
)

// tuiUnlockSupported reports whether a given provider type has an
// in-TUI unlock sub-model implemented. Every registered provider type is
// now covered; the fallback case stays so future provider additions
// default to the tested CLI flow until their sub-models ship.
func tuiUnlockSupported(providerType string) bool {
	switch providerType {
	case typePassphrase, typeTPM, typeSSHAgent, typeRecovery, typeSSHKey, typeFIDO2, typePIV:
		return true
	default:
		return false
	}
}

// --- Unlock phase ---

func (m RekeyAppModel) beginUnlock() (tea.Model, tea.Cmd) {
	m.state = rekeyAppUnlock
	m.unlockIdx = 0
	return m.startCurrentUnlock()
}

// startCurrentUnlock creates the appropriate unlock sub-model for the
// current provider, or advances past it if we can skip.
func (m RekeyAppModel) startCurrentUnlock() (tea.Model, tea.Cmd) {
	if m.unlockIdx >= len(m.profile.Providers) {
		// Ran out of providers — make sure we hit threshold.
		return m.afterUnlockLoop()
	}
	pc := m.profile.Providers[m.unlockIdx]

	// If we already have a secret for this one (e.g. from a prior pass),
	// advance.
	if _, ok := m.secrets[pc.Type+":"+pc.ID]; ok {
		m.unlockIdx++
		return m.startCurrentUnlock()
	}

	// Stop early once we've reconstructed the master key AND we have every
	// kept provider's secret. Anything beyond is unnecessary prompting.
	if m.masterKey != nil && m.allKeptSecretsCollected() {
		return m.afterUnlockLoop()
	}

	p, ok := provider.Get(pc.Type)
	if !ok {
		m.err = fmt.Errorf("provider %q not registered", pc.Type)
		m.exit = RekeyAppExitError
		m.state = rekeyAppError
		return m, tea.Quit
	}

	switch pc.Type {
	case typePassphrase:
		child := newUnlockPassphrase(m.ctx, p, pc.ID, pc.Params)
		m.passUnlock = &child
		return m, child.Init()
	case typeTPM:
		child := newUnlockAutomatic(m.ctx, p, pc.ID, pc.Params, fmt.Sprintf("Unlocking with TPM (%s)...", pc.ID))
		m.autoUnlock = &child
		return m, child.Init()
	case typeSSHAgent:
		child := newUnlockAutomatic(m.ctx, p, pc.ID, pc.Params, fmt.Sprintf("Signing with SSH agent (%s)...", pc.ID))
		m.autoUnlock = &child
		return m, child.Init()
	case typeRecovery:
		child := newUnlockRecovery(m.ctx, p, pc.ID, pc.Params)
		m.recoveryUnlock = &child
		return m, child.Init()
	case typeSSHKey:
		child := newUnlockSSHKey(m.ctx, p, pc.ID, pc.Params)
		m.sshKeyUnlock = &child
		return m, child.Init()
	case typeFIDO2:
		child := newUnlockFIDO2(m.ctx, p, pc.ID, pc.Params)
		m.fido2Unlock = &child
		return m, child.Init()
	case typePIV:
		child := newUnlockPIV(m.ctx, p, pc.ID, pc.Params)
		m.pivUnlock = &child
		return m, child.Init()
	default:
		// Should never reach here because we checked tuiUnlockSupported.
		m.exit = RekeyAppExitFallbackCLI
		m.state = rekeyAppFallback
		return m, tea.Quit
	}
}

//nolint:dupl // mirror of updateFill — different finishXxxChild + phase semantics
func (m RekeyAppModel) updateUnlock(msg tea.Msg) (tea.Model, tea.Cmd) {
	pc := m.profile.Providers[m.unlockIdx]

	switch {
	case m.passUnlock != nil:
		child, cmd := m.passUnlock.Update(msg)
		m.passUnlock = &child
		if !child.Done() {
			return m, cmd
		}
		return m.finishUnlockChild(pc, child.Skipped(), child.Secret)
	case m.autoUnlock != nil:
		child, cmd := m.autoUnlock.Update(msg)
		m.autoUnlock = &child
		if !child.Done() {
			return m, cmd
		}
		return m.finishUnlockChild(pc, child.Skipped(), child.Secret)
	case m.recoveryUnlock != nil:
		child, cmd := m.recoveryUnlock.Update(msg)
		m.recoveryUnlock = &child
		if !child.Done() {
			return m, cmd
		}
		return m.finishUnlockChild(pc, child.Skipped(), child.Secret)
	case m.sshKeyUnlock != nil:
		child, cmd := m.sshKeyUnlock.Update(msg)
		m.sshKeyUnlock = &child
		if !child.Done() {
			return m, cmd
		}
		return m.finishUnlockChild(pc, child.Skipped(), child.Secret)
	case m.fido2Unlock != nil:
		child, cmd := m.fido2Unlock.Update(msg)
		m.fido2Unlock = &child
		if !child.Done() {
			return m, cmd
		}
		return m.finishUnlockChild(pc, child.Skipped(), child.Secret)
	case m.pivUnlock != nil:
		child, cmd := m.pivUnlock.Update(msg)
		m.pivUnlock = &child
		if !child.Done() {
			return m, cmd
		}
		return m.finishUnlockChild(pc, child.Skipped(), child.Secret)
	}
	return m, nil
}

// finishUnlockChild processes the result of any unlock sub-model: records
// the secret / share if one was produced, treats derive/decrypt failures
// as "skip this provider" so a single wrong passphrase doesn't torpedo
// the whole unlock flow (matching `cryptkey derive`'s behavior), and
// advances to the next provider.
func (m RekeyAppModel) finishUnlockChild(pc config.ProviderConfig, skipped bool, result func() ([]byte, error)) (tea.Model, tea.Cmd) {
	m.passUnlock = nil
	m.autoUnlock = nil
	m.recoveryUnlock = nil
	m.sshKeyUnlock = nil
	m.fido2Unlock = nil
	m.pivUnlock = nil

	if !skipped {
		secret, err := result()
		if err == nil {
			// acceptUnlockedSecret returning an error here means the share
			// didn't decrypt with the derived secret — almost always a
			// wrong passphrase / PIN. Fall through and skip; if threshold
			// can't be met across all providers, afterUnlockLoop errors
			// out with a meaningful message.
			_ = m.acceptUnlockedSecret(pc, secret)
		}
		// derive-level errors (device not present, PIN auth blocked, …)
		// also fall through as skips. If every provider fails, the final
		// threshold check in afterUnlockLoop reports it to the user.
	}
	m.unlockIdx++
	return m.startCurrentUnlock()
}

// acceptUnlockedSecret records the secret, decrypts the share, and updates
// the running master-key reconstruction. Returns an error only for
// internal/cryptographic failures (not for wrong-secret, which manifests
// as a decryption error here).
func (m *RekeyAppModel) acceptUnlockedSecret(pc config.ProviderConfig, secret []byte) error {
	es, err := pc.EncryptedShareData()
	if err != nil {
		return fmt.Errorf("decode share for %s:%s: %w", pc.Type, pc.ID, err)
	}
	aad := []byte(pc.Type + ":" + pc.ID)
	share, err := crypto.DecryptShare(secret, aad, es)
	if err != nil {
		return fmt.Errorf("decrypt share for %s:%s: wrong secret or tampered data", pc.Type, pc.ID)
	}
	m.secrets[pc.Type+":"+pc.ID] = secret
	m.shares = append(m.shares, share)

	// Once we have threshold shares, try to reconstruct.
	if m.masterKey == nil && len(m.shares) >= m.profile.Threshold {
		mk, err := shamir.Combine(m.shares)
		if err != nil {
			return fmt.Errorf("shamir combine: %w", err)
		}
		ok, verr := m.profile.VerifyIntegrity(mk)
		if verr != nil || !ok {
			crypto.WipeBytes(mk)
			return errors.New("integrity check failed — profile may be tampered or a wrong share was accepted")
		}
		m.masterKey = mk
	}
	return nil
}

// allKeptSecretsCollected reports whether every provider the user wants to
// keep in the new profile already has its secret collected. Used to stop
// the unlock loop early once enough material is in hand.
func (m RekeyAppModel) allKeptSecretsCollected() bool {
	for _, pc := range m.keepList {
		if _, ok := m.secrets[pc.Type+":"+pc.ID]; !ok {
			return false
		}
	}
	return true
}

// afterUnlockLoop runs once every profile provider has been visited (or we
// short-circuited). Verifies we have enough to continue.
func (m RekeyAppModel) afterUnlockLoop() (tea.Model, tea.Cmd) {
	// Wipe the recovered shares — we kept them only for reconstruction.
	for _, s := range m.shares {
		crypto.WipeBytes(s)
	}
	m.shares = nil

	if m.masterKey == nil {
		m.err = fmt.Errorf("could not reconstruct master key — threshold %d not met", m.profile.Threshold)
		m.exit = RekeyAppExitError
		m.state = rekeyAppError
		return m, tea.Quit
	}

	// Compute kept providers still missing a secret — we'll derive those
	// in the fill-in phase.
	m.fillMissing = nil
	for _, pc := range m.keepList {
		if _, ok := m.secrets[pc.Type+":"+pc.ID]; !ok {
			m.fillMissing = append(m.fillMissing, pc)
		}
	}
	if len(m.fillMissing) == 0 {
		return m.beginEnroll()
	}
	m.state = rekeyAppFill
	m.fillIdx = 0
	return m.startCurrentFill()
}

// --- Fill-in phase ---

func (m RekeyAppModel) startCurrentFill() (tea.Model, tea.Cmd) {
	if m.fillIdx >= len(m.fillMissing) {
		return m.beginEnroll()
	}
	pc := m.fillMissing[m.fillIdx]
	p, _ := provider.Get(pc.Type)
	switch pc.Type {
	case typePassphrase:
		child := newUnlockPassphrase(m.ctx, p, pc.ID, pc.Params)
		m.passUnlock = &child
		return m, child.Init()
	case typeTPM:
		child := newUnlockAutomatic(m.ctx, p, pc.ID, pc.Params, fmt.Sprintf("Unlocking with TPM (%s)...", pc.ID))
		m.autoUnlock = &child
		return m, child.Init()
	case typeSSHAgent:
		child := newUnlockAutomatic(m.ctx, p, pc.ID, pc.Params, fmt.Sprintf("Signing with SSH agent (%s)...", pc.ID))
		m.autoUnlock = &child
		return m, child.Init()
	case typeRecovery:
		child := newUnlockRecovery(m.ctx, p, pc.ID, pc.Params)
		m.recoveryUnlock = &child
		return m, child.Init()
	case typeSSHKey:
		child := newUnlockSSHKey(m.ctx, p, pc.ID, pc.Params)
		m.sshKeyUnlock = &child
		return m, child.Init()
	case typeFIDO2:
		child := newUnlockFIDO2(m.ctx, p, pc.ID, pc.Params)
		m.fido2Unlock = &child
		return m, child.Init()
	case typePIV:
		child := newUnlockPIV(m.ctx, p, pc.ID, pc.Params)
		m.pivUnlock = &child
		return m, child.Init()
	default:
		m.err = fmt.Errorf("fill-in for provider type %q not yet supported in TUI mode", pc.Type)
		m.exit = RekeyAppExitError
		m.state = rekeyAppError
		return m, tea.Quit
	}
}

//nolint:dupl // mirror of updateUnlock — different finishXxxChild + phase semantics
func (m RekeyAppModel) updateFill(msg tea.Msg) (tea.Model, tea.Cmd) {
	pc := m.fillMissing[m.fillIdx]

	switch {
	case m.passUnlock != nil:
		child, cmd := m.passUnlock.Update(msg)
		m.passUnlock = &child
		if !child.Done() {
			return m, cmd
		}
		return m.finishFillChild(pc, child.Skipped(), child.Secret)
	case m.autoUnlock != nil:
		child, cmd := m.autoUnlock.Update(msg)
		m.autoUnlock = &child
		if !child.Done() {
			return m, cmd
		}
		return m.finishFillChild(pc, child.Skipped(), child.Secret)
	case m.recoveryUnlock != nil:
		child, cmd := m.recoveryUnlock.Update(msg)
		m.recoveryUnlock = &child
		if !child.Done() {
			return m, cmd
		}
		return m.finishFillChild(pc, child.Skipped(), child.Secret)
	case m.sshKeyUnlock != nil:
		child, cmd := m.sshKeyUnlock.Update(msg)
		m.sshKeyUnlock = &child
		if !child.Done() {
			return m, cmd
		}
		return m.finishFillChild(pc, child.Skipped(), child.Secret)
	case m.fido2Unlock != nil:
		child, cmd := m.fido2Unlock.Update(msg)
		m.fido2Unlock = &child
		if !child.Done() {
			return m, cmd
		}
		return m.finishFillChild(pc, child.Skipped(), child.Secret)
	case m.pivUnlock != nil:
		child, cmd := m.pivUnlock.Update(msg)
		m.pivUnlock = &child
		if !child.Done() {
			return m, cmd
		}
		return m.finishFillChild(pc, child.Skipped(), child.Secret)
	}
	return m, nil
}

// finishFillChild processes a fill-in sub-model's result. Unlike the unlock
// phase, a skip here is fatal — we'd have no way to encrypt the kept
// provider's new share without its secret.
func (m RekeyAppModel) finishFillChild(pc config.ProviderConfig, skipped bool, result func() ([]byte, error)) (tea.Model, tea.Cmd) {
	m.passUnlock = nil
	m.autoUnlock = nil
	m.recoveryUnlock = nil
	m.sshKeyUnlock = nil
	m.fido2Unlock = nil
	m.pivUnlock = nil

	if skipped {
		m.err = fmt.Errorf("kept provider %s:%s was skipped — either derive it, or --remove it", pc.Type, pc.ID)
		m.exit = RekeyAppExitError
		m.state = rekeyAppError
		return m, tea.Quit
	}
	secret, err := result()
	if err != nil {
		m.err = fmt.Errorf("derive %s:%s: %w", pc.Type, pc.ID, err)
		m.exit = RekeyAppExitError
		m.state = rekeyAppError
		return m, tea.Quit
	}
	// Verify against the stored share so a wrong secret for a kept
	// provider fails loudly here rather than producing an unreadable
	// new profile.
	es, err := pc.EncryptedShareData()
	if err != nil {
		m.err = err
		m.exit = RekeyAppExitError
		m.state = rekeyAppError
		return m, tea.Quit
	}
	aad := []byte(pc.Type + ":" + pc.ID)
	share, err := crypto.DecryptShare(secret, aad, es)
	if err != nil {
		m.err = fmt.Errorf("wrong secret for kept provider %s:%s", pc.Type, pc.ID)
		m.exit = RekeyAppExitError
		m.state = rekeyAppError
		return m, tea.Quit
	}
	crypto.WipeBytes(share)
	m.secrets[pc.Type+":"+pc.ID] = secret
	m.fillIdx++
	return m.startCurrentFill()
}

// --- Enroll phase ---

func (m RekeyAppModel) beginEnroll() (tea.Model, tea.Cmd) {
	m.state = rekeyAppEnroll
	m.addIdx = 0
	m.addSpecs = m.resolved.Add
	return m.startCurrentEnroll()
}

func (m RekeyAppModel) startCurrentEnroll() (tea.Model, tea.Cmd) {
	if m.addIdx >= len(m.addSpecs) {
		return m.beginWrite()
	}
	spec := m.addSpecs[m.addIdx]
	typeName, id := parseSpec(spec)
	p, ok := provider.Get(typeName)
	if !ok {
		m.err = fmt.Errorf("--add %q: unknown provider type", spec)
		m.exit = RekeyAppExitError
		m.state = rekeyAppError
		return m, tea.Quit
	}
	if id == "" {
		id = m.nextEnrollID(typeName)
	}

	switch typeName {
	case typePassphrase:
		child := newEnrollPassphrase(m.ctx, p, id, nil)
		m.passEnroll = &child
		return m, child.Init()
	case "fido2":
		child := newEnrollFIDO2(m.ctx, p, id, nil)
		m.fido2Enroll = &child
		return m, child.Init()
	case typeSSHAgent:
		child := newEnrollSSHAgent(m.ctx, p, id, nil)
		m.sshAgentE = &child
		return m, child.Init()
	case typeSSHKey:
		child := newEnrollSSHKey(m.ctx, p, id, nil)
		m.sshKeyE = &child
		return m, child.Init()
	case typePIV:
		child := newEnrollPIV(m.ctx, p, id, nil)
		m.pivE = &child
		return m, child.Init()
	default:
		// recovery / passkey — no pre-input; fall back for now.
		m.err = fmt.Errorf("enroll for provider type %q not yet supported in TUI mode — use --no-tui", typeName)
		m.exit = RekeyAppExitError
		m.state = rekeyAppError
		return m, tea.Quit
	}
}

func (m RekeyAppModel) updateEnroll(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch {
	case m.passEnroll != nil:
		child, cmd := m.passEnroll.Update(msg)
		m.passEnroll = &child
		if !child.Done() {
			return m, cmd
		}
		result, resErr := child.Result()
		return m.finishEnrollChild(child.Canceled(), result, resErr)
	case m.fido2Enroll != nil:
		child, cmd := m.fido2Enroll.Update(msg)
		m.fido2Enroll = &child
		if !child.Done() {
			return m, cmd
		}
		result, resErr := child.Result()
		return m.finishEnrollChild(child.Canceled(), result, resErr)
	case m.sshAgentE != nil:
		child, cmd := m.sshAgentE.Update(msg)
		m.sshAgentE = &child
		if !child.Done() {
			return m, cmd
		}
		result, resErr := child.Result()
		return m.finishEnrollChild(child.Canceled(), result, resErr)
	case m.sshKeyE != nil:
		child, cmd := m.sshKeyE.Update(msg)
		m.sshKeyE = &child
		if !child.Done() {
			return m, cmd
		}
		result, resErr := child.Result()
		return m.finishEnrollChild(child.Canceled(), result, resErr)
	case m.pivE != nil:
		child, cmd := m.pivE.Update(msg)
		m.pivE = &child
		if !child.Done() {
			return m, cmd
		}
		result, resErr := child.Result()
		return m.finishEnrollChild(child.Canceled(), result, resErr)
	}
	return m, nil
}

func (m RekeyAppModel) finishEnrollChild(canceled bool, result *enrollment.Enrollment, childErr error) (tea.Model, tea.Cmd) {
	// Clear any active child pointer.
	m.passEnroll = nil
	m.fido2Enroll = nil
	m.sshAgentE = nil
	m.sshKeyE = nil
	m.pivE = nil

	if canceled {
		m.exit = RekeyAppExitCanceled
		m.state = rekeyAppCanceled
		return m, tea.Quit
	}
	if childErr != nil {
		m.err = childErr
		m.exit = RekeyAppExitError
		m.state = rekeyAppError
		return m, tea.Quit
	}
	if result == nil {
		m.err = errors.New("enrollment returned no result")
		m.exit = RekeyAppExitError
		m.state = rekeyAppError
		return m, tea.Quit
	}
	m.newEnrolls = append(m.newEnrolls, *result)
	m.addIdx++
	return m.startCurrentEnroll()
}

func (m RekeyAppModel) nextEnrollID(typeName string) string {
	used := make(map[string]bool)
	for _, pc := range m.keepList {
		used[pc.ID] = true
	}
	for _, e := range m.newEnrolls {
		used[e.ID] = true
	}
	for i := 1; ; i++ {
		candidate := fmt.Sprintf("%s-%d", typeName, i)
		if !used[candidate] {
			return candidate
		}
	}
}

// --- Write phase ---

func (m RekeyAppModel) beginWrite() (tea.Model, tea.Cmd) {
	m.state = rekeyAppWrite

	// Assemble the enrollment list in kept-then-new order, copying kept
	// secrets so WriteProfile's own wiping doesn't trash our map.
	all := make([]enrollment.Enrollment, 0, len(m.keepList)+len(m.newEnrolls))
	for _, pc := range m.keepList {
		secret := m.secrets[pc.Type+":"+pc.ID]
		if secret == nil {
			m.err = fmt.Errorf("internal: missing secret for kept provider %s:%s", pc.Type, pc.ID)
			m.exit = RekeyAppExitError
			m.state = rekeyAppError
			return m, tea.Quit
		}
		copyB := make([]byte, len(secret))
		copy(copyB, secret)
		p, _ := provider.Get(pc.Type)
		all = append(all, enrollment.Enrollment{
			Provider: p,
			ID:       pc.ID,
			Secret:   copyB,
			Params:   pc.Params,
		})
	}
	all = append(all, m.newEnrolls...)

	newThreshold := m.profile.Threshold
	if m.resolved.Threshold > 0 {
		newThreshold = m.resolved.Threshold
	}

	outputSalt, err := hex.DecodeString(m.profile.OutputSalt)
	if err != nil {
		m.err = fmt.Errorf("decode output_salt: %w", err)
		m.exit = RekeyAppExitError
		m.state = rekeyAppError
		return m, tea.Quit
	}

	// Backup before write.
	if _, _, err := config.Backup(m.profileName); err != nil {
		m.err = fmt.Errorf("backup existing profile: %w", err)
		m.exit = RekeyAppExitError
		m.state = rekeyAppError
		return m, tea.Quit
	}
	if err := enrollment.WriteProfile(m.profileName, newThreshold, m.masterKey, outputSalt, all); err != nil {
		m.err = fmt.Errorf("write profile: %w", err)
		m.exit = RekeyAppExitError
		m.state = rekeyAppError
		return m, tea.Quit
	}

	path, _ := config.Path(m.profileName)
	m.writtenPath = path

	// Wipe master key now that it's safely written.
	crypto.WipeBytes(m.masterKey)
	m.masterKey = nil
	for _, s := range m.secrets {
		crypto.WipeBytes(s)
	}
	m.secrets = nil

	m.exit = RekeyAppExitSuccess
	m.state = rekeyAppDone
	return m, nil
}

// --- View ---

func (m RekeyAppModel) View() tea.View {
	if m.quitting {
		v := tea.NewView("")
		v.AltScreen = true
		return v
	}

	var b strings.Builder
	b.WriteString(titleStyle.Render("cryptkey rekey"))
	b.WriteString("  ")
	b.WriteString(subtitleStyle.Render(m.profileName))
	b.WriteString("\n\n")

	switch m.state {
	case rekeyAppPlan:
		// Render the planning model inline.
		b.WriteString(m.plan.View().Content)
	case rekeyAppUnlock:
		m.renderUnlockView(&b)
	case rekeyAppFill:
		m.renderFillView(&b)
	case rekeyAppEnroll:
		m.renderEnrollView(&b)
	case rekeyAppWrite:
		b.WriteString(highlightStyle.Render("Writing new profile..."))
		b.WriteString("\n")
	case rekeyAppDone:
		b.WriteString(successStyle.Render("Rekey complete."))
		b.WriteString("\n\n")
		fmt.Fprintf(&b, "Profile written to %s\n", m.writtenPath)
		b.WriteString(dimStyle.Render("Output keys derived from this profile are unchanged."))
		b.WriteString("\n\n")
		b.WriteString(dimStyle.Render("press enter or q to exit"))
	case rekeyAppCanceled:
		b.WriteString(warningStyle.Render("Rekey canceled."))
		b.WriteString("\n\n")
		b.WriteString(dimStyle.Render("press enter or q to exit"))
	case rekeyAppFallback:
		// Normally the model is Quit before the user ever sees this frame.
		b.WriteString(dimStyle.Render("Falling back to CLI flow..."))
		b.WriteString("\n")
	case rekeyAppError:
		b.WriteString(errorStyle.Render("Error: "))
		if m.err != nil {
			b.WriteString(errorStyle.Render(m.err.Error()))
		}
		b.WriteString("\n\n")
		b.WriteString(dimStyle.Render("press enter or q to exit"))
	}

	v := tea.NewView(b.String())
	v.AltScreen = true
	return v
}

// activeUnlockView returns the View() of whichever unlock sub-model is
// currently live (at most one). Empty string when none.
func (m RekeyAppModel) activeUnlockView() string {
	switch {
	case m.passUnlock != nil:
		return m.passUnlock.View()
	case m.autoUnlock != nil:
		return m.autoUnlock.View()
	case m.recoveryUnlock != nil:
		return m.recoveryUnlock.View()
	case m.sshKeyUnlock != nil:
		return m.sshKeyUnlock.View()
	case m.fido2Unlock != nil:
		return m.fido2Unlock.View()
	case m.pivUnlock != nil:
		return m.pivUnlock.View()
	}
	return ""
}

func (m RekeyAppModel) renderUnlockView(b *strings.Builder) {
	fmt.Fprintf(b, "Step 1/3: unlocking existing profile (%d/%d)\n\n",
		m.unlockIdx+1, len(m.profile.Providers))

	// Status of each provider so far.
	for _, pc := range m.profile.Providers {
		label := pc.Type + ":" + pc.ID
		if _, ok := m.secrets[pc.Type+":"+pc.ID]; ok {
			b.WriteString(successStyle.Render("  ✓ "))
			b.WriteString(label)
			b.WriteString("\n")
		}
	}
	b.WriteString("\n")

	if m.unlockIdx < len(m.profile.Providers) {
		b.WriteString(m.activeUnlockView())
	}
}

func (m RekeyAppModel) renderFillView(b *strings.Builder) {
	fmt.Fprintf(b, "Step 1b/3: collecting %d kept provider secret(s)\n\n",
		len(m.fillMissing))
	if m.fillIdx < len(m.fillMissing) {
		b.WriteString(m.activeUnlockView())
	}
}

func (m RekeyAppModel) renderEnrollView(b *strings.Builder) {
	fmt.Fprintf(b, "Step 2/3: enrolling new providers (%d/%d)\n\n",
		m.addIdx+1, len(m.addSpecs))
	for _, e := range m.newEnrolls {
		b.WriteString(successStyle.Render("  ✓ "))
		fmt.Fprintf(b, "%s:%s\n", e.Provider.Type(), e.ID)
	}
	b.WriteString("\n")
	switch {
	case m.passEnroll != nil:
		b.WriteString(m.passEnroll.View())
	case m.fido2Enroll != nil:
		b.WriteString(m.fido2Enroll.View())
	case m.sshAgentE != nil:
		b.WriteString(m.sshAgentE.View())
	case m.sshKeyE != nil:
		b.WriteString(m.sshKeyE.View())
	case m.pivE != nil:
		b.WriteString(m.pivE.View())
	}
}

// --- Helpers ---

// parseSpec is local to rekey_app; mirrors rekey/rekey.go's parseAddSpec
// without importing the command package.
func parseSpec(spec string) (typeName, id string) {
	if idx := strings.IndexByte(spec, ':'); idx >= 0 {
		return spec[:idx], spec[idx+1:]
	}
	return spec, ""
}

// resolveKeptFromPlan maps a RekeyPlan onto concrete ProviderConfigs from
// the profile, enforcing that every Keep / Remove name exists.
func resolveKeptFromPlan(profile *config.Profile, plan RekeyPlan) ([]config.ProviderConfig, error) {
	removed := make(map[string]bool, len(plan.Remove))
	for _, r := range plan.Remove {
		removed[r] = true
	}
	existing := make(map[string]config.ProviderConfig, len(profile.Providers))
	for _, pc := range profile.Providers {
		existing[pc.Type+":"+pc.ID] = pc
	}
	var keepFilter map[string]bool
	if len(plan.Keep) > 0 {
		keepFilter = make(map[string]bool, len(plan.Keep))
		for _, k := range plan.Keep {
			keepFilter[k] = true
		}
	}
	var keep []config.ProviderConfig
	for _, pc := range profile.Providers {
		key := pc.Type + ":" + pc.ID
		if removed[key] {
			continue
		}
		if keepFilter != nil && !keepFilter[key] {
			continue
		}
		keep = append(keep, pc)
	}
	for _, k := range plan.Keep {
		if _, ok := existing[k]; !ok {
			return nil, fmt.Errorf("keep %q: not a provider in this profile", k)
		}
	}
	for _, r := range plan.Remove {
		if _, ok := existing[r]; !ok {
			return nil, fmt.Errorf("remove %q: not a provider in this profile", r)
		}
	}
	return keep, nil
}
