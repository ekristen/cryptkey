package e2e

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ekristen/cryptkey/pkg/commands/rekey"
	"github.com/ekristen/cryptkey/pkg/config"
	"github.com/ekristen/cryptkey/pkg/enrollment"
	"github.com/ekristen/cryptkey/pkg/provider"
)

// commonPass is the passphrase shared by every passphrase provider in these
// tests. Each provider has its own random salt, so the same passphrase
// derives a distinct 32-byte secret per provider — exactly what enrollment
// expects, and what lets a single CtxPassphrase value satisfy a multi-
// passphrase rekey unlock.
const commonPass = "shared-test-passphrase"

// rekeyContext returns a base context that injects commonPass for every
// passphrase provider derive / enroll call made under it.
func rekeyContext(passphrase string) context.Context {
	return context.WithValue(context.Background(), provider.CtxPassphrase, []byte(passphrase))
}

// buildSharedPassProfile builds a profile with len(ids) passphrase providers,
// each enrolled with commonPass under the supplied id.
func buildSharedPassProfile(t *testing.T, name string, threshold int, ids []string) {
	t.Helper()
	enrolls := make([]enrollment.Enrollment, len(ids))
	for i, id := range ids {
		enrolls[i] = enrollPassphrase(t, commonPass, id)
	}
	require.NoError(t, enrollment.BuildProfile(name, threshold, enrolls))
}

// profilePath returns the on-disk path of the named profile's TOML file.
func profilePath(t *testing.T, name string) string {
	t.Helper()
	p, err := config.Path(name)
	require.NoError(t, err)
	return p
}

func TestRekeyAddProviderPreservesOutputKey(t *testing.T) {
	withConfigDir(t)
	buildSharedPassProfile(t, "rekey-add", 2, []string{"pass-1", "pass-2"})

	profile, err := config.Load("rekey-add")
	require.NoError(t, err)
	originalOutputSalt := profile.OutputSalt
	originalOutputKey := manualReconstruct(t, profile, map[string]string{
		"pass-1": commonPass, "pass-2": commonPass,
	})

	err = rekey.Run(rekeyContext(commonPass), "rekey-add", rekey.Options{
		Add:   []string{"passphrase:pass-3"},
		NoTUI: true,
	})
	require.NoError(t, err)

	newProfile, err := config.Load("rekey-add")
	require.NoError(t, err)
	assert.Len(t, newProfile.Providers, 3)
	assert.Equal(t, 2, newProfile.Threshold)
	assert.Equal(t, originalOutputSalt, newProfile.OutputSalt, "output_salt preserved")

	newOutputKey := manualReconstruct(t, newProfile, map[string]string{
		"pass-1": commonPass, "pass-2": commonPass, "pass-3": commonPass,
	})
	assert.True(t, bytes.Equal(originalOutputKey, newOutputKey),
		"output key must survive rekey when --use is unchanged")
}

func TestRekeyRemoveProvider(t *testing.T) {
	withConfigDir(t)
	buildSharedPassProfile(t, "rekey-remove", 2, []string{"pass-1", "pass-2", "pass-3"})

	err := rekey.Run(rekeyContext(commonPass), "rekey-remove", rekey.Options{
		Remove: []string{"passphrase:pass-3"},
		NoTUI:  true,
	})
	require.NoError(t, err)

	newProfile, err := config.Load("rekey-remove")
	require.NoError(t, err)
	assert.Len(t, newProfile.Providers, 2)
	for _, pc := range newProfile.Providers {
		assert.NotEqual(t, "pass-3", pc.ID, "removed provider should not appear")
	}
}

func TestRekeyChangesShareValues(t *testing.T) {
	withConfigDir(t)
	buildSharedPassProfile(t, "rekey-shares", 2, []string{"pass-1", "pass-2", "pass-3"})

	before, err := config.Load("rekey-shares")
	require.NoError(t, err)
	beforeShares := make(map[string]string, len(before.Providers))
	for _, pc := range before.Providers {
		beforeShares[pc.ID] = pc.EncryptedShare
	}

	err = rekey.Run(rekeyContext(commonPass), "rekey-shares", rekey.Options{
		Add:   []string{"passphrase:pass-4"},
		NoTUI: true,
	})
	require.NoError(t, err)

	after, err := config.Load("rekey-shares")
	require.NoError(t, err)
	for _, pc := range after.Providers {
		if old, ok := beforeShares[pc.ID]; ok {
			assert.NotEqual(t, old, pc.EncryptedShare,
				"share for kept provider %s should change after rekey (new polynomial)", pc.ID)
		}
	}
}

func TestRekeyChangeThreshold(t *testing.T) {
	withConfigDir(t)
	buildSharedPassProfile(t, "rekey-threshold", 2, []string{"pass-1", "pass-2", "pass-3"})

	err := rekey.Run(rekeyContext(commonPass), "rekey-threshold", rekey.Options{
		Threshold: 3,
		NoTUI:     true,
	})
	require.NoError(t, err)

	p, err := config.Load("rekey-threshold")
	require.NoError(t, err)
	assert.Equal(t, 3, p.Threshold)

	_, err = manualReconstructErr(p, map[string]string{
		"pass-1": commonPass, "pass-2": commonPass,
	})
	require.Error(t, err, "threshold 3 should reject 2-share reconstruction")

	key := manualReconstruct(t, p, map[string]string{
		"pass-1": commonPass, "pass-2": commonPass, "pass-3": commonPass,
	})
	assert.Len(t, key, 32)
}

func TestRekeyBackupWritten(t *testing.T) {
	withConfigDir(t)
	buildSharedPassProfile(t, "rekey-bak", 2, []string{"pass-1", "pass-2"})

	err := rekey.Run(rekeyContext(commonPass), "rekey-bak", rekey.Options{
		Add:   []string{"passphrase:pass-3"},
		NoTUI: true,
	})
	require.NoError(t, err)

	bakPath, err := config.BackupPath("rekey-bak")
	require.NoError(t, err)
	_, err = os.Stat(bakPath)
	assert.NoError(t, err, "backup file should exist after rekey")
}

func TestRekeyNoBackupSkipsBackup(t *testing.T) {
	withConfigDir(t)
	buildSharedPassProfile(t, "rekey-nobak", 2, []string{"pass-1", "pass-2"})

	err := rekey.Run(rekeyContext(commonPass), "rekey-nobak", rekey.Options{
		Add:      []string{"passphrase:pass-3"},
		NoTUI:    true,
		NoBackup: true,
	})
	require.NoError(t, err)

	bakPath, err := config.BackupPath("rekey-nobak")
	require.NoError(t, err)
	_, err = os.Stat(bakPath)
	assert.True(t, os.IsNotExist(err), "backup must not exist with NoBackup=true")
}

func TestRekeyAbortsOnUnlockFail(t *testing.T) {
	withConfigDir(t)
	buildSharedPassProfile(t, "rekey-fail", 2, []string{"pass-1", "pass-2"})

	originalBytes, err := os.ReadFile(profilePath(t, "rekey-fail"))
	require.NoError(t, err)

	err = rekey.Run(rekeyContext("WRONG-PASSPHRASE"), "rekey-fail", rekey.Options{
		Add:   []string{"passphrase:pass-3"},
		NoTUI: true,
	})
	require.Error(t, err, "wrong passphrase should fail rekey")

	currentBytes, err := os.ReadFile(profilePath(t, "rekey-fail"))
	require.NoError(t, err)
	assert.Equal(t, originalBytes, currentBytes,
		"profile must remain untouched when rekey aborts before write")
}

func TestRekeyKeepFiltersProviders(t *testing.T) {
	withConfigDir(t)
	buildSharedPassProfile(t, "rekey-keep", 2, []string{"pass-1", "pass-2", "pass-3"})

	err := rekey.Run(rekeyContext(commonPass), "rekey-keep", rekey.Options{
		Keep:  []string{"passphrase:pass-1", "passphrase:pass-2"},
		NoTUI: true,
	})
	require.NoError(t, err)

	p, err := config.Load("rekey-keep")
	require.NoError(t, err)
	assert.Len(t, p.Providers, 2)
	ids := []string{p.Providers[0].ID, p.Providers[1].ID}
	assert.NotContains(t, ids, "pass-3")
}

func TestRekeyKeepUnknownNameRejected(t *testing.T) {
	withConfigDir(t)
	buildSharedPassProfile(t, "rekey-bad-keep", 2, []string{"pass-1", "pass-2"})

	err := rekey.Run(rekeyContext(commonPass), "rekey-bad-keep", rekey.Options{
		Keep:  []string{"passphrase:does-not-exist"},
		NoTUI: true,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a provider in this profile")
}

func TestRekeyTooFewProvidersRejected(t *testing.T) {
	withConfigDir(t)
	buildSharedPassProfile(t, "rekey-too-few", 2, []string{"pass-1", "pass-2"})

	err := rekey.Run(rekeyContext(commonPass), "rekey-too-few", rekey.Options{
		Remove: []string{"passphrase:pass-2"},
		NoTUI:  true,
	})
	assert.Error(t, err, "removing below threshold must fail")
}

// TestRekey2of2RemoveOneAddTwo covers the reported regression: a 2-of-2 profile
// where the user removes one existing provider and adds two new ones. Unlock
// needs BOTH existing providers (threshold 2 against the old polynomial) — not
// just the one being kept. The new profile ends up with 1 kept + 2 added = 3
// providers, threshold 2.
func TestRekey2of2RemoveOneAddTwo(t *testing.T) {
	withConfigDir(t)
	buildSharedPassProfile(t, "rekey-2of2-rot", 2, []string{"pass-1", "pass-2"})

	err := rekey.Run(rekeyContext(commonPass), "rekey-2of2-rot", rekey.Options{
		Remove: []string{"passphrase:pass-2"},
		Add:    []string{"passphrase:pass-3", "passphrase:pass-4"},
		NoTUI:  true,
	})
	require.NoError(t, err, "rekey must unlock with both original providers even when one is being removed")

	p, err := config.Load("rekey-2of2-rot")
	require.NoError(t, err)
	assert.Len(t, p.Providers, 3)
	assert.Equal(t, 2, p.Threshold)

	ids := make([]string, 0, len(p.Providers))
	for _, pc := range p.Providers {
		ids = append(ids, pc.ID)
	}
	assert.ElementsMatch(t, []string{"pass-1", "pass-3", "pass-4"}, ids)
	assert.NotContains(t, ids, "pass-2")

	// Any two of the three new providers should unlock the rewritten profile.
	key := manualReconstruct(t, p, map[string]string{
		"pass-1": commonPass, "pass-3": commonPass,
	})
	assert.Len(t, key, 32)
}

// TestRekeyUnlockUsesAllProvidersNotJustKept verifies the unlock phase iterates
// the FULL current profile, not a keep-filtered subset. With 3-of-3 and we keep
// only 1 of them, unlock must still pull shares from all 3 (we don't tell the
// test which ones, but reconstruction requires any 3 shares since threshold is 3).
func TestRekeyUnlockUsesAllProvidersNotJustKept(t *testing.T) {
	withConfigDir(t)
	buildSharedPassProfile(t, "rekey-3of3", 3, []string{"pass-1", "pass-2", "pass-3"})

	err := rekey.Run(rekeyContext(commonPass), "rekey-3of3", rekey.Options{
		Keep:      []string{"passphrase:pass-1"},
		Add:       []string{"passphrase:pass-new-1", "passphrase:pass-new-2"},
		Threshold: 2,
		NoTUI:     true,
	})
	require.NoError(t, err, "rekey must unlock with all 3 current providers even when keeping only 1")

	p, err := config.Load("rekey-3of3")
	require.NoError(t, err)
	assert.Len(t, p.Providers, 3, "1 kept + 2 added")
	assert.Equal(t, 2, p.Threshold)
}
