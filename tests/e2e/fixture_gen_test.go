//go:build fixturegen

// Package e2e fixture generator. Run with `-tags=fixturegen` to regenerate
// the golden fixtures under testdata/. Do not run casually — every run
// produces a fresh profile (new random salts, nonces, master key), so
// committing the output is a deliberate "yes, this is the new baseline"
// action.
package e2e

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ekristen/cryptkey/pkg/config"
	"github.com/ekristen/cryptkey/pkg/enrollment"
	"github.com/ekristen/cryptkey/pkg/provider"
)

func enrollPassphraseForGen(t *testing.T, ctx context.Context, pass, id string) enrollment.Enrollment {
	t.Helper()
	p, ok := provider.Get("passphrase")
	require.True(t, ok)

	ctx = context.WithValue(ctx, provider.CtxPassphrase, []byte(pass))
	e, err := enrollment.EnrollProvider(ctx, p, id)
	require.NoError(t, err)
	return *e
}

func enrollRecoveryForGen(t *testing.T, ctx context.Context, id string) enrollment.Enrollment {
	t.Helper()
	p, ok := provider.Get("recovery")
	require.True(t, ok)

	ctx = context.WithValue(ctx, provider.CtxSilent, true)
	e, err := enrollment.EnrollProvider(ctx, p, id)
	require.NoError(t, err)
	require.NotEmpty(t, e.Message, "recovery enrollment should surface generated code in Message")
	return *e
}

func writeFixture(t *testing.T, name, description string, passphrases map[string]string, profileSrc string) {
	t.Helper()

	// Copy the generated profile TOML into testdata/.
	dstTOML := filepath.Join("testdata", name+".toml")
	data, err := os.ReadFile(profileSrc)
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll("testdata", 0755))
	require.NoError(t, os.WriteFile(dstTOML, data, 0644))

	// Derive the expected output key and record it alongside the TOML.
	profile, err := config.Load(name)
	require.NoError(t, err)
	key := manualReconstruct(t, profile, passphrases)

	meta := goldenFixture{
		Description:       description,
		ProfileName:       name,
		Passphrases:       passphrases,
		ExpectedOutputKey: hex.EncodeToString(key),
	}
	metaBytes, err := json.MarshalIndent(meta, "", "  ")
	require.NoError(t, err)
	metaBytes = append(metaBytes, '\n')
	require.NoError(t, os.WriteFile(filepath.Join("testdata", name+".json"), metaBytes, 0644))

	t.Logf("generated fixture %s (key=%s)", name, meta.ExpectedOutputKey)
}

func TestGenerateGoldenFixtures(t *testing.T) {
	// Writes into the repo under tests/e2e/testdata/. Uses the real
	// BuildProfile path (including random salts/nonces) so fixtures are
	// byte-identical to a real user-generated profile.

	// Fixture 1: 2-of-2 passphrase at OWASP-floor Argon2 params. Fast to
	// derive, catches envelope/HKDF/integrity format drift.
	t.Run("passphrase-floor-2of2", func(t *testing.T) {
		withConfigDir(t)

		name := "golden-passphrase-floor-2of2"
		passphrases := map[string]string{
			"pass-1": "golden-alpha-passphrase",
			"pass-2": "golden-beta-passphrase",
		}

		ctx := fastArgonContext(context.Background())
		e1 := enrollPassphraseForGen(t, ctx, passphrases["pass-1"], "pass-1")
		e2 := enrollPassphraseForGen(t, ctx, passphrases["pass-2"], "pass-2")
		require.NoError(t, enrollment.BuildProfile(name, 2, []enrollment.Enrollment{e1, e2}))

		src, err := config.Path(name)
		require.NoError(t, err)

		writeFixture(t, name,
			"2-of-2 passphrase profile at OWASP-floor Argon2id params (t=2, m=19MiB, p=1)",
			passphrases, src)
	})

	// Fixture 2: 2-of-2 passphrase at hardened Argon2 defaults (t=3, 256 MiB,
	// p=4). Catches bugs in the upper end of the param encoding — a fixture
	// that only uses the floor wouldn't notice if the stored-vs-derived
	// param conversion silently capped values.
	t.Run("passphrase-hardened-2of2", func(t *testing.T) {
		withConfigDir(t)

		name := "golden-passphrase-hardened-2of2"
		passphrases := map[string]string{
			"pass-1": "hardened-alpha-passphrase",
			"pass-2": "hardened-beta-passphrase",
		}

		// No fastArgonContext → provider uses its hardened defaults.
		ctx := context.Background()
		e1 := enrollPassphraseForGen(t, ctx, passphrases["pass-1"], "pass-1")
		e2 := enrollPassphraseForGen(t, ctx, passphrases["pass-2"], "pass-2")
		require.NoError(t, enrollment.BuildProfile(name, 2, []enrollment.Enrollment{e1, e2}))

		src, err := config.Path(name)
		require.NoError(t, err)

		writeFixture(t, name,
			"2-of-2 passphrase profile at hardened Argon2id defaults (t=3, m=256MiB, p=4)",
			passphrases, src)
	})

	// Fixture 3: mixed passphrase + recovery, threshold 2. Catches drift in
	// the recovery provider format (alphabet, normalization, salt handling)
	// and verifies that shares from different provider types combine
	// correctly.
	t.Run("mixed-passphrase-recovery-2of2", func(t *testing.T) {
		withConfigDir(t)

		name := "golden-mixed-passphrase-recovery-2of2"
		ctx := fastArgonContext(context.Background())

		e1 := enrollPassphraseForGen(t, ctx, "mixed-alpha-passphrase", "pass-1")
		e2 := enrollRecoveryForGen(t, ctx, "rec-1")

		require.NoError(t, enrollment.BuildProfile(name, 2, []enrollment.Enrollment{e1, e2}))

		// The recovery code is randomly generated at enroll time; capture
		// the formatted string from EnrollResult.Message so the regression
		// test can feed it back via CtxPassphrase during derive.
		passphrases := map[string]string{
			"pass-1": "mixed-alpha-passphrase",
			"rec-1":  e2.Message,
		}

		src, err := config.Path(name)
		require.NoError(t, err)

		writeFixture(t, name,
			"2-of-2 passphrase + recovery-code mix at OWASP-floor Argon2id params",
			passphrases, src)
	})
}
