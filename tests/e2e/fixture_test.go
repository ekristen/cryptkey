package e2e

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ekristen/cryptkey/pkg/config"
)

// goldenFixture pins a profile + its passphrases + the exact 32-byte output
// key that the profile must derive. Any change to envelope format, AAD
// construction, HKDF info, integrity HMAC, Shamir encoding, or Argon2 param
// round-trip trips these tests — which is the entire point: users' existing
// profiles must keep deriving the same key across cryptkey versions, or the
// tool has silently eaten their data.
//
// To regenerate after a deliberate format change: `go test -tags=fixturegen
// ./tests/e2e/... -run TestGenerateGoldenFixtures`. Review the diff; the
// fact that it moved is itself the news.
type goldenFixture struct {
	Description       string            `json:"description"`
	ProfileName       string            `json:"profile_name"`
	Passphrases       map[string]string `json:"passphrases"`
	ExpectedOutputKey string            `json:"expected_output_key"`
}

func loadGoldenFixture(t *testing.T, name string) goldenFixture {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name+".json"))
	require.NoError(t, err, "read fixture metadata")
	var f goldenFixture
	require.NoError(t, json.Unmarshal(data, &f), "decode fixture metadata")
	return f
}

// installFixtureProfile copies testdata/<name>.toml into the XDG config dir
// so that config.Load(name) picks it up.
func installFixtureProfile(t *testing.T, name string) {
	t.Helper()
	withConfigDir(t)

	dst, err := config.Path(name)
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Dir(dst), 0700))

	src, err := os.ReadFile(filepath.Join("testdata", name+".toml"))
	require.NoError(t, err, "read fixture profile")
	require.NoError(t, os.WriteFile(dst, src, 0600)) //nolint:gosec // dst from config.Path, name is a fixed fixture id
}

func verifyGoldenFixture(t *testing.T, fixtureName string) {
	t.Helper()
	fx := loadGoldenFixture(t, fixtureName)
	installFixtureProfile(t, fixtureName)

	profile, err := config.Load(fx.ProfileName)
	require.NoError(t, err)

	key := manualReconstruct(t, profile, fx.Passphrases)
	assert.Equal(t, fx.ExpectedOutputKey, hex.EncodeToString(key),
		"derived output key drifted — encryption format changed. If intentional, regenerate fixtures with -tags=fixturegen")
}

func TestGoldenFixture_PassphraseFloor2of2(t *testing.T) {
	verifyGoldenFixture(t, "golden-passphrase-floor-2of2")
}

func TestGoldenFixture_PassphraseHardened2of2(t *testing.T) {
	verifyGoldenFixture(t, "golden-passphrase-hardened-2of2")
}

func TestGoldenFixture_MixedPassphraseRecovery2of2(t *testing.T) {
	verifyGoldenFixture(t, "golden-mixed-passphrase-recovery-2of2")
}
