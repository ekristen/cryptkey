package sshagent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/hkdf"

	"github.com/ekristen/cryptkey/pkg/crypto/hkdfinfo"
	"github.com/ekristen/cryptkey/pkg/provider"
)

func TestBuildChallengeDeterministic(t *testing.T) {
	salt := make([]byte, 32)
	_, err := rand.Read(salt)
	require.NoError(t, err)

	fp := "SHA256:abc123"

	c1 := buildChallenge(salt, fp)
	c2 := buildChallenge(salt, fp)
	assert.Equal(t, c1, c2, "same inputs must produce same challenge")
}

func TestBuildChallengeDifferentSalts(t *testing.T) {
	salt1 := make([]byte, 32)
	salt2 := make([]byte, 32)
	_, _ = rand.Read(salt1)
	_, _ = rand.Read(salt2)

	fp := "SHA256:abc123"

	c1 := buildChallenge(salt1, fp)
	c2 := buildChallenge(salt2, fp)
	assert.NotEqual(t, c1, c2, "different salts must produce different challenges")
}

func TestDeriveSecretDeterministic(t *testing.T) {
	sig := make([]byte, 64)
	_, err := rand.Read(sig)
	require.NoError(t, err)

	salt := make([]byte, 32)
	_, err = rand.Read(salt)
	require.NoError(t, err)

	s1, err := deriveSecret(sig, salt)
	require.NoError(t, err)
	assert.Len(t, s1, 32)

	s2, err := deriveSecret(sig, salt)
	require.NoError(t, err)
	assert.Equal(t, s1, s2)
}

func TestDeriveSecretDifferentSignatures(t *testing.T) {
	salt := make([]byte, 32)
	_, _ = rand.Read(salt)

	sig1 := make([]byte, 64)
	sig2 := make([]byte, 64)
	_, _ = rand.Read(sig1)
	_, _ = rand.Read(sig2)

	s1, err := deriveSecret(sig1, salt)
	require.NoError(t, err)
	s2, err := deriveSecret(sig2, salt)
	require.NoError(t, err)

	assert.NotEqual(t, s1, s2)
}

func TestEd25519SignatureDeterminism(t *testing.T) {
	// Verify that Ed25519 signatures are deterministic — the core assumption
	// this provider relies on.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	message := []byte("cryptkey-test-challenge")

	sig1 := ed25519.Sign(priv, message)
	sig2 := ed25519.Sign(priv, message)

	assert.Equal(t, sig1, sig2, "Ed25519 signatures must be deterministic")
	assert.True(t, ed25519.Verify(pub, message, sig1))
}

func TestEndToEndWithLocalKey(t *testing.T) {
	// Simulate the full flow without an actual agent: generate a key,
	// sign a challenge, derive a secret, repeat, verify determinism.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	salt := make([]byte, 32)
	_, err = rand.Read(salt)
	require.NoError(t, err)

	fingerprint := "SHA256:test"
	challenge := buildChallenge(salt, fingerprint)

	// Sign twice — must be identical
	sig1 := ed25519.Sign(priv, challenge)
	sig2 := ed25519.Sign(priv, challenge)
	assert.Equal(t, sig1, sig2)

	// Derive secrets from both signatures
	secret1, err := deriveSecret(sig1, salt)
	require.NoError(t, err)
	secret2, err := deriveSecret(sig2, salt)
	require.NoError(t, err)

	assert.Equal(t, secret1, secret2, "same key signing same challenge must produce same secret")
	assert.Len(t, secret1, 32)
}

func TestEndToEndDifferentKeys(t *testing.T) {
	_, priv1, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	_, priv2, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	salt := make([]byte, 32)
	_, _ = rand.Read(salt)

	challenge := buildChallenge(salt, "SHA256:test")

	sig1 := ed25519.Sign(priv1, challenge)
	sig2 := ed25519.Sign(priv2, challenge)

	secret1, err := deriveSecret(sig1, salt)
	require.NoError(t, err)
	secret2, err := deriveSecret(sig2, salt)
	require.NoError(t, err)

	assert.NotEqual(t, secret1, secret2, "different keys must produce different secrets")
}

func TestSSHAgentTypeAndDescription(t *testing.T) {
	p := &SSHAgent{}
	assert.Equal(t, "ssh-agent", p.Type())
	assert.NotEmpty(t, p.Description())
}

func TestSSHAgentRegistered(t *testing.T) {
	p, ok := provider.Get("ssh-agent")
	require.True(t, ok, "ssh-agent provider should be registered")
	assert.Equal(t, "ssh-agent", p.Type())
}

func TestHKDFOutputLength(t *testing.T) {
	// Verify HKDF produces exactly keyLen bytes with our parameters
	ikm := make([]byte, 64)
	salt := make([]byte, 32)
	_, _ = rand.Read(ikm)
	_, _ = rand.Read(salt)

	r := hkdf.New(sha256.New, ikm, salt, []byte(hkdfinfo.ProviderSSHAgent))
	out := make([]byte, keyLen)
	n, err := io.ReadFull(r, out)
	require.NoError(t, err)
	assert.Equal(t, keyLen, n)
}

func TestDeriveSecretParams(t *testing.T) {
	// Verify that Derive checks for required params
	p := &SSHAgent{}

	// Missing salt
	_, err := p.Derive(context.TODO(), map[string]string{"fingerprint": "SHA256:abc"})
	require.ErrorContains(t, err, "missing salt")

	// Missing fingerprint
	_, err = p.Derive(context.TODO(), map[string]string{"salt": hex.EncodeToString(make([]byte, 32))})
	require.ErrorContains(t, err, "missing fingerprint")

	// Invalid salt hex
	_, err = p.Derive(context.TODO(), map[string]string{"salt": "zzzz", "fingerprint": "SHA256:abc"})
	require.ErrorContains(t, err, "decode salt")
}
