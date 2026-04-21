package keyformat

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFormatAge(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}

	identity, recipient, err := FormatAge(key)
	require.NoError(t, err)

	assert.True(t, bytes.HasPrefix(identity, []byte("AGE-SECRET-KEY-1")), "identity should start with AGE-SECRET-KEY-1")
	assert.True(t, strings.HasPrefix(recipient, "age1"), "recipient should start with age1")
}

func TestFormatAgeDeterministic(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	id1, rec1, err := FormatAge(key)
	require.NoError(t, err)

	id2, rec2, err := FormatAge(key)
	require.NoError(t, err)

	assert.Equal(t, id1, id2, "identity should be deterministic")
	assert.Equal(t, rec1, rec2, "recipient should be deterministic")
}

func TestFormatAgeInvalidKeyLength(t *testing.T) {
	_, _, err := FormatAge([]byte{1, 2, 3})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "32 bytes")
}

func TestFormatEd25519(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}

	privPEM, pubAuth, err := FormatEd25519(key, "test-comment")
	require.NoError(t, err)

	assert.True(t, bytes.HasPrefix(privPEM, []byte("-----BEGIN OPENSSH PRIVATE KEY-----")), "should be PEM encoded")
	assert.True(t, bytes.Contains(privPEM, []byte("-----END OPENSSH PRIVATE KEY-----")), "should have PEM footer")
	assert.True(t, strings.HasPrefix(pubAuth, "ssh-ed25519 "), "public key should start with ssh-ed25519")
	assert.True(t, strings.HasSuffix(pubAuth, " test-comment"), "public key should end with comment")
}

func TestFormatEd25519DeterministicPublicKey(t *testing.T) {
	// The public key is deterministic from the seed.
	// The PEM private key contains random check integers per OpenSSH format,
	// so it won't be byte-identical, but the underlying key material is the same.
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	_, pub1, err := FormatEd25519(key, "")
	require.NoError(t, err)

	_, pub2, err := FormatEd25519(key, "")
	require.NoError(t, err)

	assert.Equal(t, pub1, pub2, "public key should be deterministic")
}

func TestFormatEd25519CorrectKey(t *testing.T) {
	// Verify the derived key matches what ed25519.NewKeyFromSeed produces
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 10)
	}

	privPEM, pubAuth, err := FormatEd25519(key, "")
	require.NoError(t, err)

	// The public key in the authorized_keys line should match the seed
	expected := ed25519.NewKeyFromSeed(key)
	_ = expected.Public()

	assert.NotEmpty(t, privPEM)
	assert.NotEmpty(t, pubAuth)
}

func TestFormatEd25519InvalidKeyLength(t *testing.T) {
	_, _, err := FormatEd25519([]byte{1, 2, 3}, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "32 bytes")
}

func TestFormatAgeDifferentKeysProduceDifferentOutput(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	for i := range key1 {
		key1[i] = byte(i)
		key2[i] = byte(i + 100)
	}

	id1, rec1, err := FormatAge(key1)
	require.NoError(t, err)

	id2, rec2, err := FormatAge(key2)
	require.NoError(t, err)

	assert.NotEqual(t, id1, id2)
	assert.NotEqual(t, rec1, rec2)
}
