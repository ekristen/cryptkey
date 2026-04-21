package sshkey

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/ekristen/cryptkey/pkg/provider"
)

func TestSSHKeyEnrollDerive(t *testing.T) {
	keyPath := generateTestKey(t)

	ctx := context.WithValue(context.Background(), provider.CtxSSHKeyPath, keyPath)
	p := &SSHKey{}

	// Enroll
	result, err := p.Enroll(ctx, "test")
	require.NoError(t, err)
	assert.Len(t, result.Secret, 32)
	assert.NotEmpty(t, result.Params["salt"])
	assert.NotEmpty(t, result.Params["fingerprint"])
	assert.Equal(t, keyPath, result.Params["path"])

	// Derive with same key should produce same secret
	secret, err := p.Derive(ctx, result.Params)
	require.NoError(t, err)
	assert.Equal(t, result.Secret, secret)
}

func TestSSHKeyDifferentKeysDifferentSecrets(t *testing.T) {
	key1 := generateTestKey(t)
	key2 := generateTestKey(t)

	p := &SSHKey{}

	ctx1 := context.WithValue(context.Background(), provider.CtxSSHKeyPath, key1)
	result1, err := p.Enroll(ctx1, "key1")
	require.NoError(t, err)

	ctx2 := context.WithValue(context.Background(), provider.CtxSSHKeyPath, key2)
	result2, err := p.Enroll(ctx2, "key2")
	require.NoError(t, err)

	assert.NotEqual(t, result1.Secret, result2.Secret)
}

func TestSSHKeyFingerprintMismatch(t *testing.T) {
	key1 := generateTestKey(t)
	key2 := generateTestKey(t)

	p := &SSHKey{}

	// Enroll with key1
	ctx1 := context.WithValue(context.Background(), provider.CtxSSHKeyPath, key1)
	result, err := p.Enroll(ctx1, "test")
	require.NoError(t, err)

	// Try to derive with key2 — should fail fingerprint check
	ctx2 := context.WithValue(context.Background(), provider.CtxSSHKeyPath, key2)
	_, err = p.Derive(ctx2, result.Params)
	assert.ErrorContains(t, err, "fingerprint mismatch")
}

func TestSSHKeyPathFromID(t *testing.T) {
	keyPath := generateTestKey(t)

	// When id looks like a path, it should be used directly
	p := &SSHKey{}
	ctx := context.Background()

	result, err := p.Enroll(ctx, keyPath)
	require.NoError(t, err)
	assert.Len(t, result.Secret, 32)
}

func TestSSHKeyTypeAndDescription(t *testing.T) {
	p := &SSHKey{}
	assert.Equal(t, "sshkey", p.Type())
	assert.NotEmpty(t, p.Description())
}

func TestSSHKeyRegistered(t *testing.T) {
	p, ok := provider.Get("sshkey")
	require.True(t, ok, "sshkey provider should be registered")
	assert.Equal(t, "sshkey", p.Type())
}

// generateTestKey creates a temporary ed25519 SSH key and returns its path.
func generateTestKey(t *testing.T) string {
	t.Helper()

	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	pemBlock, err := ssh.MarshalPrivateKey(privKey, "")
	require.NoError(t, err)

	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	err = os.WriteFile(keyPath, pem.EncodeToMemory(pemBlock), 0600)
	require.NoError(t, err)

	return keyPath
}
