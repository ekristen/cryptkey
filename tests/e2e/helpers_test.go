package e2e

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/ekristen/cryptkey/pkg/config"
	"github.com/ekristen/cryptkey/pkg/crypto"
	"github.com/ekristen/cryptkey/pkg/crypto/hkdfinfo"
	"github.com/ekristen/cryptkey/pkg/crypto/shamir"
	"github.com/ekristen/cryptkey/pkg/provider"
)

// manualReconstruct decrypts shares using the given passphrases (id → passphrase),
// recombines via Shamir, verifies integrity, and returns the HKDF-derived output key.
func manualReconstruct(t *testing.T, profile *config.Profile, passphrases map[string]string) []byte {
	t.Helper()
	key, err := manualReconstructErr(profile, passphrases)
	require.NoError(t, err)
	return key
}

// manualReconstructErr is like manualReconstruct but returns an error instead of failing.
func manualReconstructErr(profile *config.Profile, passphrases map[string]string) ([]byte, error) {
	masterKey, err := reconstructMasterKey(profile, passphrases)
	if err != nil {
		return nil, err
	}
	defer crypto.WipeBytes(masterKey)

	ok, err := profile.VerifyIntegrity(masterKey)
	if err != nil {
		return nil, fmt.Errorf("integrity check error: %w", err)
	}
	if !ok {
		return nil, errors.New("integrity HMAC mismatch")
	}

	outputSalt, _ := hex.DecodeString(profile.OutputSalt)
	info := hkdfinfo.OutputKeyPrefix + "default"
	return crypto.DeriveOutputKey(masterKey, outputSalt, info, 32)
}

// manualReconstructMasterKey reconstructs just the master key (before HKDF output derivation).
func manualReconstructMasterKey(t *testing.T, profile *config.Profile, passphrases map[string]string) []byte {
	t.Helper()
	key, err := reconstructMasterKey(profile, passphrases)
	require.NoError(t, err)
	return key
}

// reconstructMasterKey decrypts shares and recombines them via Shamir.
func reconstructMasterKey(profile *config.Profile, passphrases map[string]string) ([]byte, error) {
	var shares [][]byte

	for _, pc := range profile.Providers {
		passphrase, ok := passphrases[pc.ID]
		if !ok {
			continue
		}

		p, ok := provider.Get(pc.Type)
		if !ok {
			continue
		}

		ctx := context.WithValue(context.Background(), provider.CtxPassphrase, []byte(passphrase))
		secret, err := p.Derive(ctx, pc.Params)
		if err != nil {
			continue // wrong passphrase, skip
		}

		es, err := pc.EncryptedShareData()
		if err != nil {
			crypto.WipeBytes(secret)
			continue
		}

		aad := []byte(pc.Type + ":" + pc.ID)
		share, err := crypto.DecryptShare(secret, aad, es)
		crypto.WipeBytes(secret)
		if err != nil {
			continue // decryption failed (wrong secret or tampered)
		}

		shares = append(shares, share)
	}

	if len(shares) < 2 {
		return nil, fmt.Errorf("not enough shares recovered (%d)", len(shares))
	}

	masterKey, err := shamir.Combine(shares)
	for _, s := range shares {
		crypto.WipeBytes(s)
	}
	if err != nil {
		return nil, fmt.Errorf("shamir combine: %w", err)
	}

	return masterKey, nil
}

// generateTestSSHKey creates a temp ed25519 SSH key and returns its path.
func generateTestSSHKey(t *testing.T) string {
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
