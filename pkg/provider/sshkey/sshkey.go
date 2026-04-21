// Package sshkey implements a provider that derives a 32-byte secret from
// an SSH private key. The key material is parsed, canonically marshaled,
// and run through HKDF-SHA256 to produce a deterministic secret.
//
// Supported key types: Ed25519, ECDSA, RSA.
// Passphrase-protected keys are supported (prompts for passphrase).
package sshkey

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/ssh"

	cryptolib "github.com/ekristen/cryptkey/pkg/crypto"
	"github.com/ekristen/cryptkey/pkg/crypto/hkdfinfo"
	"github.com/ekristen/cryptkey/pkg/provider"
)

const (
	saltLen = 32
	keyLen  = 32
)

// SSHKey is the SSH key provider.
type SSHKey struct{}

func (s *SSHKey) Type() string            { return "sshkey" }
func (s *SSHKey) Description() string     { return "Secret derived from an SSH private key" }
func (s *SSHKey) InteractiveDerive() bool { return true }

func (s *SSHKey) Enroll(ctx context.Context, id string) (*provider.EnrollResult, error) {
	keyPath, err := getKeyPath(ctx, id)
	if err != nil {
		return nil, err
	}

	privKey, fingerprint, err := loadPrivateKey(ctx, keyPath)
	if err != nil {
		return nil, err
	}

	keyBytes, err := marshalPrivateKey(privKey)
	if err != nil {
		return nil, err
	}
	defer cryptolib.WipeBytes(keyBytes)

	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("sshkey: generate salt: %w", err)
	}

	secret, err := deriveSecret(keyBytes, salt)
	if err != nil {
		return nil, err
	}

	return &provider.EnrollResult{
		Secret: secret,
		Params: map[string]string{
			"salt":        hex.EncodeToString(salt),
			"fingerprint": fingerprint,
			"path":        keyPath,
		},
	}, nil
}

func (s *SSHKey) Derive(ctx context.Context, params map[string]string) ([]byte, error) {
	saltHex, ok := params["salt"]
	if !ok {
		return nil, errors.New("sshkey: missing salt in config")
	}
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return nil, fmt.Errorf("sshkey: decode salt: %w", err)
	}

	expectedFP := params["fingerprint"]

	// Prompt for path using stored path as default hint
	storedPath := params["path"]
	keyPath, err := getKeyPath(ctx, storedPath)
	if err != nil {
		return nil, err
	}
	if keyPath == "" {
		return nil, errors.New("sshkey: no key path available")
	}

	privKey, fingerprint, err := loadPrivateKey(ctx, keyPath)
	if err != nil {
		return nil, err
	}

	if expectedFP != "" && fingerprint != expectedFP {
		return nil, fmt.Errorf("sshkey: fingerprint mismatch: expected %s, got %s", expectedFP, fingerprint)
	}

	keyBytes, err := marshalPrivateKey(privKey)
	if err != nil {
		return nil, err
	}
	defer cryptolib.WipeBytes(keyBytes)

	return deriveSecret(keyBytes, salt)
}

// loadPrivateKey reads and parses an SSH private key file. Returns the raw
// crypto.PrivateKey and the SHA256 fingerprint of the corresponding public key.
// Prompts for a passphrase if the key is encrypted.
func loadPrivateKey(ctx context.Context, path string) (crypto.PrivateKey, string, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("sshkey: read key: %w", err)
	}

	rawKey, err := ssh.ParseRawPrivateKey(pemBytes)
	if err != nil {
		var passErr *ssh.PassphraseMissingError
		if !errors.As(err, &passErr) {
			return nil, "", fmt.Errorf("sshkey: parse key: %w", err)
		}

		// Key is passphrase-protected
		passphrase, err := getPassphrase(ctx)
		if err != nil {
			return nil, "", err
		}
		defer cryptolib.WipeBytes(passphrase)

		rawKey, err = ssh.ParseRawPrivateKeyWithPassphrase(pemBytes, passphrase)
		if err != nil {
			return nil, "", fmt.Errorf("sshkey: decrypt key: %w", err)
		}
	}

	fingerprint, err := publicKeyFingerprint(rawKey)
	if err != nil {
		return nil, "", err
	}

	return rawKey, fingerprint, nil
}

// publicKeyFingerprint extracts the public key from a private key and returns
// its SSH SHA256 fingerprint.
func publicKeyFingerprint(privKey crypto.PrivateKey) (string, error) {
	signer, ok := privKey.(crypto.Signer)
	if !ok {
		return "", fmt.Errorf("sshkey: key type %T does not implement crypto.Signer", privKey)
	}
	pub := signer.Public()

	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("sshkey: convert to ssh public key: %w", err)
	}

	return ssh.FingerprintSHA256(sshPub), nil
}

// marshalPrivateKey converts a crypto.PrivateKey to a deterministic byte
// representation suitable for key derivation. For Ed25519, only the 32-byte
// seed is used (the second half of the Go representation is the public key,
// which is derivable from the seed and adds no entropy).
func marshalPrivateKey(key crypto.PrivateKey) ([]byte, error) {
	switch k := key.(type) {
	case ed25519.PrivateKey:
		seed := k.Seed()
		out := make([]byte, len(seed))
		copy(out, seed)
		return out, nil
	case *ed25519.PrivateKey:
		seed := k.Seed()
		out := make([]byte, len(seed))
		copy(out, seed)
		return out, nil
	case *ecdsa.PrivateKey:
		return x509.MarshalECPrivateKey(k)
	case *rsa.PrivateKey:
		der := x509.MarshalPKCS1PrivateKey(k)
		out := make([]byte, len(der))
		copy(out, der)
		return out, nil
	default:
		return nil, fmt.Errorf("sshkey: unsupported key type: %T", key)
	}
}

// deriveSecret runs HKDF-SHA256 over the key material to produce a 32-byte secret.
func deriveSecret(keyBytes, salt []byte) ([]byte, error) {
	hkdfReader := hkdf.New(sha256.New, keyBytes, salt, []byte(hkdfinfo.ProviderSSHKey))
	secret := make([]byte, keyLen)
	if _, err := io.ReadFull(hkdfReader, secret); err != nil {
		return nil, fmt.Errorf("sshkey: hkdf: %w", err)
	}
	return secret, nil
}

func init() {
	provider.Register(&SSHKey{})
}
