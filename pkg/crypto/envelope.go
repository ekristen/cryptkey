// Package crypto provides cryptographic primitives for cryptkey:
// HKDF-SHA256 key derivation and AES-256-GCM authenticated encryption
// of Shamir shares.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"runtime"

	"golang.org/x/crypto/hkdf"

	"github.com/ekristen/cryptkey/pkg/crypto/hkdfinfo"
)

// WipeBytes zeroes a byte slice and uses runtime.KeepAlive to discourage
// the compiler from optimizing the zeroing away. This is a best-effort
// mitigation: Go's garbage collector may copy heap objects during
// compaction, leaving prior copies in freed pages that are not wiped.
// For true memory-forensic resistance, an mlock/madvise approach or a
// non-GC language would be required. Use this for all secret material
// cleanup regardless — it raises the bar meaningfully.
func WipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

// EncryptedShare holds the ciphertext and parameters needed to decrypt
// a Shamir share given the originating provider's 32-byte secret.
type EncryptedShare struct {
	Ciphertext []byte // AES-256-GCM ciphertext (includes GCM tag)
	Nonce      []byte // GCM nonce
	Salt       []byte // HKDF salt used to derive the AES key
}

// EncryptShare encrypts a Shamir share using a provider's 32-byte secret.
// The aad parameter binds the ciphertext to context (e.g. provider type and ID).
//
// Flow: HKDF-SHA256(secret, random_salt, info) → 32-byte AES key → AES-256-GCM(share, aad).
func EncryptShare(providerSecret, share, aad []byte) (*EncryptedShare, error) {
	if len(providerSecret) != 32 {
		return nil, fmt.Errorf("crypto: provider secret must be 32 bytes, got %d", len(providerSecret))
	}

	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("crypto: generate salt: %w", err)
	}

	aesKey, err := deriveAESKey(providerSecret, salt)
	if err != nil {
		return nil, err
	}
	defer WipeBytes(aesKey)

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("crypto: new cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: new gcm: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("crypto: generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, share, aad)

	return &EncryptedShare{
		Ciphertext: ciphertext,
		Nonce:      nonce,
		Salt:       salt,
	}, nil
}

// DecryptShare decrypts a Shamir share using a provider's 32-byte secret.
// The aad must match the value used during encryption.
func DecryptShare(providerSecret, aad []byte, es *EncryptedShare) ([]byte, error) {
	if len(providerSecret) != 32 {
		return nil, fmt.Errorf("crypto: provider secret must be 32 bytes, got %d", len(providerSecret))
	}

	aesKey, err := deriveAESKey(providerSecret, es.Salt)
	if err != nil {
		return nil, err
	}
	defer WipeBytes(aesKey)

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("crypto: new cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: new gcm: %w", err)
	}

	share, err := gcm.Open(nil, es.Nonce, es.Ciphertext, aad)
	if err != nil {
		return nil, errors.New("crypto: decryption failed (wrong secret or corrupted share)")
	}

	return share, nil
}

// DeriveOutputKey stretches a reconstructed master key through HKDF-SHA256
// into a final output key of the requested length.
// salt and info provide per-profile domain separation.
func DeriveOutputKey(masterKey, salt []byte, info string, length int) ([]byte, error) {
	r := hkdf.New(sha256.New, masterKey, salt, []byte(info))
	out := make([]byte, length)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, fmt.Errorf("crypto: hkdf expand: %w", err)
	}
	return out, nil
}

// ConfigHMAC computes an HMAC-SHA256 over data using a key derived from the
// master key. Used to detect config tampering without storing the master key.
func ConfigHMAC(masterKey, data []byte) ([]byte, error) {
	r := hkdf.New(sha256.New, masterKey, nil, []byte(hkdfinfo.ConfigIntegrity))
	hmacKey := make([]byte, 32)
	if _, err := io.ReadFull(r, hmacKey); err != nil {
		return nil, fmt.Errorf("crypto: hkdf derive hmac key: %w", err)
	}
	defer WipeBytes(hmacKey)
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(data)
	return mac.Sum(nil), nil
}

// VerifyConfigHMAC checks a config HMAC against expected.
func VerifyConfigHMAC(masterKey, data, expected []byte) (bool, error) {
	computed, err := ConfigHMAC(masterKey, data)
	if err != nil {
		return false, err
	}
	return hmac.Equal(computed, expected), nil
}

func deriveAESKey(secret, salt []byte) ([]byte, error) {
	r := hkdf.New(sha256.New, secret, salt, []byte(hkdfinfo.ShareEncryption))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("crypto: hkdf derive: %w", err)
	}
	return key, nil
}
