// Package keyformat converts raw 32-byte derived keys into structured
// cryptographic key formats (age identities, OpenSSH ed25519 keys).
//
// Functions that produce secret material return it as []byte so callers can
// zero the plaintext via crypto.WipeBytes once it's no longer needed. Go
// strings are immutable and cannot be wiped, so they are used here only for
// genuinely non-secret values (age recipients, ssh public-key lines).
package keyformat

import (
	"bytes"
	"crypto/ed25519"
	"encoding/pem"
	"fmt"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ssh"

	"github.com/ekristen/cryptkey/pkg/crypto"
)

// FormatAge converts a 32-byte key into an age X25519 identity.
//
// identity is the secret key line (AGE-SECRET-KEY-1...) as a caller-owned
// []byte; the caller MUST wipe it via crypto.WipeBytes once it's no longer
// needed. recipient is the public key (age1...) and is safe as a string.
func FormatAge(key []byte) (identity []byte, recipient string, err error) {
	if len(key) != 32 {
		return nil, "", fmt.Errorf("keyformat: key must be 32 bytes, got %d", len(key))
	}

	// Clamp the scalar per RFC 7748 for X25519.
	scalar := make([]byte, 32)
	copy(scalar, key)
	scalar[0] &= 248
	scalar[31] &= 127
	scalar[31] |= 64

	pub, err := curve25519.X25519(scalar, curve25519.Basepoint)
	if err != nil {
		crypto.WipeBytes(scalar)
		return nil, "", fmt.Errorf("keyformat: x25519 scalar mult: %w", err)
	}

	// Encode identity: uppercase Bech32 with HRP "age-secret-key-".
	idLower, err := bech32Encode("age-secret-key-", scalar)
	crypto.WipeBytes(scalar)
	if err != nil {
		if idLower != nil {
			crypto.WipeBytes(idLower)
		}
		return nil, "", fmt.Errorf("keyformat: encode identity: %w", err)
	}
	identity = bytes.ToUpper(idLower)
	crypto.WipeBytes(idLower)

	// Encode recipient: lowercase Bech32 with HRP "age". The recipient is
	// a public value, so it's fine as a string.
	recipientBytes, err := bech32Encode("age", pub)
	if err != nil {
		crypto.WipeBytes(identity)
		return nil, "", fmt.Errorf("keyformat: encode recipient: %w", err)
	}
	recipient = string(recipientBytes)

	return identity, recipient, nil
}

// FormatEd25519 converts a 32-byte key into an OpenSSH ed25519 key pair.
//
// privatePEM is the PEM-encoded private key as a caller-owned []byte; the
// caller MUST wipe it via crypto.WipeBytes once it's no longer needed.
// publicAuth is the authorized_keys-format public key line; the comment is
// embedded in both. The public key is safe as a string.
func FormatEd25519(key []byte, comment string) (privatePEM []byte, publicAuth string, err error) {
	if len(key) != 32 {
		return nil, "", fmt.Errorf("keyformat: key must be 32 bytes, got %d", len(key))
	}

	// ed25519.PrivateKey is a typedef'd []byte; wipe it when we're done
	// with the intermediate copy.
	privKey := ed25519.NewKeyFromSeed(key)
	defer crypto.WipeBytes(privKey)

	sshPub, err := ssh.NewPublicKey(privKey.Public())
	if err != nil {
		return nil, "", fmt.Errorf("keyformat: ssh public key: %w", err)
	}

	pemBlock, err := ssh.MarshalPrivateKey(privKey, comment)
	if err != nil {
		return nil, "", fmt.Errorf("keyformat: marshal private key: %w", err)
	}

	privatePEM = pem.EncodeToMemory(pemBlock)

	// The intermediate pemBlock.Bytes holds an un-encoded copy of the
	// private key material; wipe it now that we've produced privatePEM.
	crypto.WipeBytes(pemBlock.Bytes)

	pubLine := bytes.TrimSpace(ssh.MarshalAuthorizedKey(sshPub))
	if comment != "" {
		publicAuth = string(pubLine) + " " + comment
	} else {
		publicAuth = string(pubLine)
	}

	return privatePEM, publicAuth, nil
}
