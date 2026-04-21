// Package tpm implements a provider that derives a 32-byte secret using a
// TPM 2.0 HMAC key. During enrollment a new HMAC key is created under the
// Storage Root Key (SRK); the key's public and private blobs are stored in
// the profile. Because the blobs are wrapped by the SRK, the key can only
// be loaded on the same TPM, binding the secret to the hardware.
package tpm

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
	"golang.org/x/crypto/hkdf"

	cryptolib "github.com/ekristen/cryptkey/pkg/crypto"
	"github.com/ekristen/cryptkey/pkg/crypto/hkdfinfo"
	"github.com/ekristen/cryptkey/pkg/provider"
)

const (
	saltLen = 32
	keyLen  = 32
)

// TPM is the TPM 2.0 provider.
type TPM struct{}

func (t *TPM) Type() string            { return "tpm" }
func (t *TPM) Description() string     { return "Secret derived from TPM 2.0 HMAC key (hardware-bound)" }
func (t *TPM) InteractiveDerive() bool { return false }

func (t *TPM) EnrollWarning(_ map[string]string) string {
	for _, path := range []string{"/dev/tpmrm0", "/dev/tpm0"} {
		if _, err := os.Stat(path); err == nil {
			return ""
		}
	}
	return "No TPM device found (checked /dev/tpmrm0, /dev/tpm0)"
}

func (t *TPM) Enroll(ctx context.Context, id string) (*provider.EnrollResult, error) {
	tpmDev, err := openTPM()
	if err != nil {
		return nil, err
	}
	defer tpmDev.Close()

	// Create the SRK (Storage Root Key) — deterministic from the template.
	srk, err := createSRK(tpmDev)
	if err != nil {
		return nil, err
	}
	defer flushContext(tpmDev, srk.ObjectHandle)

	// Generate a random salt for HKDF derivation.
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("tpm: generate salt: %w", err)
	}

	// Create an HMAC key under the SRK.
	hmacPub, hmacPriv, err := createHMACKey(tpmDev, srk)
	if err != nil {
		return nil, err
	}

	// Load the HMAC key and compute HMAC to derive the secret.
	secret, err := loadAndHMAC(tpmDev, srk, hmacPub, hmacPriv, salt)
	if err != nil {
		return nil, err
	}

	progress := provider.CtxProgressFunc
	if fn, ok := ctx.Value(progress).(func(string)); ok && fn != nil {
		fn("TPM HMAC key created and bound to this device")
	}

	return &provider.EnrollResult{
		Secret: secret,
		Params: map[string]string{
			"salt":         hex.EncodeToString(salt),
			"hmac_public":  hex.EncodeToString(hmacPub),
			"hmac_private": hex.EncodeToString(hmacPriv),
		},
	}, nil
}

func (t *TPM) Derive(ctx context.Context, params map[string]string) ([]byte, error) {
	saltHex, ok := params["salt"]
	if !ok {
		return nil, errors.New("tpm: missing salt in config")
	}
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return nil, fmt.Errorf("tpm: decode salt: %w", err)
	}

	hmacPubHex := params["hmac_public"]
	if hmacPubHex == "" {
		return nil, errors.New("tpm: missing hmac_public in config")
	}
	hmacPub, err := hex.DecodeString(hmacPubHex)
	if err != nil {
		return nil, fmt.Errorf("tpm: decode hmac_public: %w", err)
	}

	hmacPrivHex := params["hmac_private"]
	if hmacPrivHex == "" {
		return nil, errors.New("tpm: missing hmac_private in config")
	}
	hmacPriv, err := hex.DecodeString(hmacPrivHex)
	if err != nil {
		return nil, fmt.Errorf("tpm: decode hmac_private: %w", err)
	}

	tpmDev, err := openTPM()
	if err != nil {
		return nil, err
	}
	defer tpmDev.Close()

	srk, err := createSRK(tpmDev)
	if err != nil {
		return nil, err
	}
	defer flushContext(tpmDev, srk.ObjectHandle)

	return loadAndHMAC(tpmDev, srk, hmacPub, hmacPriv, salt)
}

// openTPM opens the TPM device.
func openTPM() (transport.TPMCloser, error) {
	var firstErr error
	for _, path := range []string{"/dev/tpmrm0", "/dev/tpm0"} {
		if _, err := os.Stat(path); err != nil {
			continue
		}
		dev, err := linuxtpm.Open(path)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("tpm: open %s: %w", path, err)
			}
			continue
		}
		return dev, nil
	}
	if firstErr != nil {
		return nil, firstErr
	}
	return nil, errors.New("tpm: no TPM device found (tried /dev/tpmrm0, /dev/tpm0)")
}

// createSRK creates the Storage Root Key under the owner hierarchy.
// The SRK is deterministic for a given TPM — same template always yields the same key.
func createSRK(tpmDev transport.TPM) (*tpm2.CreatePrimaryResponse, error) {
	srkTemplate := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			NoDA:                true,
			Restricted:          true,
			Decrypt:             true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Symmetric: tpm2.TPMTSymDefObject{
					Algorithm: tpm2.TPMAlgAES,
					KeyBits: tpm2.NewTPMUSymKeyBits(
						tpm2.TPMAlgAES,
						tpm2.TPMKeyBits(128),
					),
					Mode: tpm2.NewTPMUSymMode(
						tpm2.TPMAlgAES,
						tpm2.TPMAlgCFB,
					),
				},
				KeyBits: 2048,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPublicKeyRSA{
				Buffer: make([]byte, 256),
			},
		),
	}

	createPrimary := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(srkTemplate),
	}

	resp, err := createPrimary.Execute(tpmDev)
	if err != nil {
		return nil, fmt.Errorf("tpm: create SRK: %w", err)
	}

	return resp, nil
}

// createHMACKey creates an HMAC-SHA256 key under the given parent.
// Returns the marshaled public and private key blobs.
func createHMACKey(tpmDev transport.TPM, srk *tpm2.CreatePrimaryResponse) (pubBytes, privBytes []byte, err error) {
	hmacTemplate := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgKeyedHash,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			SignEncrypt:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgKeyedHash,
			&tpm2.TPMSKeyedHashParms{
				Scheme: tpm2.TPMTKeyedHashScheme{
					Scheme: tpm2.TPMAlgHMAC,
					Details: tpm2.NewTPMUSchemeKeyedHash(
						tpm2.TPMAlgHMAC,
						&tpm2.TPMSSchemeHMAC{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
			},
		),
	}

	create := tpm2.Create{
		ParentHandle: tpm2.NamedHandle{
			Handle: srk.ObjectHandle,
			Name:   srk.Name,
		},
		InPublic: tpm2.New2B(hmacTemplate),
	}

	resp, err := create.Execute(tpmDev)
	if err != nil {
		return nil, nil, fmt.Errorf("tpm: create HMAC key: %w", err)
	}

	pubBytes = tpm2.Marshal(resp.OutPublic)
	privBytes = tpm2.Marshal(resp.OutPrivate)

	return pubBytes, privBytes, nil
}

// loadAndHMAC loads a stored HMAC key and computes HMAC(challenge) → HKDF → secret.
func loadAndHMAC(tpmDev transport.TPM, srk *tpm2.CreatePrimaryResponse, pubBytes, privBytes, salt []byte) ([]byte, error) {
	outPublic, err := tpm2.Unmarshal[tpm2.TPM2BPublic](pubBytes)
	if err != nil {
		return nil, fmt.Errorf("tpm: unmarshal public: %w", err)
	}

	outPrivate, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](privBytes)
	if err != nil {
		return nil, fmt.Errorf("tpm: unmarshal private: %w", err)
	}

	load := tpm2.Load{
		ParentHandle: tpm2.NamedHandle{
			Handle: srk.ObjectHandle,
			Name:   srk.Name,
		},
		InPublic:  *outPublic,
		InPrivate: *outPrivate,
	}

	loadResp, err := load.Execute(tpmDev)
	if err != nil {
		return nil, fmt.Errorf("tpm: load HMAC key: %w", err)
	}
	defer flushContext(tpmDev, loadResp.ObjectHandle)

	// Build deterministic challenge from salt.
	challenge := buildChallenge(salt)

	// Perform HMAC using the TPM.
	hmacCmd := tpm2.Hmac{
		Handle: tpm2.AuthHandle{
			Handle: loadResp.ObjectHandle,
			Name:   loadResp.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		Buffer:  tpm2.TPM2BMaxBuffer{Buffer: challenge},
		HashAlg: tpm2.TPMAlgSHA256,
	}

	hmacResp, err := hmacCmd.Execute(tpmDev)
	if err != nil {
		return nil, fmt.Errorf("tpm: HMAC: %w", err)
	}

	hmacResult := hmacResp.OutHMAC.Buffer
	defer cryptolib.WipeBytes(hmacResult)

	return deriveSecret(hmacResult, salt)
}

// buildChallenge creates a deterministic challenge from the salt.
func buildChallenge(salt []byte) []byte {
	h := sha256.New()
	h.Write(salt)
	h.Write([]byte(hkdfinfo.TPMChallenge))
	return h.Sum(nil)
}

// deriveSecret runs HKDF-SHA256 over the HMAC output to produce the 32-byte secret.
func deriveSecret(hmacOutput, salt []byte) ([]byte, error) {
	hkdfReader := hkdf.New(sha256.New, hmacOutput, salt, []byte(hkdfinfo.ProviderTPM))
	secret := make([]byte, keyLen)
	if _, err := io.ReadFull(hkdfReader, secret); err != nil {
		return nil, fmt.Errorf("tpm: hkdf: %w", err)
	}
	return secret, nil
}

// flushContext flushes a TPM handle.
func flushContext(tpmDev transport.TPM, handle tpm2.TPMHandle) {
	flush := tpm2.FlushContext{FlushHandle: handle}
	flush.Execute(tpmDev) //nolint:errcheck
}

func init() {
	provider.Register(&TPM{})
}
