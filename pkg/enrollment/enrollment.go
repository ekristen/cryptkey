// Package enrollment contains the shared logic for enrolling providers
// and building a cryptkey profile. Both the TUI and simple CLI modes use this.
package enrollment

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/ekristen/cryptkey/pkg/config"
	"github.com/ekristen/cryptkey/pkg/crypto"
	"github.com/ekristen/cryptkey/pkg/crypto/shamir"
	"github.com/ekristen/cryptkey/pkg/provider"
)

// Enrollment holds the result of enrolling a single provider.
type Enrollment struct {
	Provider provider.Provider
	ID       string
	Secret   []byte
	Params   map[string]string
	Message  string // optional message to display after enrollment
}

// BuildProfile takes completed enrollments, generates a master key, splits it
// via Shamir, encrypts shares, computes the integrity HMAC, and saves the profile.
func BuildProfile(profileName string, threshold int, enrollments []Enrollment) error {
	masterKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		return fmt.Errorf("generate master key: %w", err)
	}
	defer crypto.WipeBytes(masterKey)

	outputSalt := make([]byte, 32)
	if _, err := rand.Read(outputSalt); err != nil {
		return fmt.Errorf("generate output salt: %w", err)
	}

	return WriteProfile(profileName, threshold, masterKey, outputSalt, enrollments)
}

// WriteProfile builds and atomically writes a profile using the supplied
// master key and output salt instead of generating them. It splits the master
// key via Shamir across the given enrollments, encrypts each share with the
// corresponding provider secret, computes the integrity HMAC, and saves.
//
// Used by both BuildProfile (which provides random K and salt) and the rekey
// command (which preserves the existing K and salt so already-derived output
// keys remain valid). The caller retains ownership of masterKey and outputSalt;
// this function does not wipe them.
func WriteProfile(profileName string, threshold int, masterKey, outputSalt []byte, enrollments []Enrollment) error {
	if len(enrollments) < threshold {
		return fmt.Errorf("not enough providers enrolled (%d < threshold %d)", len(enrollments), threshold)
	}
	if len(masterKey) != 32 {
		return fmt.Errorf("master key must be 32 bytes, got %d", len(masterKey))
	}
	if len(outputSalt) != 32 {
		return fmt.Errorf("output salt must be 32 bytes, got %d", len(outputSalt))
	}

	// Enforce unique provider IDs (AAD binding relies on this)
	seen := make(map[string]bool, len(enrollments))
	for _, e := range enrollments {
		if seen[e.ID] {
			return fmt.Errorf("duplicate provider ID %q", e.ID)
		}
		seen[e.ID] = true
	}

	n := len(enrollments)

	defer func() {
		for _, e := range enrollments {
			crypto.WipeBytes(e.Secret)
		}
	}()

	shares, err := shamir.Split(masterKey, n, threshold)
	if err != nil {
		return fmt.Errorf("shamir split: %w", err)
	}
	defer func() {
		for _, s := range shares {
			crypto.WipeBytes(s)
		}
	}()

	if !shamir.Verify(shares[:threshold], masterKey) {
		return errors.New("shamir verification failed (internal error)")
	}

	profile := &config.Profile{
		Version:    config.ProfileVersion,
		Name:       profileName,
		Threshold:  threshold,
		OutputSalt: hex.EncodeToString(outputSalt),
		Providers:  make([]config.ProviderConfig, n),
	}

	for i, e := range enrollments {
		aad := []byte(e.Provider.Type() + ":" + e.ID)
		es, err := crypto.EncryptShare(e.Secret, shares[i], aad)
		if err != nil {
			return fmt.Errorf("encrypt share for %q: %w", e.ID, err)
		}

		profile.Providers[i] = config.ProviderConfig{
			Type:           e.Provider.Type(),
			ID:             e.ID,
			EncryptedShare: hex.EncodeToString(es.Ciphertext),
			Nonce:          hex.EncodeToString(es.Nonce),
			ShareSalt:      hex.EncodeToString(es.Salt),
			Params:         e.Params,
		}
	}

	if err := profile.SetIntegrity(masterKey); err != nil {
		return fmt.Errorf("compute integrity HMAC: %w", err)
	}

	if err := config.Save(profile); err != nil {
		return fmt.Errorf("save profile: %w", err)
	}

	return nil
}

// hardwareTypes are provider types bound to specific hardware or a host's
// secure element. If the device is lost or destroyed, these may become unusable.
// Passkeys are treated as hardware-bound pessimistically since they may or may
// not be synced depending on the platform/provider.
var hardwareTypes = map[string]bool{
	"fido2":   true,
	"passkey": true,
	"piv":     true,
	"tpm":     true,
}

// RecoveryWarning checks whether the enrolled providers have enough
// non-hardware providers (passphrase, recovery) to meet the threshold
// in the event of total hardware loss. Returns a warning message or "".
func RecoveryWarning(threshold int, enrollments []Enrollment) string {
	var softCount, hwCount int
	for _, e := range enrollments {
		if hardwareTypes[e.Provider.Type()] {
			hwCount++
		} else {
			softCount++
		}
	}
	if hwCount == 0 || softCount >= threshold {
		return ""
	}
	need := threshold - softCount
	return fmt.Sprintf(
		"WARNING: You have %d hardware-bound and %d non-hardware provider(s) but threshold is %d.\n"+
			"If all hardware is lost, you cannot recover the key.\n"+
			"Consider adding %d more recovery or passphrase provider(s).",
		hwCount, softCount, threshold, need,
	)
}

// NonInteractiveWarning checks whether the threshold can be met entirely by
// non-interactive providers (e.g., tpm, ssh-agent) — meaning the key could be
// derived without any human interaction. Returns a warning message or "".
func NonInteractiveWarning(threshold int, enrollments []Enrollment) string {
	var nonInteractive int
	for _, e := range enrollments {
		if ip, ok := e.Provider.(provider.InteractiveProvider); ok && !ip.InteractiveDerive() {
			nonInteractive++
		}
	}
	if nonInteractive == 0 || threshold > nonInteractive {
		return ""
	}
	return fmt.Sprintf(
		"WARNING: Threshold %d can be met by %d non-interactive provider(s) alone.\n"+
			"The key could be derived without any human interaction.\n"+
			"Consider raising the threshold or adding interactive providers.",
		threshold, nonInteractive,
	)
}

// EnrollProvider runs enrollment for a single provider and returns the result.
func EnrollProvider(ctx context.Context, p provider.Provider, id string) (*Enrollment, error) {
	result, err := p.Enroll(ctx, id)
	if err != nil {
		return nil, err
	}
	if len(result.Secret) != 32 {
		return nil, fmt.Errorf("provider returned %d-byte secret, expected 32", len(result.Secret))
	}
	return &Enrollment{
		Provider: p,
		ID:       id,
		Secret:   result.Secret,
		Params:   result.Params,
		Message:  result.Message,
	}, nil
}
