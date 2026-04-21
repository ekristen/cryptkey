package config

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The integrity tests below exist because a silent bug in the HMAC path
// would defeat every tamper defense cryptkey has. Each test mutates one
// field of a signed profile and asserts VerifyIntegrity rejects it. If a
// future refactor (say, adding a new field) forgets to include that field
// in IntegrityDigest, these tests will keep passing for the old fields but
// we'd need to add a case — so the pattern is "exhaustive over the fields
// that currently exist".

// sampleProfile builds a minimal signed profile for tamper testing.
// Deliberately includes two providers (one with Params) so the Params
// sorting path is exercised too.
func sampleProfile(t *testing.T, masterKey []byte) *Profile {
	t.Helper()
	p := &Profile{
		Version:    ProfileVersion,
		Name:       "test",
		Threshold:  2,
		OutputSalt: "aa11bb22cc33dd44ee55ff6600112233445566778899aabbccddeeff00112233",
		Providers: []ProviderConfig{
			{
				Type:           "passphrase",
				ID:             "p1",
				EncryptedShare: "deadbeefcafebabe",
				Nonce:          "000102030405060708090a0b",
				ShareSalt:      "1011121314151617",
				Params: map[string]string{
					"salt":         "ffeeddccbbaa99887766554433221100",
					"argon_time":   "3",
					"argon_memory": "65536",
				},
			},
			{
				Type:           "fido2",
				ID:             "yk-blue",
				EncryptedShare: "0011223344556677",
				Nonce:          "00102030405060708090a0b0",
				ShareSalt:      "abcdef0123456789",
				Params: map[string]string{
					"credential_id": "ffaa",
					"uv":            "preferred",
				},
			},
		},
	}
	require.NoError(t, p.SetIntegrity(masterKey))
	return p
}

func fill32(t *testing.T, b byte) []byte {
	t.Helper()
	out := make([]byte, 32)
	for i := range out {
		out[i] = b
	}
	return out
}

// --- Round-trip ---

func TestVerifyIntegrityRoundTrip(t *testing.T) {
	mk := fill32(t, 0x42)
	p := sampleProfile(t, mk)
	ok, err := p.VerifyIntegrity(mk)
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestVerifyIntegrityRejectsWrongMasterKey(t *testing.T) {
	mk := fill32(t, 0x42)
	p := sampleProfile(t, mk)
	ok, err := p.VerifyIntegrity(fill32(t, 0x43))
	require.NoError(t, err)
	assert.False(t, ok, "verify with wrong master key must reject")
}

// --- Tamper sweep: top-level fields ---
//
// For every mutable top-level field, flipping it should invalidate the HMAC.

func TestVerifyIntegrityDetectsNameChange(t *testing.T) {
	mk := fill32(t, 0x42)
	p := sampleProfile(t, mk)
	p.Name = "renamed"
	ok, _ := p.VerifyIntegrity(mk)
	assert.False(t, ok, "Name is part of the digest; rename must break verify")
}

func TestVerifyIntegrityDetectsThresholdChange(t *testing.T) {
	mk := fill32(t, 0x42)
	p := sampleProfile(t, mk)
	p.Threshold = 3
	ok, _ := p.VerifyIntegrity(mk)
	assert.False(t, ok)
}

func TestVerifyIntegrityDetectsVersionChange(t *testing.T) {
	mk := fill32(t, 0x42)
	p := sampleProfile(t, mk)
	p.Version = 999
	ok, _ := p.VerifyIntegrity(mk)
	assert.False(t, ok)
}

func TestVerifyIntegrityDetectsOutputSaltChange(t *testing.T) {
	mk := fill32(t, 0x42)
	p := sampleProfile(t, mk)
	// Flip one hex char — still valid hex, different byte.
	runes := []byte(p.OutputSalt)
	runes[0] = 'b'
	p.OutputSalt = string(runes)
	ok, _ := p.VerifyIntegrity(mk)
	assert.False(t, ok)
}

// --- Tamper sweep: per-provider fields ---

func TestVerifyIntegrityDetectsProviderTypeChange(t *testing.T) {
	mk := fill32(t, 0x42)
	p := sampleProfile(t, mk)
	p.Providers[0].Type = "recovery"
	ok, _ := p.VerifyIntegrity(mk)
	assert.False(t, ok)
}

func TestVerifyIntegrityDetectsProviderIDChange(t *testing.T) {
	mk := fill32(t, 0x42)
	p := sampleProfile(t, mk)
	p.Providers[0].ID = "renamed"
	ok, _ := p.VerifyIntegrity(mk)
	assert.False(t, ok)
}

func TestVerifyIntegrityDetectsEncryptedShareChange(t *testing.T) {
	mk := fill32(t, 0x42)
	p := sampleProfile(t, mk)
	p.Providers[0].EncryptedShare = "ff" + p.Providers[0].EncryptedShare[2:]
	ok, _ := p.VerifyIntegrity(mk)
	assert.False(t, ok, "swapping in a different encrypted share is exactly the attack we want to detect")
}

func TestVerifyIntegrityDetectsNonceChange(t *testing.T) {
	mk := fill32(t, 0x42)
	p := sampleProfile(t, mk)
	p.Providers[0].Nonce = "aa" + p.Providers[0].Nonce[2:]
	ok, _ := p.VerifyIntegrity(mk)
	assert.False(t, ok)
}

func TestVerifyIntegrityDetectsShareSaltChange(t *testing.T) {
	mk := fill32(t, 0x42)
	p := sampleProfile(t, mk)
	p.Providers[0].ShareSalt = "aa" + p.Providers[0].ShareSalt[2:]
	ok, _ := p.VerifyIntegrity(mk)
	assert.False(t, ok)
}

// --- Tamper sweep: params ---

func TestVerifyIntegrityDetectsParamValueChange(t *testing.T) {
	mk := fill32(t, 0x42)
	p := sampleProfile(t, mk)
	p.Providers[0].Params["argon_time"] = "1" // downgrade attack
	ok, _ := p.VerifyIntegrity(mk)
	assert.False(t, ok, "lowering Argon2 cost must be detected")
}

func TestVerifyIntegrityDetectsNewParamAdded(t *testing.T) {
	mk := fill32(t, 0x42)
	p := sampleProfile(t, mk)
	p.Providers[0].Params["injected"] = "attacker-controlled"
	ok, _ := p.VerifyIntegrity(mk)
	assert.False(t, ok)
}

func TestVerifyIntegrityDetectsParamRemoved(t *testing.T) {
	mk := fill32(t, 0x42)
	p := sampleProfile(t, mk)
	delete(p.Providers[0].Params, "argon_time")
	ok, _ := p.VerifyIntegrity(mk)
	assert.False(t, ok)
}

// --- Provider list mutations ---

func TestVerifyIntegrityDetectsProviderRemoved(t *testing.T) {
	mk := fill32(t, 0x42)
	p := sampleProfile(t, mk)
	p.Providers = p.Providers[:1]
	ok, _ := p.VerifyIntegrity(mk)
	assert.False(t, ok, "dropping a provider must be detected")
}

func TestVerifyIntegrityDetectsProviderAdded(t *testing.T) {
	mk := fill32(t, 0x42)
	p := sampleProfile(t, mk)
	p.Providers = append(p.Providers, ProviderConfig{
		Type: "passphrase", ID: "injected",
		EncryptedShare: "00", Nonce: "00", ShareSalt: "00",
	})
	ok, _ := p.VerifyIntegrity(mk)
	assert.False(t, ok)
}

func TestVerifyIntegrityDetectsProviderReorder(t *testing.T) {
	mk := fill32(t, 0x42)
	p := sampleProfile(t, mk)
	p.Providers[0], p.Providers[1] = p.Providers[1], p.Providers[0]
	ok, _ := p.VerifyIntegrity(mk)
	assert.False(t, ok, "provider order is part of the digest; reordering must be detected")
}

// --- Determinism properties ---

func TestIntegrityDigestDeterministic(t *testing.T) {
	mk := fill32(t, 0x42)
	a := sampleProfile(t, mk).IntegrityDigest()
	b := sampleProfile(t, mk).IntegrityDigest()
	assert.Equal(t, a, b, "digest must be deterministic across constructions")
}

func TestIntegrityDigestParamOrderingIrrelevant(t *testing.T) {
	// The digest sorts param keys before hashing, so two profiles with
	// identical data but params iterated in different insertion order must
	// produce the same digest.
	mk := fill32(t, 0x42)
	p := sampleProfile(t, mk)
	digest := p.IntegrityDigest()

	// Build the "same" profile from scratch with params inserted in a
	// different order. Go map iteration is already non-deterministic, so
	// this exercises the sort path too.
	p2 := sampleProfile(t, mk)
	// rebuild params in opposite order via a fresh map
	np := map[string]string{}
	np["argon_memory"] = p2.Providers[0].Params["argon_memory"]
	np["argon_time"] = p2.Providers[0].Params["argon_time"]
	np["salt"] = p2.Providers[0].Params["salt"]
	p2.Providers[0].Params = np
	assert.Equal(t, digest, p2.IntegrityDigest())
}

// --- Missing / corrupt integrity HMAC itself ---

func TestVerifyIntegrityRejectsEmpty(t *testing.T) {
	mk := fill32(t, 0x42)
	p := sampleProfile(t, mk)
	p.Integrity = ""
	_, err := p.VerifyIntegrity(mk)
	assert.Error(t, err, "empty integrity HMAC should error (not silently accept)")
}

func TestVerifyIntegrityRejectsNonHexIntegrity(t *testing.T) {
	mk := fill32(t, 0x42)
	p := sampleProfile(t, mk)
	p.Integrity = "not-a-hex-string"
	_, err := p.VerifyIntegrity(mk)
	assert.Error(t, err)
}

func TestVerifyIntegrityRejectsFlippedBit(t *testing.T) {
	// Flip every byte of the stored HMAC; none should verify.
	mk := fill32(t, 0x42)
	p := sampleProfile(t, mk)
	raw, err := hex.DecodeString(p.Integrity)
	require.NoError(t, err)

	for i := range raw {
		tampered := append([]byte(nil), raw...)
		tampered[i] ^= 0x01
		p.Integrity = hex.EncodeToString(tampered)
		ok, err := p.VerifyIntegrity(mk)
		require.NoError(t, err)
		assert.Falsef(t, ok, "flipping integrity byte %d must reject verify", i)
	}
}

// --- OutputSaltBytes ---

func TestOutputSaltBytesDecodes(t *testing.T) {
	mk := fill32(t, 0x42)
	p := sampleProfile(t, mk)
	b, err := p.OutputSaltBytes()
	require.NoError(t, err)
	require.Len(t, b, 32)
}

func TestOutputSaltBytesRejectsEmpty(t *testing.T) {
	p := &Profile{Name: "test"}
	_, err := p.OutputSaltBytes()
	assert.Error(t, err)
}

func TestOutputSaltBytesRejectsNonHex(t *testing.T) {
	p := &Profile{Name: "test", OutputSalt: "not-hex"}
	_, err := p.OutputSaltBytes()
	assert.Error(t, err)
}

// --- Backup round-trip ---

func TestBackupAndRestore(t *testing.T) {
	// Isolate XDG so we don't touch the user's real config.
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	mk := fill32(t, 0x42)
	// Build the profile with the name we'll save under — IntegrityDigest
	// hashes Name, so changing it after SetIntegrity would invalidate the
	// stored HMAC.
	p := sampleProfile(t, mk)
	p.Name = "backup-test"
	require.NoError(t, p.SetIntegrity(mk))
	require.NoError(t, Save(p))

	// Take a backup and confirm both files are on disk.
	bakPath, restore, err := Backup("backup-test")
	require.NoError(t, err)
	origPath, err := Path("backup-test")
	require.NoError(t, err)

	assertExists(t, bakPath, ".bak should exist after Backup")
	assertExists(t, origPath, "original profile should still exist after Backup")

	// Overwrite the live profile with garbage to simulate a failed rekey
	// write, then restore. restore() renames .bak back over the original,
	// so after it returns the .bak file should no longer exist and the
	// original should verify under the master key.
	require.NoError(t, os.WriteFile(origPath, []byte("corrupted"), 0600))
	require.NoError(t, restore(), "restore must not error")
	assertNotExists(t, bakPath, ".bak should have moved back over the profile")

	restored, err := Load("backup-test")
	require.NoError(t, err)
	ok, err := restored.VerifyIntegrity(mk)
	require.NoError(t, err)
	assert.True(t, ok, "restored profile must still verify")
}

func TestBackupPathHasDotBakSuffix(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	got, err := BackupPath("rekey-test")
	require.NoError(t, err)
	assert.Equal(t, "rekey-test.toml.bak", filepath.Base(got))
}

func assertExists(t *testing.T, path, msg string) {
	t.Helper()
	_, err := os.Stat(path)
	assert.NoError(t, err, msg)
}

func assertNotExists(t *testing.T, path, msg string) {
	t.Helper()
	_, err := os.Stat(path)
	assert.True(t, os.IsNotExist(err), msg)
}
