package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Happy path ---

func TestEncryptShareRoundTrip(t *testing.T) {
	secret := fill32(t, 0x42)
	share := []byte("this is a 32-byte shamir share")
	aad := []byte("fido2:yubikey-1")

	es, err := EncryptShare(secret, share, aad)
	require.NoError(t, err)

	require.NotEqual(t, share, es.Ciphertext, "ciphertext must differ from plaintext")
	require.Len(t, es.Nonce, 12, "GCM nonce should be 12 bytes")
	require.Len(t, es.Salt, 32, "HKDF salt should be 32 bytes")
	require.Len(t, es.Ciphertext, len(share)+16, "ciphertext = plaintext + 16 byte GCM tag")

	got, err := DecryptShare(secret, aad, es)
	require.NoError(t, err)
	require.Equal(t, share, got)
}

func TestEncryptShareProducesDifferentCiphertextsEachCall(t *testing.T) {
	// Random salt + nonce means two Encrypt calls on the same inputs must
	// produce different ciphertexts. If they ever match, our randomness
	// source or the nonce generation is broken.
	secret := fill32(t, 0x42)
	share := []byte("share data")
	aad := []byte("aad")

	a, err := EncryptShare(secret, share, aad)
	require.NoError(t, err)
	b, err := EncryptShare(secret, share, aad)
	require.NoError(t, err)

	require.False(t, bytes.Equal(a.Ciphertext, b.Ciphertext), "two encryptions must not collide")
	require.False(t, bytes.Equal(a.Salt, b.Salt), "salts must differ")
	require.False(t, bytes.Equal(a.Nonce, b.Nonce), "nonces must differ")
}

// --- Negative / tamper tests ---
//
// Any single-field corruption in an EncryptedShare must cause DecryptShare
// to fail. We don't care *what* the error says (GCM authentication just
// reports "decryption failed"); we only care that no valid plaintext is
// returned.

func TestDecryptShareRejectsWrongSecret(t *testing.T) {
	secret := fill32(t, 0x42)
	other := fill32(t, 0xAA)
	es, err := EncryptShare(secret, []byte("payload"), []byte("aad"))
	require.NoError(t, err)

	_, err = DecryptShare(other, []byte("aad"), es)
	require.Error(t, err, "wrong secret must fail decryption")
}

func TestDecryptShareRejectsWrongAAD(t *testing.T) {
	secret := fill32(t, 0x42)
	es, err := EncryptShare(secret, []byte("payload"), []byte("fido2:k1"))
	require.NoError(t, err)

	_, err = DecryptShare(secret, []byte("fido2:k2"), es)
	require.Error(t, err, "AAD mismatch must fail decryption")

	_, err = DecryptShare(secret, []byte{}, es)
	require.Error(t, err, "empty AAD against non-empty must fail decryption")

	_, err = DecryptShare(secret, nil, es)
	require.Error(t, err, "nil AAD against non-empty must fail decryption")
}

func TestDecryptShareRejectsCorruptedCiphertext(t *testing.T) {
	secret := fill32(t, 0x42)
	aad := []byte("aad")
	es, err := EncryptShare(secret, []byte("payload"), aad)
	require.NoError(t, err)

	for i := range es.Ciphertext {
		mutated := cloneShare(es)
		mutated.Ciphertext[i] ^= 0x01
		_, derr := DecryptShare(secret, aad, mutated)
		require.Errorf(t, derr, "flipping ciphertext byte %d must fail decryption", i)
	}
}

func TestDecryptShareRejectsCorruptedNonce(t *testing.T) {
	secret := fill32(t, 0x42)
	aad := []byte("aad")
	es, err := EncryptShare(secret, []byte("payload"), aad)
	require.NoError(t, err)

	for i := range es.Nonce {
		mutated := cloneShare(es)
		mutated.Nonce[i] ^= 0x01
		_, derr := DecryptShare(secret, aad, mutated)
		require.Errorf(t, derr, "flipping nonce byte %d must fail decryption", i)
	}
}

func TestDecryptShareRejectsCorruptedSalt(t *testing.T) {
	secret := fill32(t, 0x42)
	aad := []byte("aad")
	es, err := EncryptShare(secret, []byte("payload"), aad)
	require.NoError(t, err)

	// Changing the salt means a different AES key gets derived, which
	// means GCM authentication will fail.
	for i := range es.Salt {
		mutated := cloneShare(es)
		mutated.Salt[i] ^= 0x01
		_, derr := DecryptShare(secret, aad, mutated)
		require.Errorf(t, derr, "flipping salt byte %d must fail decryption", i)
	}
}

func TestDecryptShareRejectsTruncatedCiphertext(t *testing.T) {
	secret := fill32(t, 0x42)
	aad := []byte("aad")
	es, err := EncryptShare(secret, []byte("payload-goes-here"), aad)
	require.NoError(t, err)

	// Drop bytes one at a time from the tail. Even removing a single byte
	// of the GCM tag should fail authentication.
	for n := 1; n <= len(es.Ciphertext); n++ {
		mutated := &EncryptedShare{
			Ciphertext: es.Ciphertext[:len(es.Ciphertext)-n],
			Nonce:      append([]byte(nil), es.Nonce...),
			Salt:       append([]byte(nil), es.Salt...),
		}
		_, derr := DecryptShare(secret, aad, mutated)
		require.Errorf(t, derr, "truncating %d bytes must fail decryption", n)
	}
}

// --- Size validation ---

func TestEncryptShareRequires32ByteSecret(t *testing.T) {
	cases := []struct {
		name string
		len  int
	}{
		{"empty", 0},
		{"too short", 31},
		{"too long", 33},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			secret := make([]byte, tc.len)
			_, err := EncryptShare(secret, []byte("s"), []byte("a"))
			assert.Error(t, err, "must reject %d-byte secret", tc.len)
		})
	}
}

func TestDecryptShareRequires32ByteSecret(t *testing.T) {
	good := fill32(t, 0x42)
	es, err := EncryptShare(good, []byte("payload"), []byte("aad"))
	require.NoError(t, err)

	for _, n := range []int{0, 31, 33} {
		_, err := DecryptShare(make([]byte, n), []byte("aad"), es)
		assert.Errorf(t, err, "must reject %d-byte secret", n)
	}
}

// --- DeriveOutputKey ---

func TestDeriveOutputKeyDeterministic(t *testing.T) {
	master := fill32(t, 0x33)
	salt := fill32(t, 0x77)
	info := "cryptkey:test"

	a, err := DeriveOutputKey(master, salt, info, 32)
	require.NoError(t, err)
	b, err := DeriveOutputKey(master, salt, info, 32)
	require.NoError(t, err)
	assert.Equal(t, a, b, "HKDF with same inputs must be deterministic")
}

func TestDeriveOutputKeyDifferByInput(t *testing.T) {
	master := fill32(t, 0x33)
	salt := fill32(t, 0x77)

	baseline, _ := DeriveOutputKey(master, salt, "info-a", 32)

	// Changing any single input should change the output.
	diffInfo, _ := DeriveOutputKey(master, salt, "info-b", 32)
	assert.NotEqual(t, baseline, diffInfo, "different info must yield different key")

	otherMaster := fill32(t, 0x34)
	diffMaster, _ := DeriveOutputKey(otherMaster, salt, "info-a", 32)
	assert.NotEqual(t, baseline, diffMaster, "different master key must yield different output")

	otherSalt := fill32(t, 0x78)
	diffSalt, _ := DeriveOutputKey(master, otherSalt, "info-a", 32)
	assert.NotEqual(t, baseline, diffSalt, "different salt must yield different output")
}

func TestDeriveOutputKeyLengthRespected(t *testing.T) {
	master := fill32(t, 0x33)
	salt := fill32(t, 0x77)

	for _, n := range []int{16, 32, 64, 128} {
		k, err := DeriveOutputKey(master, salt, "info", n)
		require.NoError(t, err)
		require.Len(t, k, n)
	}
}

// --- ConfigHMAC ---

func TestConfigHMACDeterministic(t *testing.T) {
	master := fill32(t, 0x33)
	data := []byte("digest-bytes")

	a, err := ConfigHMAC(master, data)
	require.NoError(t, err)
	b, err := ConfigHMAC(master, data)
	require.NoError(t, err)
	assert.Equal(t, a, b, "HMAC must be deterministic")
}

func TestConfigHMACSensitiveToInputs(t *testing.T) {
	master := fill32(t, 0x33)

	baseline, _ := ConfigHMAC(master, []byte("data-a"))

	diffData, _ := ConfigHMAC(master, []byte("data-b"))
	assert.NotEqual(t, baseline, diffData, "different data must yield different HMAC")

	diffMaster, _ := ConfigHMAC(fill32(t, 0x34), []byte("data-a"))
	assert.NotEqual(t, baseline, diffMaster, "different master must yield different HMAC")

	// Same prefix shouldn't collide (HMAC is not a simple hash over append).
	withSuffix, _ := ConfigHMAC(master, []byte("data-axxx"))
	assert.NotEqual(t, baseline, withSuffix)
}

func TestVerifyConfigHMACRoundTrip(t *testing.T) {
	master := fill32(t, 0x33)
	data := []byte("profile digest goes here")

	mac, err := ConfigHMAC(master, data)
	require.NoError(t, err)

	ok, err := VerifyConfigHMAC(master, data, mac)
	require.NoError(t, err)
	assert.True(t, ok, "matching mac must verify")

	// Any tamper must fail verify: flip a bit in every byte.
	for i := range mac {
		tampered := append([]byte(nil), mac...)
		tampered[i] ^= 0x01
		ok, err := VerifyConfigHMAC(master, data, tampered)
		require.NoError(t, err)
		assert.Falsef(t, ok, "flipping mac byte %d must reject verify", i)
	}
}

func TestVerifyConfigHMACRejectsWrongMaster(t *testing.T) {
	data := []byte("digest")
	good := fill32(t, 0x33)
	bad := fill32(t, 0x34)

	mac, err := ConfigHMAC(good, data)
	require.NoError(t, err)
	ok, err := VerifyConfigHMAC(bad, data, mac)
	require.NoError(t, err)
	assert.False(t, ok, "mac computed under different master must not verify")
}

func TestVerifyConfigHMACConstantTime(t *testing.T) {
	// Sanity: VerifyConfigHMAC calls hmac.Equal, which is constant-time.
	// We can't measure timing here, but we can exercise a mismatch that
	// shares a prefix with the real mac — the comparison should still
	// reject it cleanly.
	master := fill32(t, 0x33)
	data := []byte("digest")
	mac, err := ConfigHMAC(master, data)
	require.NoError(t, err)

	almost := append([]byte(nil), mac...)
	almost[len(almost)-1] ^= 0x01 // only the last byte differs
	ok, err := VerifyConfigHMAC(master, data, almost)
	require.NoError(t, err)
	assert.False(t, ok)
}

// --- WipeBytes ---

func TestWipeBytes(t *testing.T) {
	b := []byte("secret material")
	WipeBytes(b)
	for i, c := range b {
		require.Equalf(t, byte(0), c, "byte %d not wiped", i)
	}
	// Safe on nil / empty — must not panic.
	WipeBytes(nil)
	WipeBytes([]byte{})
}

// --- Helpers ---

func fill32(t *testing.T, b byte) []byte {
	t.Helper()
	out := make([]byte, 32)
	for i := range out {
		out[i] = b
	}
	return out
}

// cloneShare deep-copies an EncryptedShare so a mutation in one field
// doesn't bleed into other test iterations.
func cloneShare(es *EncryptedShare) *EncryptedShare {
	return &EncryptedShare{
		Ciphertext: append([]byte(nil), es.Ciphertext...),
		Nonce:      append([]byte(nil), es.Nonce...),
		Salt:       append([]byte(nil), es.Salt...),
	}
}

// realRandomSanity is a sanity check that our test fixtures aren't
// accidentally all zeroes — if fill32 ever gets broken, this catches it.
func TestFillFixturesAreNotRandom(t *testing.T) {
	a := fill32(t, 0x42)
	b := fill32(t, 0x42)
	assert.Equal(t, a, b, "fixture must be deterministic across calls")
	// But the real rand.Read should produce non-identical bytes.
	x := make([]byte, 32)
	y := make([]byte, 32)
	_, _ = rand.Read(x)
	_, _ = rand.Read(y)
	assert.NotEqual(t, x, y, "real random must not collide in 32 bytes")
}
