package shamir

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSplitCombine(t *testing.T) {
	secret := make([]byte, 32)
	_, err := rand.Read(secret)
	require.NoError(t, err)

	shares, err := Split(secret, 5, 3)
	require.NoError(t, err)
	assert.Len(t, shares, 5)

	// Any 3 of 5 should reconstruct
	for _, combo := range [][]int{
		{0, 1, 2}, {0, 1, 3}, {0, 1, 4},
		{0, 2, 3}, {0, 2, 4}, {0, 3, 4},
		{1, 2, 3}, {1, 2, 4}, {1, 3, 4},
		{2, 3, 4},
	} {
		subset := make([][]byte, len(combo))
		for i, idx := range combo {
			subset[i] = shares[idx]
		}
		got, err := Combine(subset)
		require.NoError(t, err, "combo %v", combo)
		assert.Equal(t, secret, got, "combo %v", combo)
	}
}

func TestSplitCombineMinimal(t *testing.T) {
	secret := []byte("hello world secret key material!")
	shares, err := Split(secret, 2, 2)
	require.NoError(t, err)

	got, err := Combine(shares)
	require.NoError(t, err)
	assert.Equal(t, secret, got)
}

func TestTwoOfFiveInsufficient(t *testing.T) {
	secret := make([]byte, 32)
	_, err := rand.Read(secret)
	require.NoError(t, err)

	shares, err := Split(secret, 5, 3)
	require.NoError(t, err)

	// 2 shares should NOT reconstruct a 3-of-5 scheme
	got, err := Combine(shares[:2])
	require.NoError(t, err) // Combine succeeds, but result is wrong
	assert.NotEqual(t, secret, got)
}

func TestVerify(t *testing.T) {
	secret := make([]byte, 32)
	_, err := rand.Read(secret)
	require.NoError(t, err)

	shares, err := Split(secret, 3, 2)
	require.NoError(t, err)

	assert.True(t, Verify(shares[:2], secret))
	assert.True(t, Verify(shares[1:], secret))

	wrong := make([]byte, 32)
	copy(wrong, secret)
	wrong[0] ^= 0xff
	assert.False(t, Verify(shares[:2], wrong))
}

func TestSplitValidation(t *testing.T) {
	secret := make([]byte, 16)

	_, err := Split(nil, 3, 2)
	require.Error(t, err)

	_, err = Split(secret, 3, 1)
	require.Error(t, err)

	_, err = Split(secret, 1, 2)
	require.Error(t, err)

	_, err = Split(secret, 256, 2)
	require.Error(t, err)
}

func TestCombineValidation(t *testing.T) {
	_, err := Combine([][]byte{{1, 2}})
	require.Error(t, err, "need at least 2")

	_, err = Combine([][]byte{{1, 2, 3}, {2, 4}})
	require.Error(t, err, "different lengths")

	_, err = Combine([][]byte{{1, 2}, {1, 3}})
	require.Error(t, err, "duplicate x-coordinate")

	_, err = Combine([][]byte{{0, 2}, {1, 3}})
	assert.Error(t, err, "invalid x-coordinate 0")
}

func TestGFArithmetic(t *testing.T) {
	// gfMul(a, 0) == 0
	assert.Equal(t, byte(0), gfMul(0, 42))
	assert.Equal(t, byte(0), gfMul(42, 0))

	// gfMul(a, 1) == a
	for i := range 256 {
		assert.Equal(t, byte(i), gfMul(byte(i), 1))
	}

	// a * inverse(a) == 1 for all nonzero a
	for i := 1; i < 256; i++ {
		assert.Equal(t, byte(1), gfMul(byte(i), gfInverse(byte(i))))
	}
}

func BenchmarkSplit32B_3of5(b *testing.B) {
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	b.ResetTimer()
	for range b.N {
		_, _ = Split(secret, 5, 3)
	}
}

func BenchmarkCombine32B_3of5(b *testing.B) {
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	shares, _ := Split(secret, 5, 3)
	b.ResetTimer()
	for range b.N {
		_, _ = Combine(shares[:3])
	}
}
