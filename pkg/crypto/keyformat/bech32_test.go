package keyformat

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBech32Encode(t *testing.T) {
	// Test that encoding produces valid Bech32 output with correct HRP and separator
	data := []byte{0x00, 0x01, 0x02, 0x03}
	result, err := bech32Encode("test", data)
	require.NoError(t, err)
	assert.True(t, bytes.Contains(result, []byte("test1")))
}

func TestBech32EncodeEmpty(t *testing.T) {
	result, err := bech32Encode("test", []byte{})
	require.NoError(t, err)
	assert.True(t, bytes.Contains(result, []byte("test1")))
}

func TestBech32EncodeDeterministic(t *testing.T) {
	data := []byte{0xde, 0xad, 0xbe, 0xef}
	r1, err := bech32Encode("hrp", data)
	require.NoError(t, err)
	r2, err := bech32Encode("hrp", data)
	require.NoError(t, err)
	assert.Equal(t, r1, r2)
}

func TestConvertBits(t *testing.T) {
	// 8-bit to 5-bit conversion with padding
	data := []byte{0xff}
	result, err := convertBits(data, 8, 5, true)
	require.NoError(t, err)
	// 0xff = 11111111 -> 5-bit groups: 11111 11100 (with padding) = 31, 28
	assert.Equal(t, []byte{31, 28}, result)
}
