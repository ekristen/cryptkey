package keyformat

import (
	"errors"
	"fmt"
)

// bech32 charset used for encoding.
const bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

// bech32Encode encodes data bytes with the given human-readable part (HRP)
// and returns the result as a caller-owned []byte. This implements BIP-173
// Bech32 (not Bech32m). Returning []byte (rather than string) lets callers
// wipe the encoded output when it represents secret material, since Go
// strings are immutable and cannot be zeroed.
func bech32Encode(hrp string, data []byte) ([]byte, error) {
	// Convert 8-bit data to 5-bit groups
	converted, err := convertBits(data, 8, 5, true)
	if err != nil {
		return nil, fmt.Errorf("bech32: convert bits: %w", err)
	}

	// Compute checksum
	checksum := bech32Checksum(hrp, converted)

	// Build result: HRP + "1" + data characters + checksum characters
	out := make([]byte, 0, len(hrp)+1+len(converted)+len(checksum))
	out = append(out, hrp...)
	out = append(out, '1')
	for _, d := range converted {
		out = append(out, bech32Charset[d])
	}
	for _, d := range checksum {
		out = append(out, bech32Charset[d])
	}
	return out, nil
}

// convertBits converts a byte slice from one bit-group size to another.
// pad controls whether to pad the last group with zeros.
func convertBits(data []byte, fromBits, toBits uint, pad bool) ([]byte, error) {
	acc := uint32(0)
	bits := uint(0)
	maxv := uint32((1 << toBits) - 1)

	var ret []byte
	for _, b := range data {
		acc = (acc << fromBits) | uint32(b)
		bits += fromBits
		for bits >= toBits {
			bits -= toBits
			ret = append(ret, byte((acc>>bits)&maxv)) //nolint:gosec // masked to toBits (≤5), fits in byte
		}
	}

	if pad {
		if bits > 0 {
			ret = append(ret, byte((acc<<(toBits-bits))&maxv)) //nolint:gosec // masked to toBits (≤5), fits in byte
		}
	} else if bits >= fromBits {
		return nil, errors.New("excess padding")
	} else if (acc<<(toBits-bits))&maxv != 0 {
		return nil, errors.New("non-zero padding")
	}

	return ret, nil
}

// bech32Polymod computes the Bech32 checksum polynomial.
func bech32Polymod(values []byte) uint32 {
	gen := [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := uint32(1)
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i := range 5 {
			if (top>>uint(i))&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	return chk
}

// bech32HRPExpand expands the HRP for checksum computation.
func bech32HRPExpand(hrp string) []byte {
	ret := make([]byte, 0, len(hrp)*2+1)
	for _, c := range hrp {
		ret = append(ret, byte(c>>5)) //nolint:gosec // HRP is ASCII bech32 charset, fits in byte
	}
	ret = append(ret, 0)
	for _, c := range hrp {
		ret = append(ret, byte(c&31))
	}
	return ret
}

// bech32Checksum computes the 6-byte Bech32 checksum.
func bech32Checksum(hrp string, data []byte) []byte {
	values := append(bech32HRPExpand(hrp), data...)
	values = append(values, 0, 0, 0, 0, 0, 0)
	polymod := bech32Polymod(values) ^ 1
	checksum := make([]byte, 6)
	for i := range 6 {
		checksum[i] = byte((polymod >> uint(5*(5-i))) & 31) //nolint:gosec // i ∈ [0,5]; shift amount is non-negative
	}
	return checksum
}
