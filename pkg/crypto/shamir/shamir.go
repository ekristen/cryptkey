// Package shamir implements Shamir's Secret Sharing over GF(256).
//
// Each byte of a secret is split independently using a random polynomial
// of degree (threshold-1) over GF(256) with the irreducible polynomial
// x^8 + x^4 + x^3 + x + 1 (0x11b, the AES field).
//
// Shares are encoded as [x-coordinate (1 byte)] + [y-values (len(secret) bytes)].
// x-coordinates are 1-indexed to avoid evaluating at 0 (which would leak the secret).
package shamir

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"runtime"
)

// GF(256) log/exp tables using generator 3.
var (
	expTable [512]byte // doubled for mod-free wraparound
	logTable [256]byte
)

func init() {
	var x byte = 1
	for i := range 255 {
		expTable[i] = x
		logTable[x] = byte(i)
		// Multiply x by generator 3 in GF(256): x*3 = x*2 XOR x
		hi := x >> 7
		x2 := x << 1
		if hi == 1 {
			x2 ^= 0x1b // reduction polynomial (lower 8 bits of 0x11b)
		}
		x = x2 ^ x
	}
	// Fill upper half for wraparound so we never need to mod 255
	for i := 255; i < 512; i++ {
		expTable[i] = expTable[i-255]
	}
}

func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return expTable[int(logTable[a])+int(logTable[b])]
}

func gfInverse(a byte) byte {
	if a == 0 {
		panic("shamir: inverse of zero")
	}
	return expTable[255-int(logTable[a])]
}

// evalPolynomial evaluates a polynomial at x using Horner's method in GF(256).
// coeffs[0] is the constant term (the secret byte).
func evalPolynomial(coeffs []byte, x byte) byte {
	result := coeffs[len(coeffs)-1]
	for i := len(coeffs) - 2; i >= 0; i-- {
		result = gfMul(result, x) ^ coeffs[i]
	}
	return result
}

// Split divides secret into n shares such that any threshold shares can
// reconstruct the original. threshold must be >= 2, n >= threshold, n <= 255.
// Returns n shares, each of length 1 + len(secret).
func Split(secret []byte, n, threshold int) ([][]byte, error) {
	if len(secret) == 0 {
		return nil, errors.New("shamir: secret must not be empty")
	}
	if threshold < 2 {
		return nil, errors.New("shamir: threshold must be at least 2")
	}
	if n < threshold {
		return nil, errors.New("shamir: n must be >= threshold")
	}
	if n > 255 {
		return nil, errors.New("shamir: n must be <= 255")
	}

	shares := make([][]byte, n)
	for i := range shares {
		shares[i] = make([]byte, 1+len(secret))
		shares[i][0] = byte(i + 1) // x-coordinate, 1-indexed
	}

	// For each byte of the secret, build a random polynomial and evaluate
	coeffs := make([]byte, threshold)
	for byteIdx, secretByte := range secret {
		coeffs[0] = secretByte
		if _, err := rand.Read(coeffs[1:]); err != nil {
			return nil, fmt.Errorf("shamir: random coefficients: %w", err)
		}
		for i := range n {
			shares[i][byteIdx+1] = evalPolynomial(coeffs, byte(i+1))
		}
	}

	// Wipe coefficients
	for i := range coeffs {
		coeffs[i] = 0
	}
	runtime.KeepAlive(coeffs)

	return shares, nil
}

// Combine reconstructs a secret from shares using Lagrange interpolation
// at x=0 in GF(256). All shares must have the same length and distinct
// x-coordinates.
func Combine(shares [][]byte) ([]byte, error) {
	if len(shares) < 2 {
		return nil, errors.New("shamir: need at least 2 shares")
	}

	shareLen := len(shares[0])
	if shareLen < 2 {
		return nil, errors.New("shamir: share too short")
	}

	// Validate consistent lengths and distinct x-coordinates
	seen := make(map[byte]bool)
	for i, s := range shares {
		if len(s) != shareLen {
			return nil, fmt.Errorf("shamir: share %d has length %d, expected %d", i, len(s), shareLen)
		}
		x := s[0]
		if x == 0 {
			return nil, fmt.Errorf("shamir: share %d has invalid x-coordinate 0", i)
		}
		if seen[x] {
			return nil, fmt.Errorf("shamir: duplicate x-coordinate %d", x)
		}
		seen[x] = true
	}

	secret := make([]byte, shareLen-1)

	for byteIdx := range secret {
		var result byte
		for i, si := range shares {
			xi := si[0]
			yi := si[byteIdx+1]

			// Lagrange basis polynomial evaluated at x=0:
			// L_i(0) = product_{j!=i} (0 - x_j) / (x_i - x_j)
			// In GF(256), subtraction = XOR, and 0 XOR x_j = x_j.
			num := byte(1)
			den := byte(1)
			for j, sj := range shares {
				if i == j {
					continue
				}
				xj := sj[0]
				num = gfMul(num, xj)
				den = gfMul(den, xi^xj)
			}

			lagrange := gfMul(num, gfInverse(den))
			result ^= gfMul(yi, lagrange)
		}
		secret[byteIdx] = result
	}

	return secret, nil
}

// Verify checks that a set of shares can reconstruct a known secret.
// Uses constant-time comparison.
func Verify(shares [][]byte, expected []byte) bool {
	got, err := Combine(shares)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, expected) == 1
}
