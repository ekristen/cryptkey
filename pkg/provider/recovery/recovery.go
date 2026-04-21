// Package recovery implements a provider that generates a high-entropy
// recovery code, displays it once, and derives a 32-byte secret from it
// via Argon2id. The code is never stored — the user must write it down.
package recovery

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strconv"

	"golang.org/x/crypto/argon2"
	"golang.org/x/term"

	"github.com/ekristen/cryptkey/pkg/crypto"
	"github.com/ekristen/cryptkey/pkg/provider"
)

const (
	groups   = 7
	groupLen = 6

	// Enrollment defaults: hardened for long-term disk-at-rest protection.
	// Recovery codes already carry ~208 bits of entropy so the KDF strength
	// is largely defensive; the cost matches the passphrase provider for a
	// consistent mental model.
	defaultArgonTime    = 3
	defaultArgonMemory  = 262144 // 256 MiB
	defaultArgonThreads = 4

	// Derive-time floor: OWASP's recommended minimum. A tampered profile
	// cannot request weaker parameters than this. Kept below the defaults
	// so older profiles enrolled at OWASP-minimum settings still derive.
	minArgonTime    = 2
	minArgonMemory  = 19456 // 19 MiB
	minArgonThreads = 1

	argonKeyLen = 32
	saltLen     = 32
)

// Unambiguous alphabet: A-Z + 2-9, minus 0/O/1/I/L
const alphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

type Recovery struct{}

func (r *Recovery) Type() string            { return "recovery" }
func (r *Recovery) InteractiveDerive() bool { return true }
func (r *Recovery) Description() string {
	return "Generated recovery code (shown once — print or write down)"
}

func (r *Recovery) EnrollOptions() []provider.EnrollOption {
	return argonEnrollOptions()
}

func (r *Recovery) EnrollWarning(values map[string]string) string {
	return argonEnrollWarning(values)
}

func (r *Recovery) Enroll(ctx context.Context, id string) (*provider.EnrollResult, error) {
	// Check if code was pre-collected (TUI or flag-driven)
	if v := ctx.Value(provider.CtxPassphrase); v != nil {
		if code, ok := v.([]byte); ok && len(code) > 0 {
			return r.enrollWithCode(ctx, code, "")
		}
	}

	code, err := generateCode()
	if err != nil {
		return nil, fmt.Errorf("recovery: generate code: %w", err)
	}
	defer crypto.WipeBytes(code)

	formatted := formatCode(code)

	// Print to stderr for non-TUI mode; the TUI reads Message instead
	if ctx.Value(provider.CtxSilent) == nil {
		fmt.Fprintln(os.Stderr, recoveryMessageCLI(formatted))
	}

	return r.enrollWithCode(ctx, code, formatted)
}

func (r *Recovery) enrollWithCode(ctx context.Context, code []byte, message string) (*provider.EnrollResult, error) {
	normalized, err := normalizeBytes(code)
	if err != nil {
		return nil, err
	}
	defer crypto.WipeBytes(normalized)

	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("recovery: generate salt: %w", err)
	}

	aTime, aMemory, aThreads := argonParams(ctx)
	secret := argon2.IDKey(normalized, salt, aTime, aMemory, aThreads, argonKeyLen)

	return &provider.EnrollResult{
		Secret:  secret,
		Message: message,
		Params: map[string]string{
			"salt":          hex.EncodeToString(salt),
			"argon_time":    strconv.FormatUint(uint64(aTime), 10),
			"argon_memory":  strconv.FormatUint(uint64(aMemory), 10),
			"argon_threads": strconv.FormatUint(uint64(aThreads), 10),
		},
	}, nil
}

func recoveryMessageCLI(formatted string) string {
	return fmt.Sprintf(`
  RECOVERY CODE — WRITE THIS DOWN

  %s

  This code will NOT be shown again.
  Store it in a safe place (printed, written, photographed).
`, formatted)
}

func (r *Recovery) Derive(ctx context.Context, params map[string]string) ([]byte, error) {
	saltHex, ok := params["salt"]
	if !ok {
		return nil, errors.New("recovery: missing salt in config")
	}
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return nil, fmt.Errorf("recovery: decode salt: %w", err)
	}

	var code []byte

	// Check context for pre-collected code
	if v := ctx.Value(provider.CtxPassphrase); v != nil {
		if c, ok := v.([]byte); ok && len(c) > 0 {
			code = c
		}
	}

	if len(code) == 0 {
		// Use progress prompt if available (derive path).
		// Recovery codes are secrets — mask input with bullets.
		if promptFn, ok := ctx.Value(provider.CtxPromptPassword).(func(string, string, string) (string, error)); ok {
			line, err := promptFn("recovery", "recovery code", "esc to skip")
			if err != nil {
				if errors.Is(err, provider.ErrSkipped) {
					return nil, provider.ErrSkipped
				}
				return nil, fmt.Errorf("recovery: %w", err)
			}
			code = []byte(line)
		} else {
			// Direct tty fallback — read with echo suppressed.
			tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
			if err != nil {
				return nil, fmt.Errorf("recovery: open /dev/tty: %w", err)
			}
			fmt.Fprint(tty, "Enter recovery code: ")
			pass, err := term.ReadPassword(int(tty.Fd())) //nolint:gosec // Fd() fits in int
			fmt.Fprint(tty, "\r\n")
			tty.Close()
			if err != nil {
				return nil, fmt.Errorf("recovery: read: %w", err)
			}
			code = pass
		}
	}

	normalized, err := normalizeBytes(code)
	crypto.WipeBytes(code)
	if err != nil {
		return nil, err
	}
	if len(normalized) != groups*groupLen {
		crypto.WipeBytes(normalized)
		return nil, fmt.Errorf("recovery: expected %d characters, got %d", groups*groupLen, len(normalized))
	}

	aTime, aMemory, aThreads := loadArgonParams(params)
	secret := argon2.IDKey(normalized, salt, aTime, aMemory, aThreads, argonKeyLen)
	crypto.WipeBytes(normalized)
	return secret, nil
}

// argonParams reads Argon2id parameters from context, falling back to defaults.
// TUI enroll options (string values) take priority over CLI context keys.
func argonParams(ctx context.Context) (time, memory uint32, threads uint8) {
	time = defaultArgonTime
	memory = defaultArgonMemory
	threads = defaultArgonThreads

	// TUI enroll option → CLI flag → default
	if v, err := strconv.ParseUint(ctxEnrollStr(ctx, "argon_time"), 10, 32); err == nil && v > 0 {
		time = uint32(v)
	} else if v, ok := ctx.Value(provider.CtxArgonTime).(uint32); ok && v > 0 {
		time = v
	}

	// TUI values are in MiB; convert to KiB for Argon2
	if v, err := strconv.ParseUint(ctxEnrollStr(ctx, "argon_memory"), 10, 32); err == nil && v > 0 {
		memory = uint32(v) * 1024
	} else if v, ok := ctx.Value(provider.CtxArgonMemory).(uint32); ok && v > 0 {
		memory = v
	}

	if v, err := strconv.ParseUint(ctxEnrollStr(ctx, "argon_threads"), 10, 8); err == nil && v > 0 {
		threads = uint8(v)
	} else if v, ok := ctx.Value(provider.CtxArgonThreads).(uint8); ok && v > 0 {
		threads = v
	}
	return
}

func ctxEnrollStr(ctx context.Context, key string) string {
	if v := ctx.Value(provider.CtxEnrollOption(key)); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func argonEnrollOptions() []provider.EnrollOption {
	return []provider.EnrollOption{
		{
			Key:         "argon_time",
			Label:       "Iterations",
			Shortcut:    "t",
			Values:      []string{"2", "3", "4", "8", "16"},
			Default:     strconv.Itoa(defaultArgonTime),
			Description: "Argon2id time/iteration cost",
		},
		{
			Key:         "argon_memory",
			Label:       "Memory (MiB)",
			Shortcut:    "m",
			Values:      []string{"19", "64", "256", "1024"},
			Default:     strconv.Itoa(defaultArgonMemory / 1024),
			Description: "Argon2id memory cost",
		},
		{
			Key:         "argon_threads",
			Label:       "Threads",
			Shortcut:    "p",
			Values:      []string{"1", "2", "4", "8"},
			Default:     strconv.Itoa(defaultArgonThreads),
			Description: "Argon2id parallelism",
		},
	}
}

func argonEnrollWarning(values map[string]string) string {
	t, _ := strconv.Atoi(values["argon_time"])
	mem, _ := strconv.Atoi(values["argon_memory"])

	if t >= 8 && mem >= 1024 {
		return "These settings will be EXTREMELY slow — derivation may take minutes"
	}
	if t >= 8 || mem >= 1024 {
		return "High cost parameters — derivation may be noticeably slow"
	}
	return ""
}

// loadArgonParams reads Argon2id parameters from stored profile params,
// falling back to legacy defaults (t=3, m=64MiB, p=4) for profiles
// created before params were stored. Enforces minimum values to prevent
// a tampered profile from reducing Argon2 cost to trivial levels.
func loadArgonParams(params map[string]string) (time, memory uint32, threads uint8) {
	time = 3
	memory = 64 * 1024
	threads = 4

	if v, err := strconv.ParseUint(params["argon_time"], 10, 32); err == nil && v > 0 {
		time = uint32(v)
	}
	if v, err := strconv.ParseUint(params["argon_memory"], 10, 32); err == nil && v > 0 {
		memory = uint32(v)
	}
	if v, err := strconv.ParseUint(params["argon_threads"], 10, 8); err == nil && v > 0 {
		threads = uint8(v)
	}

	// Enforce OWASP-minimum floor so a tampered profile can't weaken key
	// derivation. The floor is decoupled from the enrollment defaults so
	// profiles enrolled at OWASP minimums before defaults were hardened
	// still derive with their stored params.
	if time < minArgonTime {
		time = minArgonTime
	}
	if memory < minArgonMemory {
		memory = minArgonMemory
	}
	if threads < minArgonThreads {
		threads = minArgonThreads
	}
	return
}

// generateCode produces a random recovery code as raw bytes (no dashes).
func generateCode() ([]byte, error) {
	total := groups * groupLen
	code := make([]byte, total)
	alphabetLen := big.NewInt(int64(len(alphabet)))

	for i := range total {
		idx, err := rand.Int(rand.Reader, alphabetLen)
		if err != nil {
			return nil, err
		}
		code[i] = alphabet[idx.Int64()]
	}

	return code, nil
}

// formatCode inserts dashes between groups for display.
func formatCode(code []byte) string {
	var buf bytes.Buffer
	for i := 0; i < len(code); i += groupLen {
		if i > 0 {
			buf.WriteByte('-')
		}
		end := i + groupLen
		if end > len(code) {
			end = len(code)
		}
		buf.Write(code[i:end])
	}
	return buf.String()
}

// normalizeBytes strips dashes/spaces, uppercases, validates against the
// recovery alphabet, and returns a new []byte. Returns an error if any
// character is not in the alphabet (after normalization).
func normalizeBytes(code []byte) ([]byte, error) {
	out := make([]byte, 0, len(code))
	for _, b := range code {
		if b == '-' || b == ' ' || b == '\n' || b == '\r' {
			continue
		}
		// Uppercase ASCII lowercase letters
		if b >= 'a' && b <= 'z' {
			b -= 'a' - 'A'
		}
		if !isAlphabetChar(b) {
			return nil, fmt.Errorf("recovery: invalid character %q in code", b)
		}
		out = append(out, b)
	}
	return out, nil
}

// isAlphabetChar reports whether b is in the recovery code alphabet.
func isAlphabetChar(b byte) bool {
	for i := range len(alphabet) {
		if alphabet[i] == b {
			return true
		}
	}
	return false
}

func init() {
	provider.Register(&Recovery{})
}
