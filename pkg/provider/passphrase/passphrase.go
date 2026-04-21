// Package passphrase implements a provider that derives a 32-byte secret
// from a user-supplied passphrase using Argon2id. Intended to be enrolled
// 2+ times as offline recovery codes.
package passphrase

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"

	"golang.org/x/crypto/argon2"
	"golang.org/x/term"

	"github.com/ekristen/cryptkey/pkg/crypto"
	"github.com/ekristen/cryptkey/pkg/provider"
)

const (
	// Enrollment defaults: hardened for long-term disk-at-rest protection.
	// ~500ms on a modern laptop; imperceptible during derive, fine during init.
	defaultArgonTime    = 3
	defaultArgonMemory  = 262144 // 256 MiB
	defaultArgonThreads = 4

	// Derive-time floor: OWASP's recommended minimum. A tampered profile
	// cannot request weaker parameters than this. Kept below the defaults so
	// older profiles enrolled at OWASP-minimum settings still derive correctly.
	minArgonTime    = 2
	minArgonMemory  = 19456 // 19 MiB
	minArgonThreads = 1

	argonKeyLen = 32
	saltLen     = 32
)

type Passphrase struct{}

func (p *Passphrase) Type() string            { return "passphrase" }
func (p *Passphrase) Description() string     { return "Argon2id-derived key from a passphrase" }
func (p *Passphrase) InteractiveDerive() bool { return true }

func (p *Passphrase) EnrollOptions() []provider.EnrollOption {
	return argonEnrollOptions()
}

func (p *Passphrase) EnrollWarning(values map[string]string) string {
	return argonEnrollWarning(values)
}

func (p *Passphrase) Enroll(ctx context.Context, id string) (*provider.EnrollResult, error) {
	pass, err := getPassphrase(ctx, true)
	if err != nil {
		return nil, err
	}

	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("passphrase: generate salt: %w", err)
	}

	aTime, aMemory, aThreads := argonParams(ctx)
	secret := argon2.IDKey(pass, salt, aTime, aMemory, aThreads, argonKeyLen)
	crypto.WipeBytes(pass)

	return &provider.EnrollResult{
		Secret: secret,
		Params: map[string]string{
			"salt":          hex.EncodeToString(salt),
			"argon_time":    strconv.FormatUint(uint64(aTime), 10),
			"argon_memory":  strconv.FormatUint(uint64(aMemory), 10),
			"argon_threads": strconv.FormatUint(uint64(aThreads), 10),
		},
	}, nil
}

func (p *Passphrase) Derive(ctx context.Context, params map[string]string) ([]byte, error) {
	saltHex, ok := params["salt"]
	if !ok {
		return nil, errors.New("passphrase: missing salt in config")
	}
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return nil, fmt.Errorf("passphrase: decode salt: %w", err)
	}

	pass, err := getPassphrase(ctx, false)
	if err != nil {
		return nil, err
	}

	aTime, aMemory, aThreads := loadArgonParams(params)
	secret := argon2.IDKey(pass, salt, aTime, aMemory, aThreads, argonKeyLen)
	crypto.WipeBytes(pass)
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
	// Legacy defaults for profiles without stored argon params
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

// getPassphrase returns the passphrase, either from context (TUI pre-collected)
// or by prompting on the terminal. If confirm is true, asks twice and checks match.
func getPassphrase(ctx context.Context, confirm bool) ([]byte, error) {
	// Check if the TUI already collected the passphrase. Return a copy so the
	// caller can wipe its own slice without mutating the shared context value
	// (which may be reused across providers in non-TUI rekey/test paths).
	if v := ctx.Value(provider.CtxPassphrase); v != nil {
		pass, ok := v.([]byte)
		if ok && len(pass) > 0 {
			out := make([]byte, len(pass))
			copy(out, pass)
			return out, nil
		}
	}

	if !confirm {
		return promptPassphraseOnce(ctx)
	}
	return promptPassphraseConfirmed()
}

// promptPassphraseOnce prompts for a passphrase a single time (derive path).
// It prefers the progress-writer prompt when available and falls back to a
// direct /dev/tty read.
func promptPassphraseOnce(ctx context.Context) ([]byte, error) {
	if promptFn, ok := ctx.Value(provider.CtxPromptPassword).(func(string, string, string) (string, error)); ok {
		pin, err := promptFn("passphrase", "passphrase", "esc to skip")
		if err != nil {
			if errors.Is(err, provider.ErrSkipped) {
				return nil, provider.ErrSkipped
			}
			return nil, fmt.Errorf("passphrase: %w", err)
		}
		if pin == "" {
			return nil, errors.New("passphrase: empty passphrase")
		}
		return []byte(pin), nil
	}

	ttyFd, ttyClose, err := openTTY()
	if err != nil {
		return nil, err
	}
	fmt.Fprint(os.Stderr, "Enter passphrase: ")
	pass, err := term.ReadPassword(ttyFd)
	ttyClose()
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("passphrase: read: %w", err)
	}
	if len(pass) == 0 {
		return nil, errors.New("passphrase: empty passphrase")
	}
	return pass, nil
}

// promptPassphraseConfirmed prompts twice, verifies the passphrases match,
// and runs the strength check (enroll path).
func promptPassphraseConfirmed() ([]byte, error) {
	ttyFd, ttyClose, err := openTTY()
	if err != nil {
		return nil, err
	}
	defer ttyClose()

	fmt.Fprint(os.Stderr, "Enter passphrase: ")
	pass1, err := term.ReadPassword(ttyFd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("passphrase: read: %w", err)
	}
	if len(pass1) == 0 {
		return nil, errors.New("passphrase: empty passphrase")
	}

	fmt.Fprint(os.Stderr, "Confirm passphrase: ")
	pass2, err := term.ReadPassword(ttyFd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		crypto.WipeBytes(pass1)
		return nil, fmt.Errorf("passphrase: read confirm: %w", err)
	}
	match := len(pass1) == len(pass2) && subtle.ConstantTimeCompare(pass1, pass2) == 1
	crypto.WipeBytes(pass2)
	if !match {
		crypto.WipeBytes(pass1)
		return nil, errors.New("passphrase: passphrases do not match")
	}

	// Strength feedback. Always print a one-line summary; if the score is
	// below threshold, require the user to type 'y' before we accept it.
	// No hard block — mixing a weak passphrase with stronger providers
	// (threshold-gated) is a legitimate use case.
	if err := confirmStrengthOnTTY(os.Stderr, pass1); err != nil {
		crypto.WipeBytes(pass1)
		return nil, err
	}

	return pass1, nil
}

// confirmStrengthOnTTY writes a single-line strength summary for pass to w,
// and if the score is below threshold, prompts on /dev/tty for confirmation.
// Returns nil if the passphrase should be accepted, or an error if the user
// declined.
func confirmStrengthOnTTY(w io.Writer, pass []byte) error {
	s := ScorePassphrase(pass)
	fmt.Fprintf(w, "Passphrase strength: %s (~%s to crack offline)\n",
		s.Label(), s.CrackDisplay)
	if !s.IsWeak() {
		return nil
	}

	fmt.Fprintln(w, "Warning: this passphrase is below the recommended strength.")
	fmt.Fprintln(w, "  If this provider alone meets the profile's threshold, an attacker")
	fmt.Fprintln(w, "  who obtains the profile file can attempt offline brute force.")
	fmt.Fprint(w, "Proceed anyway? [y/N]: ")

	ttyFd, ttyClose, err := openTTY()
	if err != nil {
		// Can't read a y/n. Be conservative and accept — we already warned.
		return nil
	}
	defer ttyClose()

	var buf [1]byte
	tty := os.NewFile(uintptr(ttyFd), "/dev/tty") //nolint:gosec // Fd fits in uintptr
	n, err := tty.Read(buf[:])
	fmt.Fprintln(w)
	if err != nil || n != 1 || (buf[0] != 'y' && buf[0] != 'Y') {
		return errors.New("passphrase: rejected by user at strength warning")
	}
	return nil
}

func init() {
	provider.Register(&Passphrase{})
}
