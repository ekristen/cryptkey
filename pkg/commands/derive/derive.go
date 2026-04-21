package derive

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
	"golang.org/x/term"

	"github.com/ekristen/cryptkey/pkg/common"
	"github.com/ekristen/cryptkey/pkg/config"
	"github.com/ekristen/cryptkey/pkg/crypto"
	"github.com/ekristen/cryptkey/pkg/crypto/hkdfinfo"
	"github.com/ekristen/cryptkey/pkg/crypto/keyformat"
	"github.com/ekristen/cryptkey/pkg/crypto/shamir"
	"github.com/ekristen/cryptkey/pkg/progress"
	"github.com/ekristen/cryptkey/pkg/provider"
	"github.com/ekristen/cryptkey/pkg/timeout"
)

// outputKeyLen is the fixed derived key length (32 bytes / 256 bits).
const outputKeyLen = 32

// ReconstructOpts controls provider filtering, skip behavior, and output
// during key reconstruction.
type ReconstructOpts struct {
	// ProviderFilter limits derivation to these providers. Each entry is
	// matched as "type:id" (exact) or just "type" (all of that type).
	// Empty means use all providers.
	ProviderFilter []string

	// SkipFilter excludes these providers. Same matching as ProviderFilter.
	SkipFilter []string

	// Quiet suppresses all stderr output except fatal errors.
	Quiet bool

	// Timeout overrides the default hardware provider timeout.
	// Zero means use the provider's default.
	Timeout time.Duration

	// Use is an optional context label appended to the HKDF info string
	// to derive different keys from the same profile (e.g., "disk", "signing").
	Use string

	// NoTUI forces plain-line prompts and output even when stderr is a TTY.
	// Intended for scripts and CI.
	NoTUI bool
}

// matchesFilter returns true if pc matches any entry in the filter.
func matchesFilter(pc *config.ProviderConfig, filter []string) bool {
	full := pc.Type + ":" + pc.ID
	for _, f := range filter {
		if f == full || f == pc.Type {
			return true
		}
	}
	return false
}

// isTTY reports whether stderr is connected to a terminal.
func isTTY() bool {
	return term.IsTerminal(int(os.Stderr.Fd())) //nolint:gosec
}

// MasterKeyResult is returned by ReconstructMasterKey. It holds the
// reconstructed master key and the provider secrets collected during unlock.
// Caller owns everything and must call Wipe() when done.
type MasterKeyResult struct {
	MasterKey []byte
	Secrets   map[string][]byte // key "type:id" → 32-byte provider secret
	Profile   *config.Profile
}

// Wipe zeroes the master key and every collected secret. Safe to call
// multiple times.
func (r *MasterKeyResult) Wipe() {
	if r == nil {
		return
	}
	crypto.WipeBytes(r.MasterKey)
	r.MasterKey = nil
	for k, s := range r.Secrets {
		crypto.WipeBytes(s)
		delete(r.Secrets, k)
	}
}

// InstallPromptCallbacks wires the progress writer into the context so
// providers can prompt inline while preserving the masked-input UX. Exposed
// so callers that want to reuse a single pw across multiple derive-style
// phases (e.g. rekey) can set up the context once.
func InstallPromptCallbacks(ctx context.Context, pw *progress.Writer) context.Context {
	ctx = context.WithValue(ctx, provider.CtxPromptPassword,
		func(provType, label, hint string) (string, error) {
			return pw.PromptPassword(provType, label, hint)
		})
	ctx = context.WithValue(ctx, provider.CtxPromptLine,
		func(provType, label, hint string) (string, error) {
			return pw.PromptLine(provType, label, hint)
		})
	ctx = context.WithValue(ctx, provider.CtxProgressFunc, func(msg string) {
		pw.Info(msg)
	})
	ctx = context.WithValue(ctx, provider.CtxProgressLink, func(prefix, url string) {
		pw.Link(prefix, url)
	})
	return ctx
}

// Reconstruct loads a profile, tries providers, combines shares progressively,
// and verifies the config integrity HMAC. Returns the 32-byte derived output key.
func Reconstruct(ctx context.Context, profileName string, opts ...ReconstructOpts) ([]byte, error) {
	var o ReconstructOpts
	if len(opts) > 0 {
		o = opts[0]
	}

	res, err := ReconstructMasterKey(ctx, profileName, opts...)
	if err != nil {
		return nil, err
	}
	defer res.Wipe()

	// The HKDF info string intentionally omits the profile name so that
	// renaming a profile file (which we don't enforce or pin) doesn't
	// change the derived output key. Domain separation across distinct
	// profiles is provided by the per-profile OutputSalt.
	outputSalt, _ := hex.DecodeString(res.Profile.OutputSalt)
	info := hkdfinfo.OutputKeyPrefix + o.Use
	outputKey, err := crypto.DeriveOutputKey(res.MasterKey, outputSalt, info, outputKeyLen)
	if err != nil {
		return nil, fmt.Errorf("derive output key: %w", err)
	}
	return outputKey, nil
}

// ReconstructMasterKey runs the full provider-iteration + share-combine flow
// and returns the master key plus the provider secrets collected along the
// way, keyed by "type:id". It iterates every provider in the profile (subject
// to --provider / --skip filters), lets the user skip individual ones, and
// stops as soon as the threshold is met and the integrity HMAC verifies.
//
// Used by rekey, which needs the master key to re-Split and at least some of
// the provider secrets to re-encrypt kept providers' new shares.
//
//nolint:gocyclo,funlen // main reconstruction function; refactoring would hurt readability
func ReconstructMasterKey(ctx context.Context, profileName string, opts ...ReconstructOpts) (*MasterKeyResult, error) {
	var o ReconstructOpts
	if len(opts) > 0 {
		o = opts[0]
	}

	profile, err := config.Load(profileName)
	if err != nil {
		return nil, err
	}

	pw := progress.New(os.Stderr, isTTY(), o.NoTUI, o.Quiet)
	ctx = InstallPromptCallbacks(ctx, pw)

	var recoveredShares [][]byte
	secrets := make(map[string][]byte)

	// cleanupOnError wipes all state and returns err. Used on failure paths
	// so we don't leak secrets if reconstruction aborts.
	cleanupOnError := func() {
		for _, s := range recoveredShares {
			crypto.WipeBytes(s)
		}
		for _, s := range secrets {
			crypto.WipeBytes(s)
		}
	}

	for _, pc := range profile.Providers {
		if len(o.ProviderFilter) > 0 && !matchesFilter(&pc, o.ProviderFilter) {
			logrus.WithField("provider", pc.Type).WithField("id", pc.ID).
				Debug("skipped by --provider filter")
			continue
		}

		if len(o.SkipFilter) > 0 && matchesFilter(&pc, o.SkipFilter) {
			logrus.WithField("provider", pc.Type).WithField("id", pc.ID).
				Debug("skipped by --skip filter")
			continue
		}

		p, ok := provider.Get(pc.Type)
		if !ok {
			pw.Emit(progress.Event{
				Provider: pc.Type, ID: pc.ID,
				Status:  progress.StatusSkipped,
				Message: "not registered",
			})
			continue
		}

		secret, skipped := deriveWithProvider(ctx, p, &pc, pw, o.Timeout)
		if ctx.Err() != nil {
			cleanupOnError()
			return nil, ctx.Err()
		}
		if skipped || secret == nil {
			continue
		}

		es, err := pc.EncryptedShareData()
		if err != nil {
			pw.Emit(progress.Event{
				Provider: pc.Type, ID: pc.ID,
				Status:  progress.StatusFailed,
				Message: "invalid share data",
			})
			crypto.WipeBytes(secret)
			continue
		}

		aad := []byte(pc.Type + ":" + pc.ID)
		share, err := crypto.DecryptShare(secret, aad, es)
		if err != nil {
			pw.Emit(progress.Event{
				Provider: pc.Type, ID: pc.ID,
				Status:  progress.StatusFailed,
				Message: "share decryption failed",
			})
			crypto.WipeBytes(secret)
			continue
		}

		recoveredShares = append(recoveredShares, share)
		secrets[pc.Type+":"+pc.ID] = secret
		pw.Emit(progress.Event{
			Provider: pc.Type, ID: pc.ID,
			Status: progress.StatusSucceeded,
		})

		minShares := profile.Threshold
		if minShares < 2 {
			minShares = 2
		}
		if len(recoveredShares) >= minShares {
			masterKey, err := shamir.Combine(recoveredShares)
			if err != nil {
				logrus.WithError(err).Debug("shamir combine failed, need more shares")
				continue
			}

			ok, err := profile.VerifyIntegrity(masterKey)
			if err != nil {
				logrus.WithError(err).Debug("integrity check error, need more shares")
				crypto.WipeBytes(masterKey)
				continue
			}
			if !ok {
				logrus.Debug("integrity HMAC mismatch, need more shares")
				crypto.WipeBytes(masterKey)
				continue
			}

			// Threshold met and integrity verified. Wipe only the shares
			// (the secrets are returned to the caller).
			for _, s := range recoveredShares {
				crypto.WipeBytes(s)
			}
			return &MasterKeyResult{
				MasterKey: masterKey,
				Secrets:   secrets,
				Profile:   profile,
			}, nil
		}
	}

	cleanupOnError()
	return nil, fmt.Errorf(
		"could not reconstruct key (%d shares recovered, none produced a valid key)",
		len(recoveredShares),
	)
}

// DeriveSingleProvider runs the same hardware-aware single-provider derive
// path used by Reconstruct. Returned values: the 32-byte secret (caller must
// wipe), whether the user skipped the provider (via esc or timeout), and any
// terminal error. Exposed so rekey can collect a missing kept provider's
// secret after the main unlock loop has already met threshold.
func DeriveSingleProvider(
	ctx context.Context,
	p provider.Provider,
	pc *config.ProviderConfig,
	pw *progress.Writer,
	timeoutOverride time.Duration,
) (secret []byte, skipped bool) {
	return deriveWithProvider(ctx, p, pc, pw, timeoutOverride)
}

// deriveWithProvider handles a single provider attempt with appropriate
// timeout/progress behavior based on provider type. Returns the secret
// and whether the provider was skipped.
func deriveWithProvider(
	ctx context.Context,
	p provider.Provider,
	pc *config.ProviderConfig,
	pw *progress.Writer,
	timeoutOverride time.Duration,
) (secret []byte, skipped bool) {
	// Check if this is a hardware provider with a timeout
	hp, isHardware := p.(provider.HardwareProvider)

	if isHardware {
		return deriveHardware(ctx, p, hp, pc, pw, timeoutOverride)
	}

	// Non-hardware provider: call directly, no timeout. For non-interactive
	// providers (tpm, ssh-agent) emit a transient waiting line so the user
	// sees that work is happening while we block on hardware or socket I/O —
	// without it, the command appears to hang until the final ✓ appears.
	// Interactive providers have their own prompt UI as feedback.
	if ip, ok := p.(provider.InteractiveProvider); ok && !ip.InteractiveDerive() {
		pw.Emit(progress.Event{
			Provider: pc.Type, ID: pc.ID,
			Status:  progress.StatusWaiting,
			Message: waitingMessageFor(pc.Type),
		})
	}
	secret, err := p.Derive(ctx, pc.Params)
	if errors.Is(err, provider.ErrSkipped) {
		pw.Emit(progress.Event{
			Provider: pc.Type, ID: pc.ID,
			Status:  progress.StatusSkipped,
			Message: "user skipped",
		})
		return nil, true
	}
	if err != nil {
		pw.Emit(progress.Event{
			Provider: pc.Type, ID: pc.ID,
			Status:  progress.StatusFailed,
			Message: err.Error(),
		})
		return nil, false
	}
	return secret, false
}

// runPreDerive runs the optional PreDeriver hook outside the timeout window
// so interactive input (e.g. PINs) can be collected without tty conflicts.
// Returns the (possibly augmented) context, whether the step succeeded, and
// whether the caller should short-circuit as skipped.
func runPreDerive(
	ctx context.Context,
	p provider.Provider,
	pc *config.ProviderConfig,
	pw *progress.Writer,
) (newCtx context.Context, ok, skipped bool) {
	pd, hasPre := p.(provider.PreDeriver)
	if !hasPre {
		return ctx, true, false
	}
	newCtx, err := pd.PreDerive(ctx, pc.Params)
	if errors.Is(err, provider.ErrSkipped) {
		pw.Emit(progress.Event{
			Provider: pc.Type, ID: pc.ID,
			Status:  progress.StatusSkipped,
			Message: "user skipped",
		})
		return ctx, false, true
	}
	if err != nil {
		pw.Emit(progress.Event{
			Provider: pc.Type, ID: pc.ID,
			Status:  progress.StatusFailed,
			Message: err.Error(),
		})
		return ctx, false, false
	}
	return newCtx, true, false
}

// emitTimeoutResult translates a timeout.Result into a progress event and
// returns the (secret, skipped) pair the caller reports upward.
func emitTimeoutResult(result timeout.Result, pc *config.ProviderConfig, pw *progress.Writer) (secret []byte, skipped bool) {
	switch result.SkipReason {
	case timeout.SkippedTimeout:
		pw.Emit(progress.Event{
			Provider: pc.Type, ID: pc.ID,
			Status:  progress.StatusSkipped,
			Message: "timeout",
		})
		return nil, true
	case timeout.SkippedUser:
		pw.Emit(progress.Event{
			Provider: pc.Type, ID: pc.ID,
			Status:  progress.StatusSkipped,
			Message: "user skipped",
		})
		return nil, true
	}
	if result.Err != nil {
		if errors.Is(result.Err, provider.ErrSkipped) {
			pw.Emit(progress.Event{
				Provider: pc.Type, ID: pc.ID,
				Status:  progress.StatusSkipped,
				Message: "user skipped",
			})
			return nil, true
		}
		pw.Emit(progress.Event{
			Provider: pc.Type, ID: pc.ID,
			Status:  progress.StatusFailed,
			Message: result.Err.Error(),
		})
		return nil, false
	}
	return result.Secret, false
}

// deriveHardware wraps a hardware provider's Derive call with a timeout
// and countdown display. If the provider implements PreDeriver, that runs
// first (outside the timeout) to collect interactive input like PINs.
func deriveHardware(
	ctx context.Context,
	p provider.Provider,
	hp provider.HardwareProvider,
	pc *config.ProviderConfig,
	pw *progress.Writer,
	timeoutOverride time.Duration,
) (secret []byte, skipped bool) {
	ctx, ok, sk := runPreDerive(ctx, p, pc, pw)
	if !ok {
		return nil, sk
	}

	d := hp.DeriveTimeout()
	if timeoutOverride > 0 {
		d = timeoutOverride
	}

	waitingMsg := waitingMessageFor(pc.Type)
	pw.Emit(progress.Event{
		Provider: pc.Type, ID: pc.ID,
		Status:  progress.StatusWaiting,
		Message: waitingMsg,
	})

	// waitingDetail is an optional right-aligned dim suffix on the
	// countdown line (e.g. passkey's auth URL). Providers update it via
	// CtxUpdateWaitingDetail; the ticker reads it each tick so changes
	// propagate without adding any extra lines.
	var detailMu sync.Mutex
	var waitingDetail string

	deadline := time.Now().Add(d)
	ticker := time.NewTicker(1 * time.Second)
	countdownDone := make(chan struct{})
	countdownExited := make(chan struct{})
	go func() {
		defer close(countdownExited)
		defer ticker.Stop()
		for {
			select {
			case <-countdownDone:
				return
			case <-ticker.C:
				remaining := time.Until(deadline)
				if remaining < 0 {
					return
				}
				detailMu.Lock()
				detail := waitingDetail
				detailMu.Unlock()
				pw.Countdown(pc.Type, waitingMsg, detail, remaining)
			}
		}
	}()

	// Suppress the provider's own progress announcements during the
	// waiting window. The StatusWaiting line + countdown ticker above
	// already conveys the same information; without this, the provider's
	// pw.Info or pw.Link calls would clear our transient line, print a
	// redundant announcement on its own line, and the ticker would then
	// repaint on a fresh line underneath — the "hang + flash" artifact.
	// Providers that need to surface detail (e.g. passkey's auth URL)
	// route it through CtxUpdateWaitingDetail, which repaints the
	// countdown line in place with a right-aligned dim suffix.
	silentCtx := context.WithValue(ctx, provider.CtxProgressFunc, func(string) {})
	silentCtx = context.WithValue(silentCtx, provider.CtxProgressLink, func(string, string) {})
	silentCtx = context.WithValue(silentCtx, provider.CtxUpdateWaitingDetail, func(d string) {
		detailMu.Lock()
		waitingDetail = d
		detailMu.Unlock()
		// Repaint immediately so the detail is visible without waiting
		// up to a full tick.
		if remaining := time.Until(deadline); remaining > 0 {
			pw.Countdown(pc.Type, waitingMsg, d, remaining)
		}
	})
	result := timeout.Run(silentCtx, d, func(tCtx context.Context) ([]byte, error) {
		return p.Derive(tCtx, pc.Params)
	})

	close(countdownDone)
	<-countdownExited // wait for ticker goroutine to finish writing
	pw.FinishLine()

	return emitTimeoutResult(result, pc, pw)
}

// waitingMessageFor returns a per-provider-type status string shown while
// a provider blocks — either on background I/O (tpm, ssh-agent) or on
// user interaction with a hardware device / browser (fido2, piv, passkey).
// The same string is reused by the countdown ticker so the line reads
// consistently as the seconds tick down.
func waitingMessageFor(providerType string) string {
	switch providerType {
	case "tpm":
		return "connecting to TPM..."
	case "ssh-agent":
		return "signing via ssh-agent..."
	case "passkey":
		return "waiting for browser..."
	case "fido2", "piv":
		return "waiting for touch..."
	default:
		return "deriving..."
	}
}

// findChildArgs returns the arguments after "--" in os.Args, if any.
func findChildArgs() []string {
	for i, arg := range os.Args {
		if arg == "--" && i+1 < len(os.Args) {
			return os.Args[i+1:]
		}
	}
	return nil
}

// outputFormat holds the resolved set of mutually exclusive output flags.
type outputFormat struct {
	raw, b64, age, ageRecipient, ed25519 bool
}

// resolveOutputFormat folds --format into the bool flags and rejects any
// combination with more than one output mode selected.
func resolveOutputFormat(cmd *cli.Command) (outputFormat, error) {
	of := outputFormat{
		raw:          cmd.Bool("raw"),
		b64:          cmd.Bool("base64"),
		age:          cmd.Bool("age"),
		ageRecipient: cmd.Bool("age-recipient"),
		ed25519:      cmd.Bool("ed25519"),
	}
	switch cmd.String("format") {
	case "":
	case "age":
		of.age = true
	case "age-recipient":
		of.ageRecipient = true
	case "ed25519":
		of.ed25519 = true
	default:
		return of, fmt.Errorf("unknown format %q (supported: age, age-recipient, ed25519)", cmd.String("format"))
	}
	count := 0
	for _, f := range []bool{of.raw, of.b64, of.age, of.ageRecipient, of.ed25519} {
		if f {
			count++
		}
	}
	if count > 1 {
		return of, errors.New("--raw, --base64, --age, --age-recipient, and --ed25519 are mutually exclusive")
	}
	return of, nil
}

// runChild executes the user-supplied command, converting an ExitError into
// a cli.Exit with the child's code and wrapping other errors.
func runChild(child *exec.Cmd) error {
	if err := child.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return cli.Exit("", exitErr.ExitCode())
		}
		return fmt.Errorf("exec %q: %w", child.Path, err)
	}
	return nil
}

// emitAgeRecipient writes the age recipient (public key) to stdout, or feeds
// it to a child command via env var or stdin.
func emitAgeRecipient(ctx context.Context, cmd *cli.Command, key []byte) error {
	identity, recipient, err := keyformat.FormatAge(key)
	if err != nil {
		return err
	}
	// The age identity is secret and would be pointless here (we only
	// want the public recipient) — wipe it immediately.
	crypto.WipeBytes(identity)

	childArgs := findChildArgs()
	if len(childArgs) == 0 {
		fmt.Fprintln(os.Stdout, recipient)
		return nil
	}

	child := exec.CommandContext(ctx, childArgs[0], childArgs[1:]...) //nolint:gosec // intentional: CLI pipes to user-specified command
	child.Stderr = os.Stderr
	child.Stdout = os.Stdout

	if envVar := cmd.String("env"); envVar != "" {
		child.Env = append(os.Environ(), fmt.Sprintf("%s=%s", envVar, recipient))
		child.Stdin = os.Stdin
	} else {
		child.Stdin = strings.NewReader(recipient + "\n")
	}
	return runChild(child)
}

// emitStructured writes an age identity or ed25519 private key to stdout, or
// pipes it to a child command.
func emitStructured(ctx context.Context, cmd *cli.Command, key []byte, age bool, comment string) error {
	childArgs := findChildArgs()

	if len(childArgs) == 0 {
		formatted, stderr, err := formatStructuredKey(key, age, comment)
		if err != nil {
			return err
		}
		fmt.Fprint(os.Stderr, stderr)
		fmt.Fprint(os.Stdout, formatted)
		return nil
	}

	child := exec.CommandContext(ctx, childArgs[0], childArgs[1:]...) //nolint:gosec // intentional: CLI pipes to user-specified command
	child.Stderr = os.Stderr
	child.Stdout = os.Stdout

	if envVar := cmd.String("env"); envVar != "" {
		// Env path: Go's exec.Cmd.Env is []string-typed, so the secret
		// can't be wiped from our address space (it lives until GC).
		// Prefer stdin delivery where possible; see docs/commands/derive.md.
		formatted, _, err := formatStructuredKey(key, age, comment)
		if err != nil {
			return err
		}
		child.Env = append(os.Environ(), fmt.Sprintf("%s=%s", envVar, strings.TrimSpace(formatted)))
		child.Stdin = os.Stdin
	} else {
		primary, _, err := formatStructuredKeyBytes(key, age, comment)
		if err != nil {
			return err
		}
		defer crypto.WipeBytes(primary)
		child.Stdin = bytes.NewReader(primary)
	}
	return runChild(child)
}

// emitRawKey writes the raw key (hex/base64/binary) to stdout, or pipes it
// to a child command via env var or stdin.
func emitRawKey(ctx context.Context, cmd *cli.Command, key []byte, raw, b64 bool) error {
	childArgs := findChildArgs()
	if len(childArgs) == 0 {
		return EmitKey(key, raw, b64)
	}

	child := exec.CommandContext(ctx, childArgs[0], childArgs[1:]...) //nolint:gosec // intentional: CLI pipes to user-specified command
	child.Stderr = os.Stderr
	child.Stdout = os.Stdout

	if envVar := cmd.String("env"); envVar != "" {
		// Env path: Go's exec.Cmd.Env is []string-typed, so the secret
		// can't be wiped from our address space (it lives until GC).
		// Prefer stdin delivery where possible; see docs/commands/derive.md.
		child.Env = append(os.Environ(), fmt.Sprintf("%s=%s", envVar, FormatKey(key, raw, b64)))
		child.Stdin = os.Stdin
	} else {
		// Stdin path: use a caller-owned []byte so the plaintext copy can
		// be zeroed as soon as the child has consumed it.
		buf := FormatKeyBytes(key, raw, b64)
		defer crypto.WipeBytes(buf)
		child.Stdin = bytes.NewReader(buf)
	}
	return runChild(child)
}

func Execute(ctx context.Context, cmd *cli.Command) error {
	profileName := cmd.Args().First()
	if profileName == "" {
		profileName = config.DefaultProfile
	}

	of, err := resolveOutputFormat(cmd)
	if err != nil {
		return err
	}

	opts := ReconstructOpts{
		ProviderFilter: cmd.StringSlice("provider"),
		SkipFilter:     cmd.StringSlice("skip"),
		Quiet:          cmd.Bool("quiet"),
		Timeout:        cmd.Duration("timeout"),
		Use:            cmd.String("use"),
		NoTUI:          cmd.Bool("no-tui"),
	}

	key, err := Reconstruct(ctx, profileName, opts)
	if err != nil {
		return err
	}
	defer func() { crypto.WipeBytes(key) }()

	switch {
	case of.ageRecipient:
		return emitAgeRecipient(ctx, cmd, key)
	case of.age || of.ed25519:
		return emitStructured(ctx, cmd, key, of.age, profileName+"/"+opts.Use)
	default:
		return emitRawKey(ctx, cmd, key, of.raw, of.b64)
	}
}

// EmitKey writes a key to stdout in the requested format.
// Default is hex. Shared by derive and pipe commands.
func EmitKey(key []byte, raw, b64 bool) error {
	switch {
	case raw:
		_, err := os.Stdout.Write(key)
		return err
	case b64:
		_, err := fmt.Fprintln(os.Stdout, base64.StdEncoding.EncodeToString(key))
		return err
	default:
		_, err := fmt.Fprintln(os.Stdout, hex.EncodeToString(key))
		return err
	}
}

// FormatKey returns the key as a string in the requested format. Used on the
// env-var delivery path where Go's exec.Cmd.Env is []string-typed and the
// string can't be wiped. Prefer FormatKeyBytes for stdin delivery — that
// returns a caller-owned []byte which the caller can zero via WipeBytes.
func FormatKey(key []byte, raw, b64 bool) string {
	switch {
	case raw:
		return string(key)
	case b64:
		return base64.StdEncoding.EncodeToString(key)
	default:
		return hex.EncodeToString(key)
	}
}

// FormatKeyBytes returns the key as a fresh caller-owned []byte in the
// requested format. Callers MUST wipe the returned slice (via
// crypto.WipeBytes) once the plaintext key is no longer needed — this is the
// wipeable counterpart to FormatKey for use on the stdin delivery path,
// where we want to zero the in-memory copy as soon as the child process has
// consumed it.
func FormatKeyBytes(key []byte, raw, b64 bool) []byte {
	switch {
	case raw:
		out := make([]byte, len(key))
		copy(out, key)
		return out
	case b64:
		out := make([]byte, base64.StdEncoding.EncodedLen(len(key)))
		base64.StdEncoding.Encode(out, key)
		return out
	default:
		out := make([]byte, hex.EncodedLen(len(key)))
		hex.Encode(out, key)
		return out
	}
}

// formatStructuredKeyBytes formats the key as an age identity or ed25519
// SSH key. Returns the primary output as a caller-owned []byte (the secret —
// caller MUST wipe via crypto.WipeBytes) and the info/metadata as a string
// (public — age recipient or ssh public line; no wipe needed).
func formatStructuredKeyBytes(key []byte, age bool, comment string) (primary []byte, info string, err error) {
	if age {
		identity, recipient, err := keyformat.FormatAge(key)
		if err != nil {
			return nil, "", err
		}
		// Append a trailing newline into a fresh buffer so callers get a
		// single wipeable slice, then zero the keyformat-owned identity.
		primary = make([]byte, 0, len(identity)+1)
		primary = append(primary, identity...)
		primary = append(primary, '\n')
		crypto.WipeBytes(identity)
		info = fmt.Sprintf("# created: cryptkey/%s\n# recipient: %s\n", comment, recipient)
		return primary, info, nil
	}

	// ed25519. privPEM already carries a trailing newline from
	// pem.EncodeToMemory, so we return it directly.
	privPEM, pubAuth, err := keyformat.FormatEd25519(key, "cryptkey/"+comment)
	if err != nil {
		return nil, "", err
	}
	info = fmt.Sprintf("# %s\n", pubAuth)
	return privPEM, info, nil
}

// formatStructuredKey is the string-returning variant used on the env
// delivery path. Go's exec.Cmd.Env is []string-typed, so the plaintext
// identity / PEM body unavoidably lives as a Go string that cannot be
// wiped (it's cleaned up by GC). We still wipe the intermediate []byte we
// received from formatStructuredKeyBytes so the window is as short as
// possible. Prefer formatStructuredKeyBytes for stdin delivery.
func formatStructuredKey(key []byte, age bool, comment string) (primary, info string, err error) {
	primaryBytes, info, err := formatStructuredKeyBytes(key, age, comment)
	if err != nil {
		return "", "", err
	}
	primary = string(primaryBytes)
	crypto.WipeBytes(primaryBytes)
	return primary, info, nil
}

func init() {
	cmd := &cli.Command{
		Name:      "derive",
		Aliases:   []string{"d"},
		Usage:     "Reconstruct the key from enrolled providers and emit it, or exec a command with it",
		ArgsUsage: "[profile] [-- <command> [args...]]",
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:  "raw",
				Usage: "Output raw bytes",
			},
			&cli.BoolFlag{
				Name:  "base64",
				Usage: "Output base64-encoded key",
			},
			&cli.StringFlag{
				Name:    "env",
				Aliases: []string{"e"},
				Usage:   "Pass key as this environment variable instead of stdin (requires -- command)",
			},
			&cli.BoolFlag{
				Name:  "age",
				Usage: "Output an age X25519 identity (secret key to stdout, recipient to stderr)",
			},
			&cli.BoolFlag{
				Name:  "age-recipient",
				Usage: "Output only the age recipient (public key) for use with age -r",
			},
			&cli.BoolFlag{
				Name:  "ed25519",
				Usage: "Output an OpenSSH ed25519 private key (PEM to stdout, public key to stderr)",
			},
			&cli.StringFlag{
				Name:  "format",
				Usage: "Output key format: age, age-recipient, ed25519 (alternative to --age/--ed25519 flags)",
			},
			&cli.StringSliceFlag{
				Name:  "provider",
				Usage: "Only attempt these providers (type:id or type, repeatable)",
			},
			&cli.StringSliceFlag{
				Name:  "skip",
				Usage: "Skip these providers (type:id or type, repeatable)",
			},
			&cli.BoolFlag{
				Name:    "quiet",
				Aliases: []string{"q"},
				Usage:   "Suppress all stderr output except fatal errors",
			},
			&cli.DurationFlag{
				Name:  "timeout",
				Usage: "Hardware provider timeout (default: provider-specific, typically 30s)",
			},
			&cli.StringFlag{
				Name:  "use",
				Usage: "Context label for deriving a purpose-specific key (e.g., \"disk\", \"signing\")",
				Value: "default",
			},
			&cli.BoolFlag{
				Name:  "no-tui",
				Usage: "Force plain-line prompts and output (no colors, no inline editing). Implied when stderr is not a terminal.",
			},
		},
		Action: Execute,
	}
	common.RegisterCommand(cmd)
}
