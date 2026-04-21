// Package fido2 implements a provider that derives a 32-byte secret from
// a FIDO2 hardware key using the hmac-secret extension.
//
// Requires: libfido2 development headers and CGO_ENABLED=1.
package fido2

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	libfido2 "github.com/keys-pub/go-libfido2"
	"golang.org/x/term"

	"github.com/ekristen/cryptkey/pkg/provider"
)

const (
	rpID = "cryptkey.local"

	uvDiscouraged = "discouraged"
	uvPreferred   = "preferred"
	uvRequired    = "required"
)

type FIDO2 struct{}

func (f *FIDO2) Type() string                 { return "fido2" }
func (f *FIDO2) Description() string          { return "FIDO2 hardware key (hmac-secret)" }
func (f *FIDO2) InteractiveDerive() bool      { return true }
func (f *FIDO2) DeriveTimeout() time.Duration { return 30 * time.Second }

// PreDerive collects the FIDO2 PIN before the timeout-wrapped assertion.
// This avoids tty conflicts between PIN prompt and Enter-to-skip listener.
func (f *FIDO2) PreDerive(ctx context.Context, params map[string]string) (context.Context, error) {
	uv := params["uv"]
	// Skip PIN collection if already in context or UV is discouraged
	if ctx.Value(provider.CtxFIDO2PIN) != nil || uv == uvDiscouraged {
		return ctx, nil
	}

	pin, err := collectPINIfNeeded(ctx, uv)
	if err != nil {
		// Surface ErrSkipped upward so the derive command treats this as a
		// deliberate skip (no device tap, no touch wait) rather than a failure.
		return ctx, err
	}
	// Always seed the context, even for an empty PIN — an empty value is the
	// user's deliberate answer ("proceed with UP-only"). If we left the key
	// unset, Derive() would re-prompt and the user would never get past it.
	ctx = context.WithValue(ctx, provider.CtxFIDO2PIN, pin)
	return ctx, nil
}

func (f *FIDO2) EnrollOptions() []provider.EnrollOption {
	return []provider.EnrollOption{
		{
			Key:         "uv",
			Label:       "User Verification",
			Shortcut:    "u",
			Values:      []string{uvPreferred, uvRequired, uvDiscouraged},
			Default:     uvPreferred,
			Description: "PIN or biometric verification mode",
		},
	}
}

// DeviceInfo holds device metadata safe for use outside CGo contexts.
type DeviceInfo struct {
	Path         string
	Manufacturer string
	Product      string
	DisplayName  string
}

// ListDevices returns available FIDO2 devices.
func ListDevices() ([]DeviceInfo, error) {
	locs, err := libfido2.DeviceLocations()
	if err != nil {
		return nil, fmt.Errorf("fido2: detect devices: %w", err)
	}
	devices := make([]DeviceInfo, len(locs))
	for i, loc := range locs {
		devices[i] = DeviceInfo{
			Path:         loc.Path,
			Manufacturer: loc.Manufacturer,
			Product:      loc.Product,
			DisplayName:  deviceName(loc),
		}
	}
	return devices, nil
}

func (f *FIDO2) Enroll(ctx context.Context, id string) (*provider.EnrollResult, error) {
	silent := ctx.Value(provider.CtxSilent) != nil
	progress := provider.GetProgressFunc(ctx)

	locs, err := libfido2.DeviceLocations()
	if err != nil {
		return nil, fmt.Errorf("fido2: detect devices: %w", err)
	}
	if len(locs) == 0 {
		return nil, errors.New("fido2: no FIDO2 devices detected — insert a key and try again")
	}

	loc, err := pickDevice(ctx, locs)
	if err != nil {
		return nil, err
	}

	dev, err := libfido2.NewDevice(loc.Path)
	if err != nil {
		return nil, fmt.Errorf("fido2: open device %s: %w", loc.Path, err)
	}

	// Generate random credential salt for hmac-secret
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("fido2: generate salt: %w", err)
	}

	userID := make([]byte, 32)
	if _, err := rand.Read(userID); err != nil {
		return nil, fmt.Errorf("fido2: generate user id: %w", err)
	}

	cdh := make([]byte, 32)
	if _, err := rand.Read(cdh); err != nil {
		return nil, fmt.Errorf("fido2: generate cdh: %w", err)
	}

	uv := getUVPreference(ctx)
	uvOpt := uvToOptionValue(uv)

	pin, err := collectPINIfNeeded(ctx, uv)
	if err != nil {
		return nil, err
	}

	announce(fmt.Sprintf("Touch your %s to create credential...", deviceName(loc)), silent, progress)

	rp := libfido2.RelyingParty{ID: rpID, Name: "cryptkey"}
	user := libfido2.User{ID: userID, Name: id}
	credOpts := &libfido2.MakeCredentialOpts{
		Extensions: []libfido2.Extension{libfido2.HMACSecretExtension},
		UV:         uvOpt,
	}
	attest, pin, err := makeCredentialWithPINRetry(ctx, dev, cdh, rp, user, credOpts, pin)
	if err != nil {
		return nil, err
	}

	credID := attest.CredentialID

	announce(fmt.Sprintf("Touch your %s again to derive secret...", deviceName(loc)), silent, progress)

	assertCDH := make([]byte, 32)
	if _, err := rand.Read(assertCDH); err != nil {
		return nil, fmt.Errorf("fido2: generate assert cdh: %w", err)
	}

	assertOpts := &libfido2.AssertionOpts{
		Extensions: []libfido2.Extension{libfido2.HMACSecretExtension},
		HMACSalt:   salt,
		UV:         uvOpt,
		UP:         libfido2.True,
	}
	assertion, _, err := assertionWithPINRetry(ctx, dev, rpID, assertCDH, [][]byte{credID}, pin, assertOpts)
	if err != nil {
		return nil, err
	}
	if len(assertion.HMACSecret) == 0 {
		return nil, errors.New("fido2: hmac-secret not returned by device")
	}

	secret := assertion.HMACSecret
	if len(secret) != 32 {
		return nil, fmt.Errorf("fido2: expected 32-byte hmac-secret, got %d", len(secret))
	}

	return &provider.EnrollResult{
		Secret: secret,
		Params: map[string]string{
			"credential_id": hex.EncodeToString(credID),
			"salt":          hex.EncodeToString(salt),
			"rp_id":         rpID,
			"device_name":   deviceName(loc),
			"uv":            uv,
		},
	}, nil
}

// deriveParams bundles the decoded params needed for a FIDO2 assertion.
type deriveParams struct {
	credID []byte
	salt   []byte
	rpID   string
	uv     string
}

// parseDeriveParams decodes the stored config fields that Derive needs.
func parseDeriveParams(params map[string]string) (*deriveParams, error) {
	credIDHex, ok := params["credential_id"]
	if !ok {
		return nil, errors.New("fido2: missing credential_id in config")
	}
	credID, err := hex.DecodeString(credIDHex)
	if err != nil {
		return nil, fmt.Errorf("fido2: decode credential_id: %w", err)
	}
	saltHex, ok := params["salt"]
	if !ok {
		return nil, errors.New("fido2: missing salt in config")
	}
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return nil, fmt.Errorf("fido2: decode salt: %w", err)
	}
	rpIDVal := params["rp_id"]
	if rpIDVal == "" {
		rpIDVal = rpID
	}
	return &deriveParams{credID: credID, salt: salt, rpID: rpIDVal, uv: params["uv"]}, nil
}

func (f *FIDO2) Derive(ctx context.Context, params map[string]string) ([]byte, error) {
	dp, err := parseDeriveParams(params)
	if err != nil {
		return nil, err
	}
	uvOpt := uvToOptionValue(dp.uv)

	// Collect PIN if UV requires it
	pin, err := collectPINIfNeeded(ctx, dp.uv)
	if err != nil {
		return nil, err
	}

	locs, err := libfido2.DeviceLocations()
	if err != nil {
		return nil, fmt.Errorf("fido2: detect devices: %w", err)
	}
	if len(locs) == 0 {
		return nil, errors.New("fido2: no FIDO2 devices detected")
	}

	cdh := make([]byte, 32)
	if _, err := rand.Read(cdh); err != nil {
		return nil, fmt.Errorf("fido2: generate cdh: %w", err)
	}

	assertOpts := &libfido2.AssertionOpts{
		Extensions: []libfido2.Extension{libfido2.HMACSecretExtension},
		HMACSalt:   dp.salt,
		UV:         uvOpt,
		UP:         libfido2.True,
	}

	// Tell the UI to surface the touch prompt — Assertion below blocks
	// until the user taps, and the TUI / progress writer relies on this
	// callback to render the "Touch your key..." status. Use the stored
	// device_name when available, fall back to a generic phrase.
	progress := provider.GetProgressFunc(ctx)
	deviceName := params["device_name"]
	if deviceName == "" {
		deviceName = "FIDO2 key"
	}
	touchMsg := fmt.Sprintf("Touch your %s to derive secret...", deviceName)
	progress(touchMsg)

	return assertWithPINRetry(ctx, locs, dp.rpID, cdh, dp.credID, pin, assertOpts, progress, touchMsg)
}

// assertWithPINRetry runs tryAssertionAcrossDevices, re-prompting for a new
// PIN on wrong-PIN failures up to maxPINAttempts. A wrong PIN is one of the
// most common mistakes — device locking is handled by libfido2
// (ErrPinAuthBlocked); we don't silently keep retrying past that.
func assertWithPINRetry(
	ctx context.Context,
	locs []*libfido2.DeviceLocation,
	rpIDVal string,
	cdh, credID []byte,
	pin string,
	assertOpts *libfido2.AssertionOpts,
	progress func(string),
	touchMsg string,
) ([]byte, error) {
	for attempt := range maxPINAttempts {
		if attempt > 0 {
			// Re-emit the touch prompt after a wrong-PIN retry so the
			// UI doesn't sit on a stale "wrong PIN" hint while we wait
			// for the next tap.
			progress(touchMsg)
		}
		secret, pinInvalid, err := tryAssertionAcrossDevices(
			locs, rpIDVal, cdh, credID, pin, assertOpts,
		)
		if err == nil {
			return secret, nil
		}
		if !pinInvalid {
			return nil, err
		}
		// PIN was wrong on every device that responded. Re-prompt.
		newPIN, perr := retryPINPrompt(ctx, attempt+1, maxPINAttempts)
		if perr != nil {
			return nil, perr
		}
		pin = newPIN
	}
	return nil, fmt.Errorf("fido2: too many PIN attempts (%d) — aborting to avoid locking the device", maxPINAttempts)
}

// tryAssertionAcrossDevices runs Assertion on each device in order,
// returning on the first success. If every device failed and at least one
// failure was due to a wrong PIN, pinInvalid is true so the caller can
// prompt for a new PIN and retry.
func tryAssertionAcrossDevices(
	locs []*libfido2.DeviceLocation,
	rpIDVal string,
	cdh []byte,
	credID []byte,
	pin string,
	opts *libfido2.AssertionOpts,
) (secret []byte, pinInvalid bool, err error) {
	var lastErr error
	for _, loc := range locs {
		dev, derr := libfido2.NewDevice(loc.Path)
		if derr != nil {
			lastErr = derr
			continue
		}

		assertion, aerr := dev.Assertion(rpIDVal, cdh, [][]byte{credID}, pin, opts)
		if aerr != nil {
			if errors.Is(aerr, libfido2.ErrPinInvalid) {
				pinInvalid = true
			}
			if errors.Is(aerr, libfido2.ErrPinAuthBlocked) {
				return nil, false, errors.New("fido2: PIN auth blocked — re-insert the device or reset the PIN")
			}
			lastErr = aerr
			continue
		}
		if len(assertion.HMACSecret) == 0 {
			lastErr = errors.New("hmac-secret not returned")
			continue
		}
		if len(assertion.HMACSecret) != 32 {
			lastErr = fmt.Errorf("expected 32-byte hmac-secret, got %d", len(assertion.HMACSecret))
			continue
		}
		return assertion.HMACSecret, false, nil
	}
	if pinInvalid {
		return nil, true, nil
	}
	return nil, false, fmt.Errorf("fido2: no device matched credential: %w", lastErr)
}

// maxPINAttempts caps how many consecutive wrong-PIN errors we tolerate
// before giving up. FIDO2 devices typically lock after 8 total bad PIN
// attempts (counter persists across power cycles until a correct PIN is
// entered), so we cap well below that to leave room for attempts from
// other applications.
const maxPINAttempts = 3

// announce emits msg via the progress callback when silent (typically the
// TUI routing status updates to its display), or directly to stderr when
// not. Exactly one of the two fires — before, both fired whenever the
// caller set a non-noop progress callback without also setting CtxSilent,
// which duplicated every touch prompt during rekey.
func announce(msg string, silent bool, progress func(string)) {
	if silent {
		progress(msg)
		return
	}
	fmt.Fprintln(os.Stderr, msg)
}

// retryPINPrompt re-asks the user for a FIDO2 PIN after a wrong attempt.
// Returns provider.ErrSkipped when the user presses esc so the caller can
// abort cleanly. Returns an error if no interactive prompt is available.
func retryPINPrompt(ctx context.Context, attempt, maxAttempts int) (string, error) {
	hint := fmt.Sprintf("wrong PIN — attempt %d/%d, esc to abort", attempt+1, maxAttempts)

	if promptFn, ok := ctx.Value(provider.CtxPromptPassword).(func(string, string, string) (string, error)); ok {
		pin, err := promptFn("fido2", "PIN", hint)
		if errors.Is(err, provider.ErrSkipped) {
			return "", provider.ErrSkipped
		}
		if err != nil {
			return "", fmt.Errorf("fido2: %w", err)
		}
		return pin, nil
	}

	// No progress-writer prompt callback — fall back to direct tty read.
	// Without a callback we can still prompt, just without the dim hint
	// styling. This path hits during CLI enrollment (init / rekey phase 2
	// after we split the context).
	fmt.Fprintf(os.Stderr, "Wrong PIN — attempt %d/%d, press enter with no input to abort: ", attempt+1, maxAttempts)
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", fmt.Errorf("fido2: open /dev/tty: %w", err)
	}
	defer tty.Close()
	pass, err := term.ReadPassword(int(tty.Fd())) //nolint:gosec
	fmt.Fprint(tty, "\r\n")
	if err != nil {
		return "", fmt.Errorf("fido2: read PIN: %w", err)
	}
	if len(pass) == 0 {
		return "", provider.ErrSkipped
	}
	return string(pass), nil
}

// makeCredentialWithPINRetry wraps dev.MakeCredential with a retry loop
// that handles wrong-PIN errors by re-prompting. Non-PIN errors and
// "auth blocked" errors abort immediately. Returns the working PIN so the
// subsequent assertion call uses the same one.
func makeCredentialWithPINRetry(
	ctx context.Context,
	dev *libfido2.Device,
	cdh []byte,
	rp libfido2.RelyingParty,
	user libfido2.User,
	opts *libfido2.MakeCredentialOpts,
	pin string,
) (*libfido2.Attestation, string, error) {
	for attempt := range maxPINAttempts {
		attest, err := dev.MakeCredential(cdh, rp, user, libfido2.ES256, pin, opts)
		if err == nil {
			return attest, pin, nil
		}
		if errors.Is(err, libfido2.ErrPinAuthBlocked) {
			return nil, "", errors.New("fido2: PIN auth blocked — re-insert the device or reset the PIN")
		}
		if !errors.Is(err, libfido2.ErrPinInvalid) {
			return nil, "", fmt.Errorf("fido2: make credential: %w", err)
		}

		newPIN, perr := retryPINPrompt(ctx, attempt+1, maxPINAttempts)
		if perr != nil {
			return nil, "", perr
		}
		pin = newPIN
	}
	return nil, "", fmt.Errorf("fido2: too many PIN attempts (%d) — aborting to avoid locking the device", maxPINAttempts)
}

// assertionWithPINRetry wraps dev.Assertion with the same retry loop as
// makeCredentialWithPINRetry. Returns the working PIN.
func assertionWithPINRetry(
	ctx context.Context,
	dev *libfido2.Device,
	rpIDVal string,
	cdh []byte,
	credIDs [][]byte,
	pin string,
	opts *libfido2.AssertionOpts,
) (*libfido2.Assertion, string, error) {
	for attempt := range maxPINAttempts {
		assertion, err := dev.Assertion(rpIDVal, cdh, credIDs, pin, opts)
		if err == nil {
			return assertion, pin, nil
		}
		if errors.Is(err, libfido2.ErrPinAuthBlocked) {
			return nil, "", errors.New("fido2: PIN auth blocked — re-insert the device or reset the PIN")
		}
		if !errors.Is(err, libfido2.ErrPinInvalid) {
			return nil, "", fmt.Errorf("fido2: assertion: %w", err)
		}

		newPIN, perr := retryPINPrompt(ctx, attempt+1, maxPINAttempts)
		if perr != nil {
			return nil, "", perr
		}
		pin = newPIN
	}
	return nil, "", fmt.Errorf("fido2: too many PIN attempts (%d) — aborting to avoid locking the device", maxPINAttempts)
}

// getUVPreference reads the FIDO2 UV preference from context.
// Checks the TUI enroll option key first, then the CLI flag key.
// Returns "discouraged", "preferred", or "required". Default is "preferred".
func getUVPreference(ctx context.Context) string {
	// Check TUI-set enroll option first
	if v := ctx.Value(provider.CtxEnrollOption("uv")); v != nil {
		if s, ok := v.(string); ok {
			switch s {
			case uvDiscouraged, uvPreferred, uvRequired:
				return s
			}
		}
	}
	// Fall back to CLI flag
	if v := ctx.Value(provider.CtxFIDO2UV); v != nil {
		if s, ok := v.(string); ok {
			switch s {
			case uvDiscouraged, uvPreferred, uvRequired:
				return s
			}
		}
	}
	return uvPreferred
}

// uvToOptionValue maps a UV preference string to a libfido2 OptionValue.
func uvToOptionValue(uv string) libfido2.OptionValue {
	switch uv {
	case uvDiscouraged:
		return libfido2.False
	case uvRequired:
		return libfido2.True
	default:
		return libfido2.Default
	}
}

// collectPINIfNeeded prompts for a FIDO2 PIN when UV is "required" or "preferred".
// For "discouraged", no PIN is collected.
func collectPINIfNeeded(ctx context.Context, uv string) (string, error) {
	if uv == uvDiscouraged {
		return "", nil
	}

	// Check context for pre-collected PIN (TUI path)
	if v := ctx.Value(provider.CtxFIDO2PIN); v != nil {
		if pin, ok := v.(string); ok {
			return pin, nil
		}
	}

	// Legacy: check passphrase context key
	if v := ctx.Value(provider.CtxPassphrase); v != nil {
		if pass, ok := v.([]byte); ok && len(pass) > 0 {
			return string(pass), nil
		}
	}

	// Use progress writer prompt if available (derive path)
	if promptFn, ok := ctx.Value(provider.CtxPromptPassword).(func(string, string, string) (string, error)); ok {
		hint := "esc to skip"
		if uv == uvRequired {
			hint = ""
		}
		pin, err := promptFn("fido2", "PIN", hint)
		if err != nil {
			if errors.Is(err, provider.ErrSkipped) {
				return "", provider.ErrSkipped
			}
			return "", fmt.Errorf("fido2: %w", err)
		}
		if uv == uvRequired && pin == "" {
			return "", errors.New("fido2: PIN is required but was empty")
		}
		return pin, nil
	}

	// Fall back to direct tty prompting (CLI enrollment path)
	return promptPINDirect(uv)
}

// promptPINDirect prompts for PIN directly on /dev/tty (for CLI enrollment).
func promptPINDirect(uv string) (string, error) {
	prompt := "Enter FIDO2 PIN (or press Esc to skip): "
	if uv == uvRequired {
		prompt = "Enter FIDO2 PIN: "
	}

	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", fmt.Errorf("fido2: open /dev/tty: %w", err)
	}
	defer tty.Close()

	fmt.Fprint(tty, prompt)
	pass, err := term.ReadPassword(int(tty.Fd())) //nolint:gosec // Fd() fits in int on all supported platforms
	fmt.Fprint(tty, "\r\n")
	if err != nil {
		return "", fmt.Errorf("fido2: read PIN: %w", err)
	}
	if uv == uvRequired && len(pass) == 0 {
		return "", errors.New("fido2: PIN is required but was empty")
	}
	return string(pass), nil
}

// pickDevice selects a FIDO2 device. Checks context for a pre-selected device path
// (TUI mode), otherwise prompts interactively.
func pickDevice(ctx context.Context, locs []*libfido2.DeviceLocation) (*libfido2.DeviceLocation, error) {
	// Check context for pre-selected device (TUI path)
	if v := ctx.Value(provider.CtxFIDO2DevicePath); v != nil {
		if path, ok := v.(string); ok && path != "" {
			for _, loc := range locs {
				if loc.Path == path {
					return loc, nil
				}
			}
			return nil, fmt.Errorf("fido2: device %s not found", path)
		}
	}

	if len(locs) == 1 {
		fmt.Fprintf(os.Stderr, "Using %s\n", deviceName(locs[0]))
		return locs[0], nil
	}

	fmt.Fprintln(os.Stderr, "Multiple FIDO2 devices detected:")
	for i, loc := range locs {
		fmt.Fprintf(os.Stderr, "  [%d] %s (%s)\n", i+1, deviceName(loc), loc.Path)
	}
	fmt.Fprint(os.Stderr, "Select device: ")

	tty, err := os.Open("/dev/tty")
	if err != nil {
		tty = os.Stdin
	} else {
		defer tty.Close()
	}

	scanner := bufio.NewScanner(tty)
	if !scanner.Scan() {
		return nil, errors.New("fido2: no input")
	}

	idx, err := strconv.Atoi(strings.TrimSpace(scanner.Text()))
	if err != nil || idx < 1 || idx > len(locs) {
		return nil, errors.New("fido2: invalid selection")
	}

	return locs[idx-1], nil
}

func deviceName(loc *libfido2.DeviceLocation) string {
	if loc.Product != "" {
		if loc.Manufacturer != "" {
			return fmt.Sprintf("%s %s", loc.Manufacturer, loc.Product)
		}
		return loc.Product
	}
	return loc.Path
}

func init() {
	provider.Register(&FIDO2{})
}
