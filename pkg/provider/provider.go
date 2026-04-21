// Package provider defines the interface for cryptkey authentication providers.
//
// Each provider can produce a deterministic 32-byte secret during enrollment
// and re-derive it during key reconstruction. The secret is used to encrypt
// that provider's Shamir share; it never leaves the provider boundary.
package provider

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// ErrSkipped signals that the user declined to participate in the current
// provider derivation (e.g. by pressing Escape on a PIN prompt). The derive
// command treats this as a deliberate skip rather than a failure, so the
// provider is omitted from Shamir share recovery and the threshold check
// continues with the remaining providers.
var ErrSkipped = errors.New("provider skipped by user")

// Context keys for passing pre-collected input to providers.
// When set, providers should use these instead of prompting.

// ContextKey is the type for provider context keys. Exported so that
// provider packages can define their own keys of the same type.
type ContextKey string

const (
	// CtxPassphrase carries a []byte passphrase collected by the TUI.
	CtxPassphrase ContextKey = "passphrase"

	// CtxArgonTime carries the Argon2id time/iterations parameter.
	CtxArgonTime ContextKey = "argon_time"

	// CtxArgonMemory carries the Argon2id memory parameter in KiB.
	CtxArgonMemory ContextKey = "argon_memory"

	// CtxArgonThreads carries the Argon2id parallelism parameter.
	CtxArgonThreads ContextKey = "argon_threads"

	// CtxFIDO2UV carries the FIDO2 user verification preference.
	// Values: "discouraged", "preferred", "required".
	CtxFIDO2UV ContextKey = "fido2_uv"

	// CtxFIDO2DevicePath carries the selected FIDO2 device path (e.g., "/dev/hidraw3").
	CtxFIDO2DevicePath ContextKey = "fido2_device_path"

	// CtxFIDO2PIN carries the FIDO2 PIN as a string.
	CtxFIDO2PIN ContextKey = "fido2_pin"

	// CtxSSHAgentKeyFingerprint carries the selected SSH agent key fingerprint.
	CtxSSHAgentKeyFingerprint ContextKey = "sshagent_key_fingerprint"

	// CtxSSHKeyPath carries the absolute path to the SSH private key file.
	CtxSSHKeyPath ContextKey = "sshkey_path"

	// CtxSSHKeyPassphrase carries the SSH key passphrase ([]byte).
	CtxSSHKeyPassphrase ContextKey = "sshkey_passphrase" //nolint:gosec // not a credential, just a context key name

	// CtxPIVPIN carries the PIV PIN as a string.
	CtxPIVPIN ContextKey = "piv_pin"

	// CtxPIVSerial carries the pre-selected PIV device serial number.
	CtxPIVSerial ContextKey = "piv_serial"

	// CtxPIVOverwrite carries a bool indicating the user confirmed
	// overwriting existing PIV slot key material during enrollment.
	CtxPIVOverwrite ContextKey = "piv_overwrite"

	// CtxSilent suppresses stderr output from providers. Set by the TUI
	// since it controls all display.
	CtxSilent ContextKey = "silent"

	// CtxProgressFunc carries a func(string) that providers call to report
	// progress (e.g., "Touch again to derive secret..."). The TUI uses this
	// to update status while enrollment runs in a goroutine.
	CtxProgressFunc ContextKey = "progress_func"

	// CtxPromptPassword carries a func(providerType, label, hint string) (string, error)
	// for reading secrets inline with progress output during derive. The
	// display masks each keystroke with a bullet on a TTY; hint (optional)
	// renders in dim text next to the label (e.g. "esc to skip").
	CtxPromptPassword ContextKey = "prompt_password"

	// CtxPromptLine carries a func(providerType, label, hint string) (string, error)
	// for reading lines (with echo) inline with progress output during derive.
	// hint (optional) renders in dim text next to the label.
	CtxPromptLine ContextKey = "prompt_line"

	// CtxProgressLink carries a func(prefix, url string) that providers
	// call to emit a labeled URL line with the URL rendered in dim text
	// on interactive terminals (e.g. the passkey browser open message).
	CtxProgressLink ContextKey = "progress_link"

	// CtxUpdateWaitingDetail carries a func(string) that a hardware
	// provider can call to set a right-aligned dim detail string on the
	// derive command's existing waiting line — e.g. passkey surfacing the
	// local auth URL as a fallback in case auto-browser-open fails. The
	// caller (derive command) repaints the line with the new detail so
	// no extra lines appear.
	CtxUpdateWaitingDetail ContextKey = "update_waiting_detail"
)

// Provider is the interface all authentication providers implement.
type Provider interface {
	// Type returns the provider type name (e.g. "passphrase", "fido2").
	Type() string

	// Description returns a short human-readable description.
	Description() string

	// Enroll performs interactive enrollment and returns the 32-byte secret
	// along with provider-specific metadata to persist in the config file.
	Enroll(ctx context.Context, id string) (*EnrollResult, error)

	// Derive re-derives the 32-byte secret from stored metadata.
	Derive(ctx context.Context, params map[string]string) ([]byte, error)
}

// InteractiveProvider is an optional interface that providers can implement
// to indicate whether their Derive method reads from the terminal (e.g.,
// prompting for a passphrase or PIN). When true, no timeout is applied
// during derivation since the user is actively providing input.
// Providers that do not implement this interface are assumed interactive.
type InteractiveProvider interface {
	InteractiveDerive() bool
}

// HardwareProvider is an optional interface for providers that block on
// physical user interaction (touch, browser). These get automatic timeouts
// during derivation.
type HardwareProvider interface {
	DeriveTimeout() time.Duration
}

// PreDeriver is an optional interface for providers that need interactive
// setup (e.g., PIN collection) before the timeout-wrapped hardware call.
// The returned context should carry any collected values (e.g., PIN).
// This runs BEFORE the timeout starts, so there's no tty conflict.
type PreDeriver interface {
	PreDerive(ctx context.Context, params map[string]string) (context.Context, error)
}

// EnrollOption describes a configurable option for a provider during enrollment.
type EnrollOption struct {
	Key         string            // internal key (e.g., "uv")
	Label       string            // display label (e.g., "User Verification")
	Shortcut    string            // TUI key shortcut (e.g., "u")
	Values      []string          // allowed values in cycle order
	Default     string            // default value
	Description string            // short description shown in TUI
	ValueHelp   map[string]string // optional per-value help text shown when focused
}

// ConfigurableProvider is an optional interface for providers that have
// options the user can configure during enrollment (e.g., FIDO2 UV mode).
type ConfigurableProvider interface {
	// EnrollOptions returns the configurable options for this provider.
	EnrollOptions() []EnrollOption
}

// OptionWarner is an optional interface for configurable providers that can
// warn about potentially problematic option combinations (e.g., high Argon2 cost).
type OptionWarner interface {
	// EnrollWarning returns a warning string for the current option values,
	// or "" if no warning applies.
	EnrollWarning(values map[string]string) string
}

// CtxEnrollOption returns a ContextKey for a provider-specific enrollment option.
func CtxEnrollOption(key string) ContextKey {
	return ContextKey("enroll_opt_" + key)
}

// WithEnrollOptions returns a context with each option stored under
// CtxEnrollOption(key). Centralizing the loop keeps call sites tidy and means
// the "nested context in loop" pattern only appears here, once.
//
//nolint:fatcontext // intentional — each option is a distinct context key
func WithEnrollOptions(ctx context.Context, options map[string]string) context.Context {
	for k, v := range options {
		ctx = context.WithValue(ctx, CtxEnrollOption(k), v)
	}
	return ctx
}

// GetProgressFunc returns the progress callback stored on ctx (set by the CLI
// or TUI to route status updates), or a no-op func when no callback is set.
// Providers call this to surface interim status without having to branch on
// whether a callback is present. Callers that want a stderr fallback when no
// callback is set (e.g. passkey's browser flow) should implement that locally.
func GetProgressFunc(ctx context.Context) func(string) {
	if v := ctx.Value(CtxProgressFunc); v != nil {
		if fn, ok := v.(func(string)); ok {
			return fn
		}
	}
	return func(string) {}
}

// EnrollResult is returned by a successful Enroll call.
type EnrollResult struct {
	Secret  []byte            // exactly 32 bytes
	Params  map[string]string // metadata to store in the profile config
	Message string            // optional message to display after enrollment (e.g. recovery code)
}

// --- Registry ---

var (
	mu       sync.RWMutex
	registry = map[string]Provider{}
)

// Register adds a provider to the global registry. Called from init().
func Register(p Provider) {
	mu.Lock()
	defer mu.Unlock()
	if _, dup := registry[p.Type()]; dup {
		panic(fmt.Sprintf("provider: duplicate registration for %q", p.Type()))
	}
	registry[p.Type()] = p
}

// Get returns a registered provider by type name.
func Get(name string) (Provider, bool) {
	mu.RLock()
	defer mu.RUnlock()
	p, ok := registry[name]
	return p, ok
}

// List returns all registered provider type names, sorted.
func List() []string {
	mu.RLock()
	defer mu.RUnlock()
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// All returns all registered providers, sorted by type name.
func All() []Provider {
	mu.RLock()
	defer mu.RUnlock()
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	sort.Strings(names)
	providers := make([]Provider, len(names))
	for i, name := range names {
		providers[i] = registry[name]
	}
	return providers
}
