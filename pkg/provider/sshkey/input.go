package sshkey

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	cryptolib "github.com/ekristen/cryptkey/pkg/crypto"
	"github.com/ekristen/cryptkey/pkg/provider"
)

// getKeyPath returns the SSH key file path. It checks:
// 1. Context (TUI pre-collected)
// 2. Progress prompt with hint as default (derive path)
// 3. If hint is a path, use it directly (enroll/test path)
// 4. Direct stderr prompt as fallback
func getKeyPath(ctx context.Context, hint string) (string, error) {
	// Check context first (TUI pre-collected)
	if v := ctx.Value(provider.CtxSSHKeyPath); v != nil {
		if p, ok := v.(string); ok && p != "" {
			return expandPath(p), nil
		}
	}

	if hint == "" {
		hint = "~/.ssh/id_ed25519"
	}

	// Use progress prompt if available (derive path — lets user override stored path)
	if promptFn, ok := ctx.Value(provider.CtxPromptLine).(func(string, string, string) (string, error)); ok {
		line, err := promptFn("sshkey", "key path", fmt.Sprintf("default %s", hint))
		if err != nil {
			return "", fmt.Errorf("sshkey: %w", err)
		}
		if line == "" {
			line = hint
		}
		return expandPath(line), nil
	}

	// If hint looks like a file path, use it directly (enroll with --add sshkey:/path)
	if strings.HasPrefix(hint, "/") || strings.HasPrefix(hint, "~") || strings.HasPrefix(hint, ".") {
		return expandPath(hint), nil
	}

	// Direct stderr fallback
	fmt.Fprintf(os.Stderr, "SSH key path [%s]: ", hint)
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("sshkey: read path: %w", err)
	}
	line = strings.TrimSpace(line)
	if line == "" {
		line = hint
	}

	return expandPath(line), nil
}

// getPassphrase prompts for an SSH key passphrase (with echo suppressed).
func getPassphrase(ctx context.Context) ([]byte, error) {
	// Check context for pre-collected SSH key passphrase (TUI path)
	if v := ctx.Value(provider.CtxSSHKeyPassphrase); v != nil {
		if pass, ok := v.([]byte); ok && len(pass) > 0 {
			out := make([]byte, len(pass))
			copy(out, pass)
			return out, nil
		}
	}

	// Legacy: check general passphrase context key
	if v := ctx.Value(provider.CtxPassphrase); v != nil {
		if pass, ok := v.([]byte); ok && len(pass) > 0 {
			out := make([]byte, len(pass))
			copy(out, pass)
			return out, nil
		}
	}

	// Use progress prompt if available (derive path)
	if promptFn, ok := ctx.Value(provider.CtxPromptPassword).(func(string, string, string) (string, error)); ok {
		pin, err := promptFn("sshkey", "key passphrase", "esc to skip")
		if err != nil {
			if errors.Is(err, provider.ErrSkipped) {
				return nil, provider.ErrSkipped
			}
			return nil, fmt.Errorf("sshkey: %w", err)
		}
		if pin == "" {
			return nil, errors.New("sshkey: empty passphrase")
		}
		return []byte(pin), nil
	}

	// Direct tty fallback
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("sshkey: open /dev/tty: %w", err)
	}
	defer tty.Close()

	fmt.Fprint(os.Stderr, "Enter SSH key passphrase: ")
	pass, err := term.ReadPassword(int(tty.Fd())) //nolint:gosec // Fd() fits in int on all supported platforms
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("sshkey: read passphrase: %w", err)
	}
	if len(pass) == 0 {
		cryptolib.WipeBytes(pass)
		return nil, errors.New("sshkey: empty passphrase")
	}
	return pass, nil
}

// ProbeKeyFile checks if an SSH key file exists and whether it needs a passphrase.
// Returns (needsPassphrase, error). Error is non-nil if the file can't be read or parsed.
func ProbeKeyFile(path string) (bool, error) {
	expanded := expandPath(path)
	pemBytes, err := os.ReadFile(expanded)
	if err != nil {
		return false, fmt.Errorf("sshkey: read key: %w", err)
	}

	_, err = ssh.ParseRawPrivateKey(pemBytes)
	if err != nil {
		var passErr *ssh.PassphraseMissingError
		if errors.As(err, &passErr) {
			return true, nil
		}
		return false, fmt.Errorf("sshkey: parse key: %w", err)
	}
	return false, nil
}

// expandPath expands ~ to the user's home directory.
func expandPath(path string) string {
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		return home + path[1:]
	}
	return path
}
