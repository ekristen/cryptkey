// Package sshagent implements a provider that derives a 32-byte secret by
// having the SSH agent sign a deterministic challenge. The secret is the
// HKDF-SHA256 of the resulting Ed25519 signature.
//
// Only Ed25519 keys are supported because their signatures are deterministic
// (same key + same message = same signature), which is required for reliable
// key reconstruction.
package sshagent

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	cryptolib "github.com/ekristen/cryptkey/pkg/crypto"
	"github.com/ekristen/cryptkey/pkg/crypto/hkdfinfo"
	"github.com/ekristen/cryptkey/pkg/provider"
)

const (
	saltLen = 32
	keyLen  = 32
)

// AgentKeyInfo holds metadata about an Ed25519 key in the agent.
type AgentKeyInfo struct {
	Fingerprint string
	Comment     string
}

// ListEd25519Keys connects to the SSH agent and returns Ed25519 keys.
func ListEd25519Keys() ([]AgentKeyInfo, error) {
	ag, conn, err := connectAgent()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	keys, err := ag.List()
	if err != nil {
		return nil, fmt.Errorf("ssh-agent: list keys: %w", err)
	}

	var result []AgentKeyInfo
	for _, k := range keys {
		if k.Type() == ssh.KeyAlgoED25519 {
			result = append(result, AgentKeyInfo{
				Fingerprint: ssh.FingerprintSHA256(k),
				Comment:     k.Comment,
			})
		}
	}
	return result, nil
}

// SSHAgent is the SSH agent provider.
type SSHAgent struct{}

func (s *SSHAgent) Type() string { return "ssh-agent" }
func (s *SSHAgent) Description() string {
	return "Secret derived from SSH agent signing (Ed25519 only)"
}
func (s *SSHAgent) InteractiveDerive() bool { return false }

func (s *SSHAgent) Enroll(ctx context.Context, id string) (*provider.EnrollResult, error) {
	ag, conn, err := connectAgentCtx(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	key, err := selectKey(ctx, ag)
	if err != nil {
		return nil, err
	}

	fingerprint := ssh.FingerprintSHA256(key)

	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("ssh-agent: generate salt: %w", err)
	}

	secret, err := signAndDerive(ag, key, salt, fingerprint)
	if err != nil {
		return nil, err
	}

	return &provider.EnrollResult{
		Secret: secret,
		Params: map[string]string{
			"salt":        hex.EncodeToString(salt),
			"fingerprint": fingerprint,
		},
	}, nil
}

func (s *SSHAgent) Derive(ctx context.Context, params map[string]string) ([]byte, error) {
	saltHex, ok := params["salt"]
	if !ok {
		return nil, errors.New("ssh-agent: missing salt in config")
	}
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return nil, fmt.Errorf("ssh-agent: decode salt: %w", err)
	}

	expectedFP := params["fingerprint"]
	if expectedFP == "" {
		return nil, errors.New("ssh-agent: missing fingerprint in config")
	}

	ag, conn, err := connectAgentCtx(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	key, err := findKeyByFingerprint(ag, expectedFP)
	if err != nil {
		return nil, err
	}

	return signAndDerive(ag, key, salt, expectedFP)
}

// connectAgent connects to the SSH agent via SSH_AUTH_SOCK.
func connectAgent() (agent.ExtendedAgent, net.Conn, error) {
	return connectAgentCtx(context.Background())
}

// connectAgentCtx connects to the SSH agent via SSH_AUTH_SOCK using the provided context.
// Callers must close the returned net.Conn when done.
func connectAgentCtx(ctx context.Context) (agent.ExtendedAgent, net.Conn, error) {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return nil, nil, errors.New("ssh-agent: SSH_AUTH_SOCK not set")
	}

	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", sock)
	if err != nil {
		return nil, nil, fmt.Errorf("ssh-agent: connect to agent: %w", err)
	}

	return agent.NewClient(conn), conn, nil
}

// selectKey lets the user choose an Ed25519 key from the agent during enrollment.
// Checks context for a pre-selected fingerprint (TUI path) first.
func selectKey(ctx context.Context, ag agent.ExtendedAgent) (ssh.PublicKey, error) {
	// Check context for pre-selected key (TUI path)
	if v := ctx.Value(provider.CtxSSHAgentKeyFingerprint); v != nil {
		if fp, ok := v.(string); ok && fp != "" {
			return findKeyByFingerprint(ag, fp)
		}
	}

	keys, err := ag.List()
	if err != nil {
		return nil, fmt.Errorf("ssh-agent: list keys: %w", err)
	}

	// Filter to Ed25519 keys only
	var ed25519Keys []*agent.Key
	for _, k := range keys {
		if k.Type() == ssh.KeyAlgoED25519 {
			ed25519Keys = append(ed25519Keys, k)
		}
	}

	if len(ed25519Keys) == 0 {
		return nil, errors.New("ssh-agent: no Ed25519 keys found in agent")
	}

	fmt.Fprintln(os.Stderr, "Ed25519 keys in agent:")
	for i, k := range ed25519Keys {
		fmt.Fprintf(os.Stderr, "  [%d] %s %s\n", i+1, ssh.FingerprintSHA256(k), k.Comment)
	}

	reader := bufio.NewReader(os.Stdin)
	var choice int
	for {
		fmt.Fprintf(os.Stderr, "Select key [1-%d] (default 1): ", len(ed25519Keys))
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("ssh-agent: read choice: %w", err)
		}
		line = strings.TrimSpace(line)
		if line == "" {
			choice = 1
			break
		}
		n, err := strconv.Atoi(line)
		if err != nil || n < 1 || n > len(ed25519Keys) {
			fmt.Fprintln(os.Stderr, "Invalid choice, try again.")
			continue
		}
		choice = n
		break
	}

	selected := ed25519Keys[choice-1]
	fmt.Fprintf(os.Stderr, "Using: %s %s\n", ssh.FingerprintSHA256(selected), selected.Comment)
	return selected, nil
}

// findKeyByFingerprint looks up a specific key in the agent by its SHA256 fingerprint.
func findKeyByFingerprint(ag agent.ExtendedAgent, fingerprint string) (ssh.PublicKey, error) {
	keys, err := ag.List()
	if err != nil {
		return nil, fmt.Errorf("ssh-agent: list keys: %w", err)
	}

	for _, k := range keys {
		if ssh.FingerprintSHA256(k) == fingerprint {
			if k.Type() != ssh.KeyAlgoED25519 {
				return nil, fmt.Errorf("ssh-agent: key %s is %s, not Ed25519", fingerprint, k.Type())
			}
			return k, nil
		}
	}

	return nil, fmt.Errorf("ssh-agent: key %s not found in agent", fingerprint)
}

// signAndDerive signs a deterministic challenge with the agent and derives a secret.
func signAndDerive(ag agent.ExtendedAgent, key ssh.PublicKey, salt []byte, fingerprint string) ([]byte, error) {
	challenge := buildChallenge(salt, fingerprint)

	if key.Type() != ssh.KeyAlgoED25519 {
		return nil, fmt.Errorf("ssh-agent: expected Ed25519 key, got %s", key.Type())
	}

	sig, err := ag.Sign(key, challenge)
	if err != nil {
		return nil, fmt.Errorf("ssh-agent: sign challenge: %w", err)
	}
	defer cryptolib.WipeBytes(sig.Blob)

	return deriveSecret(sig.Blob, salt)
}

func buildChallenge(salt []byte, fingerprint string) []byte {
	h := sha256.New()
	h.Write(salt)
	h.Write([]byte(fingerprint))
	h.Write([]byte(hkdfinfo.SSHAgentChallenge))
	return h.Sum(nil)
}

func deriveSecret(sigBytes, salt []byte) ([]byte, error) {
	hkdfReader := hkdf.New(sha256.New, sigBytes, salt, []byte(hkdfinfo.ProviderSSHAgent))
	secret := make([]byte, keyLen)
	if _, err := io.ReadFull(hkdfReader, secret); err != nil {
		return nil, fmt.Errorf("ssh-agent: hkdf: %w", err)
	}
	return secret, nil
}

func init() {
	provider.Register(&SSHAgent{})
}
