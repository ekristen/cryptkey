// Package config handles reading and writing cryptkey profile files.
//
// Profiles live at ~/.config/cryptkey/<name>.toml and contain only
// encrypted shares, credential IDs, salts, and provider metadata —
// never raw secret material. An HMAC derived from the master key
// protects the config against tampering.
package config

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/ekristen/cryptkey/pkg/crypto"
)

// ProfileVersion is the current profile format version.
const ProfileVersion = 1

// DefaultProfile is the profile name used when the user omits one on the CLI.
const DefaultProfile = "default"

// Profile is the top-level config for one cryptkey identity.
type Profile struct {
	Version    int              `toml:"version"`
	Name       string           `toml:"name"`
	Threshold  int              `toml:"threshold"`
	OutputSalt string           `toml:"output_salt"` // hex-encoded random salt for HKDF output key derivation
	Integrity  string           `toml:"integrity"`   // hex-encoded HMAC-SHA256 of provider data
	Providers  []ProviderConfig `toml:"providers"`
}

// ProviderConfig stores the encrypted share and metadata for one provider.
type ProviderConfig struct {
	Type           string            `toml:"type"`
	ID             string            `toml:"id"`
	EncryptedShare string            `toml:"encrypted_share"` // hex-encoded AES-GCM ciphertext
	Nonce          string            `toml:"nonce"`           // hex-encoded GCM nonce
	ShareSalt      string            `toml:"share_salt"`      // hex-encoded HKDF salt
	Params         map[string]string `toml:"params"`          // provider-specific metadata
}

// EncryptedShareData converts the hex-encoded fields back to an EncryptedShare.
func (pc *ProviderConfig) EncryptedShareData() (*crypto.EncryptedShare, error) {
	ct, err := hex.DecodeString(pc.EncryptedShare)
	if err != nil {
		return nil, fmt.Errorf("config: decode encrypted_share for %q: %w", pc.ID, err)
	}
	nonce, err := hex.DecodeString(pc.Nonce)
	if err != nil {
		return nil, fmt.Errorf("config: decode nonce for %q: %w", pc.ID, err)
	}
	salt, err := hex.DecodeString(pc.ShareSalt)
	if err != nil {
		return nil, fmt.Errorf("config: decode share_salt for %q: %w", pc.ID, err)
	}
	return &crypto.EncryptedShare{
		Ciphertext: ct,
		Nonce:      nonce,
		Salt:       salt,
	}, nil
}

// IntegrityDigest computes a deterministic hash over all provider config data.
// This is the payload that gets HMAC'd with the master key.
func (p *Profile) IntegrityDigest() []byte {
	h := sha256.New()
	fmt.Fprintf(h, "version=%d\n", p.Version)
	fmt.Fprintf(h, "name=%s\n", p.Name)
	fmt.Fprintf(h, "threshold=%d\n", p.Threshold)
	fmt.Fprintf(h, "output_salt=%s\n", p.OutputSalt)
	for _, pc := range p.Providers {
		// Length-prefixed fields prevent field boundary collisions
		fmt.Fprintf(h, "type=%s\n", pc.Type)
		fmt.Fprintf(h, "id=%s\n", pc.ID)
		fmt.Fprintf(h, "encrypted_share=%s\n", pc.EncryptedShare)
		fmt.Fprintf(h, "nonce=%s\n", pc.Nonce)
		fmt.Fprintf(h, "share_salt=%s\n", pc.ShareSalt)
		// Sort param keys for deterministic ordering
		keys := make([]string, 0, len(pc.Params))
		for k := range pc.Params {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(h, "param:%s=%s\n", k, pc.Params[k])
		}
	}
	return h.Sum(nil)
}

// SetIntegrity computes and stores the integrity HMAC using the master key.
func (p *Profile) SetIntegrity(masterKey []byte) error {
	digest := p.IntegrityDigest()
	mac, err := crypto.ConfigHMAC(masterKey, digest)
	if err != nil {
		return err
	}
	p.Integrity = hex.EncodeToString(mac)
	return nil
}

// OutputSaltBytes returns the profile's output_salt as raw bytes.
func (p *Profile) OutputSaltBytes() ([]byte, error) {
	if p.OutputSalt == "" {
		return nil, fmt.Errorf("config: profile %q missing output_salt", p.Name)
	}
	return hex.DecodeString(p.OutputSalt)
}

// VerifyIntegrity checks the stored HMAC against the master key.
func (p *Profile) VerifyIntegrity(masterKey []byte) (bool, error) {
	if p.Integrity == "" {
		return false, fmt.Errorf("config: profile %q has no integrity HMAC", p.Name)
	}
	expected, err := hex.DecodeString(p.Integrity)
	if err != nil {
		return false, fmt.Errorf("config: decode integrity HMAC: %w", err)
	}
	digest := p.IntegrityDigest()
	return crypto.VerifyConfigHMAC(masterKey, digest, expected)
}

// CustomDir allows overriding the default config directory.
// When empty, Dir() falls back to ~/.config/cryptkey.
var CustomDir string

// Dir returns the cryptkey config directory.
// If CustomDir is set (via --config-dir or CRYPTKEY_CONFIG_DIR), it is used directly.
// Otherwise defaults to ~/.config/cryptkey.
func Dir() (string, error) {
	if CustomDir != "" {
		return CustomDir, nil
	}
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("config: user config dir: %w", err)
	}
	return filepath.Join(configDir, "cryptkey"), nil
}

// Path returns the full path for a named profile.
func Path(name string) (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, name+".toml")
	if !strings.HasPrefix(filepath.Clean(path), filepath.Clean(dir)+string(os.PathSeparator)) {
		return "", fmt.Errorf("config: invalid profile name %q", name)
	}
	return path, nil
}

// Load reads and decodes a profile from disk.
func Load(name string) (*Profile, error) {
	path, err := Path(name)
	if err != nil {
		return nil, err
	}

	var p Profile
	if _, err := toml.DecodeFile(path, &p); err != nil {
		return nil, fmt.Errorf("config: load %q: %w", name, err)
	}

	if len(p.Providers) < 2 {
		return nil, fmt.Errorf("config: profile %q has fewer than 2 providers", name)
	}

	return &p, nil
}

// Save writes a profile to disk atomically, creating the config directory
// if needed. It writes to a temporary file, fsyncs, and renames to prevent
// corruption from interrupted writes (crash, power loss, SIGKILL).
func Save(p *Profile) error {
	path, err := Path(p.Name)
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("config: create dir: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".cryptkey-*.tmp")
	if err != nil {
		return fmt.Errorf("config: create temp file: %w", err)
	}
	tmpPath := tmp.Name()

	// Clean up the temp file on any failure path
	success := false
	defer func() {
		if !success {
			tmp.Close()
			os.Remove(tmpPath)
		}
	}()

	if err := os.Chmod(tmpPath, 0600); err != nil {
		return fmt.Errorf("config: chmod temp file: %w", err)
	}

	enc := toml.NewEncoder(tmp)
	if err := enc.Encode(p); err != nil {
		return fmt.Errorf("config: encode %q: %w", p.Name, err)
	}

	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("config: fsync: %w", err)
	}

	if err := tmp.Close(); err != nil {
		return fmt.Errorf("config: close temp file: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("config: rename to %q: %w", path, err)
	}

	success = true
	return nil
}

// List returns the names of all profiles in the config directory.
func List() ([]string, error) {
	dir, err := Dir()
	if err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("config: read dir: %w", err)
	}

	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(name, ".toml") {
			names = append(names, strings.TrimSuffix(name, ".toml"))
		}
	}
	sort.Strings(names)
	return names, nil
}

// BackupPath returns the path of the rolling backup file for a profile.
func BackupPath(name string) (string, error) {
	p, err := Path(name)
	if err != nil {
		return "", err
	}
	return p + ".bak", nil
}

// Backup copies the existing profile file to <profile>.toml.bak. It overwrites
// any existing backup. Returns the backup path and a no-op restore function
// the caller can defer; calling restore renames the .bak back over the
// profile, useful when a partially-completed rekey needs to be rolled back.
func Backup(name string) (backupPath string, restore func() error, err error) {
	src, err := Path(name)
	if err != nil {
		return "", nil, err
	}
	dst, err := BackupPath(name)
	if err != nil {
		return "", nil, err
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return "", nil, fmt.Errorf("config: read profile for backup: %w", err)
	}
	if err := os.WriteFile(dst, data, 0600); err != nil { //nolint:gosec // dst is constructed via Path() which validates against traversal
		return "", nil, fmt.Errorf("config: write backup: %w", err)
	}
	restore = func() error {
		return os.Rename(dst, src)
	}
	return dst, restore, nil
}

// Exists checks whether a profile config file exists on disk.
func Exists(name string) (bool, error) {
	path, err := Path(name)
	if err != nil {
		return false, err
	}
	_, err = os.Stat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	return err == nil, err
}
