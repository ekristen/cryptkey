// Package piv implements a provider that derives a 32-byte secret from a
// PIV-compatible hardware token (e.g., YubiKey) using the go-piv library.
//
// During enrollment, an ECC P-256 key is generated on the token in the chosen
// slot. A deterministic challenge is signed, and the signature is run through
// HKDF-SHA256 to produce the 32-byte secret. Because the private key never
// leaves the device, the secret is hardware-bound.
//
// Requires: PC/SC (pcscd on Linux, CryptoTokenKit on macOS).
package piv

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	gopiv "github.com/go-piv/piv-go/v2/piv"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/term"

	cryptolib "github.com/ekristen/cryptkey/pkg/crypto"
	"github.com/ekristen/cryptkey/pkg/crypto/hkdfinfo"
	"github.com/ekristen/cryptkey/pkg/provider"
)

const (
	saltLen = 32
	keyLen  = 32

	serialUnknown = "unknown"
)

// wrapPCSCError checks if an error looks like a PC/SC sharing conflict and
// augments it with an actionable hint. The underlying error is preserved via
// %w so the caller can still see what pcsclite actually returned. Returns nil
// if the error doesn't match a known sharing-conflict pattern.
func wrapPCSCError(err error) error {
	if err == nil {
		return nil
	}

	errStr := strings.ToLower(err.Error())
	isSharing := strings.Contains(errStr, "sharing violation")
	isSecurity := strings.Contains(errStr, "security violation")
	if !isSharing && !isSecurity {
		return nil
	}

	var hint string
	switch {
	case scdaemonRunning():
		hint = "piv: smart card reader is in use — gpg-agent's scdaemon is holding the device.\n" +
			"  Run: gpgconf --kill scdaemon\n" +
			"  To prevent this permanently, add \"disable-ccid\" to ~/.gnupg/scdaemon.conf"
	case gpgAgentRunning():
		hint = "piv: smart card reader is in use — gpg-agent is running and may be holding the CCID interface.\n" +
			"  Run: gpgconf --kill gpg-agent   (or: pkill -x gpg-agent)"
	case isSecurity:
		hint = "piv: pcscd denied access — most likely a polkit authorization issue.\n" +
			"  Confirm with: journalctl -u pcscd | grep 'NOT authorized'\n" +
			"  If present, add a rule at /etc/polkit-1/rules.d/99-pcscd.rules allowing\n" +
			"  org.debian.pcsc-lite.access_pcsc (and access_card) for your user/group."
	default:
		hint = "piv: smart card reader is in use by another process.\n" +
			"  Check for other processes using the card (ykman, pivy-tool, another cryptkey instance)."
	}
	return fmt.Errorf("%s\n  underlying error: %w", hint, err)
}

// ListCards wraps gopiv.Cards with actionable error messages for PC/SC conflicts.
func ListCards() ([]string, error) {
	cards, err := gopiv.Cards()
	if err != nil {
		if pcscErr := wrapPCSCError(err); pcscErr != nil {
			return nil, pcscErr
		}
		return nil, fmt.Errorf("piv: detect cards: %w", err)
	}
	return cards, nil
}

// openCard opens a PIV card by name, wrapping PC/SC conflicts with
// actionable error messages.
func openCard(cardName string) (*gopiv.YubiKey, error) {
	yk, err := gopiv.Open(cardName)
	if err != nil {
		if pcscErr := wrapPCSCError(err); pcscErr != nil {
			return nil, pcscErr
		}
		return nil, fmt.Errorf("piv: open card %s: %w", cardName, err)
	}
	return yk, nil
}

// scdaemonRunning checks whether a scdaemon process is currently running.
// Uses pgrep rather than gpg-connect-agent to avoid auto-starting gpg-agent
// (and potentially scdaemon) as a side effect of the check itself.
func scdaemonRunning() bool {
	return pgrepRunning("scdaemon")
}

// gpgAgentRunning checks whether a gpg-agent process is currently running.
// gpg-agent can hold the CCID interface even without a separate scdaemon
// process, so it's worth flagging on its own when diagnosing PC/SC conflicts.
func gpgAgentRunning() bool {
	return pgrepRunning("gpg-agent")
}

// pgrepRunning returns true if `pgrep -x name` matches a running process.
// A 2s timeout keeps the check from hanging diagnostics.
func pgrepRunning(name string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "pgrep", "-x", name).Run() == nil
}

// CardSerial opens a card by name and returns its serial number as a string.
// Returns "unknown" if the serial cannot be read.
func CardSerial(cardName string) string {
	yk, err := openCard(cardName)
	if err != nil {
		return serialUnknown
	}
	defer yk.Close()
	s, err := yk.Serial()
	if err != nil {
		return serialUnknown
	}
	return strconv.FormatUint(uint64(s), 10)
}

// PIV is the PIV smart card provider.
type PIV struct{}

func (p *PIV) Type() string                 { return "piv" }
func (p *PIV) Description() string          { return "PIV smart card / YubiKey (hardware-bound)" }
func (p *PIV) InteractiveDerive() bool      { return true }
func (p *PIV) DeriveTimeout() time.Duration { return 30 * time.Second }

// PreDerive collects the PIV PIN before the timeout-wrapped ECDH operation.
func (p *PIV) PreDerive(ctx context.Context, _ map[string]string) (context.Context, error) {
	if ctx.Value(provider.CtxPIVPIN) != nil {
		return ctx, nil
	}

	pin, err := collectPIN(ctx)
	if err != nil {
		return ctx, err
	}
	// Always seed the context, even for an empty PIN — the user pressing Enter
	// for the default PIN is a deliberate answer. Otherwise Derive() re-prompts.
	ctx = context.WithValue(ctx, provider.CtxPIVPIN, pin)
	return ctx, nil
}

func (p *PIV) EnrollOptions() []provider.EnrollOption {
	return []provider.EnrollOption{
		{
			Key:         "slot",
			Label:       "PIV Slot",
			Shortcut:    "s",
			Values:      []string{"9d", "9a", "9e", "82", "83", "84", "85"},
			Default:     "9d",
			Description: "Which key slot on the device to use (must support ECDH / KEY_MANAGEMENT_DECIPHER)",
			ValueHelp: map[string]string{
				"9d": "Key Management — recommended for cryptkey, designed for key agreement",
				"9a": "Authentication — commonly used for SSH, VPN, and PIV login",
				"9e": "Card Authentication — low-security contactless operations, no PIN on some devices",
				"82": "Retired slot — available for any use, no standard purpose",
				"83": "Retired slot — available for any use, no standard purpose",
				"84": "Retired slot — available for any use, no standard purpose",
				"85": "Retired slot — available for any use, no standard purpose",
			},
		},
		{
			Key:         "touch_policy",
			Label:       "Touch Policy",
			Shortcut:    "t",
			Values:      []string{"never", "always", "cached"},
			Default:     "never",
			Description: "Whether physical touch is required when using this key",
			ValueHelp: map[string]string{
				"never":  "No touch required — key operations happen silently with just a PIN",
				"always": "Touch required every time — physical presence proof for each derive",
				"cached": "Touch cached for 15 seconds — touch once, then reuse briefly",
			},
		},
		{
			Key:         "mode",
			Label:       "Key Material",
			Shortcut:    "m",
			Values:      []string{"use-existing", "overwrite"},
			Default:     "use-existing",
			Description: "Whether to reuse an existing slot key or generate a fresh one",
			ValueHelp: map[string]string{
				"use-existing": "Use the existing key in this slot if present, otherwise generate a new one",
				"overwrite":    "Always generate a new key — if the slot already has key material, require typed confirmation before destroying it",
			},
		},
	}
}

//nolint:gocyclo,funlen // sequential enrollment flow with clear error handling
func (p *PIV) Enroll(ctx context.Context, id string) (*provider.EnrollResult, error) {
	silent := ctx.Value(provider.CtxSilent) != nil
	progress := provider.GetProgressFunc(ctx)

	if !silent {
		fmt.Fprintf(os.Stderr, "Enrolling PIV provider %q\n", id)
	}

	cards, err := ListCards()
	if err != nil {
		return nil, err
	}
	if len(cards) == 0 {
		return nil, errors.New("piv: no PIV-compatible cards detected — insert a YubiKey or smart card and try again")
	}

	cardName, err := pickCard(ctx, cards)
	if err != nil {
		return nil, err
	}

	yk, err := openCard(cardName)
	if err != nil {
		return nil, err
	}
	defer yk.Close()

	serial, err := yk.Serial()
	if err != nil {
		// Some cards don't support serial — use 0
		serial = 0
	}

	slot, err := parseSlot(getSlotPreference(ctx))
	if err != nil {
		return nil, err
	}

	touchPolicy := getTouchPreference(ctx)
	pivTouch := parseTouchPolicy(touchPolicy)

	pin, err := collectPIN(ctx)
	if err != nil {
		return nil, err
	}
	if pin == "" {
		pin = gopiv.DefaultPIN
	}

	// Check if the slot already has key material. Use the Yubico GET METADATA
	// extension (exposed as KeyInfo) as the authoritative source — this is
	// what `ykman piv info` reads, so cryptkey and ykman will always agree on
	// slot occupancy. Attest is avoided because it can report key material
	// in cases where no user key actually exists.
	var ecPub *ecdsa.PublicKey
	existingKey := false

	ki, kiErr := yk.KeyInfo(slot)
	if kiErr == nil && ki.PublicKey != nil {
		existingKey = true
		var ok bool
		ecPub, ok = ki.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("piv: existing key in slot %s is not ECDSA (got %T) — cannot reuse", slotHex(slot), ki.PublicKey)
		}
		if ecPub.Curve != elliptic.P256() {
			return nil, fmt.Errorf("piv: existing key in slot %s is not P-256 — cannot reuse", slotHex(slot))
		}
	}

	mode := getModePreference(ctx)
	if existingKey {
		switch mode {
		case "overwrite":
			// Overwrite was selected. In CLI mode, require an on-tty typed
			// confirmation unless the caller (e.g. TUI) has already set
			// CtxPIVOverwrite to signal the user has confirmed.
			confirmed, _ := ctx.Value(provider.CtxPIVOverwrite).(bool)
			if !confirmed {
				ok, err := confirmOverwriteOnTTY(slotHex(slot), silent)
				if err != nil {
					return nil, err
				}
				confirmed = ok
			}
			if !confirmed {
				return nil, fmt.Errorf("piv: slot %s already contains key material — overwrite was not confirmed", slotHex(slot))
			}
			existingKey = false
			ecPub = nil
		default: // "use-existing"
			msg := fmt.Sprintf("Using existing key in slot %s", slotHex(slot))
			progress(msg)
			if !silent {
				fmt.Fprintln(os.Stderr, msg)
			}
		}
	}

	if !existingKey {
		progress("Generating key on PIV device...")
		if !silent {
			fmt.Fprintln(os.Stderr, "Generating ECC P-256 key on device...")
		}

		key := gopiv.Key{
			Algorithm:   gopiv.AlgorithmEC256,
			PINPolicy:   gopiv.PINPolicyOnce,
			TouchPolicy: pivTouch,
		}

		pub, err := yk.GenerateKey(gopiv.DefaultManagementKey, slot, key)
		if err != nil {
			return nil, fmt.Errorf("piv: generate key in slot %s: %w", slotHex(slot), err)
		}

		var ok bool
		ecPub, ok = pub.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("piv: expected ECDSA public key, got %T", pub)
		}
	}

	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("piv: generate salt: %w", err)
	}

	// Derive a peer ECDH public key from the salt. Running ECDH between the
	// on-device private key and this peer gives us a deterministic shared
	// secret — scalar multiplication has no nonce, so the output is the same
	// on every derive regardless of firmware. (ECDSA signing cannot be used
	// here: YubiKey 5.7+ firmware uses random nonces for side-channel
	// resistance, so signatures are not byte-stable across calls.)
	peerPub, peerScalar, err := peerPubForSalt(salt)
	if err != nil {
		return nil, fmt.Errorf("piv: derive peer key: %w", err)
	}

	if touchPolicy == "always" || touchPolicy == "cached" {
		msg := "Touch your PIV device to perform ECDH key agreement..."
		progress(msg)
		if !silent {
			fmt.Fprintln(os.Stderr, msg)
		}
	}

	auth := gopiv.KeyAuth{PIN: pin}
	priv, err := yk.PrivateKey(slot, ecPub, auth)
	if err != nil {
		return nil, fmt.Errorf("piv: get private key handle: %w", err)
	}

	ecdhPriv, ok := priv.(*gopiv.ECDSAPrivateKey)
	if !ok {
		return nil, fmt.Errorf("piv: private key is not ECDSA (got %T) — cryptkey requires an ECDSA P-256 slot", priv)
	}

	shared, err := ecdhPriv.SharedKey(peerPub)
	if err != nil {
		return nil, fmt.Errorf("piv: ECDH failed (slot %s may not support KEY_MANAGEMENT_DECIPHER — try slot 9d): %w", slotHex(slot), err)
	}
	defer cryptolib.WipeBytes(shared)

	// Verify the card performed ECDH correctly by locally computing
	//   expected_x = (peer_scalar * slot_pub).X
	// which, by commutativity of scalar multiplication, must equal
	//   (slot_priv * peer_pub).X — the card's output. If these differ the
	// slot is producing garbage and the derivation would be irrecoverable.
	expX, _ := elliptic.P256().ScalarMult(ecPub.X, ecPub.Y, peerScalar.Bytes()) //nolint:staticcheck // ScalarMult is fine for verification
	expected := padLeftZero(expX.Bytes(), 32)
	if !bytes.Equal(shared, expected) {
		return nil, fmt.Errorf("piv: card ECDH output does not match expected value — slot %s key is unusable", slotHex(slot))
	}

	secret, err := deriveSecret(shared, salt)
	if err != nil {
		return nil, err
	}

	// Encode public key for storage (uncompressed point)
	pubBytes := elliptic.Marshal(ecPub.Curve, ecPub.X, ecPub.Y) //nolint:staticcheck // Marshal is fine for storage

	progress("PIV key created and bound to device")

	return &provider.EnrollResult{
		Secret: secret,
		Params: map[string]string{
			"salt":         hex.EncodeToString(salt),
			"slot":         slotHex(slot),
			"serial":       strconv.FormatUint(uint64(serial), 10),
			"public_key":   hex.EncodeToString(pubBytes),
			"card_name":    cardName,
			"touch_policy": touchPolicy,
		},
	}, nil
}

// pivDeriveParams bundles the decoded fields Derive reads from the profile.
type pivDeriveParams struct {
	salt  []byte
	slot  gopiv.Slot
	ecPub *ecdsa.PublicKey
}

func parsePIVDeriveParams(params map[string]string) (*pivDeriveParams, error) {
	saltHex, ok := params["salt"]
	if !ok {
		return nil, errors.New("piv: missing salt in config")
	}
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return nil, fmt.Errorf("piv: decode salt: %w", err)
	}
	slotHexStr := params["slot"]
	if slotHexStr == "" {
		return nil, errors.New("piv: missing slot in config")
	}
	slot, err := parseSlot(slotHexStr)
	if err != nil {
		return nil, err
	}
	pubKeyHex := params["public_key"]
	if pubKeyHex == "" {
		return nil, errors.New("piv: missing public_key in config")
	}
	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return nil, fmt.Errorf("piv: decode public_key: %w", err)
	}
	ecPub, err := unmarshalECPublicKey(pubKeyBytes)
	if err != nil {
		return nil, err
	}
	return &pivDeriveParams{salt: salt, slot: slot, ecPub: ecPub}, nil
}

func (p *PIV) Derive(ctx context.Context, params map[string]string) ([]byte, error) {
	dp, err := parsePIVDeriveParams(params)
	if err != nil {
		return nil, err
	}

	pin, err := collectPIN(ctx)
	if err != nil {
		return nil, err
	}
	if pin == "" {
		pin = gopiv.DefaultPIN
	}

	cards, err := ListCards()
	if err != nil {
		return nil, err
	}
	if len(cards) == 0 {
		return nil, errors.New("piv: no PIV-compatible cards detected")
	}

	peerPub, _, err := peerPubForSalt(dp.salt)
	if err != nil {
		return nil, fmt.Errorf("piv: derive peer key: %w", err)
	}

	// Surface the touch prompt to whatever UI is hooked up — PIV cards
	// with touch_policy != "never" block the PrivateKey/SharedKey call
	// below until the user taps. Without this the TUI's progress
	// checklist sits empty showing "Working..." while the user wonders
	// what's happening.
	progress := provider.GetProgressFunc(ctx)
	cardName := params["card_name"]
	if cardName == "" {
		cardName = "PIV card"
	}
	if params["touch_policy"] == "never" {
		progress(fmt.Sprintf("Deriving with %s...", cardName))
	} else {
		progress(fmt.Sprintf("Touch your %s to derive secret...", cardName))
	}

	return tryDeriveOnCards(cards, params["serial"], dp, pin, peerPub)
}

// tryDeriveOnCards iterates over detected cards looking for the one whose
// serial matches expectedSerial (or any card if expectedSerial is empty/0),
// runs ECDH against the stored public key, and returns the derived secret.
func tryDeriveOnCards(
	cards []string,
	expectedSerial string,
	dp *pivDeriveParams,
	pin string,
	peerPub *ecdsa.PublicKey,
) ([]byte, error) {
	var lastErr error
	for _, cardName := range cards {
		yk, err := openCard(cardName)
		if err != nil {
			lastErr = err
			continue
		}

		if expectedSerial != "" && expectedSerial != "0" {
			if serial, err := yk.Serial(); err == nil {
				if strconv.FormatUint(uint64(serial), 10) != expectedSerial {
					yk.Close()
					continue
				}
			}
		}

		auth := gopiv.KeyAuth{PIN: pin}
		priv, err := yk.PrivateKey(dp.slot, dp.ecPub, auth)
		if err != nil {
			yk.Close()
			lastErr = err
			continue
		}

		ecdhPriv, ok := priv.(*gopiv.ECDSAPrivateKey)
		if !ok {
			yk.Close()
			lastErr = errors.New("private key is not ECDSA")
			continue
		}

		shared, err := ecdhPriv.SharedKey(peerPub)
		yk.Close()
		if err != nil {
			lastErr = err
			continue
		}

		secret, err := deriveSecret(shared, dp.salt)
		cryptolib.WipeBytes(shared)
		if err != nil {
			lastErr = err
			continue
		}

		return secret, nil
	}

	return nil, fmt.Errorf("piv: no card matched: %w", lastErr)
}

// peerPubForSalt derives a deterministic P-256 peer keypair from the salt.
// The scalar is produced via HKDF-SHA256 and clamped into [1, N-1]. Returning
// both the public point and the scalar lets callers verify the card's ECDH
// output by computing (scalar * slot_pub) locally.
func peerPubForSalt(salt []byte) (*ecdsa.PublicKey, *big.Int, error) {
	h := hkdf.New(sha256.New, salt, nil, []byte(hkdfinfo.PIVECDHScalar))
	raw := make([]byte, 64) // 64 bytes → reduce mod-bias after mod(N-1)
	if _, err := io.ReadFull(h, raw); err != nil {
		return nil, nil, fmt.Errorf("piv: hkdf scalar: %w", err)
	}
	curve := elliptic.P256()
	nMinus1 := new(big.Int).Sub(curve.Params().N, big.NewInt(1))
	s := new(big.Int).SetBytes(raw)
	s.Mod(s, nMinus1)
	s.Add(s, big.NewInt(1))                 // s ∈ [1, N-1]
	x, y := curve.ScalarBaseMult(s.Bytes()) //nolint:staticcheck // ScalarBaseMult is still correct for this use
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, s, nil
}

// padLeftZero returns b left-padded with zeros to exactly size bytes.
func padLeftZero(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}

// deriveSecret runs HKDF-SHA256 over the signature to produce a 32-byte secret.
func deriveSecret(sig, salt []byte) ([]byte, error) {
	hkdfReader := hkdf.New(sha256.New, sig, salt, []byte(hkdfinfo.ProviderPIV))
	secret := make([]byte, keyLen)
	if _, err := io.ReadFull(hkdfReader, secret); err != nil {
		return nil, fmt.Errorf("piv: hkdf: %w", err)
	}
	return secret, nil
}

// unmarshalECPublicKey reconstructs an ECDSA P-256 public key from uncompressed point bytes.
func unmarshalECPublicKey(data []byte) (*ecdsa.PublicKey, error) {
	x, y := elliptic.Unmarshal(elliptic.P256(), data) //nolint:staticcheck // Unmarshal is fine for stored keys
	if x == nil {
		return nil, errors.New("piv: invalid public key encoding")
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}

// getSlotPreference reads the PIV slot preference from context.
func getSlotPreference(ctx context.Context) string {
	if v := ctx.Value(provider.CtxEnrollOption("slot")); v != nil {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	return "9d"
}

// getTouchPreference reads the PIV touch policy from context.
func getTouchPreference(ctx context.Context) string {
	if v := ctx.Value(provider.CtxEnrollOption("touch_policy")); v != nil {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	return "never"
}

// getModePreference reads the PIV enrollment mode from context.
// Returns "use-existing" (default) or "overwrite".
func getModePreference(ctx context.Context) string {
	if v := ctx.Value(provider.CtxEnrollOption("mode")); v != nil {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	return "use-existing"
}

// confirmOverwriteOnTTY prompts the user on /dev/tty to type the exact phrase
// "confirm overwrite" before destroying existing PIV key material. In silent
// mode (TUI), there is no tty to prompt on — the caller is expected to have
// gated this via its own confirmation and set CtxPIVOverwrite, so silent mode
// returns (false, nil) to let Enroll reject the operation with a clear error.
func confirmOverwriteOnTTY(slotHexStr string, silent bool) (bool, error) {
	if silent {
		return false, nil
	}
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return false, fmt.Errorf("piv: open /dev/tty for overwrite confirmation: %w", err)
	}
	defer tty.Close()

	fmt.Fprintf(tty, "Slot %s already contains key material. Overwriting will permanently destroy it.\n", slotHexStr)
	fmt.Fprint(tty, `Type "confirm overwrite" to proceed: `)

	line, err := bufio.NewReader(tty).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, fmt.Errorf("piv: read overwrite confirmation: %w", err)
	}
	return strings.TrimSpace(line) == "confirm overwrite", nil
}

// parseSlot converts a hex slot string to a piv.Slot.
func parseSlot(hexStr string) (gopiv.Slot, error) {
	hexStr = strings.TrimPrefix(strings.ToLower(hexStr), "0x")
	switch hexStr {
	case "9a":
		return gopiv.SlotAuthentication, nil
	case "9c":
		return gopiv.SlotSignature, nil
	case "9d":
		return gopiv.SlotKeyManagement, nil
	case "9e":
		return gopiv.SlotCardAuthentication, nil
	}

	// Retired key management slots 82-95
	val, err := strconv.ParseUint(hexStr, 16, 8)
	if err != nil {
		return gopiv.Slot{}, fmt.Errorf("piv: invalid slot %q", hexStr)
	}
	if val >= 0x82 && val <= 0x95 {
		slot, ok := gopiv.RetiredKeyManagementSlot(uint32(val))
		if !ok {
			return gopiv.Slot{}, fmt.Errorf("piv: unsupported retired slot 0x%s", hexStr)
		}
		return slot, nil
	}
	return gopiv.Slot{}, fmt.Errorf("piv: unsupported slot 0x%s", hexStr)
}

// slotHex returns the hex representation of a PIV slot.
func slotHex(slot gopiv.Slot) string {
	return fmt.Sprintf("%02x", slot.Key)
}

// parseTouchPolicy converts a string to a piv.TouchPolicy.
func parseTouchPolicy(policy string) gopiv.TouchPolicy {
	switch policy {
	case "always":
		return gopiv.TouchPolicyAlways
	case "cached":
		return gopiv.TouchPolicyCached
	default:
		return gopiv.TouchPolicyNever
	}
}

// SlotHasKey checks if a PIV slot already has key material on the given card.
// Returns the public key if found, nil if empty. Uses the Yubico GET METADATA
// extension (KeyInfo), which is the same source `ykman piv info` reads, so
// cryptkey and ykman agree on slot occupancy.
func SlotHasKey(cardName string, slot gopiv.Slot) (*ecdsa.PublicKey, error) {
	yk, err := openCard(cardName)
	if err != nil {
		return nil, err
	}
	defer yk.Close()

	ki, err := yk.KeyInfo(slot)
	if err != nil {
		// Empty slot (or GET METADATA unsupported) — treat as no key.
		return nil, nil
	}
	if ecPub, ok := ki.PublicKey.(*ecdsa.PublicKey); ok {
		return ecPub, nil
	}
	return nil, nil
}

// collectPIN prompts for the PIV PIN using the standard provider pattern.
func collectPIN(ctx context.Context) (string, error) {
	// Check context for pre-collected PIN (TUI path)
	if v := ctx.Value(provider.CtxPIVPIN); v != nil {
		if pin, ok := v.(string); ok {
			return pin, nil
		}
	}

	// Use progress writer prompt if available (derive path)
	if promptFn, ok := ctx.Value(provider.CtxPromptPassword).(func(string, string, string) (string, error)); ok {
		pin, err := promptFn("piv", "PIN", "esc to skip")
		if err != nil {
			if errors.Is(err, provider.ErrSkipped) {
				return "", provider.ErrSkipped
			}
			return "", fmt.Errorf("piv: %w", err)
		}
		return pin, nil
	}

	// Direct tty fallback (CLI enrollment path)
	return promptPINDirect()
}

// promptPINDirect prompts for PIN directly on /dev/tty.
func promptPINDirect() (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", fmt.Errorf("piv: open /dev/tty: %w", err)
	}
	defer tty.Close()

	fmt.Fprint(tty, "Enter PIV PIN (or press Enter for default 123456): ")
	pass, err := term.ReadPassword(int(tty.Fd())) //nolint:gosec // Fd() fits in int on all supported platforms
	fmt.Fprint(tty, "\r\n")
	if err != nil {
		return "", fmt.Errorf("piv: read PIN: %w", err)
	}
	return string(pass), nil
}

// pickCardBySerial returns the card whose serial matches the given string,
// or an error if no such card is present.
func pickCardBySerial(cards []string, serialStr string) (string, error) {
	for _, c := range cards {
		yk, err := openCard(c)
		if err != nil {
			return "", err
		}
		serial, err := yk.Serial()
		yk.Close()
		if err != nil {
			continue
		}
		if strconv.FormatUint(uint64(serial), 10) == serialStr {
			return c, nil
		}
	}
	return "", fmt.Errorf("piv: card with serial %s not found", serialStr)
}

// promptCardSelection prints the card list to stderr and reads a selection
// from stdin.
func promptCardSelection(cards []string) (string, error) {
	fmt.Fprintln(os.Stderr, "Multiple PIV cards detected:")
	for i, c := range cards {
		serial := serialUnknown
		if yk, err := openCard(c); err == nil {
			if s, err := yk.Serial(); err == nil {
				serial = strconv.FormatUint(uint64(s), 10)
			}
			yk.Close()
		}
		fmt.Fprintf(os.Stderr, "  [%d] %s (serial: %s)\n", i+1, c, serial)
	}
	fmt.Fprint(os.Stderr, "Select card: ")

	var input string
	if _, err := fmt.Scanln(&input); err != nil {
		return "", fmt.Errorf("piv: read selection: %w", err)
	}
	idx, err := strconv.Atoi(strings.TrimSpace(input))
	if err != nil || idx < 1 || idx > len(cards) {
		return "", errors.New("piv: invalid selection")
	}
	return cards[idx-1], nil
}

// pickCard selects a PIV card. Checks context for a pre-selected serial,
// otherwise uses the first card or prompts.
func pickCard(ctx context.Context, cards []string) (string, error) {
	if v := ctx.Value(provider.CtxPIVSerial); v != nil {
		if serialStr, ok := v.(string); ok && serialStr != "" {
			return pickCardBySerial(cards, serialStr)
		}
	}
	if len(cards) == 1 {
		return cards[0], nil
	}
	return promptCardSelection(cards)
}

func init() {
	provider.Register(&PIV{})
}
