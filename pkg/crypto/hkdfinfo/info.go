// Package hkdfinfo is the central registry of HKDF info strings used
// throughout cryptkey. Every domain that derives keys via HKDF MUST use
// a distinct info string so that keys derived in one domain cannot be
// confused with keys derived in another, even when sharing input key
// material.
//
// When adding a new provider or crypto operation that performs key
// derivation, add a new constant here and reference it — do not inline
// a string literal at the call site, and never reuse an existing
// constant for a new purpose. The constant values are part of cryptkey's
// on-disk compatibility surface: changing a value invalidates every
// profile that was enrolled with the old value.
package hkdfinfo

const (
	// ConfigIntegrity is the HKDF info for the HMAC key that protects
	// the profile TOML's integrity digest. Used by crypto.ConfigHMAC.
	ConfigIntegrity = "cryptkey-config-integrity"

	// ShareEncryption is the HKDF info for the AES-256-GCM key that
	// protects each Shamir share. Used by crypto.EncryptShare and
	// crypto.DecryptShare.
	ShareEncryption = "cryptkey-share-encryption"

	// OutputKeyPrefix is prepended to the --use label to form the HKDF
	// info for the user-visible output key. The full info is
	// "cryptkey:" + label (e.g. "cryptkey:default", "cryptkey:disk").
	OutputKeyPrefix = "cryptkey:"
)

// Per-provider secret derivation. Each provider runs its raw material
// through HKDF with these info strings to isolate providers from one
// another, so the same input material can never yield the same secret
// across two different provider types.
const (
	ProviderPIV      = "cryptkey-piv-provider"
	ProviderTPM      = "cryptkey-tpm-provider"
	ProviderSSHAgent = "cryptkey-sshagent-provider"
	ProviderSSHKey   = "cryptkey-ssh-provider"
)

// Domain-specific info strings used inside a provider's own derivation
// chain, independent of the provider-isolation HKDF above.
const (
	// PIVECDHScalar binds the ECDH scalar derivation inside the PIV
	// provider so the scalar is specific to this tool rather than
	// reusable elsewhere.
	PIVECDHScalar = "cryptkey-piv-ecdh-scalar"

	// TPMChallenge binds the challenge value fed into the TPM so the
	// TPM's resulting HMAC is specific to this tool.
	TPMChallenge = "cryptkey-tpm-challenge"

	// SSHAgentChallenge binds the challenge the SSH agent signs so its
	// signature is specific to this tool.
	SSHAgentChallenge = "cryptkey-sshagent-challenge"
)
