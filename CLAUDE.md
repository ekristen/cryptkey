# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Cryptkey is a Go CLI tool that uses Shamir's Secret Sharing to recover encryption keys from multiple authentication providers. Users enroll providers (FIDO2 keys, passkeys, recovery codes, passphrases), each producing a 32-byte secret. A random master key is split via Shamir sharing, and each share is encrypted with its provider's secret. Only a threshold of providers is needed to reconstruct the master key.

## PRIMARY INSTRUCTION: Release binaries must be portable (statically linked)

**Any change that affects how release binaries are built must preserve portable, statically-linked output.** Users install cryptkey on machines that do not have `libfido2`, `libcbor`, `libcrypto`, or `libpcsclite` installed. If the binary links against those dynamically, it crashes at startup with a dynamic linker error before any Go code runs — no `Available()` check can catch it.

Rules, in priority order:

1. **Never change `.github/workflows/build.yml` or `Makefile` targets (`build-linux-static`, `build-darwin-static`) in ways that drop the static linkage.** Specifically: do not remove `-extldflags=-static` on Linux, do not switch macOS back to `-L$(brew --prefix libfido2)/lib -lfido2`.
2. **If you add a new CGO dependency, add it to the static build.** The Linux build uses Alpine `.a` packages + source-built `libcbor`; the macOS build uses source-built `libfido2` + `libcbor` + Homebrew `openssl@3`'s `libcrypto.a`. A new CGO dep means updating both.
3. **Every release build must pass `scripts/verify-static.sh <binary>`.** This is wired into `build.yml` and the Makefile static targets. The script checks: ELF binaries are fully static (no dynamic section), Mach-O binaries link only `/usr/lib/` and `/System/Library/` paths (no Homebrew), and the `go-libfido2` + `go-piv` Go packages are compiled in. **Do not weaken or skip this verification.** If it trips on a legitimate change, fix the build, don't disable the check.
4. **Keep the `go-libfido2` fork replace pinned.** `go.mod` replaces `github.com/keys-pub/go-libfido2` with `github.com/ekristen/go-libfido2`. That fork strips the upstream `#cgo` directives that hardcode `/usr/local`, `/opt/homebrew`, and `openssl@1.1` paths. Do not remove the replace directive or switch back to upstream without first re-introducing a patching strategy. If the fork needs updating, update it in the sibling checkout and bump the commit pin here.
5. **`make build` (dev build) stays dynamically linked** for fast iteration. Bare `make` (the default goal) dispatches to `build-linux-static` or `build-darwin-static` based on `uname -s` so the common case produces a portable binary; the dynamic dev build is always available as an explicit `make build`.

See [docs/development/static-builds.md](docs/development/static-builds.md) for the full rationale and the go-libfido2 fork details.

## SECONDARY INSTRUCTION: Secret material flows as []byte, not string

**Every code path that carries plaintext key material must use `[]byte`, not `string`.** Go strings are immutable — `crypto.WipeBytes` cannot zero them, so a string copy of a secret lingers in the heap until GC runs, which is a meaningful forensics window on a compromised host. Every `[]byte` copy we own must be wiped as soon as the secret is no longer needed (typically via `defer crypto.WipeBytes(buf)`).

Rules:

1. **Functions that produce secret material return `[]byte`.** Examples already in the codebase: `crypto.DeriveOutputKey`, `crypto.DecryptShare`, `provider.EnrollResult.Secret`, `keyformat.FormatAge` (identity), `keyformat.FormatEd25519` (privatePEM), `derive.FormatKeyBytes`, `derive.formatStructuredKeyBytes`. Name the field clearly (`identity []byte`, `privatePEM []byte`) so the ownership contract is obvious.
2. **`string` is allowed only for genuinely non-secret values** — age recipients, ssh public-key lines, provider IDs, profile names, HKDF info labels, error messages, log lines, TOML fields that store already-encrypted material (hex nonces, hex salts, base64 ciphertexts).
3. **Callers that receive a secret `[]byte` own its lifetime.** Wipe via `defer crypto.WipeBytes(buf)` at the call site, not "some time later." If you pass the slice onward, the receiver takes over the wipe; document who wipes in the function comment.
4. **`exec.Cmd.Env` is the only documented exception.** Go's `os/exec` takes `Env []string`, so the env delivery path in `pkg/commands/derive` unavoidably materializes the secret as a Go string. Any function using this path must be documented as "env path — string is unavoidable" in its comment, and users must be told (via docs) that stdin delivery is preferred. Do not add new string-typed secret paths for any other reason.
5. **When an external API returns a string holding a secret (e.g. PEM encoders), convert to `[]byte` at the call site and wipe the intermediate if practical.** See `formatStructuredKeyBytes` for the pattern.

See `pkg/crypto/envelope.go`, `pkg/provider/passphrase/passphrase.go`, and `pkg/crypto/keyformat/keyformat.go` for reference implementations of the discipline.

## Build Commands

```bash
make                      # Default: portable static binary for the current OS
make build                # Dev build, dynamic linking (fast iteration)
make build-linux-static   # Portable Linux binary (Alpine Docker, musl, fully static)
make build-darwin-static  # Portable macOS binary (source-built libfido2/libcbor + openssl@3 .a)
make verify-static BIN=bin/cryptkey-linux-static   # Run the portability check on any binary
make test                 # Run all Go tests
make docs-serve           # Serve docs locally with Docker
```

Run a single test:
```bash
go test ./pkg/crypto/shamir/... -run TestSplitCombine
```

Build tags: `dynamic` is a go-libfido2 build tag used by both the dev and macOS static builds; it selects the `fido2_dynamic.go` file, which in our fork is a stub that expects `CGO_CFLAGS` / `CGO_LDFLAGS` to provide actual paths.

## Architecture

### Data Flow

**Enrollment (`init`):** Select providers → each generates 32-byte secret → generate random master key → Shamir split → encrypt each share with provider's secret (HKDF→AES-256-GCM) → compute integrity HMAC → save TOML profile.

**Reconstruction (`derive`):** Load profile → each provider re-derives its secret → decrypt share → Shamir combine when threshold met → verify HMAC → HKDF derive output key.

### Key Packages

- **`pkg/provider/`** — Provider registry and `Provider` interface (`Type`, `Description`, `Enroll`, `Derive`). Implementations: fido2, passkey, passphrase, recovery, sshkey, sshagent, tpm.
- **`pkg/crypto/`** — `envelope.go` (AES-256-GCM, HKDF, config HMAC), `shamir/` (secret sharing over GF(256)).
- **`pkg/config/`** — TOML profile I/O at `~/.config/cryptkey/<name>.toml`. Profiles contain encrypted shares, nonces, salts, provider metadata, and an integrity HMAC.
- **`pkg/commands/`** — CLI commands: `init`, `derive`, `list`, `info`.
- **`pkg/enrollment/`** — Shared enrollment logic (collect secrets, build profile, recovery warnings).
- **`pkg/tui/`** — Bubbletea-based terminal UI with state machine for interactive enrollment.
- **`pkg/common/`** — Global command registration, versioning, logging setup.

### Patterns

- **Registry pattern:** Providers and commands self-register via `init()` functions. Main imports them with `_` for side effects.
- **Strategy pattern:** Provider interface swapped at enrollment/derivation time.
- **Secure wiping:** Secrets flow as `[]byte` and are explicitly zeroed via `crypto.WipeBytes` after use — see the `[]byte, not string` rule under SECONDARY INSTRUCTION above.
- **Context-based secrets:** TUI mode pre-collects provider secrets into context before enrollment.

### CLI Structure

```
cryptkey init [profile] [--threshold N] [--no-tui] [--add type:id] [--force] [--fido2-uv MODE] [--argon-time N] [--argon-memory N] [--argon-threads N]
cryptkey derive [profile] [--raw] [--base64] [--use LABEL] [--env VAR] [--provider TYPE] [--skip TYPE] [--quiet] [--timeout DURATION] [-- <command>]
cryptkey rekey [profile] [--threshold N] [--keep TYPE:ID] [--remove TYPE:ID] [--add TYPE:ID] [--no-tui] [--no-backup]
cryptkey list
cryptkey info [profile]
```

`rekey` rebuilds the Shamir share set for an existing profile under a new (n', t') and provider list while preserving the master key and `output_salt` — so output keys derived from the profile (age identities, ed25519 keys, etc.) stay valid. Every kept provider must unlock during rekey because a fresh polynomial means every share value changes.

## Dependencies

- CLI: `urfave/cli/v3`
- TUI: `bubbletea/v2`, `bubbles/v2`, `lipgloss/v2`
- Crypto: `golang.org/x/crypto` (HKDF, Argon2), go-libfido2 (CGO, optional)
- Config: `BurntSushi/toml`
- Testing: `stretchr/testify`
- Linting: golangci-lint (see `.golangci.yml` for enabled linters)
