# Passphrase Provider

The passphrase provider derives a 32-byte secret from a user-memorized passphrase using Argon2id.

**Type:** `passphrase`

## How It Works

### Enrollment

1. The user enters a passphrase (terminal echo suppressed).
2. The passphrase is confirmed by entering it a second time.
3. The passphrase is scored with [zxcvbn](#strength-feedback); if weak, the user is asked to confirm before proceeding (no hard block).
4. A random 32-byte salt is generated.
5. Argon2id stretches the passphrase into a 32-byte secret.
6. The salt and Argon2id parameters are stored in the profile; the passphrase bytes are wiped from memory.

### Derivation

1. The user re-enters the passphrase.
2. The stored salt and Argon2id parameters are loaded from the profile.
3. Argon2id reproduces the same 32-byte secret.
4. The passphrase bytes are wiped from memory.

## Usage

```bash
# Interactive TUI
cryptkey init
# Select "passphrase" from the menu

# Non-interactive
cryptkey init --add passphrase:primary --add passphrase:backup
```

## Strength feedback

Cryptkey uses [nbutton23/zxcvbn-go](https://github.com/nbutton23/zxcvbn-go) — a Go port of Dropbox's [zxcvbn](https://github.com/dropbox/zxcvbn) — to estimate passphrase strength during enrollment. zxcvbn is a dictionary- and pattern-aware scorer that catches common failure modes (leaked passwords, keyboard walks, repeated characters, dates, l33t-speak substitutions) that simple length-based heuristics miss. The check runs entirely offline, with no network calls.

Scores are on zxcvbn's 0–4 scale:

| Score | Label | Rough guessability |
|-------|---------------|-----------------------|
| 0     | weak          | < 10³ guesses (instant) |
| 1     | weak          | < 10⁶ guesses |
| 2     | fair          | < 10⁸ guesses |
| 3     | strong        | < 10¹⁰ guesses |
| 4     | very strong   | ≥ 10¹⁰ guesses |

Cryptkey's warn threshold is **3** — anything at "strong" or above passes silently; anything below triggers an explicit confirmation step. Argon2id stretching already puts a 1–2 second cost on top of each zxcvbn guess, so a "fair" passphrase is expensive to attack in practice — the warning exists so a user making a throwaway test profile isn't surprised when the profile leaks and a determined attacker on rented hardware eventually wins.

### What you see

**In the TUI**, an inline strength label is rendered next to the prompt as you type. Empty input shows nothing; once you start typing, the label is red for weak/fair and green for strong/very strong. After you confirm the passphrase, if the score was below threshold, cryptkey shows a warn screen explaining the risk and asks `[y/N]` before proceeding.

**In `--no-tui` / plain-CLI enrollment**, after both entries match, cryptkey prints a single-line summary to stderr:

```
Passphrase strength: strong (~centuries to crack offline)
```

If the passphrase is weak, the summary is followed by a warning and a `[y/N]` prompt on `/dev/tty`. Anything other than `y` rejects the enrollment — you retry with a stronger passphrase.

### No hard block

Cryptkey won't refuse a weak passphrase outright. Using a deliberately weak "something you have" passphrase as *one* of N providers under a 2-of-N threshold is a legitimate configuration — the weak passphrase alone can't reconstruct the key because the threshold forces combining it with something stronger. The warning just surfaces the trade-off.

## Stored Parameters

| Parameter | Description |
|-----------|-------------|
| `salt` | Hex-encoded 32-byte Argon2id salt |
| `argon_time` | Argon2id iterations used at enrollment |
| `argon_memory` | Argon2id memory (KiB) used at enrollment |
| `argon_threads` | Argon2id parallelism used at enrollment |

## Argon2id Parameters

Defaults are hardened for long-term disk-at-rest protection:

| Parameter | Default | Purpose |
|-----------|---------|---------|
| Time | 3 iterations | Computational cost |
| Memory | 256 MiB (262 144 KiB) | Memory hardness (resists GPU attacks) |
| Threads | 4 | Parallelism |
| Key length | 32 bytes | Output size |

On a modern laptop this takes roughly 500 ms — imperceptible during `derive`. If you need faster unlocks (or you're targeting a lower-powered device) you can dial the cost down at enrollment time:

```bash
cryptkey init --argon-memory 19456 --argon-time 2 --argon-threads 1 \
  --add passphrase:primary --add passphrase:backup
```

(`--argon-memory` is in KiB: `19456 KiB = 19 MiB` — OWASP's recommended minimum — and `262144 KiB = 256 MiB`.)

Parameters are stored per-provider in the profile, so derivation always uses the same settings that were used at enrollment. Profiles written before parameters were stored fall back to `t=3, m=64 MiB, p=4` during derive. Cryptkey enforces the OWASP minimum (`t=2, m=19 MiB, p=1`) as a floor at derive time so a tampered profile can't weaken key derivation to trivial costs.

## Security Notes

- Use a strong passphrase — Argon2id protects against brute force but can't save a weak passphrase that is also not mixed with a stronger provider.
- Use different passphrases for each passphrase provider in the same profile.
- The passphrase is never stored — only the Argon2id salt and parameters.
- Terminal echo is suppressed during input (TUI and raw-mode CLI both).
- Passphrase bytes are explicitly zeroed after Argon2id consumes them, both in the provider and in the TUI components that captured them.

## Tips

- You can enroll multiple passphrase providers in the same profile with different IDs.
- Passphrases are the simplest "offline" provider — no hardware, no network, no browser.
- Consider pairing with a recovery code for a fully offline profile.
- A four-word diceware-style passphrase ("correct-horse-battery-staple") easily clears the zxcvbn threshold and is easier to remember than a random-character string of equivalent entropy.
