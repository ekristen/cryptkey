# Recovery Code Provider

The recovery code provider generates a high-entropy code during enrollment, displays it once, and derives a 32-byte secret from it via Argon2id. The code is never stored — you must write it down.

**Type:** `recovery`

## How It Works

### Enrollment

1. A random 42-character recovery code is generated
2. The code is displayed in a prominent box — **this is the only time it is shown**
3. A random 32-byte salt is generated
4. Argon2id stretches the code into a 32-byte secret
5. The salt and Argon2id parameters are stored in the profile; the code is wiped from memory

### Derivation

1. The user enters their recovery code
2. The code is normalized (stripped of dashes/spaces, uppercased)
3. The stored salt is loaded from the profile
4. Argon2id reproduces the same 32-byte secret

## Usage

```bash
# Interactive TUI
cryptkey init
# Select "recovery" from the menu
# IMPORTANT: write down the displayed code immediately

# Non-interactive
cryptkey init --add recovery:backup --add passphrase:primary
```

## Recovery Code Format

The code is 42 characters from an unambiguous alphabet, displayed in 7 groups of 6:

```
ABCDEF-GHJKMN-PQRSTU-VWXYZ2-345678-9ABCDE-FGHJKM
```

**Alphabet:** A-Z (minus O, I, L) plus 2-9 (minus 0, 1) = 31 characters (23 letters + 8 digits).

This provides approximately **208 bits of entropy** (42 chars × log₂(31) ≈ 208).

Characters that look similar (`0`/`O`, `1`/`I`/`L`) are excluded to reduce transcription errors.

## Stored Parameters

| Parameter | Description |
|-----------|-------------|
| `salt` | Hex-encoded 32-byte Argon2id salt |
| `argon_time` | Argon2id iterations used at enrollment |
| `argon_memory` | Argon2id memory (KiB) used at enrollment |
| `argon_threads` | Argon2id parallelism used at enrollment |

## Security Notes

- The recovery code is shown **once** during enrollment and never stored digitally
- Write it down on paper, print it, or photograph it — store physically
- Do not store the code in a password manager alongside your profile (this defeats the purpose)
- Dashes and spaces are ignored when entering the code; case is insensitive
- The code has ~208 bits of entropy — it cannot be brute-forced even with Argon2id's relatively low parameters

## Tips

- Always include at least one recovery provider in your profile
- Store the code in a physically secure location (safe, safety deposit box)
- Consider making a second copy stored at a different physical location
- The recovery code is your last resort if all hardware is lost and all passphrases are forgotten
