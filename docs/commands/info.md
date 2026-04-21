# cryptkey info

Show details about a profile without deriving any keys.

## Usage

```bash
cryptkey info [profile]
```

If `profile` is omitted, cryptkey uses `default`.

## Output

```
Profile:   vault
Threshold: 2 of 3

TYPE        ID
----        --
passkey     passkey-1
fido2       fido2-1
passphrase  passphrase-1
```

## What It Shows

- **Profile name** as stored in the config file
- **Threshold** — how many providers are needed, out of how many are enrolled
- **Provider table** — the type and ID of each enrolled provider

## Notes

- This command is read-only and does not require any authentication
- No secrets or encrypted data are displayed
- Use this to check what providers are enrolled before running `derive`
