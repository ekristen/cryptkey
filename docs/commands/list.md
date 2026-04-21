# cryptkey list

List all available profiles.

## Usage

```bash
cryptkey list
```

## Output

Prints one profile name per line, sorted alphabetically:

```
default
production
vault
```

If no profiles exist, prints `No profiles found.`

## Notes

- Profiles are discovered by scanning the config directory (`~/.config/cryptkey/`) for `.toml` files
- Use `--config-dir` to list profiles in a non-default directory
