# Static Builds

Release binaries of cryptkey are built with all third-party C dependencies
(`libfido2`, `libcbor`, `libcrypto`, `libpcsclite`, `libudev`) statically linked
into the executable. This document explains why that matters, the moving parts
that make it work, and the fork of `keys-pub/go-libfido2` that makes it possible.

If you only want to build a static binary locally, skip to [Commands](#commands).

---

## Why static linking matters

cryptkey is a CGO binary. Go's runtime doesn't care about missing C libraries —
but the dynamic linker does. When a dynamically-linked binary is invoked, the
OS loader resolves every `.so` / `.dylib` dependency *before* any Go code runs.
If `libfido2.so.1` is missing, the process dies with a linker error before the
`main()` function starts. No runtime check, no graceful "FIDO2 unavailable"
degradation — the binary simply won't start.

That would mean users who don't have `libfido2-dev` installed (the majority on
fresh machines) can't run cryptkey at all, even when they're only using the
passphrase or SSH key providers. Static linking embeds the C libraries directly
into the executable so it runs anywhere.

The requirement is a **primary instruction** documented in
[`CLAUDE.md`](https://github.com/ekristen/cryptkey/blob/master/CLAUDE.md).

## The shape of a cryptkey release binary

| Platform       | Linked libraries                                                                      |
| -------------- | ------------------------------------------------------------------------------------- |
| Linux amd64    | Fully static (musl). No dynamic dependencies at all.                                  |
| Linux arm64    | Fully static (musl). No dynamic dependencies at all.                                  |
| macOS amd64    | Third-party libs statically embedded. Only `/usr/lib/` and `/System/Library/` dylibs. |
| macOS arm64    | Third-party libs statically embedded. Only `/usr/lib/` and `/System/Library/` dylibs. |

macOS binaries can never be 100% static — `libSystem`, `CoreFoundation`, and
`IOKit` must link dynamically because Apple doesn't ship static versions of
system libraries. What matters is that no path under `/opt/homebrew/`,
`/usr/local/opt/`, or `/usr/local/Cellar/` ever leaks into the binary.

## Build strategy per platform

### Linux (Alpine + musl)

The Linux build runs inside a `golang:1.25-alpine` Docker container. Alpine is
chosen because it's one of the few distributions that ships static `.a`
archives for the libraries we need (`libfido2-dev`, `openssl-libs-static`,
`pcsc-lite-static`, `eudev-dev`). Ubuntu and Debian ship shared objects only.

`libcbor` is the one exception — Alpine ships only `libcbor.so`, so the build
clones the source and compiles it as a static archive before invoking `go build`.

Linking uses `-ldflags="-s -w -extldflags=-static"`, which tells Go's external
linker to produce a fully static musl executable.

Because GitHub Actions' JavaScript actions (`actions/checkout`, `actions/setup-go`,
`actions/upload-artifact`) can't run inside Alpine containers on ARM64 runners,
the workflow runs natively on Ubuntu and invokes Alpine via `docker run` only
for the compilation step. The runner architecture determines which Alpine image
Docker pulls, so the same workflow produces native amd64 and arm64 binaries.

The build logic lives in
[`scripts/build-linux-static.sh`](https://github.com/ekristen/cryptkey/blob/master/scripts/build-linux-static.sh)
and is invoked both by CI and by `make build-linux-static`, so there's no drift.

### macOS (source-built static libs + Homebrew openssl)

Homebrew's `libfido2` and `libcbor` formulas only install shared libraries, so
the macOS build clones both upstream repositories and compiles them as static
archives into `.static-deps/lib/`. `libcrypto.a` comes from Homebrew's
`openssl@3` formula (OpenSSL's build always produces both shared and static).

The final `CGO_LDFLAGS` passes the `.a` files directly, alongside the required
macOS system frameworks (`CoreFoundation`, `IOKit`):

```
-framework CoreFoundation -framework IOKit
/path/to/libfido2.a /path/to/libcbor.a /path/to/libcrypto.a
```

PC/SC (for the PIV provider) is referenced via `-framework PCSC`, which is a
system framework present on every macOS install, so no third-party dependency
is introduced.

---

## Why PIV is easy and FIDO2 is not

The PIV provider (via [`go-piv/piv-go`](https://pkg.go.dev/github.com/go-piv/piv-go/v2))
and the FIDO2 provider (via `keys-pub/go-libfido2`) both use CGO, but only one
needs a fork. The difference comes down to how each upstream binding
declares its C dependency:

|                          | `go-piv/piv-go`                         | `keys-pub/go-libfido2`                                      |
| ------------------------ | --------------------------------------- | ----------------------------------------------------------- |
| Linux `#cgo` style       | `pkg-config: libpcsclite`               | `-L/usr/lib/x86_64-linux-gnu -lfido2` (hardcoded path)      |
| macOS `#cgo` style       | `-framework PCSC` (system framework)    | Hardcoded `/opt/homebrew/opt/libfido2/lib/libfido2.a` etc.  |
| OpenSSL coupling         | None                                    | References `openssl@1.1` (removed from Homebrew)            |
| Upstream activity        | Actively maintained                     | No releases since 2022                                      |
| Fork required            | No                                      | Yes — three files, two platforms                            |

**PIV on Linux** works because `pkg-config` asks the system where `libpcsclite`
lives. On Alpine with the `pcsc-lite-static` package installed,
`pkg-config --static libpcsclite` returns `-lpcsclite -pthread` and the linker
finds `libpcsclite.a` automatically under `-extldflags=-static`.

**PIV on macOS** works because `-framework PCSC` points at
`/System/Library/Frameworks/PCSC.framework/`, which ships with every macOS
install. Apple owns it; we don't have to. `verify-static.sh` accepts
`/System/Library/` paths as legitimate, which is why the macOS static binary
can still include `PCSC.framework` in its `otool -L` output and pass the check.

If you ever add another CGO provider, this table is the deciding factor. An
upstream that uses `pkg-config` or system frameworks will fold into the static
build with no extra work. An upstream with hardcoded vendor paths will need
something similar to what FIDO2 has — a fork, or an upstream fix.

---

## The go-libfido2 fork

### The problem

[`github.com/keys-pub/go-libfido2`](https://pkg.go.dev/github.com/keys-pub/go-libfido2)
v1.5.3 is the Go binding for `libfido2`. It ships several files with platform-
specific `#cgo` directives that CGO combines at build time:

```text
fido2.go                  — main package, `import "C"`
fido2_dynamic.go          — `// +build dynamic`, darwin-only
fido2_static_amd64.go     — darwin/amd64 static linking
fido2_static_arm64.go     — darwin/arm64 static linking
fido2_other.go            — linux + windows
```

Three of these files — `fido2_dynamic.go`, `fido2_static_amd64.go`, and
`fido2_static_arm64.go` — hardcode paths that no longer resolve on modern
Homebrew:

```c
// fido2_static_arm64.go
#cgo darwin LDFLAGS: -framework CoreFoundation -framework IOKit \
    /opt/homebrew/opt/libfido2/lib/libfido2.a \
    /opt/homebrew/opt/openssl@1.1/lib/libcrypto.a \
    ${SRCDIR}/darwin/arm64/lib/libcbor.a
#cgo darwin CFLAGS: -I/opt/homebrew/opt/libfido2/include \
    -I/opt/homebrew/opt/openssl@1.1/include
```

Two things are broken here:

1. **`openssl@1.1` was removed from Homebrew core in 2023.** The include and
   library paths don't exist. `brew install openssl@1.1` fails.
2. **`libfido2.a` isn't shipped by Homebrew's `libfido2` formula.** The formula
   uses `BUILD_SHARED_LIBS=ON` (the CMake default), producing `libfido2.dylib`
   only.

Worse still, the static files have **no build tag**, so they compile on every
darwin build regardless of whether `-tags dynamic` is set. That means a
build-time `CGO_LDFLAGS` env variable can't override them — CGO appends env
flags after the package's `#cgo` directives, and the linker processes both.

### The fix

We maintain a fork at
[`github.com/ekristen/go-libfido2`](https://github.com/ekristen/go-libfido2)
with the three offending files replaced by minimal stubs:

```go
// +build dynamic

package libfido2
```

```go
package libfido2
```

Each stub keeps the original build constraint (dynamic tag, filename-based
`_amd64`/`_arm64` suffix) but contains no `import "C"` and no `#cgo`
directives. The only `#cgo` flags that remain in the package come from
`fido2.go` (nothing) and from the environment, which the cryptkey build
controls.

cryptkey's `go.mod` pins the fork via a `replace` directive:

```
replace github.com/keys-pub/go-libfido2 => github.com/ekristen/go-libfido2 <commit>
```

The fork's `CLAUDE.md` documents the divergence so it doesn't drift back to
upstream accidentally.

### Updating the fork

If an upstream change needs to be pulled in, or the stripped paths need
adjusting:

1. Work in the sibling `../go-libfido2` checkout.
2. Commit and push.
3. Bump the commit pin in cryptkey with `go mod edit -replace=...@<newcommit>`.
4. Run `go mod tidy` and rebuild the full matrix (`make build`,
   `make build-linux-static`, `make build-darwin-static`).

---

## Verification

Every static build runs
[`scripts/verify-static.sh`](https://github.com/ekristen/cryptkey/blob/master/scripts/verify-static.sh)
against the produced binary. The script performs platform-appropriate checks:

**On ELF binaries (Linux):**

- `file(1)` reports `statically linked`.
- `readelf -d` reports no dynamic section.
- `ldd` reports `not a dynamic executable` (glibc) or `Not a valid dynamic program` (musl).

**On Mach-O binaries (macOS):**

- `otool -L` references only `/usr/lib/` and `/System/Library/` paths.
- No `/opt/homebrew/`, `/usr/local/opt/`, or `/usr/local/Cellar/` paths appear.

**On both:**

- `strings` finds residual Go type names like `*libfido2.User` and `*piv.PIV`,
  proving the `go-libfido2` and `go-piv` packages were compiled in. These
  strings survive `-ldflags="-s -w"` stripping because Go's runtime keeps type
  names for reflection.

A failing verification fails the CI build. Don't weaken or skip it — if a
legitimate change trips the script, fix the build, not the check.

---

## Commands

### Local builds

```bash
make                                                # default goal — dispatches to
                                                    # build-linux-static on Linux or
                                                    # build-darwin-static on macOS
make build                                          # dev build, dynamic linking (fast iteration)
make build-linux-static                             # static Linux binary (Docker + Alpine)
make build-darwin-static                            # static macOS binary (source-built libs)
make verify-static BIN=bin/cryptkey-linux-static    # run the portability check
make clean-static-deps                              # remove .static-deps/
```

Bare `make` produces the portable artifact — the same thing that ships in GitHub releases — so a fresh clone plus `make` gives you a binary you can actually distribute. `make build` is kept for fast iteration during development; it links dynamically against a locally installed `libfido2` and only runs on the machine that built it.

### Scripts

| Script                               | Purpose                                                  |
| ------------------------------------ | -------------------------------------------------------- |
| `scripts/build-linux-static.sh`      | Compile a static Linux binary inside Alpine              |
| `scripts/verify-static.sh`           | Verify a binary has no third-party dynamic dependencies  |

### CI workflows

| Workflow                      | Job             | Purpose                                     |
| ----------------------------- | --------------- | ------------------------------------------- |
| `.github/workflows/build.yml` | `build-linux`   | Static Linux binary (amd64 + arm64)         |
| `.github/workflows/build.yml` | `build-darwin`  | Static macOS binary (amd64 + arm64)         |
| `.github/workflows/tests.yml` | `test`          | Unit + e2e tests on Ubuntu and macOS        |

---

## When upstream catches up

If upstream `go-libfido2` ever ships a clean static linking configuration
(no hardcoded vendor paths, proper build tags on the static files), the
fork and the `replace` directive can both be removed and we can consume
upstream directly.
