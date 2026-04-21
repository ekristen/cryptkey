#!/usr/bin/env bash
# Verify a cryptkey binary is portable — no runtime dependencies on third-party
# libraries like libfido2, libcbor, libcrypto, or libpcsclite.
#
# On Linux: binary must be fully statically linked (no dynamic section at all).
# On macOS: binary may link only system libs/frameworks — no Homebrew paths.
# On both: the go-libfido2 and go-piv Go packages must be compiled in (detected
# via residual Go type strings, which survive -ldflags="-s -w" stripping).
#
# Usage: scripts/verify-static.sh <binary-path>
#
# Exits 0 if the binary passes all checks, non-zero otherwise.

set -euo pipefail

if [ $# -ne 1 ]; then
    echo "Usage: $0 <binary-path>" >&2
    exit 2
fi

BIN="$1"

if [ ! -f "$BIN" ] || [ ! -x "$BIN" ]; then
    echo "ERROR: $BIN is not an executable file" >&2
    exit 2
fi

FILE_OUT=$(file "$BIN")
echo "file: $FILE_OUT"
echo ""

FAILED=0
fail() { echo "FAIL: $1" >&2; FAILED=1; }
pass() { echo "PASS: $1"; }

# --- Platform-specific link checks ---

case "$FILE_OUT" in
    *"ELF"*"statically linked"*)
        pass "ELF binary is statically linked (per file(1))"

        # Double-check: a truly static binary has no dynamic section.
        if command -v readelf >/dev/null 2>&1; then
            if readelf -d "$BIN" 2>&1 | grep -qE "no dynamic section|There is no dynamic section"; then
                pass "ELF binary has no dynamic section (confirmed static)"
            else
                fail "ELF binary has a dynamic section — not fully static"
                readelf -d "$BIN" 2>&1 | sed 's/^/    /' >&2
            fi
        else
            echo "SKIP: readelf not available; relying on file(1) and ldd"
        fi

        # ldd sanity check. ldd exits non-zero on static binaries, so capture
        # its output separately rather than piping (pipefail would trip).
        # Different libc implementations phrase it differently:
        #   glibc:  "not a dynamic executable"
        #   musl:   "Not a valid dynamic program"
        #   (both): "statically linked"
        LDD_OUT=$(ldd "$BIN" 2>&1 || true)
        if echo "$LDD_OUT" | grep -qEi "not a dynamic executable|not a valid dynamic program|statically linked"; then
            pass "ldd confirms no dynamic dependencies"
        else
            fail "ldd reports dynamic dependencies"
            echo "$LDD_OUT" | sed 's/^/    /' >&2
        fi
        ;;

    *"ELF"*"dynamically linked"*)
        fail "ELF binary is dynamically linked — must be static for portability"
        echo "  ldd output:" >&2
        ldd "$BIN" 2>&1 | sed 's/^/    /' >&2
        ;;

    *"Mach-O"*)
        # macOS binaries always dynamically link libSystem + system frameworks.
        # Verify only system paths are referenced — no Homebrew leaks.
        echo "Mach-O binary — checking dynamic library references..."
        DYLIBS=$(otool -L "$BIN" | tail -n +2)
        echo "$DYLIBS" | sed 's/^/    /'
        echo ""

        HOMEBREW=$(echo "$DYLIBS" | grep -E '/opt/homebrew|/usr/local/opt|/usr/local/Cellar' || true)
        if [ -n "$HOMEBREW" ]; then
            fail "binary links against Homebrew paths (third-party libs should be statically embedded)"
            echo "$HOMEBREW" | sed 's/^/    /' >&2
        else
            pass "no Homebrew paths in linked libraries"
        fi

        NON_SYSTEM=$(echo "$DYLIBS" | awk '{print $1}' \
            | grep -vE '^(/usr/lib/|/System/Library/)' || true)
        if [ -n "$NON_SYSTEM" ]; then
            fail "binary links against non-system libraries"
            echo "$NON_SYSTEM" | sed 's/^/    /' >&2
        else
            pass "only system libraries/frameworks are dynamically linked"
        fi
        ;;

    *)
        fail "unrecognized binary format: $FILE_OUT"
        ;;
esac

# --- Go package presence check ---
# Go's runtime keeps type names in the binary even after -ldflags="-s -w" for
# reflection. Presence of `*libfido2.Xxx` and `*piv.Xxx` strings proves those
# Go packages are compiled in. Combined with a fully-static link above, this
# proves the C libraries they wrap are embedded (otherwise the link would
# have produced dynamic deps).

echo ""
echo "--- checking for embedded Go package types ---"
# Write strings(1) output to a temp file — echo'ing a multi-MB string into a
# pipe causes grep to see it as binary and match unreliably.
STRINGS_FILE=$(mktemp)
trap 'rm -f "$STRINGS_FILE"' EXIT
strings "$BIN" > "$STRINGS_FILE" 2>/dev/null || true

check_pkg() {
    local pattern="$1"
    local desc="$2"
    if grep -qE "$pattern" "$STRINGS_FILE"; then
        pass "$desc package is compiled in (matched: $pattern)"
    else
        fail "$desc package NOT found in binary — build may be missing providers"
    fi
}

check_pkg '\*libfido2\.' "go-libfido2 (fido2 provider)"
check_pkg '\*piv\.'      "go-piv (piv provider)"

echo ""
if [ "$FAILED" -ne 0 ]; then
    echo "RESULT: FAILED — binary is not portable" >&2
    exit 1
fi

echo "RESULT: PASSED — binary is portable (static third-party deps)"
