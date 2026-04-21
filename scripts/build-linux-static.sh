#!/usr/bin/env sh
# Build a fully static Linux cryptkey binary. Designed to run inside an Alpine
# container with the required apk packages already installed; it builds libcbor
# from source (Alpine doesn't ship libcbor.a) and links everything statically.
#
# Expects these env vars:
#   SRC_DIR      — source tree (read-only OK; will be copied to a writable dir)
#   OUT_PATH     — output binary path
#   VERSION      — version string for -ldflags -X
#   REF_NAME     — git ref name for -ldflags -X
#   COMMIT_SHA   — git commit SHA for -ldflags -X
#
# Exits non-zero on failure.

set -eu

: "${SRC_DIR:?SRC_DIR required}"
: "${OUT_PATH:?OUT_PATH required}"
: "${VERSION:?VERSION required}"
: "${REF_NAME:?REF_NAME required}"
: "${COMMIT_SHA:?COMMIT_SHA required}"

LIBCBOR_VERSION="${LIBCBOR_VERSION:-0.12.0}"

# --- Alpine deps ---
apk add --no-cache \
    bash git build-base cmake file \
    libfido2-dev \
    openssl-dev openssl-libs-static \
    libcbor-dev \
    pcsc-lite-dev pcsc-lite-static \
    eudev-dev

# --- Build static libcbor (Alpine ships .so, not .a) ---
git clone --depth 1 --branch "v${LIBCBOR_VERSION}" https://github.com/PJK/libcbor.git /tmp/libcbor
cd /tmp/libcbor
cmake -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
      -DCMAKE_BUILD_TYPE=Release \
      -DBUILD_SHARED_LIBS=OFF \
      -DCMAKE_INSTALL_PREFIX=/usr .
make -j"$(nproc)"
cp src/libcbor.a /usr/lib/

# --- Build cryptkey ---
# Copy source to a writable location (the mount is read-only).
cp -r "$SRC_DIR" /tmp/cryptkey-src
cd /tmp/cryptkey-src
git config --global --add safe.directory /tmp/cryptkey-src

export CGO_ENABLED=1
export GOOS=linux
export CGO_LDFLAGS="-lcbor -lcrypto -ludev"

go build -trimpath -buildvcs=false \
    -ldflags "-s -w -extldflags=-static \
        -X 'github.com/ekristen/cryptkey/pkg/common.SUMMARY=${VERSION}' \
        -X 'github.com/ekristen/cryptkey/pkg/common.BRANCH=${REF_NAME}' \
        -X 'github.com/ekristen/cryptkey/pkg/common.VERSION=${VERSION}' \
        -X 'github.com/ekristen/cryptkey/pkg/common.COMMIT=${COMMIT_SHA}'" \
    -o "$OUT_PATH" .

# --- Verify ---
/tmp/cryptkey-src/scripts/verify-static.sh "$OUT_PATH"
