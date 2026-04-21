BINARY := cryptkey

.PHONY: default build build-linux-static build-darwin-static static-deps-darwin verify-static clean-static-deps snapshot release test clean docs-build docs-serve docs-seed

# --- Versions for static builds ---
LIBCBOR_VERSION  := 0.12.0
LIBFIDO2_VERSION := 1.17.0
STATIC_PREFIX    := $(CURDIR)/.static-deps

# --- Default target: produce a portable statically-linked binary for the
# current OS. `make build` remains the dynamic dev build for fast iteration.
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
  DEFAULT_STATIC := build-linux-static
else ifeq ($(UNAME_S),Darwin)
  DEFAULT_STATIC := build-darwin-static
else
  DEFAULT_STATIC := build
endif

.DEFAULT_GOAL := default

default: $(DEFAULT_STATIC)

# --- Local dev build (CGO + FIDO2, requires libfido2-dev) ---

ifeq ($(UNAME_S),Darwin)
  CGO_CFLAGS  := -I$(shell brew --prefix libfido2)/include -I$(shell brew --prefix openssl@3)/include
  CGO_LDFLAGS := -L$(shell brew --prefix libfido2)/lib -L$(shell brew --prefix openssl@3)/lib
  export CGO_CFLAGS CGO_LDFLAGS
endif

build:
	CGO_ENABLED=1 go build -tags dynamic -trimpath -o bin/$(BINARY) .

# --- Static Linux build (matches CI, runs in Alpine Docker) ---

build-linux-static:
	mkdir -p bin
	docker run --rm \
		-v $(CURDIR):/src:ro \
		-v $(CURDIR)/bin:/out \
		-e SRC_DIR=/src \
		-e OUT_PATH=/out/$(BINARY)-linux-static \
		-e VERSION="dev-$(shell git describe --tags --always --dirty 2>/dev/null || echo local)" \
		-e REF_NAME="$(shell git rev-parse --abbrev-ref HEAD 2>/dev/null || echo local)" \
		-e COMMIT_SHA="$(shell git rev-parse HEAD 2>/dev/null || echo local)" \
		-e LIBCBOR_VERSION=$(LIBCBOR_VERSION) \
		-e HOST_UID=$(shell id -u) -e HOST_GID=$(shell id -g) \
		golang:1.25-alpine sh -eu -c '\
			/src/scripts/build-linux-static.sh && \
			chown $$HOST_UID:$$HOST_GID /out/$(BINARY)-linux-static \
		'

# --- Static macOS build (matches CI; requires Homebrew: cmake, pkgconf, openssl@3) ---
# Builds libcbor + libfido2 from source into $(STATIC_PREFIX), then links cryptkey
# against those .a archives plus Homebrew's libcrypto.a. go.mod pins a fork of
# go-libfido2 (github.com/ekristen/go-libfido2) with hardcoded `#cgo` paths
# stripped, so the CGO_CFLAGS/CGO_LDFLAGS below provide the actual locations.

$(STATIC_PREFIX)/lib/libcbor.a:
	@which cmake >/dev/null || (echo "ERROR: cmake not found — run: brew install cmake pkgconf openssl@3"; exit 1)
	rm -rf /tmp/cryptkey-libcbor
	git clone --depth 1 --branch v$(LIBCBOR_VERSION) https://github.com/PJK/libcbor.git /tmp/cryptkey-libcbor
	cd /tmp/cryptkey-libcbor && \
		cmake -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
			-DCMAKE_BUILD_TYPE=Release \
			-DBUILD_SHARED_LIBS=OFF \
			-DCMAKE_INSTALL_PREFIX=$(STATIC_PREFIX) \
			-DWITH_EXAMPLES=OFF . && \
		make -j$$(sysctl -n hw.ncpu) && \
		make install

$(STATIC_PREFIX)/lib/libfido2.a: $(STATIC_PREFIX)/lib/libcbor.a
	rm -rf /tmp/cryptkey-libfido2
	git clone --depth 1 --branch $(LIBFIDO2_VERSION) https://github.com/Yubico/libfido2.git /tmp/cryptkey-libfido2
	OPENSSL_PREFIX="$$(brew --prefix openssl@3)"; \
	cd /tmp/cryptkey-libfido2 && \
		cmake -DCMAKE_BUILD_TYPE=Release \
			-DBUILD_SHARED_LIBS=OFF \
			-DBUILD_STATIC_LIBS=ON \
			-DBUILD_MANPAGES=OFF \
			-DBUILD_EXAMPLES=OFF \
			-DBUILD_TOOLS=OFF \
			-DCMAKE_PREFIX_PATH="$(STATIC_PREFIX);$$OPENSSL_PREFIX" \
			-DCMAKE_INSTALL_PREFIX=$(STATIC_PREFIX) . && \
		make -j$$(sysctl -n hw.ncpu) && \
		make install

static-deps-darwin: $(STATIC_PREFIX)/lib/libfido2.a

build-darwin-static: $(STATIC_PREFIX)/lib/libfido2.a
	@[ "$$(uname -s)" = "Darwin" ] || (echo "ERROR: build-darwin-static must run on macOS"; exit 1)
	mkdir -p bin
	set -e; \
	OPENSSL_PREFIX="$$(brew --prefix openssl@3)"; \
	CGO_ENABLED=1 \
	CGO_CFLAGS="-I$(STATIC_PREFIX)/include -I$$OPENSSL_PREFIX/include" \
	CGO_LDFLAGS="-framework CoreFoundation -framework IOKit $(STATIC_PREFIX)/lib/libfido2.a $(STATIC_PREFIX)/lib/libcbor.a $$OPENSSL_PREFIX/lib/libcrypto.a" \
	go build -trimpath -tags dynamic -o bin/$(BINARY)-darwin-static .
	./scripts/verify-static.sh bin/$(BINARY)-darwin-static

# --- Verify an arbitrary binary is portably linked ---
# Usage: make verify-static BIN=path/to/binary
verify-static:
	@[ -n "$(BIN)" ] || (echo "Usage: make verify-static BIN=path/to/binary"; exit 2)
	./scripts/verify-static.sh $(BIN)

clean-static-deps:
	rm -rf $(STATIC_PREFIX) /tmp/cryptkey-libcbor /tmp/cryptkey-libfido2

# --- Test ---

test:
	go test ./...

# --- Cleanup ---

clean:
	rm -rf bin/ dist/

# --- Docs ---

docs-build:
	docker run --rm -it -p 8000:8000 -v ${PWD}:/docs squidfunk/mkdocs-material build

docs-serve:
	docker run --rm -it -p 8000:8000 -v ${PWD}:/docs squidfunk/mkdocs-material

docs-seed:
	cp README.md docs/index.md
