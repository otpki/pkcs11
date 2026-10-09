set dotenv-load := false

# ------------------------------------------------------------------
# Paths / Config
# ------------------------------------------------------------------

root      := justfile_directory()
tool_path := root / ".tool/bin"

export PATH := tool_path + ":" + env_var("PATH")
export AQUA_ROOT_DIR := root / ".tool"
export AQUA_DISABLE_POLICY := "true"

default:
    @just --list

shell:
    exec "${SHELL:-/bin/sh}" -i

# -----------------------------
# aqua bootstrap + tool install
# -----------------------------

# install aqua itself into .tool/bin — no global install needed
aqua:
    mkdir -p "{{ tool_path }}"
    test -x "{{ tool_path }}/aqua" || curl -sSfL https://raw.githubusercontent.com/aquaproj/aqua-installer/v4.0.5/aqua-installer | bash

# install every tool pinned in .aqua.yaml (or a tag subset: just tools lint)
tools *tags: aqua
    aqua install {{ if tags == "" { "" } else { "-t " + replace(tags, " ", " -t ") } }}

# -----------------------------
# Build / check recipes
# -----------------------------

build:
    go run build.go

# gofmt + goimports per .golangci.yml formatters
fmt:
    golangci-lint fmt ./...

# golangci-lint fmt -d diffs without rewriting; empty output means formatted.
format-check:
    test -z "$(golangci-lint fmt -d ./...)"

lint:
    golangci-lint run ./...

gen:
    go generate ./...

tidy:
    go mod tidy
    cd conformance/testcontainers && go mod tidy

test:
    go test ./...

# CGO-less fallback: exercises the automatic PureGo path
test-nocgo:
    CGO_ENABLED=0 go test ./...

test-purego:
    CGO_ENABLED=1 go test -tags=pkcs11_purego ./...

test-race:
    CGO_ENABLED=1 go test -race ./...

test-race-purego:
    CGO_ENABLED=1 go test -race -tags=pkcs11_purego ./...

vet:
    CGO_ENABLED=1 go vet ./...
    CGO_ENABLED=0 go vet ./...
    CGO_ENABLED=1 go vet -tags=pkcs11_purego ./...

# cross-compile smoke build (no test run — CI matrix supplies GOOS/GOARCH)
cross-build goos goarch:
    CGO_ENABLED=0 GOOS={{ goos }} GOARCH={{ goarch }} go build -buildvcs=false ./...

# vendored OASIS headers + native/Windows LLP64 ABI layout validation
abi-check:
    cd raw/internal/cryptoki/oasis/3.2 && (sha256sum -c MANIFEST.sha256 2>/dev/null || shasum -a 256 -c MANIFEST.sha256)
    cc -std=c11 -Wall -Wextra -Werror -Iraw/internal/cryptoki -fsyntax-only raw/internal/cryptoki/abi_layout_test.c
    clang --target=x86_64-pc-windows-msvc -std=c11 -Wall -Wextra -Werror -fdeclspec -DCRYPTOKI_FORCE_WIN32 -Iraw/internal/cryptoki -fsyntax-only raw/internal/cryptoki/abi_layout_test.c
    clang --target=aarch64-pc-windows-msvc -std=c11 -Wall -Wextra -Werror -fdeclspec -DCRYPTOKI_FORCE_WIN32 -Iraw/internal/cryptoki -fsyntax-only raw/internal/cryptoki/abi_layout_test.c

verify-backends:
    go test -run TestNativeBackendsRemainSeparated .

vulncheck:
    govulncheck ./...

# Same checks CI's lint job runs: formatting, lint, tidy, generation, and a
# clean working tree — fails on tracked diffs and untracked leftovers alike.
check: tools
    just format-check
    just lint
    just tidy
    just gen
    @if [ -n "$(git status --porcelain)" ]; then \
        echo "Generation, tidy, or formatting left changes:"; \
        git status --porcelain; \
        git diff --stat; \
        exit 1; \
    fi

# -----------------------------
# Development
# -----------------------------

# run the broker in hardware-free test mode with the dev UI on :9443
serve args="":
    go run ./cmd/pkcs11-proxy serve --test --insecure --dev_ui.enabled {{ args }}

# multiarch image build, matching the release pipeline's zig cross-compile
# (.git is excluded from the context, so the version stamp arrives as args.
# the same GIT_* inputs the release workflow passes)
docker platform="linux/arm64":
    docker build --platform {{ platform }} \
        --build-arg GIT_TAG="$(git tag --points-at HEAD 2>/dev/null | head -1)" \
        --build-arg GIT_BRANCH="$(git symbolic-ref --short HEAD 2>/dev/null || true)" \
        --build-arg GIT_HASH="$(git rev-parse --short HEAD 2>/dev/null || true)" \
        -t pkcs11-proxy:dev .

# run a provider's conformance suite in its fixture container. Builds the
# fixture image via testcontainers (the first SoftHSM source build is slow,
# but Docker layer cache keeps reruns fast). Pass a prebuilt image to skip the
# build entirely, as CI does:
#   just conformance softhsm2 otpki/conformance-softhsm2-cgo:local
conformance provider image="":
    cd "{{ root }}/conformance/testcontainers" && go run . -root "{{ root }}" -provider {{ provider }} {{ if image != "" { "-image " + image } else { "" } }}

# build a vendor's integration image (the Dockerfile's integration target) and
# run the PKCS11_MODULE-gated tests inside it (ex. just integration softhsm)
integration vendor tag="local":
    docker buildx build --load --target integration \
        -f "{{ root }}/vendors/{{ vendor }}/conformance/docker/Dockerfile" \
        -t otpki/integration-{{ vendor }}-cgo:{{ tag }} "{{ root }}"
    docker run --rm otpki/integration-{{ vendor }}-cgo:{{ tag }}
