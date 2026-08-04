# Testcontainers conformance launcher

This nested Go module keeps Testcontainers/Docker dependencies out of
applications that import the PKCS #11 driver.

The launcher is provider-neutral. It loads `containerfixture.Fixture` values
from `vendors/conformance/all`; each provider owns its Dockerfile, external
assets, preparation logic, environment defaults, timeout, and cleanup.

## Public providers

```sh
go run . -root ../.. -provider softhsm2
go run . -root ../.. -provider softhsm2 -backend purego
go run . -root ../.. -provider kryoptic-pqc -timeout 140m
go run . -root ../.. -provider all
```

`all` includes only fixtures whose provider marks `IncludeInAll`. Licensed and
private fixtures are excluded.

## Generic flags

```text
-provider ID[,ID...]   fixture ID, comma-separated IDs, or all
-backend NAME          test binary native backend: cgo (default) or purego
-root PATH             repository root; auto-detected when omitted
-output PATH           report root
-timeout DURATION      override provider default
-build-logs BOOL       print Docker build output; defaults to true
-live-logs BOOL        stream startup stages and per-case conformance output; defaults to true
-asset NAME=PATH       provider asset; repeatable
-env NAME=VALUE        container environment override; repeatable
```

`-native-backend` remains as a deprecated alias for `-backend`. Supplying both
is accepted only when they resolve to the same backend.

The launcher defaults to `cgo`, matching a normal build with cgo enabled.
`-backend purego` builds the provider's Go test binary with `CGO_ENABLED=0` and therefore tests
the automatic fallback rather than a cgo-enabled binary forced by build tags.

A provider-specific asset can be scoped as `provider.NAME=PATH` when running
multiple fixtures.

## Docker build portability

Provider Dockerfiles avoid BuildKit-only instructions, so the public fixtures
also work with Docker's classic image builder. Executable permissions are set
with portable `RUN chmod` steps rather than `COPY --chmod`.

The repository `.dockerignore` keeps VCS, IDE, test binary, and report data out
of build contexts. Dockerfiles copy `go.mod` and `go.sum` before the source tree
to preserve the module-download cache, and retry package-manager and upstream
source downloads to tolerate transient network failures.

The SoftHSM fixture pins an upstream development revision with PKCS #11 3.2
ML-DSA and ML-KEM support. It builds against OpenSSL 3.5 on Debian trixie and
explicitly enables ECC, EdDSA, ML-DSA, and ML-KEM during configuration.

## Progress and failure artifacts

The launcher prints each orchestration stage and streams standard verbose
`go test` output. Disable either stream only when needed with
`-build-logs=false` or `-live-logs=false`.

Runs write `test.log`, `exit-code`, and `container.log` below
`<output>/<provider>/<backend>/`. Cases appear as ordinary Go subtests, so the
standard exit status is authoritative and no JSON or JUnit translation is
required. Keeping both backends in separate directories allows direct parity
comparisons. If a native module crashes, the wrapper still records the process
status and partial test log. Early container failures use `startup-container.log`.

The launcher passes `PKCS11_BACKEND` as a Docker build argument and sets
`CONFORMANCE_EXPECT_BACKEND` in the container. The test helper refuses to run when
the compiled backend does not match the requested one. This prevents a cached
cgo image from being mistaken for a PureGo parity run. The backend is also
printed in the Go test output.

A Docker error containing `content digest ... not found` or `does not provide
the specified platform` occurs before the provider container starts and
normally indicates a stale or cross-architecture cache reference. The launcher
automatically retries that build once with cache disabled and parent images
refreshed. Platform-specific fixtures are built separately with `docker buildx
build --load`, because the classic Docker builder can otherwise reuse a
host-architecture intermediate image and the daemon's legacy build API can
close its stream during cross-platform builds. Buildx keeps its normal cache;
the launcher retries once with `--no-cache --pull` only when it detects an
inconsistent cache. If the daemon still returns the error, the launcher prints
a repair command. Because pruning removes build cache used by other projects,
run it manually after reviewing the impact:

```sh
docker buildx prune -af
# For the legacy builder:
docker builder prune -af
```

Restart Docker Desktop and retry if the daemon still references the missing
blob.

## Licensed Utimaco simulator

```sh
go run . \
  -root ../.. \
  -provider utimaco-quantumprotect-simulator \
  -asset runtime=/secure/u.trust-GP-HSM-Simulator_v6.4.0.0.zip \
  -asset quantumprotect=/secure/QuantumProtect-1.5.0.0-Evaluation.zip
```

The fixture also accepts `UTIMACO_SIMULATOR_ARCHIVE` and
`UTIMACO_QUANTUMPROTECT_ARCHIVE`.

The supplied simulator is x86-only. Its fixture declares `linux/amd64`, and the
launcher applies that OCI platform to both the Docker build and the started
container. Setting `--platform` only in a Dockerfile is not sufficient with
every Docker builder, so the platform build uses the standard Docker Buildx
plugin. Docker Desktop on Apple Silicon can build the image, but cannot run the
simulator's 32-bit host timer correctly; execute this provider on native Linux
amd64. The entrypoint detects the emulator failure and exits immediately.

`vendors/utimaco/conformance.SimulatorFixture` creates a temporary build
context, copies the repository without VCS/report material, extracts only the
required licensed Linux files, validates the expected archive layout, and
removes the context after the run. The original archives are never copied into
reports. The built local image and Docker cache still contain licensed material
and remain subject to the applicable agreement.

## Adding a provider

Do not add provider conditionals here. Implement
`containerfixture.Fixture` beside the vendor module and include it from
`vendors/conformance/all`. Set `Definition.Platform` when the provider runtime
is architecture-specific. The central launcher should remain pure orchestration.
