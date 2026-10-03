# Testcontainers conformance launcher

This nested Go module runs provider conformance tests in Docker without adding
Testcontainers dependencies to applications that import the main driver.

The launcher itself is provider-neutral. Each provider owns its fixture,
Dockerfile, assets, defaults, timeout, and cleanup.

## Public providers

```sh
go run . -root ../.. -provider softhsm2
go run . -root ../.. -provider softhsm2 -backend purego
go run . -root ../.. -provider kryoptic-pqc -timeout 140m
go run . -root ../.. -provider all
```

`all` only includes fixtures marked `IncludeInAll`. Private and licensed
fixtures are excluded.

## Flags

```text
-provider ID[,ID...]   provider ID, comma-separated IDs, or all
-backend NAME          cgo (default) or purego
-root PATH             repository root (auto-detected when omitted)
-output PATH           report directory
-timeout DURATION      override the provider timeout
-build-logs BOOL       show Docker build output (default true)
-live-logs BOOL        stream startup and go test output (default true)
-asset NAME=PATH       provider asset (repeatable)
-env NAME=VALUE        container environment override (repeatable)
```

`-native-backend` is kept as a deprecated alias for `-backend`.

`-backend purego` builds the test binary with `CGO_ENABLED=0`, so it exercises
the real no-cgo fallback.

When running several providers, scope an asset as `provider.NAME=PATH` if only
one fixture should receive it.

## Docker portability

Public provider Dockerfiles avoid BuildKit-only syntax where practical. They
also copy `go.mod` and `go.sum` before source files so Docker can reuse the Go
module cache.

Platform-specific fixtures use Buildx. This avoids classic-builder cache issues
when the requested container architecture differs from the host.

If Docker reports a stale content digest or platform mismatch, the launcher
retries once with a refreshed build. If the error persists, review the cache
before pruning it:

```sh
docker buildx prune -af
# Legacy builder:
docker builder prune -af
```

Pruning affects other projects that share the same Docker cache.

## Output

Runs are written under:

```text
<output>/<provider>/<backend>/
```

Important files include:

- `test.log`
- `exit-code`
- `container.log`
- `startup-container.log` for early startup failures

Conformance cases are normal Go subtests, so the `go test` exit code is the
source of truth. Keeping cgo and PureGo results in separate directories makes
backend comparisons straightforward.

The launcher also checks that the binary actually uses the requested backend.
This prevents a stale cached cgo image from being mistaken for a PureGo run.

## Licensed fixtures

Licensed Utimaco fixtures live in the private `pkcs11-private-vendors` module.
The private launcher composes this public runner with those fixtures, so this
module does not need private imports or credentials.

## Adding a provider

Do not add provider switches to the launcher. Implement
`containerfixture.Fixture` beside the vendor module and register it through
`vendors/conformance/all`.

Set `Definition.Platform` when the provider runtime is architecture-specific.
The central launcher should remain orchestration only.
