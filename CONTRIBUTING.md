# Contributing

## Requirements

- Go 1.27 or newer
- `just` and `curl` on `PATH`. Everything else is pinned and installed under
  `.tool/` by `just tools` (golangci-lint, govulncheck, zig, ...)

## Workflow

1. Open an issue first for anything beyond a small fix so the direction is
   agreed before the work happens.
2. Make the change on a branch.
3. Run `just check`. It is the same quality gate CI runs: formatting,
   lint, `go mod tidy`, `go generate`, and a clean working tree.
4. Run `go test ./...` (plus `just test-nocgo` for backend parity when the
   change touches the raw ABI layer).
5. Open a PR with a short summary and a test plan.

Generated artifacts (command docs, the example YAML, vendored headers) are
checked in. Regenerate with `just gen` rather than editing by hand.

## Layout notes for contributors

- `pkcs11-private-vendors/` is an optional submodule holding licensed vendor
  integrations. The public repo builds and tests fine without it. Do not move
  restricted constants, simulator files, or licensed material into the public
  tree; they belong there.
- Vendor-specific behavior goes through `pkcs11.VendorModule`
  (`docs/VENDOR_MODULES.md`). The root package stays provider-neutral.
- The proxy broker binary lives in `cmd/pkcs11-proxy` (public vendors) and is
  rebuilt with private vendors when the submodule is present (`just build`).

## Conformance tests

`conformance/` runs hardware-backed suites through testcontainers. Provider
fixtures need the vendor's simulator or HSM, see
`pkcs11-private-vendors/docs/SIMULATORS.md` for the licensed simulators.
Hardware-free paths (SoftHSM, kryoptic, the in-memory test module) cover most
code. Prefer extending those before requiring a licensed fixture.

## Security

Do not report vulnerabilities through public issues or PRs. See
`docs/SECURITY.md`.
