# Shipped conformance integrations

`vendors/conformance/all` aggregates provider-owned container fixtures for the
Testcontainers launcher. It is separate from `vendors/all` so applications do
not pull in test orchestration.

Portable cases remain in the root `conformance` package. Vendor-specific case
extensions are imported directly by their provider's integration test.
