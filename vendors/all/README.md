# All shipped vendor modules

`all.Modules()` returns every `VendorModule` shipped by this repository. It is
intended for diagnostics, the conformance command, and applications that truly
need broad multi-provider discovery.

Production services should normally import individual provider packages and
pass a smaller trusted set. Importing this package does not register anything
globally; the returned modules have an effect only when supplied to
`Config.Vendors`, `Discover`, `DetectModules`, or the conformance runner.
