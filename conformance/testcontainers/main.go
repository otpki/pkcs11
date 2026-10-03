package main

import (
	"github.com/otpki/pkcs11/conformance/testcontainers/runner"
	vendorconformance "github.com/otpki/pkcs11/vendors/conformance/all"
)

func main() { runner.Main(vendorconformance.Fixtures()) }
