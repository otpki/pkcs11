package main

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/internal/testmock"
)

// testModuleScheme is the module value prefix that selects the in-memory test
// module instead of a shared library. "test" alone publishes a one-token
// virtual HSM named "test"; "test:<name>" names the HSM and "test:<name>:<n>"
// gives it n token-present slots. Two routes that configure the same test
// module share the virtual HSM, so token_label or slot_id can bind each route
// to a different token on it — the same way one vendor library fronts several
// partitions.
const testModuleScheme = "test"

var testModuleName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]*$`)

// testTargets is the canned route topology used by --test: two tokens on one
// shared virtual HSM plus a second HSM, so the dashboard and route catalog show
// multi-token and multi-module routes at once. All tokens accept PIN "1234".
func testTargets() []targetSpec {
	return []targetSpec{
		{Name: "test-alpha", Module: "test:demo-hsm:2", TokenLabel: "demo-hsm-token-1"},
		{Name: "test-beta", Module: "test:demo-hsm:2", TokenLabel: "demo-hsm-token-2"},
		{Name: "test-gamma", Module: "test:sidecar-hsm"},
	}
}

// testModuleSource parses "test[:<name>[:<tokens>]]" into a module source. The
// boolean reports whether spec selected the test scheme at all.
func testModuleSource(spec string) (pkcs11.ModuleSource, bool, error) {
	if spec != testModuleScheme && !strings.HasPrefix(spec, testModuleScheme+":") {
		return nil, false, nil
	}
	parts := strings.Split(spec, ":")
	if len(parts) > 3 {
		return nil, true, fmt.Errorf("test module takes at most name and token count: %q", spec)
	}
	source := testmock.Source{Name: testModuleScheme, Tokens: 1}
	if len(parts) >= 2 && parts[1] != "" {
		if !testModuleName.MatchString(parts[1]) {
			return nil, true, fmt.Errorf("test module name %q is invalid", parts[1])
		}
		source.Name = parts[1]
	}
	if len(parts) == 3 {
		count, err := strconv.Atoi(parts[2])
		if err != nil || count < 1 || count > 8 {
			return nil, true, fmt.Errorf("test module token count %q must be 1-8", parts[2])
		}
		source.Tokens = count
	}
	return source, true, nil
}

// targetModuleSource resolves spec.Module to either the in-memory test module
// or the configured shared library path.
func targetModuleSource(spec string) (pkcs11.ModuleSource, error) {
	if source, isTest, err := testModuleSource(spec); isTest || err != nil {
		return source, err
	}
	return pkcs11.LocalModule(spec), nil
}
