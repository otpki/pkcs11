package proxycmd

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/internal/testmock"
	"github.com/otpki/pkcs11/proxy"
)

// testModuleScheme selects the in-memory test HSM. Use test, test:<name>, or test:<name>:<count>.
// Multiple routes can point at different tokens on the same test module.
const testModuleScheme = "test"

var testModuleName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]*$`)

// TestServer builds the same in-memory broker as `serve --test --insecure`,
// bound to an already-created listener and without loading flags, YAML, or
// environment configuration. It exists so consumers of this module can run
// hermetic integration tests against the proxy. The workload credential is
// any non-empty token and every token accepts PIN testmock.DefaultPIN
// ("1234"). The caller runs Serve and Close; vendors follows the usual
// bundling rule where nil selects the public module set.
func TestServer(ctx context.Context, listener net.Listener, vendors []pkcs11.VendorModule) (*proxy.Server, error) {
	cfg := options{bundledVendors: vendors, Insecure: true}
	specs := testTargets()
	targets := make([]proxy.TargetConfig, 0, len(specs))
	for _, spec := range specs {
		target, err := cfg.targetConfig(spec)
		if err != nil {
			return nil, fmt.Errorf("target %q: %w", spec.Name, err)
		}
		targets = append(targets, target)
	}
	return proxy.NewServer(ctx, proxy.ServerConfig{
		Listener:      listener,
		AllowInsecure: true,
		Authenticator: workloadAuthenticator,
	}, targets...)
}

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
