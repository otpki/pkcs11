package conformance

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	pkcs11 "github.com/otpki/pkcs11"
)

// CaseExtension adds vendor-specific conformance case kinds without coupling
// the portable runner to a concrete HSM package.
//
// Implementations conventionally live beside their VendorModule, for example
// vendors/acme/conformance. Tests opt into them through WithCaseExtensions.
type CaseExtension interface {
	// ID is a stable diagnostic identifier for the extension.
	ID() string
	// Kinds lists the case kinds accepted by Execute. Kinds should be namespaced,
	// for example "vendor:acme:backup".
	Kinds() []string
	// Execute runs one case against the already-open managed client.
	Execute(context.Context, ExtensionContext, Case) (map[string]any, error)
}

// ExtensionContext exposes only the runner services required by a vendor case.
// The Client remains fully managed; raw diagnostics should use
// Client.WithRawSession rather than loading the module independently.
type ExtensionContext struct {
	Client   *pkcs11.Client
	Cleanup  bool
	Prefix   string
	identity func(string) string
}

// Identity returns a deterministic, profile-prefixed token object label that
// is unique within the current conformance process.
func (context ExtensionContext) Identity(name string) string {
	if context.identity != nil {
		return context.identity(name)
	}
	return strings.TrimSpace(context.Prefix + "-" + name)
}

type extensionRegistry struct {
	byKind map[string]CaseExtension
	all    []CaseExtension
}

func buildExtensionRegistry(extensions []CaseExtension) (extensionRegistry, error) {
	registry := extensionRegistry{byKind: make(map[string]CaseExtension), all: append([]CaseExtension(nil), extensions...)}
	ids := make(map[string]struct{}, len(extensions))
	for index, extension := range extensions {
		if extension == nil {
			return extensionRegistry{}, fmt.Errorf("conformance extension %d is nil", index)
		}
		id := strings.TrimSpace(extension.ID())
		if id == "" {
			return extensionRegistry{}, fmt.Errorf("conformance extension %d has an empty ID", index)
		}
		if _, exists := ids[id]; exists {
			return extensionRegistry{}, fmt.Errorf("duplicate conformance extension ID %q", id)
		}
		ids[id] = struct{}{}
		for _, rawKind := range extension.Kinds() {
			kind := strings.ToLower(strings.TrimSpace(rawKind))
			if kind == "" {
				return extensionRegistry{}, fmt.Errorf("conformance extension %q has an empty case kind", id)
			}
			if _, portable := knownCaseKinds[kind]; portable {
				return extensionRegistry{}, fmt.Errorf("conformance extension %q attempts to replace portable kind %q", id, kind)
			}
			if previous, exists := registry.byKind[kind]; exists {
				return extensionRegistry{}, fmt.Errorf("conformance case kind %q is provided by both %q and %q", kind, previous.ID(), id)
			}
			registry.byKind[kind] = extension
		}
	}
	return registry, nil
}

// CaseExtensionKinds returns all namespaced kinds supplied by extensions in
// stable lexical order. It is useful for documentation and CLI diagnostics.
func CaseExtensionKinds(extensions ...CaseExtension) ([]string, error) {
	registry, err := buildExtensionRegistry(extensions)
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(registry.byKind))
	for kind := range registry.byKind {
		result = append(result, kind)
	}
	sort.Strings(result)
	return result, nil
}

// RunOption configures a conformance test.
type RunOption func(*runConfig) error

type runConfig struct {
	module     pkcs11.ModuleSource
	vendors    []pkcs11.VendorModule
	extensions []CaseExtension
}

// WithModuleSource overrides the plan's local module path with an immutable
// ModuleSource, such as a proxy.RemoteModule.
func WithModuleSource(source pkcs11.ModuleSource) RunOption {
	return func(config *runConfig) error {
		if source == nil {
			return errors.New("conformance: module source is nil")
		}
		config.module = source
		return nil
	}
}

// WithVendorModules supplies the same VendorModule set used by the application
// under test. A plan cannot implicitly enable vendor code.
func WithVendorModules(modules ...pkcs11.VendorModule) RunOption {
	return func(config *runConfig) error {
		config.vendors = append(config.vendors, modules...)
		return nil
	}
}

// WithCaseExtensions installs vendor-specific case executors.
func WithCaseExtensions(extensions ...CaseExtension) RunOption {
	return func(config *runConfig) error {
		config.extensions = append(config.extensions, extensions...)
		return nil
	}
}

func resolveRunConfig(options []RunOption) (runConfig, extensionRegistry, error) {
	var config runConfig
	for _, option := range options {
		if option != nil {
			if err := option(&config); err != nil {
				return runConfig{}, extensionRegistry{}, err
			}
		}
	}
	registry, err := buildExtensionRegistry(config.extensions)
	if err != nil {
		return runConfig{}, extensionRegistry{}, err
	}
	return config, registry, nil
}
