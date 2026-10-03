package pkcs11

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/otpki/pkcs11/raw"
)

// ModuleSource opens one logical PKCS #11 module and supplies its process-wide
// registry key. A source may represent a local library or a remote target.
// Treat source configuration as immutable and change RegistryKey when behavior
// or trust settings change.
type ModuleSource interface {
	// OpenModule creates one fresh logical module instance when the managed
	// process registry does not already own RegistryKey.
	OpenModule(context.Context) (raw.Module, error)
	// RegistryKey returns the immutable process-wide sharing identity. It must
	// change whenever configuration that affects behavior or trust changes.
	RegistryKey() string
	// String returns a non-secret diagnostic description.
	String() string
}

// ModuleSourceVendors lets a source provide vendor modules needed by its
// logical token. Open merges them with Config.Vendors, with explicit config
// taking precedence for duplicate vendor IDs.
type ModuleSourceVendors interface {
	// VendorModules returns candidates needed to interpret the logical module.
	// Implementations must return a defensive copy.
	VendorModules() []VendorModule
}

func mergeSourceVendors(source ModuleSource, explicit []VendorModule) []VendorModule {
	byID := make(map[AdapterFamily]VendorModule)
	order := make([]AdapterFamily, 0)
	add := func(module VendorModule) {
		if module == nil {
			return
		}
		id := normalizeAdapterFamily(module.Definition().ID)
		if _, exists := byID[id]; !exists {
			order = append(order, id)
		}
		byID[id] = module
	}
	if provider, ok := source.(ModuleSourceVendors); ok {
		for _, module := range provider.VendorModules() {
			add(module)
		}
	}
	for _, module := range explicit {
		add(module)
	}
	result := make([]VendorModule, 0, len(order))
	for _, id := range order {
		result = append(result, byID[id])
	}
	return result
}

// LocalModuleSource identifies one local PKCS #11 shared library.
type LocalModuleSource struct {
	// Path is the trusted native module path. It is canonicalized and symlinks
	// are resolved when the file exists.
	Path string
}

// LocalModule constructs a source for a local .so, .dylib, or .dll.
func LocalModule(path string) ModuleSource { return LocalModuleSource{Path: path} }

// OpenModule loads the local module through raw.Open. Context cancellation is
// checked before entering the native loader because native loading itself is
// not portably cancellable.
func (source LocalModuleSource) OpenModule(ctx context.Context) (raw.Module, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	path, err := canonicalLocalModulePath(source.Path)
	if err != nil {
		return nil, err
	}
	return raw.Open(path)
}

// RegistryKey returns a canonical, process-local library identity.
func (source LocalModuleSource) RegistryKey() string {
	path, err := canonicalLocalModulePath(source.Path)
	if err != nil {
		return "local-invalid:" + strings.TrimSpace(source.Path)
	}
	return "local:" + path
}

// String returns the canonical path when possible.
func (source LocalModuleSource) String() string {
	path, err := canonicalLocalModulePath(source.Path)
	if err != nil {
		return strings.TrimSpace(source.Path)
	}
	return path
}

func canonicalLocalModulePath(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("pkcs11: module path is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("pkcs11: canonicalize module path: %w", err)
	}
	if resolved, resolveErr := filepath.EvalSymlinks(absolute); resolveErr == nil {
		absolute = resolved
	}
	absolute = filepath.Clean(absolute)
	if runtime.GOOS == "windows" {
		absolute = strings.ToLower(absolute)
	}
	return absolute, nil
}

func validateModuleSource(source ModuleSource) error {
	if source == nil {
		return errors.New("pkcs11: module source is required; use LocalModule(path), OpenAuto, or OpenDetected")
	}
	if strings.TrimSpace(source.RegistryKey()) == "" {
		return errors.New("pkcs11: module source returned an empty registry key")
	}
	return nil
}
