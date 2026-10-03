package raw

import (
	"errors"
	"slices"
)

var (
	// ErrClosed indicates that an operation was attempted through a nil,
	// destroyed, or otherwise unavailable module context.
	ErrClosed = errors.New("pkcs11: module is closed")

	// ErrNativeUnavailable indicates that the native backend selected for this
	// build cannot load modules on the current operating system or architecture.
	// cgo-enabled builds select the cgo bridge by default; builds without cgo
	// automatically use the PureGo fallback on its supported targets.
	ErrNativeUnavailable = errors.New("pkcs11: native module loading is unavailable on this platform")
)

// OpenConfig controls function-table selection for a loaded PKCS #11 module.
// Open tries Versions in order through C_GetInterface and can fall back to
// C_GetFunctionList for legacy modules. Initialization and token policy happen
// later.
type OpenConfig struct {
	// InterfaceName requests a specific named interface from C_GetInterface.
	// The empty string passes a nil name and asks the module for its default
	// interface for each requested version.
	InterfaceName string

	// InterfaceFlags is forwarded to C_GetInterface. Its meaning is defined by
	// the PKCS #11 interface-selection contract and, for nonstandard bits, by
	// the module providing the interface.
	InterfaceFlags uint

	// Versions lists acceptable PKCS #11 interface versions in priority order.
	// Open stops at the first successful selection. An empty list skips the
	// C_GetInterface path and proceeds directly to legacy fallback when allowed.
	Versions []Version

	// AllowLegacy permits Open to use C_GetFunctionList after all requested
	// C_GetInterface attempts fail. Disable it when the application requires a
	// PKCS #11 3.x interface and must reject legacy-only modules.
	AllowLegacy bool
}

// OpenOption mutates the configuration used by Open.
//
// Options are applied in argument order to a fresh copy of the default
// configuration. Later options may replace values established by earlier ones.
type OpenOption func(*OpenConfig)

// WithInterfaceName requests name through C_GetInterface.
//
// Passing an empty string restores default-interface selection rather than
// requesting an interface whose literal name is empty.
func WithInterfaceName(name string) OpenOption {
	return func(c *OpenConfig) { c.InterfaceName = name }
}

// WithInterfaceFlags sets the flags forwarded to C_GetInterface during every
// version-selection attempt.
func WithInterfaceFlags(flags uint) OpenOption {
	return func(c *OpenConfig) { c.InterfaceFlags = flags }
}

// WithInterfaceVersions replaces the default version preference list.
//
// Versions are tried exactly in the supplied order. The slice is copied both
// when the option is created and when configuration is resolved, so callers
// may safely reuse or modify their input slice afterward.
func WithInterfaceVersions(versions ...Version) OpenOption {
	return func(c *OpenConfig) {
		c.Versions = slices.Clone(versions)
	}
}

// WithoutLegacyFallback requires selection through C_GetInterface.
//
// Use this when the application depends on PKCS #11 3.x semantics and should
// reject modules that provide only C_GetFunctionList.
func WithoutLegacyFallback() OpenOption {
	return func(c *OpenConfig) { c.AllowLegacy = false }
}

// defaultOpenConfig prefers the newest supported standard interface and keeps
// legacy compatibility enabled.
func defaultOpenConfig() OpenConfig {
	return OpenConfig{
		Versions: []Version{
			{Major: 3, Minor: 2},
			{Major: 3, Minor: 1},
			{Major: 3, Minor: 0},
		},
		AllowLegacy: true,
	}
}

// ResolveOpenConfig applies Open options and returns an independent copy.
func ResolveOpenConfig(options ...OpenOption) OpenConfig {
	config := defaultOpenConfig()
	for _, option := range options {
		if option != nil {
			option(&config)
		}
	}

	config.Versions = slices.Clone(config.Versions)
	return config
}

// OutputBufferPolicy handles modules that reject the normal nil-output sizing
// probe. RejectNullProbe starts with a real buffer and grows it on
// CKR_BUFFER_TOO_SMALL up to MaximumSize. It only changes raw output allocation.
type OutputBufferPolicy struct {
	// RejectNullProbe skips the ordinary nil-output sizing call and starts with
	// a real allocation. Leave false for conforming modules.
	RejectNullProbe bool

	// InitialSize is the first allocation used by the fallback path. Zero means
	// the default of 4 KiB.
	InitialSize uint

	// MaximumSize bounds fallback growth and protects the process from an
	// unreasonable or malicious length response. Zero means the default of
	// 64 MiB. Values smaller than InitialSize are raised to InitialSize.
	MaximumSize uint
}

// normalized fills zero-valued limits and enforces MaximumSize >= InitialSize.
// It returns a copy and does not mutate the caller's value.
func (p OutputBufferPolicy) normalized() OutputBufferPolicy {
	if p.InitialSize == 0 {
		p.InitialSize = 4 << 10
	}
	if p.MaximumSize == 0 {
		p.MaximumSize = 64 << 20
	}
	p.MaximumSize = max(p.MaximumSize, p.InitialSize)
	return p
}
