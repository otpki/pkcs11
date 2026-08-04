package raw

import "errors"

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

// OpenConfig controls how Open chooses a function table from a loaded PKCS #11
// module.
//
// PKCS #11 3.0 introduced C_GetInterface, which allows a module to expose
// named and versioned function tables. Older modules expose only one table
// through C_GetFunctionList. Open tries Versions in order and optionally falls
// back to the legacy table.
//
// OpenConfig does not control C_Initialize, slot selection, session flags,
// login, or mechanism policy. Those occur after the module is opened.
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
		c.Versions = append([]Version(nil), versions...)
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

// ResolveOpenConfig applies options to the defaults used by Open and returns an
// independent configuration value.
//
// The returned Versions slice does not alias the defaults or a slice captured
// by WithInterfaceVersions. Managed module registries can therefore retain and
// compare the result when deciding whether multiple clients may safely share
// one process-wide native module instance.
func ResolveOpenConfig(options ...OpenOption) OpenConfig {
	config := defaultOpenConfig()
	for _, option := range options {
		if option != nil {
			option(&config)
		}
	}

	config.Versions = append([]Version(nil), config.Versions...)
	return config
}

// OutputBufferPolicy controls compatibility behavior for Cryptoki functions
// that produce variable-length output.
//
// The normal PKCS #11 convention is a two-call sequence:
//
//  1. Call with a nil output pointer to obtain the required length.
//  2. Allocate that many bytes and call again to receive the output.
//
// Some vendor modules reject the nil-pointer probe even for operations where
// the specification permits it. RejectNullProbe enables a bounded fallback
// that starts with InitialSize bytes and grows the buffer when the module
// returns CKR_BUFFER_TOO_SMALL, never exceeding MaximumSize.
//
// This policy affects raw output-buffer allocation only. It does not alter
// mechanism selection, retry semantics, session recovery, or operation limits
// imposed by the token itself.
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
	if p.MaximumSize < p.InitialSize {
		p.MaximumSize = p.InitialSize
	}
	return p
}
