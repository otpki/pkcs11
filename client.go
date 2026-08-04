package pkcs11

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/otpki/pkcs11/raw"
)

// TokenSelector identifies one token-bearing slot. Zero values match any
// token; when multiple tokens match, Open requires a more specific selector.
type TokenSelector struct {
	// SlotID matches the module-assigned PKCS #11 slot identifier. It is more
	// stable than SlotIndex within one running module but may change after token
	// or module reconfiguration.
	SlotID *raw.SlotID
	// SlotIndex selects by position in the token-present slot list returned
	// during discovery. Prefer SlotID or SerialNumber for durable configuration.
	SlotIndex *int
	// Label matches the blank-trimmed token label exactly.
	Label string
	// SerialNumber matches the blank-trimmed token serial number exactly.
	SerialNumber string
	// Model matches the blank-trimmed token model exactly.
	Model string
}

// LoginMode controls when the managed client authenticates to the selected token.
type LoginMode string

const (
	// LoginNone never asks the driver to authenticate automatically. Public
	// operations remain available, while private operations may fail with
	// CKR_USER_NOT_LOGGED_IN.
	LoginNone LoginMode = "none"
	// LoginLazy authenticates on the first operation that requires a logged-in
	// session. This is the default when a PIN provider or protected path exists.
	LoginLazy LoginMode = "lazy"
	// LoginEager establishes the configured login state before Open returns.
	LoginEager LoginMode = "eager"
	// LoginManual defers authentication until Activate is called explicitly.
	LoginManual LoginMode = "manual"
)

// UserRole selects the standard PKCS #11 login role. Vendor login scope is
// detected and managed internally.
type UserRole string

const (
	// UserRoleUser maps to CKU_USER, the normal application identity.
	UserRoleUser UserRole = "user"
	// UserRoleSecurityOfficer maps to CKU_SO and is normally used only for token
	// administration and user-PIN initialization.
	UserRoleSecurityOfficer UserRole = "security-officer"
	// UserRoleContextSpecific maps to CKU_CONTEXT_SPECIFIC for keys configured
	// with CKA_ALWAYS_AUTHENTICATE.
	UserRoleContextSpecific UserRole = "context-specific"
)

// LoginConfig contains application login policy only.
type LoginConfig struct {
	// Mode controls whether and when authentication is performed. The zero value
	// selects LoginLazy when credentials are available, otherwise LoginNone.
	Mode LoginMode
	// Role selects the standard Cryptoki user type. The zero value is UserRoleUser.
	Role UserRole
	// Username is passed only to vendor adapters whose login protocol supports a
	// separate username. Standard PKCS #11 login normally ignores it.
	Username string
}

// userType translates the public role into its raw Cryptoki identifier.
func (config LoginConfig) userType() uint {
	switch config.Role {
	case UserRoleSecurityOfficer:
		return raw.CKU_SO
	case UserRoleContextSpecific:
		return raw.CKU_CONTEXT_SPECIFIC
	default:
		return raw.CKU_USER
	}
}

// SessionConfig controls application resource use. The driver automatically
// clamps these values to token limits and vendor compatibility requirements.
type SessionConfig struct {
	// Min is the number of sessions the pool attempts to establish during
	// activation. Zero allows the pool to start empty.
	Min int
	// Max bounds concurrent leases in each read-only and read-write pool. Zero
	// selects the default; the driver may lower it for token or adapter limits.
	Max int
	// ReadOnlyMax and ReadWriteMax optionally place different bounds on the two
	// pools. Zero inherits Max. MaxTotal remains the authoritative combined native
	// handle limit.
	ReadOnlyMax  int
	ReadWriteMax int
	// MaxTotal bounds the combined number of native session handles owned by
	// both pools. Zero defaults to Max, preventing RO and RW pools from each
	// consuming the complete token session allowance.
	MaxTotal int
	// IdleTimeout replaces unused sessions older than this duration. Zero selects
	// the default; a negative value disables idle-age replacement.
	IdleTimeout time.Duration
	// MaxLifetime retires a native handle after this wall-clock lifetime even when
	// it remains healthy. A negative value disables lifetime retirement.
	MaxLifetime time.Duration
	// MaxOperations retires a native handle after this many managed calls. Zero
	// disables operation-count retirement.
	MaxOperations uint64
	// Async requests CKF_ASYNC_SESSION when both the selected interface and token
	// advertise asynchronous-session support.
	Async bool
}

// DefaultSessionConfig returns the normal bounded pool and idle-replacement
// policy: at most 16 native sessions combined across both pools, with idle
// handles replaced after five minutes.
func DefaultSessionConfig() SessionConfig {
	return SessionConfig{Max: 16, MaxTotal: 16, IdleTimeout: 5 * time.Minute}
}

// normalized applies defaults without applying token- or adapter-specific caps;
// those constraints are enforced when the pools are created.
func (config SessionConfig) normalized() SessionConfig {
	defaults := DefaultSessionConfig()
	if config.Max <= 0 {
		config.Max = defaults.Max
	}
	if config.MaxTotal <= 0 {
		config.MaxTotal = config.Max
	}
	if config.ReadOnlyMax <= 0 {
		config.ReadOnlyMax = config.Max
	}
	if config.ReadWriteMax <= 0 {
		config.ReadWriteMax = config.Max
	}
	if config.IdleTimeout == 0 {
		config.IdleTimeout = defaults.IdleTimeout
	}
	return config
}

// CompatibilityConfig is a deliberately narrow expert surface. Normal
// applications should leave it at its zero value.
type CompatibilityConfig struct {
	// StrictStandard disables vendor aliases and compatibility adaptations. It
	// is intended for conformance testing, not routine production use.
	StrictStandard bool
	// AdapterFamily forces one supplied VendorModule when a module has unusual or
	// redacted fingerprint metadata. Individual behaviors remain owned by that module.
	AdapterFamily AdapterFamily
}

// Config contains application policy. Module initialization/finalization,
// session pooling, login scope, output buffers, recovery, templates, and vendor
// adaptations are owned by the driver.
type Config struct {
	// Module opens the local or remote logical PKCS #11 module. Use
	// LocalModule(path) for a native library or a proxy-provided ModuleSource
	// for a remote target. Sources are immutable and registry-keyed.
	Module ModuleSource
	// Token identifies the one token this Client manages. An empty selector is
	// valid only when exactly one token-present slot is discovered.
	Token TokenSelector
	// PIN supplies credentials on demand. It may be nil for public-only access or
	// when the token uses a protected authentication path.
	PIN PINProvider
	// Login controls authentication timing and role.
	Login LoginConfig
	// Sessions bounds pooled native resources.
	Sessions SessionConfig
	// Retry controls replay of operations that the driver knows are idempotent.
	Retry RetryPolicy
	// Cache controls short-lived object-handle and public-attribute caching.
	Cache CacheConfig
	// Hooks receives lifecycle, operation, and recovery observations.
	Hooks Hooks
	// Compatibility provides the narrow expert controls used for conformance or
	// modules whose identifying strings are unavailable.
	Compatibility CompatibilityConfig
	// Vendors are the candidate VendorModule implementations considered during
	// discovery and dynamic selection. Standard PKCS #11 works with an empty
	// slice; pass vendors/all.Modules() or a smaller explicit set for provider behavior.
	Vendors []VendorModule
}

// validate rejects contradictory policy before a module is loaded or any native
// resources are allocated.
func (config Config) validate() error {
	if err := validateModuleSource(config.Module); err != nil {
		return err
	}
	if config.Compatibility.StrictStandard && config.Compatibility.AdapterFamily != "" {
		return fmt.Errorf("pkcs11: strict-standard mode cannot force a vendor module")
	}
	vendors, _, err := validateVendorModules(mergeSourceVendors(config.Module, config.Vendors))
	if err != nil {
		return fmt.Errorf("pkcs11: %w", err)
	}
	if config.Compatibility.AdapterFamily != "" && !knownAdapterFamily(config.Compatibility.AdapterFamily, vendors) {
		return fmt.Errorf("pkcs11: unknown adapter family %q", config.Compatibility.AdapterFamily)
	}
	if config.Sessions.Min < 0 || config.Sessions.Max < 0 || config.Sessions.MaxTotal < 0 || config.Sessions.ReadOnlyMax < 0 || config.Sessions.ReadWriteMax < 0 {
		return fmt.Errorf("pkcs11: session limits cannot be negative")
	}
	maximum := max(config.Sessions.ReadWriteMax, max(config.Sessions.ReadOnlyMax, config.Sessions.Max))
	if maximum > 0 && config.Sessions.Min > maximum {
		return fmt.Errorf("pkcs11: minimum sessions cannot exceed maximum sessions")
	}
	switch config.Login.Mode {
	case "", LoginNone, LoginLazy, LoginEager, LoginManual:
	default:
		return fmt.Errorf("pkcs11: unsupported login mode %q", config.Login.Mode)
	}
	switch config.Login.Role {
	case "", UserRoleUser, UserRoleSecurityOfficer, UserRoleContextSpecific:
	default:
		return fmt.Errorf("pkcs11: unsupported user role %q", config.Login.Role)
	}
	return nil
}

// Client represents one selected token and owns its module lifecycle, login,
// internal session pools, caching, recovery, and vendor adaptation.
type Client struct {
	// module is shared by every Client opened against the same canonical library
	// path; pools and selected token state remain Client-specific.
	module *moduleRef

	// device may be replaced after rediscovery, so all readers use deviceMu and
	// exported accessors return defensive copies.
	deviceMu      sync.RWMutex
	device        Device
	selector      TokenSelector
	compatibility CompatibilityConfig
	vendors       []VendorModule

	// Separate pools avoid consuming read/write sessions for read-only work while
	// still supporting adapters that force every operation onto the RW pool.
	roPool  *sessionPool
	rwPool  *sessionPool
	retry   RetryPolicy
	cache   *tokenCache
	login   *loginCoordinator
	hooks   Hooks
	limiter *sessionLimiter

	deactivateMu sync.Mutex
	closed       atomic.Bool
	closeOnce    sync.Once
	closeErr     error
}

// Open loads a native module, selects exactly one token, detects its HSM family,
// and creates a managed Client.
//
// The module lifecycle is shared process-wide by canonical library path, while
// token selection, session pools, login state, caches, and recovery policy are
// private to the returned Client. An empty TokenSelector succeeds only when the
// module exposes exactly one token-present slot.
//
// Module loading and discovery are synchronous native operations and cannot be
// interrupted once entered. Open observes ctx during optional eager activation
// and again before returning. Call Close when the Client is no longer needed.
func Open(ctx context.Context, config Config) (*Client, error) {
	if err := config.validate(); err != nil {
		return nil, err
	}
	// Module acquisition performs process-wide load and C_Initialize exactly
	// once for all Clients using the same canonical path.
	module, err := acquireModule(ctx, config.Module)
	if err != nil {
		return nil, err
	}
	client := &Client{
		module: module, selector: config.Token, compatibility: config.Compatibility,
		vendors: append([]VendorModule(nil), mergeSourceVendors(config.Module, config.Vendors)...),
		retry:   config.Retry.normalized(), cache: newTokenCache(config.Cache),
		login: newLoginCoordinator(), hooks: config.Hooks,
	}
	// Every failure after acquisition follows the same idempotent cleanup path.
	cleanup := true
	defer func() {
		if cleanup {
			_ = client.Close()
		}
	}()

	// Discovery fingerprints every token-present slot and dynamically selects
	// the best matching VendorModule supplied in Config.Vendors. When none
	// matches, the standards-only generic module remains available as fallback.
	devices, err := discoverManaged(module, config.Compatibility, client.vendors)
	if err != nil {
		return nil, err
	}
	device, err := selectDevice(devices, config.Token)
	if err != nil {
		return nil, err
	}
	client.device = device
	// Some adapter decisions affect process-wide module behavior. Such decisions
	// are promoted into the shared module before sessions are opened.
	module.applyPlan(device.plan)

	loginMode := config.Login.Mode
	protectedPath := device.Fingerprint.Token.Flags&raw.CKF_PROTECTED_AUTHENTICATION_PATH != 0 || device.plan.login.protectedPathOnEmptyPIN
	if loginMode == "" {
		// Credentials or a protected path imply useful automatic authentication;
		// otherwise default to public-only access rather than prompting unexpectedly.
		if config.PIN != nil || protectedPath {
			loginMode = LoginLazy
		} else {
			loginMode = LoginNone
		}
	}
	sessions := config.Sessions.normalized()
	maxTotal := sessions.MaxTotal
	if reported := device.Fingerprint.Token.MaxSessionCount; reported != 0 && reported != raw.CK_UNAVAILABLE_INFORMATION && uint(maxTotal) > reported {
		maxTotal = int(reported)
	}
	if device.plan.sessions.forceSerial {
		maxTotal = 1
	}
	client.limiter = newSessionLimiter(maxTotal)
	pool := poolConfig{MinSessions: min(sessions.Min, sessions.ReadOnlyMax), MaxSessions: sessions.ReadOnlyMax, IdleTimeout: sessions.IdleTimeout, MaxLifetime: sessions.MaxLifetime, MaxOperations: sessions.MaxOperations}
	base := sessionPoolConfig{
		Owner: client, Module: module, Device: device, Limiter: client.limiter, Async: sessions.Async,
		UserType: config.Login.userType(), Username: config.Login.Username,
		PIN: config.PIN, LoginMode: loginMode,
		ProtectedAuthenticationPath: protectedPath, Pool: pool, Hooks: config.Hooks,
	}
	base.ReadWrite = device.plan.sessions.readWriteOnly
	client.roPool, err = newSessionPool(base)
	if err != nil {
		return nil, err
	}
	base.ReadWrite = true
	base.Pool = poolConfig{MinSessions: min(sessions.Min, sessions.ReadWriteMax), MaxSessions: sessions.ReadWriteMax, IdleTimeout: sessions.IdleTimeout, MaxLifetime: sessions.MaxLifetime, MaxOperations: sessions.MaxOperations}
	client.rwPool, err = newSessionPool(base)
	if err != nil {
		return nil, err
	}
	if loginMode == LoginEager {
		if err := client.Activate(ctx); err != nil {
			return nil, err
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	cleanup = false
	return client, nil
}

// selectDevice applies deterministic selector semantics. SlotIndex is an
// explicit positional selector and therefore takes precedence over all textual
// fields; otherwise every non-zero field is combined with logical AND.
func selectDevice(devices []Device, selector TokenSelector) (Device, error) {
	if len(devices) == 0 {
		return Device{}, fmt.Errorf("pkcs11: module has no token-present slots")
	}
	if selector.SlotIndex != nil {
		index := *selector.SlotIndex
		if index < 0 || index >= len(devices) {
			return Device{}, fmt.Errorf("pkcs11: slot index %d outside [0,%d)", index, len(devices))
		}
		return devices[index], nil
	}
	var matches []Device
	for _, device := range devices {
		fingerprint := device.Fingerprint
		if selector.SlotID != nil && fingerprint.SlotID != *selector.SlotID {
			continue
		}
		if selector.Label != "" && fingerprint.Token.Label != selector.Label {
			continue
		}
		if selector.SerialNumber != "" && fingerprint.Token.SerialNumber != selector.SerialNumber {
			continue
		}
		if selector.Model != "" && fingerprint.Token.Model != selector.Model {
			continue
		}
		matches = append(matches, device)
	}
	if len(matches) == 0 {
		return Device{}, fmt.Errorf("pkcs11: no token matches selector")
	}
	if len(matches) > 1 {
		return Device{}, fmt.Errorf("pkcs11: selector matches %d tokens; add slot ID or serial number", len(matches))
	}
	return matches[0], nil
}

// ModulePath returns the canonical native-library path used by the Client. It
// returns an empty string for a nil or uninitialized Client.
func (c *Client) ModulePath() string {
	if c == nil || c.module == nil {
		return ""
	}
	return c.module.path
}

// Interface returns metadata for the Cryptoki interface selected while loading
// the module. The zero value is returned for a nil or uninitialized Client.
func (c *Client) Interface() raw.InterfaceInfo {
	if c == nil || c.module == nil {
		return raw.InterfaceInfo{}
	}
	return c.module.raw.Interface()
}

// Version returns the version of the selected Cryptoki interface.
func (c *Client) Version() raw.Version { return c.Interface().Version }

// currentDevice returns the current internal snapshot. Callers that expose the
// value publicly must clone it before returning.
func (c *Client) currentDevice() Device {
	if c == nil {
		return Device{}
	}
	c.deviceMu.RLock()
	defer c.deviceMu.RUnlock()
	return c.device
}

// Device returns an independent diagnostics snapshot. Mutating its maps or
// slices cannot alter the driver's selected adapter or behavior plan.
func (c *Client) Device() Device { return cloneDevice(c.currentDevice()) }

// Adapter returns diagnostics for the automatically selected HSM-family
// adapter. It does not expose or permit mutation of private compatibility rules.
func (c *Client) Adapter() AdapterInfo { return cloneAdapterInfo(c.currentDevice().Adapter) }

// Capabilities returns an independent snapshot of the token's advertised
// standard capabilities plus any identifiers supplied by the selected adapter
// or configured extensions.
func (c *Client) Capabilities() Capabilities {
	return cloneCapabilities(c.currentDevice().Capabilities)
}

// LoginScope reports how the selected module applies ordinary user login to
// native sessions. The proxy uses this to decide whether one control-session
// login is sufficient or every physical session must authenticate separately.
type LoginScope string

const (
	// LoginScopeAuto follows standard application-wide token login semantics and
	// relies on ordinary recovery if a provider does not preserve that state.
	LoginScopeAuto LoginScope = "auto"
	// LoginScopeToken coordinates one login state for the token/application.
	LoginScopeToken LoginScope = "token"
	// LoginScopeSession requires each newly used native session to log in.
	LoginScopeSession LoginScope = "session"
)

// LoginScope returns the effective login scope selected by vendor detection.
func (c *Client) LoginScope() LoginScope {
	if c == nil {
		return LoginScopeAuto
	}
	switch c.currentDevice().plan.login.scope {
	case loginScopeToken:
		return LoginScopeToken
	case loginScopeSession:
		return LoginScopeSession
	default:
		return LoginScopeAuto
	}
}

// SessionStats reports read-only and read-write pool usage.
type SessionStats struct {
	// ReadOnly describes the pool normally used for non-mutating operations.
	ReadOnly PoolStats `json:"read_only"`
	// ReadWrite describes the pool used for object mutation and adapters that
	// require read/write sessions for every operation.
	ReadWrite PoolStats `json:"read_write"`
}

// SessionStats returns a point-in-time snapshot of both internal pools.
func (c *Client) SessionStats() SessionStats {
	if c == nil {
		return SessionStats{}
	}
	return SessionStats{ReadOnly: c.roPool.stats(), ReadWrite: c.rwPool.stats()}
}

// Activate eagerly establishes each pool's minimum sessions and the configured
// login state. It is primarily useful with LoginManual; LoginLazy activates
// resources automatically as operations need them.
func (c *Client) Activate(ctx context.Context) error {
	if c == nil || c.closed.Load() {
		return errors.New("pkcs11: client is closed")
	}
	if err := c.roPool.Activate(ctx); err != nil {
		return err
	}
	return c.rwPool.Activate(ctx)
}

// Deactivate drains both pools, performs at most one coordinated physical
// logout, and closes pooled sessions without unloading the module. It leaves
// automatic login disabled; call Activate to re-enable login and warm sessions.
func (c *Client) Deactivate(ctx context.Context) error {
	if c == nil || c.closed.Load() {
		return errors.New("pkcs11: client is closed")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	// PKCS #11 login state is commonly application-wide. Deactivation must
	// therefore drain both pools and issue at most one C_Logout; allowing each
	// pool to log out independently can race active work and invalidate sibling
	// sessions unexpectedly.
	c.deactivateMu.Lock()
	deactivated := false
	roWasActive := c.roPool.beginDeactivate()
	rwWasActive := c.rwPool.beginDeactivate()
	defer func() {
		c.roPool.endDeactivate(!deactivated && roWasActive)
		c.rwPool.endDeactivate(!deactivated && rwWasActive)
		c.deactivateMu.Unlock()
	}()

	if err := c.roPool.waitDrained(ctx); err != nil {
		return err
	}
	if err := c.rwPool.waitDrained(ctx); err != nil {
		return err
	}

	var (
		pool    *sessionPool
		item    pooledSession
		cleanup func() error
	)
	for _, candidate := range []*sessionPool{c.rwPool, c.roPool} {
		selected, selectedCleanup, ok, err := candidate.takeIdleForDeactivate(ctx)
		if err != nil {
			return err
		}
		if ok {
			pool, item, cleanup = candidate, selected, selectedCleanup
			break
		}
	}
	if pool == nil {
		pool = c.rwPool
		if err := pool.module.acquireLease(); err != nil {
			return err
		}
		opened, err := pool.openHandle(ctx, false)
		if err != nil {
			pool.module.releaseLease()
			return err
		}
		item = opened
		cleanup = func() error {
			err := pool.closeHandle(item)
			pool.module.releaseLease()
			return err
		}
	}

	logoutErr := pool.execute(ctx, item.worker, func(module raw.Module) error {
		return module.Logout(item.handle)
	})
	if raw.IsError(logoutErr, raw.CKR_USER_NOT_LOGGED_IN) {
		logoutErr = nil
	}
	closeErr := cleanup()

	device := c.currentDevice()
	if c.login != nil {
		c.login.resetSlot(device.Fingerprint.SlotID)
	}
	// Any other idle session may carry obsolete token-wide login or operation
	// state. Close it rather than letting a later caller inherit that state.
	c.roPool.Invalidate()
	c.rwPool.Invalidate()
	c.cache.invalidate()
	deactivated = true
	return errors.Join(logoutErr, closeErr)
}

// sessionOptions is the internal execution contract shared by high-level and raw
// session operations.
type sessionOptions struct {
	ReadWrite  bool
	Idempotent bool
	Operation  string
	Retry      *RetryPolicy
}

// RawModuleOptions controls a direct module-level callback. Most applications
// should use Device, Capabilities, Health, and WatchSlotEvents instead.
type RawModuleOptions struct {
	// Operation is used for tracing, metrics, and audit hooks.
	Operation string
}

// WithRawModule runs an advanced non-session Cryptoki operation while retaining
// module lifecycle protection, vendor serialization, OS-thread affinity, and
// observability. The raw context is valid only during fn and must not be stored.
//
// Prefer the high-level Client methods or an vendors/<vendor> helper whenever one
// models the operation: raw callbacks intentionally expose ABI-level behavior.
func (c *Client) WithRawModule(ctx context.Context, options RawModuleOptions, fn func(raw.Module) error) error {
	if fn == nil {
		return fmt.Errorf("pkcs11: nil raw module callback")
	}
	operation := strings.TrimSpace(options.Operation)
	if operation == "" {
		operation = "raw-module"
	}
	return c.call(ctx, operation, fn)
}

// RawSessionOptions controls the managed session used by WithRawSession.
//
// Raw callbacks participate in the same session pooling, login, serialization,
// OS-thread affinity, stale-session replacement, and retry machinery as the
// high-level API. Set Idempotent only when replaying the complete callback is
// safe: a transport failure can occur after an HSM has already completed an
// operation even though the caller did not receive its result.
type RawSessionOptions struct {
	// ReadWrite requests a read/write PKCS #11 session. It is required for
	// object creation, mutation, and destruction on most tokens.
	ReadWrite bool
	// Idempotent permits the driver to replay the entire callback after a
	// recoverable session or device failure.
	Idempotent bool
	// Operation is used only for diagnostics, tracing, and audit hooks.
	Operation string
	// Retry overrides the client retry policy for this callback. A nil value
	// uses the policy configured on Client.
	Retry *RetryPolicy
}

// WithRawSession is the advanced escape hatch for Cryptoki operations that are
// not modeled by the high-level Client API or by an vendors/<vendor> package.
//
// The callback receives the complete raw PKCS #11 module and a managed session
// handle. The handle is valid only for the duration of the callback and must not
// be retained. Calls must be made synchronously from the callback so adapters
// that require module serialization or OS-thread affinity remain correct.
func (c *Client) WithRawSession(
	ctx context.Context,
	options RawSessionOptions,
	fn func(raw.Module, raw.SessionHandle) error,
) error {
	if fn == nil {
		return fmt.Errorf("pkcs11: nil raw session callback")
	}
	operation := strings.TrimSpace(options.Operation)
	if operation == "" {
		operation = "raw-session"
	}
	// The public raw callback is reduced to the same internal execution contract
	// used by modeled operations, so it receives identical recovery semantics.
	err := c.withSession(ctx, sessionOptions{
		ReadWrite:  options.ReadWrite,
		Idempotent: options.Idempotent,
		Operation:  operation,
		Retry:      options.Retry,
	}, func(session *sessionLease) error {
		return session.DoRaw(ctx, fn)
	})
	if options.ReadWrite && c != nil && c.cache != nil {
		// A raw write callback may have changed any object or attribute. The
		// driver cannot infer the exact mutation, so invalidate conservatively.
		c.cache.invalidate()
	}
	return err
}

// withReadOnlySession runs an idempotent operation through the preferred pool.
func (c *Client) withReadOnlySession(ctx context.Context, fn func(*sessionLease) error) error {
	return c.withSession(ctx, sessionOptions{Operation: "session", Idempotent: true}, fn)
}

// withReadWriteSession runs a non-replayable mutating operation through the RW
// pool unless the caller supplies a more specific sessionOptions contract.
func (c *Client) withReadWriteSession(ctx context.Context, fn func(*sessionLease) error) error {
	return c.withSession(ctx, sessionOptions{ReadWrite: true, Operation: "session"}, fn)
}

// withSession is the central acquire, execute, classify, recover, and retry loop.
// It retries only when the complete operation is explicitly marked idempotent.
func (c *Client) withSession(ctx context.Context, options sessionOptions, fn func(*sessionLease) error) error {
	if c == nil || c.closed.Load() {
		return errors.New("pkcs11: client is closed")
	}
	if fn == nil {
		return fmt.Errorf("pkcs11: nil session callback")
	}
	policy := c.retry
	if options.Retry != nil {
		policy = options.Retry.normalized()
	}
	if !options.Idempotent {
		// A device error may be reported after the HSM committed an operation.
		// Never replay a mutation or signature unless the caller proved safety.
		policy.MaxAttempts = 1
	}
	pool := c.roPool
	if c.currentDevice().plan.sessions.readWriteOnly {
		// Some modules reject RO sessions or implement only one effective session
		// class. The adapter hides that detail from high-level callers.
		options.ReadWrite = true
	}
	if options.ReadWrite {
		pool = c.rwPool
	}
	var last error
	for attempt := 1; attempt <= policy.MaxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		session, err := pool.Acquire(ctx)
		if err != nil {
			last = err
		} else {
			// Operation metadata is attached before execution so hooks and pool
			// diagnostics can attribute failures to this attempt.
			session.operation = options.Operation
			session.attempt = attempt
			func() {
				defer func() {
					if recovered := recover(); recovered != nil {
						// A panic can leave unknown native operation state. Discard the
						// session before propagating the panic to the application.
						session.MarkBroken()
						_ = session.Close()
						panic(recovered)
					}
				}()
				last = fn(session)
				if action := classifyDeviceError(c.currentDevice(), last, policy.RetryGeneralErrors); action != RecoveryNone {
					session.MarkBroken()
				}
				if closeErr := session.Close(); last == nil && closeErr != nil {
					last = closeErr
				}
			}()
		}
		action := classifyDeviceError(c.currentDevice(), last, policy.RetryGeneralErrors)
		if last == nil || attempt >= policy.MaxAttempts || action == RecoveryNone {
			return last
		}
		if recoveryErr := c.recover(ctx, action); recoveryErr != nil {
			return errors.Join(last, recoveryErr)
		}
		delay := policy.delay(attempt)
		if delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
	}
	return last
}

// recover invalidates all state that may have become stale, then performs the
// minimum module-level action requested by error classification.
func (c *Client) recover(ctx context.Context, action RecoveryAction) error {
	// Invalidate first so no concurrent acquisition can reuse a session, login
	// assumption, or object handle from before recovery.
	c.roPool.Invalidate()
	c.rwPool.Invalidate()
	c.cache.invalidate()
	c.login.reset()
	if action == RecoveryRelogin {
		return nil
	}
	if action == RecoveryReinitialize || action == RecoveryRediscover {
		if err := c.module.reinitialize(c.currentDevice().plan); err != nil {
			return err
		}
	}
	if action == RecoveryRediscover {
		// Rediscovery may select a changed slot, adapter, capability set, or output
		// buffer policy after token replacement or network failover.
		current := c.currentDevice()
		devices, err := discoverManagedWithPlan(c.module, current.plan, c.compatibility, c.vendors)
		if err != nil {
			return err
		}
		device, err := selectDevice(devices, c.selector)
		if err != nil {
			return err
		}
		c.deviceMu.Lock()
		c.device = device
		c.deviceMu.Unlock()
		c.module.applyPlan(device.plan)
		c.roPool.SetDevice(device)
		c.rwPool.SetDevice(device)
	}
	return ctx.Err()
}

// invalidateState discards all Client-local state derived from native sessions
// without reinitializing or unloading the shared module.
func (c *Client) invalidateState() {
	if c == nil {
		return
	}
	if c.roPool != nil {
		c.roPool.Invalidate()
	}
	if c.rwPool != nil {
		c.rwPool.Invalidate()
	}
	if c.cache != nil {
		c.cache.invalidate()
	}
	if c.login != nil {
		c.login.reset()
	}
}

// Resolve translates a vendor-neutral Intent into the concrete standard or
// vendor route selected for this token. Standard PKCS #11 mechanisms are
// preferred whenever the token advertises them.
func (c *Client) Resolve(intent Intent) (Route, error) {
	return ResolveRoute(c.currentDevice(), intent)
}

// Close releases both pools and the Client's process-wide module reference. The
// underlying shared library is finalized and unloaded only after the final
// Client using that canonical module path closes. Close is idempotent and may be
// called concurrently.
func (c *Client) Close() error {
	if c == nil {
		return nil
	}
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		var errs []error
		if c.roPool != nil {
			if err := c.roPool.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		if c.rwPool != nil {
			if err := c.rwPool.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		if c.limiter != nil {
			c.limiter.close()
		}
		if err := releaseModule(c.module); err != nil {
			errs = append(errs, err)
		}
		c.closeErr = errors.Join(errs...)
	})
	return c.closeErr
}

// rawModule returns the internally owned raw context. It must never escape the
// managed operation that requested it.
func (c *Client) rawModule() raw.Module { return c.module.raw }
