package proxy

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/raw"
)

// SessionBudget is the authoritative physical-resource budget for one HSM
// target. Virtual client sessions consume no physical handle until work is
// admitted or state must be pinned.
type SessionBudget struct {
	// MaxPhysicalTotal is the authoritative combined number of native HSM
	// sessions, including the reserved control session, idle pool entries,
	// checked-out calls, multipart pins, and session-object affinity.
	MaxPhysicalTotal int
	// MaxPhysicalReadWrite bounds the subset of native sessions opened read/write.
	MaxPhysicalReadWrite int
	// ReservedControlSessions is currently required to be exactly one. The
	// control session anchors token-wide login and prevents last-session logout.
	ReservedControlSessions int
	// MaxPinned bounds physical leases retained across network requests by
	// multipart operations or session objects.
	MaxPinned int
	// MaxQueued bounds requests admitted to wait for a physical session. A full
	// queue fails immediately rather than accumulating unbounded goroutines.
	MaxQueued int
	// MaxClients bounds concurrently retained logical Cryptoki applications.
	MaxClients int
	// MaxVirtualSessionsTotal bounds virtual sessions across all logical clients.
	// Opening a virtual session does not itself consume a physical HSM session.
	MaxVirtualSessionsTotal int
	// MaxVirtualSessionsPerClient bounds virtual sessions owned by one Client ID.
	MaxVirtualSessionsPerClient int
	// MaxObjectsPerClient bounds virtual object-handle mappings retained for one
	// logical client.
	MaxObjectsPerClient int
	// QueueTimeout bounds how long an admitted request may wait for native
	// session capacity.
	QueueTimeout time.Duration
	// VirtualSessionIdleTimeout expires an unused virtual session and releases any
	// associated session objects or pinned operation.
	VirtualSessionIdleTimeout time.Duration
	// PinnedOperationIdleTimeout cancels or discards an abandoned multipart or
	// session-object-affine physical lease.
	PinnedOperationIdleTimeout time.Duration
	// ClientIdleTimeout expires an inactive logical client after all in-flight
	// requests have drained.
	ClientIdleTimeout time.Duration
	// MaxSessionLifetime proactively rotates otherwise healthy native sessions,
	// protecting long-running brokers from vendor middleware age limits.
	MaxSessionLifetime time.Duration
	// MaxOperationsPerSession retires a native session after this many managed
	// calls. Zero disables operation-count retirement.
	MaxOperationsPerSession uint64
	// DedupEntries bounds request IDs retained for replay of non-idempotent calls.
	DedupEntries int
	// DedupMaximumBytes bounds completed response material retained for
	// same-request replay after a dropped connection. One response may exceed
	// this limit, but all other completed entries are evicted in that case.
	DedupMaximumBytes int
	// DedupTTL bounds how long a completed non-idempotent response can be replayed.
	DedupTTL time.Duration
}

func (budget SessionBudget) normalized() SessionBudget {
	if budget.MaxPhysicalTotal <= 0 {
		budget.MaxPhysicalTotal = 16
	}
	if budget.ReservedControlSessions <= 0 {
		budget.ReservedControlSessions = 1
	}
	if budget.MaxPhysicalReadWrite <= 0 || budget.MaxPhysicalReadWrite > budget.MaxPhysicalTotal {
		budget.MaxPhysicalReadWrite = budget.MaxPhysicalTotal
	}
	if budget.MaxPinned <= 0 {
		budget.MaxPinned = max(1, (budget.MaxPhysicalTotal-budget.ReservedControlSessions)/2)
	}
	if budget.MaxQueued <= 0 {
		budget.MaxQueued = 256
	}
	if budget.MaxClients <= 0 {
		budget.MaxClients = 4096
	}
	if budget.MaxVirtualSessionsTotal <= 0 {
		budget.MaxVirtualSessionsTotal = 16384
	}
	if budget.MaxVirtualSessionsPerClient <= 0 {
		budget.MaxVirtualSessionsPerClient = 64
	}
	if budget.MaxObjectsPerClient <= 0 {
		budget.MaxObjectsPerClient = 4096
	}
	if budget.QueueTimeout <= 0 {
		budget.QueueTimeout = 5 * time.Second
	}
	if budget.VirtualSessionIdleTimeout <= 0 {
		budget.VirtualSessionIdleTimeout = 15 * time.Minute
	}
	if budget.PinnedOperationIdleTimeout <= 0 {
		budget.PinnedOperationIdleTimeout = 2 * time.Minute
	}
	if budget.ClientIdleTimeout <= 0 {
		budget.ClientIdleTimeout = 30 * time.Minute
	}
	if budget.DedupEntries <= 0 {
		budget.DedupEntries = 4096
	}
	if budget.DedupMaximumBytes <= 0 {
		budget.DedupMaximumBytes = 64 << 20
	}
	if budget.DedupTTL <= 0 {
		budget.DedupTTL = 10 * time.Minute
	}
	return budget
}

// LoginAttempt is presented to the logical authenticator before a client is
// granted access to private operations. PIN is a short-lived copy and must not
// be retained.
type LoginAttempt struct {
	// Identity describes the authenticated transport principal and requested route.
	Identity RequestIdentity
	// UserType and Username are the logical Cryptoki identity requested by the
	// remote client. Shared targets normally permit only the configured physical
	// CKU_USER identity.
	UserType uint
	Username string
	// PIN is the client-provided login credential. It is wiped after the
	// callback returns. In PhysicalLoginClientActivated mode, the exact caller
	// selected as activation leader also supplies this value to the physical
	// C_Login/C_LoginUser call; followers and already-active clients use it only
	// for this logical authentication callback.
	PIN []byte
}

// LogicalAuthenticator validates or audits every remote client's login
// credential and workload policy. In client-activated mode this callback runs
// for every caller before the target-wide activation coordinator is entered;
// only the selected activation leader's PIN can subsequently reach the HSM.
type LogicalAuthenticator func(context.Context, LoginAttempt) error

// LoginPolicy separates client authorization from the physical HSM login
// coordinated by the broker.
type LoginPolicy struct {
	// Mode selects whether the physical PIN is server-managed, supplied by the
	// first activating client, or obtained through a protected authentication
	// path. The zero value infers server-managed mode when PhysicalPIN is set and
	// protected-path mode when the token advertises it. Client-activated mode must
	// be selected explicitly.
	Mode PhysicalLoginMode
	// PhysicalPIN supplies the broker-owned credential in server-managed mode. It
	// is never sent to clients. It must be nil in client-activated and protected-
	// path modes.
	PhysicalPIN pkcs11.PINProvider
	// PhysicalUserType and PhysicalUsername select the one physical identity the
	// shared broker keeps active. Zero PhysicalUserType defaults to CKU_USER.
	PhysicalUserType uint
	PhysicalUsername string
	// Authenticate validates client-provided logical credentials and application
	// policy before a logical grant is issued. In client-activated mode it runs
	// before the PIN can reach the HSM. It must not retain LoginAttempt.PIN.
	Authenticate LogicalAuthenticator
	// TrustTransportIdentity grants logical login after the network principal has
	// been authenticated, without a separate logical credential check. It
	// requires verified mTLS or ServerConfig.Authenticator/Authorizer.
	TrustTransportIdentity bool
	// AllowedUserTypes restricts logical C_Login/C_LoginUser requests. Empty means
	// only PhysicalUserType is allowed.
	AllowedUserTypes []uint
	// EagerPhysicalLogin establishes physical login while the target is opened.
	// It is valid only for server-managed and protected-path modes.
	EagerPhysicalLogin bool
	// ActivationFailureCooldown suppresses repeated physical attempts for a
	// short interval after a failed client activation. Zero selects a conservative
	// one-second default so a burst of independently scheduled pods cannot turn
	// into many sequential HSM PIN attempts; a negative value disables the
	// post-failure cooldown. Concurrent callers always collapse onto one attempt.
	ActivationFailureCooldown time.Duration
}

// MaintenancePolicy gates destructive token administration. Normal shared
// application targets should leave Enabled false.
type MaintenancePolicy struct {
	// Enabled permits token initialization, PIN administration, and SO-oriented
	// operations. Shared application targets should leave it false.
	Enabled bool
	// Authorize is called for each maintenance method after transport
	// authentication. A nil callback denies maintenance even when Enabled is true.
	Authorize func(context.Context, RequestIdentity, string) error
}

// TargetConfig binds one public route to one local managed HSM client.
type TargetConfig struct {
	// ID is the public route name selected by proxy.Target.Route.
	ID string
	// Revision is the immutable configuration version accepted from clients.
	// ReplaceTarget should publish a new revision whenever local module, token,
	// vendor, login, policy, or resource configuration changes.
	Revision string
	// Client configures the local managed PKCS #11 client. The broker overrides
	// its login mode and session limits so physical ownership remains centralized.
	// Client.PIN must be nil; physical credentials are configured only through
	// Login.PhysicalPIN or supplied by an activating remote client.
	Client pkcs11.Config
	// Sessions defines all physical and virtual resource bounds for this target.
	Sessions SessionBudget
	// Login separates logical client authorization from physical HSM activation.
	Login LoginPolicy
	// Authorize applies target-level authorization after transport authentication
	// and before HSM capacity is consumed. It also receives the synthetic
	// AuthorizationOperationActivateTarget operation for the exact client selected
	// to activate an inactive client-activated target.
	Authorize OperationAuthorizer
	// Maintenance gates destructive or application-wide token administration.
	Maintenance MaintenancePolicy
	// Codecs adds target-specific semantic vendor parameter codecs. Codecs
	// contributed by Client.Vendors are merged automatically.
	Codecs []ParameterCodec
}

func cloneTargetConfig(config TargetConfig) TargetConfig {
	config.Client.Vendors = append([]pkcs11.VendorModule(nil), config.Client.Vendors...)
	config.Login.AllowedUserTypes = append([]uint(nil), config.Login.AllowedUserTypes...)
	config.Codecs = append([]ParameterCodec(nil), config.Codecs...)
	return config
}

// TargetStats is a point-in-time view of one broker route. It intentionally
// reports counts and configured limits only; no PIN, object label, key ID, or
// operation payload is exposed.
type TargetStats struct {
	// Clients is the number of retained logical Cryptoki applications.
	Clients int `json:"clients"`
	// Authenticated is the number of logical clients with at least one grant.
	Authenticated int `json:"authenticated_clients"`
	// VirtualSessions is the total remote session count across clients.
	VirtualSessions int `json:"virtual_sessions"`
	// PinnedSessions is the number of physical leases retained across requests.
	PinnedSessions int `json:"pinned_sessions"`
	// QueuedRequests is the number currently admitted to the physical-session wait path.
	QueuedRequests int `json:"queued_requests"`
	// PhysicalOpened and PhysicalActive report managed native pool usage.
	PhysicalOpened int `json:"physical_opened"`
	PhysicalActive int `json:"physical_active"`
	// MaxPhysical, MaxPinned, MaxQueued, and MaxVirtual are configured limits.
	MaxPhysical int `json:"max_physical"`
	MaxPinned   int `json:"max_pinned"`
	MaxQueued   int `json:"max_queued"`
	MaxVirtual  int `json:"max_virtual"`
	// DedupEntries and DedupBytes report retained non-idempotent replay results.
	DedupEntries int `json:"dedup_entries"`
	DedupBytes   int `json:"dedup_bytes"`
	// MaxDedupBytes is the configured completed-response memory bound.
	MaxDedupBytes int `json:"max_dedup_bytes"`
	// Activation reports secret-free physical-login state and generation.
	Activation ActivationStatus `json:"activation"`
}

func (target *brokerTarget) stats() TargetStats {
	if target == nil {
		return TargetStats{}
	}
	target.clientsMu.Lock()
	clients := make([]*logicalClient, 0, len(target.clients))
	for _, client := range target.clients {
		clients = append(clients, client)
	}
	target.clientsMu.Unlock()
	authenticated := 0
	for _, client := range clients {
		if client.authenticated() {
			authenticated++
		}
	}
	client := target.currentClient()
	pool := pkcs11.SessionStats{}
	if client != nil {
		pool = client.SessionStats()
	}
	dedupEntries, dedupBytes := target.ledger.stats()
	return TargetStats{
		Clients: len(clients), Authenticated: authenticated,
		VirtualSessions: int(target.virtualSessions.Load()),
		PinnedSessions:  int(target.pinned.Load()), QueuedRequests: len(target.queueSlots),
		PhysicalOpened: pool.ReadOnly.Opened + pool.ReadWrite.Opened,
		PhysicalActive: pool.ReadOnly.Active + pool.ReadWrite.Active,
		MaxPhysical:    target.budget.MaxPhysicalTotal, MaxPinned: target.budget.MaxPinned,
		MaxQueued: target.budget.MaxQueued, MaxVirtual: target.budget.MaxVirtualSessionsTotal,
		DedupEntries: dedupEntries, DedupBytes: dedupBytes, MaxDedupBytes: target.budget.DedupMaximumBytes,
		Activation: target.activation.snapshot(),
	}
}

type brokerTarget struct {
	id               string
	revision         string
	epochMu          sync.RWMutex
	epoch            [16]byte
	clientMu         sync.RWMutex
	client           *pkcs11.Client
	clientConfig     pkcs11.Config
	registry         *CodecRegistry
	budget           SessionBudget
	login            LoginPolicy
	authorize        OperationAuthorizer
	maintenance      MaintenancePolicy
	control          *pkcs11.RawSessionLease
	activation       activationCoordinator
	physicalUserType uint
	physicalUsername string
	loginScope       pkcs11.LoginScope
	controlMu        sync.Mutex
	remoteSlot       raw.SlotID
	physicalSlot     raw.SlotID

	clientsMu       sync.Mutex
	clients         map[[16]byte]*logicalClient
	queueSlots      chan struct{}
	pinned          atomic.Int64
	virtualSessions atomic.Int64
	ledger          *dedupLedger
	maintenanceLock sync.RWMutex
	closed          atomic.Bool
	stop            chan struct{}
	closeOnce       sync.Once
	closeErr        error
}

func (target *brokerTarget) currentEpoch() [16]byte {
	if target == nil {
		return [16]byte{}
	}
	target.epochMu.RLock()
	epoch := target.epoch
	target.epochMu.RUnlock()
	return epoch
}

func (target *brokerTarget) rotateEpoch() error {
	var epoch [16]byte
	if _, err := rand.Read(epoch[:]); err != nil {
		return fmt.Errorf("generate target epoch: %w", err)
	}
	target.epochMu.Lock()
	target.epoch = epoch
	target.epochMu.Unlock()
	return nil
}

func brokerClientConfig(config pkcs11.Config, budget SessionBudget) pkcs11.Config {
	config.Sessions.Min = 0
	config.Sessions.Max = budget.MaxPhysicalTotal
	config.Sessions.MaxTotal = budget.MaxPhysicalTotal
	config.Sessions.ReadOnlyMax = budget.MaxPhysicalTotal
	config.Sessions.ReadWriteMax = budget.MaxPhysicalReadWrite
	config.Sessions.MaxLifetime = budget.MaxSessionLifetime
	config.Sessions.MaxOperations = budget.MaxOperationsPerSession
	config.Login.Mode = pkcs11.LoginNone
	config.PIN = nil
	return config
}

func (target *brokerTarget) currentClient() *pkcs11.Client {
	if target == nil {
		return nil
	}
	target.clientMu.RLock()
	client := target.client
	target.clientMu.RUnlock()
	return client
}

// swapClient atomically replaces the managed local client and returns the
// previous value. Callers must hold maintenanceLock for writing before using
// this helper so no ordinary request can retain a client from the old token
// generation while a maintenance operation publishes the replacement.
func (target *brokerTarget) swapClient(replacement *pkcs11.Client) *pkcs11.Client {
	if target == nil {
		return nil
	}
	target.clientMu.Lock()
	previous := target.client
	target.client = replacement
	target.clientMu.Unlock()
	return previous
}

func newBrokerTarget(ctx context.Context, config TargetConfig) (*brokerTarget, error) {
	config.ID = strings.TrimSpace(config.ID)
	config.Revision = strings.TrimSpace(config.Revision)
	if config.ID == "" || config.Revision == "" {
		return nil, fmt.Errorf("target ID and revision are required")
	}
	budget := config.Sessions.normalized()
	if budget.MaxPhysicalTotal <= budget.ReservedControlSessions {
		return nil, fmt.Errorf("MaxPhysicalTotal must exceed reserved control sessions")
	}
	if budget.ReservedControlSessions != 1 {
		return nil, fmt.Errorf("ReservedControlSessions must be exactly 1")
	}
	if budget.MaxPinned > budget.MaxPhysicalTotal-budget.ReservedControlSessions {
		budget.MaxPinned = budget.MaxPhysicalTotal - budget.ReservedControlSessions
	}
	registry, err := NewCodecRegistry(combinedCodecs(config.Codecs, config.Client.Vendors)...)
	if err != nil {
		return nil, err
	}
	if config.Login.Authenticate == nil && !config.Login.TrustTransportIdentity {
		return nil, fmt.Errorf("logical Authenticate or TrustTransportIdentity is required")
	}
	if config.Client.PIN != nil {
		return nil, fmt.Errorf("TargetConfig.Client.PIN is not used by the broker; configure Login.PhysicalPIN for server-managed mode or leave both nil for client-activated mode")
	}
	clientConfig := brokerClientConfig(config.Client, budget)
	client, err := pkcs11.Open(ctx, clientConfig)
	if err != nil {
		return nil, err
	}
	mode, err := config.Login.resolvePhysicalMode(client.Device().Fingerprint.Token)
	if err != nil {
		_ = client.Close()
		return nil, err
	}
	config.Login.Mode = mode
	if mode == PhysicalLoginClientActivated {
		switch {
		case config.Login.ActivationFailureCooldown == 0:
			config.Login.ActivationFailureCooldown = defaultActivationFailureCooldown
		case config.Login.ActivationFailureCooldown < 0:
			config.Login.ActivationFailureCooldown = 0
		}
	}
	if mode == PhysicalLoginClientActivated && client.LoginScope() == pkcs11.LoginScopeSession {
		_ = client.Close()
		return nil, clientActivationUnsupportedError("selected vendor requires per-session physical login; the broker cannot authenticate future sessions without retaining the client PIN")
	}
	physicalUserType := config.Login.PhysicalUserType
	if physicalUserType == 0 {
		physicalUserType = raw.CKU_USER
	}
	for _, userType := range config.Login.AllowedUserTypes {
		if userType != physicalUserType {
			_ = client.Close()
			return nil, fmt.Errorf("logical user type %d does not match the configured physical identity %d", userType, physicalUserType)
		}
	}
	if physicalUserType == raw.CKU_SO {
		if !config.Maintenance.Enabled {
			_ = client.Close()
			return nil, fmt.Errorf("CKU_SO physical identity requires maintenance mode")
		}
		if budget.MaxClients != 1 {
			_ = client.Close()
			return nil, fmt.Errorf("CKU_SO maintenance target requires MaxClients=1")
		}
	}
	target := &brokerTarget{
		id: config.ID, revision: config.Revision, client: client, clientConfig: clientConfig, registry: registry,
		budget: budget, login: config.Login, authorize: config.Authorize, maintenance: config.Maintenance,
		activation:       newActivationCoordinator(),
		physicalUserType: physicalUserType, physicalUsername: config.Login.PhysicalUsername,
		loginScope: client.LoginScope(), remoteSlot: raw.SlotID(1), physicalSlot: client.Device().Fingerprint.SlotID,
		clients: make(map[[16]byte]*logicalClient), queueSlots: make(chan struct{}, budget.MaxQueued), ledger: newDedupLedger(budget.DedupEntries, budget.DedupMaximumBytes, budget.DedupTTL), stop: make(chan struct{}),
	}
	if err := target.rotateEpoch(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("generate target epoch: %w", err)
	}
	control, err := client.AcquireRawSession(ctx, pkcs11.RawSessionOptions{ReadWrite: physicalUserType == raw.CKU_SO, Operation: "proxy-control-session"})
	if err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("open control session: %w", err)
	}
	target.control = control
	if config.Login.EagerPhysicalLogin {
		if _, err := target.ensurePhysicalLogin(ctx, RequestIdentity{Principal: "proxy-bootstrap", Target: target.id, Revision: target.revision}, [16]byte{}, target.physicalUserType, target.physicalUsername, nil, false, false); err != nil {
			_ = target.close()
			return nil, err
		}
	}
	go target.sweep()
	return target, nil
}

func (target *brokerTarget) handle(ctx context.Context, identity RequestIdentity, req request) response {
	// Read-only/idempotent calls may be executed again safely and are deliberately
	// not retained in the deduplication ledger, avoiding long-lived copies of
	// attributes, plaintext, or random output. Non-idempotent calls retain their
	// exact response for bounded same-request replay after a transport failure.
	if methodIdempotent(req.Method) {
		return target.execute(ctx, identity, req)
	}
	fingerprint, err := requestFingerprint(req)
	if err != nil {
		return response{Version: protocolVersion, Epoch: target.currentEpoch(), Error: encodeError(err)}
	}
	key := dedupKey{principal: identity.Principal, client: req.ClientID, request: req.RequestID}
	entry, leader, replay, err := target.ledger.begin(ctx, key, fingerprint)
	if err != nil {
		return response{Version: protocolVersion, Epoch: target.currentEpoch(), Error: encodeError(err)}
	}
	if !leader {
		return replay
	}
	result := target.execute(ctx, identity, req)
	target.ledger.complete(key, entry, result)
	return result
}

func (target *brokerTarget) execute(ctx context.Context, identity RequestIdentity, req request) (result response) {
	result.Version = protocolVersion
	result.Epoch = target.currentEpoch()
	defer func() {
		wipe(req.Auth)
		wipe(identity.Auth)
		for index := range req.Arguments {
			wipeWireValue(&req.Arguments[index])
		}
		if recovered := recover(); recovered != nil {
			result = response{Version: protocolVersion, Epoch: target.currentEpoch(), Error: encodeError(&RemoteError{Code: "internal", Message: "broker request failed"})}
		}
	}()
	if target.closed.Load() {
		result.Error = encodeError(raw.ErrClosed)
		return
	}
	if err := target.authorizeOperation(ctx, identity, req.ClientID, req.Method, false); err != nil {
		result.Error = encodeError(err)
		return
	}

	// Describe is deliberately stateless: opening a remote module must not consume
	// a logical-client quota until C_Initialize establishes a Cryptoki client.
	if req.Method == methodDescribe {
		client := target.currentClient()
		if client == nil {
			result.Error = encodeError(raw.ErrClosed)
			return
		}
		description := describeResult{Path: "p11proxy://" + target.id + "@" + target.revision, Interface: client.Interface(), Epoch: target.currentEpoch(), Codecs: target.registry.Descriptors()}
		encoded, err := encodeWireValue(description, target.registry)
		if err != nil {
			result.Error = encodeError(err)
		} else {
			result.Results = []wireValue{encoded}
		}
		return
	}
	if req.Epoch != target.currentEpoch() {
		result.Error = encodeError(&RemoteError{Code: "target_epoch_mismatch", Message: "target process generation changed"})
		return
	}
	if req.Method == methodDestroy {
		client, err := target.existingClient(req.ClientID, identity.Principal)
		if err != nil {
			result.Error = encodeError(err)
			return
		}
		if client == nil {
			return
		}
		// Every ordinary request holds authMu for its complete decoded and native
		// execution lifetime. Taking the write side here drains this logical client
		// before any pinned physical session or session object is closed.
		client.authMu.Lock()
		defer client.authMu.Unlock()
		result.Error = encodeError(target.removeClient(req.ClientID, client))
		return
	}

	method, ok := rawModuleType.MethodByName(req.Method)
	if !ok {
		result.Error = encodeError(&RemoteError{Code: "unknown_method", Message: req.Method})
		return
	}
	if len(req.Arguments) != method.Type.NumIn() {
		result.Error = encodeError(raw.Error(raw.CKR_ARGUMENTS_BAD))
		return
	}

	client, err := target.clientFor(req.ClientID, identity.Principal)
	if err != nil {
		result.Error = encodeError(err)
		return
	}

	arguments := make([]any, len(req.Arguments))
	defer func() {
		for _, argument := range arguments {
			wipeAny(argument)
		}
	}()
	for index, encoded := range req.Arguments {
		if err := validateWireValue(encoded); err != nil {
			result.Error = encodeError(fmt.Errorf("validate argument %d: %w", index, err))
			return
		}
		value, err := decodeWireValue(encoded, method.Type.In(index), target.registry)
		if err != nil {
			result.Error = encodeError(fmt.Errorf("decode argument %d: %w", index, err))
			return
		}
		arguments[index] = value.Interface()
	}

	if clientAuthExclusive(req.Method) {
		client.authMu.Lock()
		defer client.authMu.Unlock()
	} else {
		client.authMu.RLock()
		defer client.authMu.RUnlock()
	}
	// Recheck the logical client only after acquiring the authentication lease.
	// A concurrent Destroy may have marked it closed while this request waited.
	if err := client.beginRequest(); err != nil {
		result.Error = encodeError(err)
		return
	}
	defer client.endRequest()

	// Administrative operations and login transitions are exclusive because PKCS
	// #11 login and token state are application-wide at the physical module. All
	// ordinary operations hold the read side so token reset, PIN changes, and SO
	// transitions cannot invalidate an in-flight request.
	if maintenanceExclusive(req.Method) {
		target.maintenanceLock.Lock()
		defer target.maintenanceLock.Unlock()
	} else {
		target.maintenanceLock.RLock()
		defer target.maintenanceLock.RUnlock()
	}

	values, updates, callErr := target.invoke(ctx, identity, client, req.Method, arguments)
	for _, value := range values {
		encoded, err := encodeWireValue(value, target.registry)
		if err != nil {
			result.Error = encodeError(err)
			return
		}
		result.Results = append(result.Results, encoded)
	}
	for index, argument := range arguments {
		declared := method.Type.In(index)
		if !argumentMayMutate(req.Method, index, declared) {
			continue
		}
		encoded, err := encodeTypedWireValue(argument, declared, target.registry)
		if err != nil {
			result.Error = encodeError(fmt.Errorf("encode updated argument %d: %w", index, err))
			return
		}
		result.ArgumentUpdates = append(result.ArgumentUpdates, argumentUpdate{Index: index, Value: encoded})
	}
	result.Updates = updates
	result.Error = encodeError(callErr)
	result.Epoch = target.currentEpoch()
	return
}

func clientAuthExclusive(method string) bool {
	switch method {
	case "Login", "LoginUser", "Logout", "Finalize":
		return true
	default:
		return false
	}
}

func maintenanceExclusive(method string) bool {
	switch method {
	case "InitToken", "InitPIN", "SetPIN", "Login", "LoginUser":
		return true
	default:
		return false
	}
}

func (target *brokerTarget) clientFor(id [16]byte, principal string) (*logicalClient, error) {
	target.clientsMu.Lock()
	defer target.clientsMu.Unlock()
	client := target.clients[id]
	if client != nil && client.principal != principal {
		return nil, &RemoteError{Code: "client_identity_mismatch", Message: "logical client ID belongs to a different authenticated principal"}
	}
	if client == nil {
		if len(target.clients) >= target.budget.MaxClients {
			return nil, raw.Error(raw.CKR_TOKEN_RESOURCE_EXCEEDED)
		}
		client = newLogicalClient(target, id, principal, target.budget.MaxObjectsPerClient)
		target.clients[id] = client
	}
	return client, nil
}

func (target *brokerTarget) existingClient(id [16]byte, principal string) (*logicalClient, error) {
	target.clientsMu.Lock()
	defer target.clientsMu.Unlock()
	client := target.clients[id]
	if client != nil && client.principal != principal {
		return nil, &RemoteError{Code: "client_identity_mismatch", Message: "logical client ID belongs to a different authenticated principal"}
	}
	return client, nil
}

func (target *brokerTarget) removeClient(id [16]byte, expected *logicalClient) error {
	target.clientsMu.Lock()
	client := target.clients[id]
	if client == expected {
		delete(target.clients, id)
	}
	target.clientsMu.Unlock()
	if client == nil || client != expected {
		return nil
	}
	return client.close(target)
}

func (target *brokerTarget) acquirePhysical(ctx context.Context, readWrite bool, operation string) (*pkcs11.RawSessionLease, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	// The queue token is acquired before entering the managed client pool, so an
	// unbounded Kubernetes caller population cannot turn into an unbounded set of
	// goroutines parked inside the HSM session semaphore.
	select {
	case target.queueSlots <- struct{}{}:
		defer func() { <-target.queueSlots }()
	default:
		return nil, raw.Error(raw.CKR_TOKEN_RESOURCE_EXCEEDED)
	}

	queueCtx := ctx
	if target.budget.QueueTimeout > 0 {
		var cancel context.CancelFunc
		queueCtx, cancel = context.WithTimeout(ctx, target.budget.QueueTimeout)
		defer cancel()
	}
	client := target.currentClient()
	if client == nil {
		return nil, raw.ErrClosed
	}
	lease, err := client.AcquireRawSession(queueCtx, pkcs11.RawSessionOptions{ReadWrite: readWrite, Operation: operation})
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, raw.Error(raw.CKR_SESSION_COUNT)
		}
		return nil, err
	}
	return lease, nil
}

func (target *brokerTarget) reservePinned() error {
	if target.pinned.Add(1) > int64(target.budget.MaxPinned) {
		target.pinned.Add(-1)
		return raw.Error(raw.CKR_TOKEN_RESOURCE_EXCEEDED)
	}
	return nil
}

func (target *brokerTarget) reserveVirtualSession() error {
	if target.virtualSessions.Add(1) > int64(target.budget.MaxVirtualSessionsTotal) {
		target.virtualSessions.Add(-1)
		return raw.Error(raw.CKR_SESSION_COUNT)
	}
	return nil
}

// callControl executes an operation on the reserved session that anchors the
// token-wide physical login. A stale control session is replaced for future
// work. retry permits one re-execution after replacement; client-supplied PIN
// activation passes false so one audited request can cause at most one physical
// PIN attempt.
func (target *brokerTarget) callControl(ctx context.Context, operation string, retry bool, fn func(raw.Module, raw.SessionHandle) error) error {
	target.controlMu.Lock()
	defer target.controlMu.Unlock()
	call := func() error {
		if target.control == nil {
			return raw.Error(raw.CKR_SESSION_HANDLE_INVALID)
		}
		return target.control.Call(ctx, operation, fn)
	}
	err := call()
	if err == nil || !isFatalPhysicalError(err) {
		return err
	}
	if target.control != nil {
		target.control.MarkBroken()
		_ = target.control.Close()
		target.control = nil
	}
	if raw.IsError(err, raw.CKR_DEVICE_REMOVED) || raw.IsError(err, raw.CKR_DEVICE_ERROR) || raw.IsError(err, raw.CKR_CRYPTOKI_NOT_INITIALIZED) {
		target.invalidatePhysicalLogin()
		// The configured physical identity is immutable target policy. A stale
		// control session invalidates only the login fact, never the identity that
		// must be restored on the replacement session.
		client := target.currentClient()
		if client == nil {
			return errors.Join(err, raw.ErrClosed)
		}
		if refreshErr := client.Refresh(ctx); refreshErr != nil {
			return errors.Join(err, refreshErr)
		}
		target.physicalSlot = client.Device().Fingerprint.SlotID
	}
	client := target.currentClient()
	if client == nil {
		return errors.Join(err, raw.ErrClosed)
	}
	control, acquireErr := client.AcquireRawSession(ctx, pkcs11.RawSessionOptions{ReadWrite: target.physicalUserType == raw.CKU_SO, Operation: "proxy-control-session-replacement"})
	if acquireErr != nil {
		return errors.Join(err, acquireErr)
	}
	target.control = control
	if !retry {
		return err
	}
	return call()
}

func (target *brokerTarget) releaseVirtualSession() {
	if target.virtualSessions.Add(-1) < 0 {
		panic("pkcs11 proxy: negative virtual session count")
	}
}

func (target *brokerTarget) logicalSessionCount() int {
	return int(target.virtualSessions.Load())
}

func (target *brokerTarget) releasePinned() {
	if target.pinned.Add(-1) < 0 {
		panic("pkcs11 proxy: negative pinned session count")
	}
}

func (target *brokerTarget) close() error {
	if target == nil {
		return nil
	}
	target.closeOnce.Do(func() {
		target.closed.Store(true)
		close(target.stop)
		target.maintenanceLock.Lock()
		defer target.maintenanceLock.Unlock()
		if target.ledger != nil {
			target.ledger.close()
		}
		target.clientsMu.Lock()
		clients := target.clients
		target.clients = make(map[[16]byte]*logicalClient)
		target.clientsMu.Unlock()
		var errs []error
		for _, client := range clients {
			if err := client.close(target); err != nil {
				errs = append(errs, err)
			}
		}
		if target.control != nil {
			if err := target.control.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		client := target.swapClient(nil)
		if client != nil {
			if err := client.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		target.closeErr = errors.Join(errs...)
	})
	return target.closeErr
}

func (target *brokerTarget) sweep() {
	ticker := time.NewTicker(target.sweepInterval())
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			target.sweepClients()
		case <-target.stop:
			return
		}
	}
}

func (target *brokerTarget) sweepInterval() time.Duration {
	interval := time.Minute
	for _, ttl := range []time.Duration{
		target.budget.ClientIdleTimeout,
		target.budget.VirtualSessionIdleTimeout,
		target.budget.PinnedOperationIdleTimeout,
	} {
		if ttl <= 0 {
			continue
		}
		candidate := max(ttl/2, 100*time.Millisecond)
		if candidate < interval {
			interval = candidate
		}
	}
	return interval
}

func (target *brokerTarget) sweepClients() {
	now := time.Now()
	target.clientsMu.Lock()
	var expired []*logicalClient
	var active []*logicalClient
	for id, client := range target.clients {
		if client.claimExpired(now, target.budget.ClientIdleTimeout) {
			expired = append(expired, client)
			delete(target.clients, id)
		} else {
			active = append(active, client)
		}
	}
	target.clientsMu.Unlock()

	// Native session cleanup can block in vendor middleware. Never hold
	// clientsMu while closing or expiring sessions.
	for _, client := range active {
		client.expireSessions(target, now)
	}
	for _, client := range expired {
		_ = client.closeRuntimeState(target)
	}
}

var rawModuleType = reflect.TypeFor[raw.Module]()

func isFatalPhysicalError(err error) bool {
	for _, value := range []uint{
		raw.CKR_SESSION_CLOSED,
		raw.CKR_SESSION_HANDLE_INVALID,
		raw.CKR_DEVICE_REMOVED,
		raw.CKR_DEVICE_ERROR,
		raw.CKR_CRYPTOKI_NOT_INITIALIZED,
	} {
		if raw.IsError(err, value) {
			return true
		}
	}
	return false
}
