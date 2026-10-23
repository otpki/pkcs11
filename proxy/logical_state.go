package proxy

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/raw"
)

type loginGrant struct {
	userType             uint
	username             string
	granted              time.Time
	activationGeneration uint64
}

type sessionObjectKey struct {
	session raw.SessionHandle
	native  raw.ObjectHandle
}

type logicalClient struct {
	target    *brokerTarget
	id        [16]byte
	principal string

	// createdAt and via record when this logical client was established and by
	// which establishing method (Initialize, ...); the dev dashboard shows them
	// so operators can attribute clients to workloads without joining audit
	// events.
	createdAt time.Time
	via       string

	// authMu gives one logical Cryptoki application application-wide login
	// semantics. Ordinary calls take a read lease; login, logout, and finalize
	// take the write side so private work on sibling sessions cannot race a
	// logical authentication transition.
	authMu sync.RWMutex

	stateMu     sync.Mutex
	initialized bool
	lastUsed    time.Time
	active      int
	grants      map[string]loginGrant
	closed      bool

	sessionsMu  sync.Mutex
	sessions    map[raw.SessionHandle]*virtualSession
	nextSession uint64

	objectsMu       sync.Mutex
	objects         map[raw.ObjectHandle]*virtualObject
	objectsByNative map[sessionObjectKey]raw.ObjectHandle
	resolved        map[resolvedObjectKey]raw.ObjectHandle
	nextObject      uint64
	maxObjects      int
}

// resolvedObjectKey memoizes one recoverable token object's native handle in
// one physical session, so repeated operations on an unchanged object do not
// pay a locator find per call.
type resolvedObjectKey struct {
	handle  raw.ObjectHandle
	session raw.SessionHandle
}

func newLogicalClient(target *brokerTarget, id [16]byte, principal, via string, maxObjects int) *logicalClient {
	if maxObjects <= 0 {
		maxObjects = 4096
	}
	return &logicalClient{
		target:          target,
		id:              id,
		principal:       principal,
		createdAt:       time.Now(),
		via:             via,
		lastUsed:        time.Now(),
		grants:          make(map[string]loginGrant),
		sessions:        make(map[raw.SessionHandle]*virtualSession),
		nextSession:     1,
		objects:         make(map[raw.ObjectHandle]*virtualObject),
		objectsByNative: make(map[sessionObjectKey]raw.ObjectHandle),
		resolved:        make(map[resolvedObjectKey]raw.ObjectHandle),
		nextObject:      1,
		maxObjects:      maxObjects,
	}
}

// ClientInfo is a secret-free snapshot of one established logical client for
// the dev dashboard: identity, establishing method, age, and resource use.
type ClientInfo struct {
	ID              string    `json:"id"`
	Target          string    `json:"target"`
	Principal       string    `json:"principal"`
	Via             string    `json:"via"`
	Since           time.Time `json:"since"`
	LastUsed        time.Time `json:"last_used"`
	Authenticated   bool      `json:"authenticated"`
	ActiveRequests  int       `json:"active_requests"`
	VirtualSessions int       `json:"virtual_sessions"`
	Objects         int       `json:"objects"`
}

func (client *logicalClient) info() ClientInfo {
	client.stateMu.Lock()
	info := ClientInfo{
		ID:             hexID(client.id),
		Target:         client.target.id,
		Principal:      client.principal,
		Via:            client.via,
		Since:          client.createdAt,
		LastUsed:       client.lastUsed,
		ActiveRequests: client.active,
	}
	client.stateMu.Unlock()
	info.Authenticated = client.authenticated()
	client.sessionsMu.Lock()
	info.VirtualSessions = len(client.sessions)
	client.sessionsMu.Unlock()
	client.objectsMu.Lock()
	info.Objects = len(client.objects)
	client.objectsMu.Unlock()
	return info
}

func (client *logicalClient) initialize() error {
	client.stateMu.Lock()
	defer client.stateMu.Unlock()
	if client.closed {
		return raw.ErrClosed
	}
	if client.initialized {
		return raw.Error(raw.CKR_CRYPTOKI_ALREADY_INITIALIZED)
	}
	client.initialized = true
	client.lastUsed = time.Now()
	return nil
}

func (client *logicalClient) isInitialized() bool {
	client.stateMu.Lock()
	defer client.stateMu.Unlock()
	return client.initialized && !client.closed
}

func (client *logicalClient) beginRequest() error {
	client.stateMu.Lock()
	defer client.stateMu.Unlock()
	if client.closed {
		return raw.ErrClosed
	}
	client.active++
	client.lastUsed = time.Now()
	return nil
}

func (client *logicalClient) endRequest() {
	client.stateMu.Lock()
	if client.active <= 0 {
		client.stateMu.Unlock()
		panic("pkcs11 proxy: logical client request accounting underflow")
	}
	client.active--
	client.lastUsed = time.Now()
	client.stateMu.Unlock()
}

// claimExpired atomically prevents new requests from entering an idle logical
// client. The caller may remove it from the target map and close runtime state
// after releasing the target registry lock.
func (client *logicalClient) claimExpired(now time.Time, ttl time.Duration) bool {
	client.stateMu.Lock()
	defer client.stateMu.Unlock()
	if client.closed || client.active != 0 || ttl <= 0 || now.Sub(client.lastUsed) <= ttl {
		return false
	}
	client.closed = true
	client.initialized = false
	client.grants = make(map[string]loginGrant)
	return true
}

func grantKey(userType uint, username string) string {
	return fmt.Sprintf("%d\x00%s", userType, username)
}

func (client *logicalClient) grantIsCurrent(grant loginGrant) bool {
	if client == nil || client.target == nil || client.target.login.Mode != PhysicalLoginClientActivated {
		return true
	}
	generation, active := client.target.activation.activeGeneration()
	return active && grant.activationGeneration == generation
}

func (client *logicalClient) authenticated() bool {
	client.stateMu.Lock()
	defer client.stateMu.Unlock()
	for _, grant := range client.grants {
		if client.grantIsCurrent(grant) {
			return true
		}
	}
	return false
}

func (client *logicalClient) loginIdentity() (uint, bool) {
	client.stateMu.Lock()
	defer client.stateMu.Unlock()
	for _, grant := range client.grants {
		if client.grantIsCurrent(grant) {
			return grant.userType, true
		}
	}
	return 0, false
}

// authenticationRequiredError preserves the ordinary PKCS #11 result while
// exposing why a previously authenticated client lost access. Only an inactive
// client-activated target receives ErrActivationRequired; a client that simply
// never logged in still receives the normal CKR_USER_NOT_LOGGED_IN.
func (client *logicalClient) authenticationRequiredError() error {
	if client != nil && client.target != nil && client.target.login.Mode == PhysicalLoginClientActivated {
		if _, active := client.target.activation.activeGeneration(); !active {
			return activationRequiredError()
		}
	}
	return raw.Error(raw.CKR_USER_NOT_LOGGED_IN)
}

func (client *logicalClient) sessionCount() int {
	client.sessionsMu.Lock()
	defer client.sessionsMu.Unlock()
	return len(client.sessions)
}

func (client *logicalClient) readWriteSessionCount() int {
	client.sessionsMu.Lock()
	defer client.sessionsMu.Unlock()
	count := 0
	for _, session := range client.sessions {
		if session.readWrite {
			count++
		}
	}
	return count
}

func (client *logicalClient) hasReadOnlySession() bool {
	client.sessionsMu.Lock()
	defer client.sessionsMu.Unlock()
	for _, session := range client.sessions {
		if !session.readWrite {
			return true
		}
	}
	return false
}

func (target *brokerTarget) hasReadOnlySession() bool {
	if target == nil {
		return false
	}
	target.clientsMu.Lock()
	clients := make([]*logicalClient, 0, len(target.clients))
	for _, client := range target.clients {
		clients = append(clients, client)
	}
	target.clientsMu.Unlock()
	for _, client := range clients {
		if client != nil && client.hasReadOnlySession() {
			return true
		}
	}
	return false
}

func (client *logicalClient) openSession(target *brokerTarget, slot raw.SlotID, flags uint) (raw.SessionHandle, error) {
	if !client.isInitialized() {
		return 0, raw.Error(raw.CKR_CRYPTOKI_NOT_INITIALIZED)
	}
	const allowedFlags = raw.CKF_SERIAL_SESSION | raw.CKF_RW_SESSION | raw.CKF_ASYNC_SESSION
	if flags&raw.CKF_SERIAL_SESSION == 0 {
		return 0, raw.Error(raw.CKR_SESSION_PARALLEL_NOT_SUPPORTED)
	}
	if flags&^allowedFlags != 0 {
		return 0, raw.Error(raw.CKR_ARGUMENTS_BAD)
	}
	managed := target.currentClient()
	if managed == nil {
		return 0, raw.ErrClosed
	}
	device := managed.Device()
	if flags&raw.CKF_ASYNC_SESSION != 0 {
		// The proxy cannot safely preserve provider-owned pointers after a native
		// call returns CKR_PENDING. Local raw modules still expose the PKCS #11 3.2
		// async API; remote modules fail closed instead of risking use-after-free.
		return 0, raw.Error(raw.CKR_SESSION_ASYNC_NOT_SUPPORTED)
	}
	if flags&raw.CKF_RW_SESSION != 0 && device.Fingerprint.Token.Flags&raw.CKF_WRITE_PROTECTED != 0 {
		return 0, raw.Error(raw.CKR_TOKEN_WRITE_PROTECTED)
	}

	client.sessionsMu.Lock()
	defer client.sessionsMu.Unlock()
	client.stateMu.Lock()
	closed := client.closed
	client.stateMu.Unlock()
	if closed {
		return 0, raw.ErrClosed
	}
	if len(client.sessions) >= target.budget.MaxVirtualSessionsPerClient {
		return 0, raw.Error(raw.CKR_SESSION_COUNT)
	}
	if err := target.reserveVirtualSession(); err != nil {
		return 0, err
	}
	reserved := true
	defer func() {
		if reserved {
			target.releaseVirtualSession()
		}
	}()

	handle := raw.SessionHandle(client.nextSession)
	client.nextSession++
	client.sessions[handle] = &virtualSession{
		handle:     handle,
		slot:       slot,
		flags:      flags,
		readWrite:  flags&raw.CKF_RW_SESSION != 0,
		lastUsed:   time.Now(),
		operations: make(map[string]bool),
		parameters: make(map[string][]*raw.Mechanism),
	}
	reserved = false
	return handle, nil
}

func (client *logicalClient) session(handle raw.SessionHandle) (*virtualSession, error) {
	client.sessionsMu.Lock()
	session := client.sessions[handle]
	client.sessionsMu.Unlock()
	if session == nil {
		return nil, raw.Error(raw.CKR_SESSION_HANDLE_INVALID)
	}
	return session, nil
}

func (client *logicalClient) clearLoginAfterLastSessionLocked() {
	// sessionsMu is held by the caller, preventing a new logical session from
	// observing the old grant after the last prior session has closed. Cryptoki
	// returns an application to public-session state when its final session ends;
	// the proxy mirrors that rule logically without calling physical C_Logout.
	if len(client.sessions) != 0 {
		return
	}
	client.stateMu.Lock()
	client.grants = make(map[string]loginGrant)
	client.stateMu.Unlock()
	client.objectsMu.Lock()
	for handle, object := range client.objects {
		if object == nil || !object.private {
			continue
		}
		key := sessionObjectKey{native: object.native}
		if object.affine {
			key.session = object.ownerSession
		}
		delete(client.objectsByNative, key)
		delete(client.objects, handle)
	}
	client.objectsMu.Unlock()
}

func (client *logicalClient) closeSession(ctx context.Context, target *brokerTarget, handle raw.SessionHandle) error {
	client.sessionsMu.Lock()
	session := client.sessions[handle]
	if session != nil {
		delete(client.sessions, handle)
		client.clearLoginAfterLastSessionLocked()
	}
	client.sessionsMu.Unlock()
	if session == nil {
		return raw.Error(raw.CKR_SESSION_HANDLE_INVALID)
	}
	client.removeAffineObjects(handle)
	target.releaseVirtualSession()
	return session.close(ctx, target)
}

func (client *logicalClient) closeAllSessions(ctx context.Context, target *brokerTarget, slot raw.SlotID) error {
	client.sessionsMu.Lock()
	var sessions []*virtualSession
	for handle, session := range client.sessions {
		if session.slot == slot {
			sessions = append(sessions, session)
			delete(client.sessions, handle)
		}
	}
	client.clearLoginAfterLastSessionLocked()
	client.sessionsMu.Unlock()
	var errs []error
	for _, session := range sessions {
		client.removeAffineObjects(session.handle)
		target.releaseVirtualSession()
		errs = append(errs, session.close(ctx, target))
	}
	return errors.Join(errs...)
}

func (client *logicalClient) finalize(ctx context.Context, target *brokerTarget) error {
	client.stateMu.Lock()
	if client.closed {
		client.stateMu.Unlock()
		return raw.ErrClosed
	}
	if !client.initialized {
		client.stateMu.Unlock()
		return raw.Error(raw.CKR_CRYPTOKI_NOT_INITIALIZED)
	}
	client.initialized = false
	client.grants = make(map[string]loginGrant)
	client.lastUsed = time.Now()
	client.stateMu.Unlock()
	return client.closeRuntimeState(ctx, target)
}

func (client *logicalClient) closeRuntimeState(ctx context.Context, target *brokerTarget) error {
	client.sessionsMu.Lock()
	sessions := client.sessions
	client.sessions = make(map[raw.SessionHandle]*virtualSession)
	client.sessionsMu.Unlock()
	client.objectsMu.Lock()
	client.objects = make(map[raw.ObjectHandle]*virtualObject)
	client.objectsByNative = make(map[sessionObjectKey]raw.ObjectHandle)
	client.objectsMu.Unlock()
	// Every native session object this client owned is gone with its sessions;
	// the provenance records must not survive to mislabel a reused handle.
	target.objectScope.dropClient(client.id)
	var errs []error
	for _, session := range sessions {
		target.releaseVirtualSession()
		errs = append(errs, session.close(ctx, target))
	}
	return errors.Join(errs...)
}

func (client *logicalClient) resetAfterTokenInitialization() {
	if client == nil {
		return
	}
	client.stateMu.Lock()
	client.grants = make(map[string]loginGrant)
	client.lastUsed = time.Now()
	client.stateMu.Unlock()
	client.objectsMu.Lock()
	client.objects = make(map[raw.ObjectHandle]*virtualObject)
	client.objectsByNative = make(map[sessionObjectKey]raw.ObjectHandle)
	client.nextObject = 1
	client.objectsMu.Unlock()
	client.target.objectScope.dropClient(client.id)
}

func (client *logicalClient) close(ctx context.Context, target *brokerTarget) error {
	client.stateMu.Lock()
	if client.closed {
		client.stateMu.Unlock()
		return nil
	}
	client.closed = true
	client.initialized = false
	client.grants = make(map[string]loginGrant)
	client.stateMu.Unlock()
	return client.closeRuntimeState(ctx, target)
}

func (client *logicalClient) expireSessions(ctx context.Context, target *brokerTarget, now time.Time) {
	client.sessionsMu.Lock()
	var expired []*virtualSession
	for handle, session := range client.sessions {
		session.mu.Lock()
		idle := now.Sub(session.lastUsed)
		pinned := session.hasPinnedLease()
		session.mu.Unlock()
		ttl := target.budget.VirtualSessionIdleTimeout
		if pinned {
			ttl = target.budget.PinnedOperationIdleTimeout
		}
		if ttl > 0 && idle > ttl {
			expired = append(expired, session)
			delete(client.sessions, handle)
		}
	}
	client.clearLoginAfterLastSessionLocked()
	client.sessionsMu.Unlock()
	for _, session := range expired {
		client.removeAffineObjects(session.handle)
		target.releaseVirtualSession()
		_ = session.close(ctx, target)
	}
}

func (client *logicalClient) logicalLogin(ctx context.Context, target *brokerTarget, identity RequestIdentity, userType uint, pin []byte, username string) error {
	if userType == raw.CKU_CONTEXT_SPECIFIC {
		return raw.Error(raw.CKR_OPERATION_NOT_INITIALIZED)
	}
	if !target.allowedUserType(userType) {
		return raw.Error(raw.CKR_USER_TYPE_INVALID)
	}
	if userType != target.physicalUserType || username != target.physicalUsername {
		return raw.Error(raw.CKR_USER_ANOTHER_ALREADY_LOGGED_IN)
	}

	// Every logical client is authenticated/audited independently, including
	// followers that wait for another pod's physical activation attempt.
	if err := target.authenticateLogical(ctx, identity, userType, username, pin); err != nil {
		return err
	}
	// The PIN gate runs before the grant short circuit: once activation has
	// armed the verifier, a repeated login still must present the PIN the HSM
	// accepted, so a granted client retrying with a wrong PIN gets
	// CKR_PIN_INCORRECT rather than CKR_USER_ALREADY_LOGGED_IN.
	if err := target.verifySuppliedPIN(ctx, identity, client.id, pin); err != nil {
		return err
	}

	client.stateMu.Lock()
	// PIN verification may have rotated the physical activation. Prune grants
	// afterwards so the client that led rotation receives a new usable grant,
	// rather than CKR_USER_ALREADY_LOGGED_IN for its obsolete generation.
	for key, grant := range client.grants {
		if !client.grantIsCurrent(grant) {
			delete(client.grants, key)
		}
	}
	if len(client.grants) > 0 {
		if _, ok := client.grants[grantKey(userType, username)]; ok {
			client.stateMu.Unlock()
			return raw.Error(raw.CKR_USER_ALREADY_LOGGED_IN)
		}
		client.stateMu.Unlock()
		return raw.Error(raw.CKR_USER_ANOTHER_ALREADY_LOGGED_IN)
	}
	client.stateMu.Unlock()

	generation, err := target.ensurePhysicalLogin(ctx, identity, client.id, target.physicalUserType, target.physicalUsername, pin, true, true)
	if err != nil {
		return err
	}
	// A follower joins the shared attempt while the verifier is unarmed, so the
	// pre-activation check passes vacuously. Once the leader's PIN has armed the
	// digest for this generation, prove this caller supplied the same PIN before
	// its grant is written — a queued wrong PIN must not ride on the activation.
	if verifier := target.pinVerifier; verifier != nil {
		if armed, matched := verifier.verify(pin, generation); armed && !matched {
			return raw.Error(raw.CKR_PIN_INCORRECT)
		}
	}
	client.stateMu.Lock()
	client.grants[grantKey(userType, username)] = loginGrant{
		userType: userType, username: username, granted: time.Now(), activationGeneration: generation,
	}
	client.stateMu.Unlock()
	target.obs.emitAudit(ctx, AuditEvent{Type: "login_grant", Target: target.id, ClientID: hexID(client.id), Principal: identity.Principal})
	return nil
}

func (target *brokerTarget) authenticateLogical(ctx context.Context, identity RequestIdentity, userType uint, username string, pin []byte) error {
	credential := slices.Clone(pin)
	defer wipe(credential)
	if target.login.Authenticate != nil {
		if err := target.login.Authenticate(ctx, LoginAttempt{Identity: identity, UserType: userType, Username: username, PIN: credential}); err != nil {
			return err
		}
		return nil
	}
	if target.login.TrustTransportIdentity {
		return nil
	}
	return &RemoteError{Code: "logical_authentication_required", Message: "target has no logical authenticator"}
}

// verifySuppliedPIN checks later logins against the last PIN accepted by the HSM,
// including while a failed rotation has left the target inactive. If rotation is
// enabled and enough time has passed, a mismatch may lead one physical attempt.
func (target *brokerTarget) verifySuppliedPIN(ctx context.Context, identity RequestIdentity, clientID [16]byte, pin []byte) error {
	verifier := target.pinVerifier
	if verifier == nil {
		return nil
	}
	armed, matched := verifier.verifyArmed(pin)
	if !armed || matched {
		return nil
	}
	interval := target.login.PINRotationInterval
	if interval <= 0 || time.Since(target.activation.lastAttempt()) < interval || time.Now().Before(target.activation.snapshot().RetryAfter) {
		// The cooldown can exceed the rotation interval. Do not repeat token-wide
		// logout and cleanup while the coordinator would refuse a physical login.
		return raw.Error(raw.CKR_PIN_INCORRECT)
	}
	return target.rotatePINActivation(ctx, identity, clientID, pin)
}

// rotatePINActivation ends the old activation and lets this caller try one fresh
// physical login. The armed PIN survives failure. The caller already holds the
// maintenance lock for writing, excluding ordinary requests on every client.
func (target *brokerTarget) rotatePINActivation(ctx context.Context, identity RequestIdentity, clientID [16]byte, pin []byte) (err error) {
	defer func() {
		code := ""
		if err != nil {
			code = outcomeCode(response{Error: encodeError(err)})
		}
		target.obs.emitAudit(ctx, AuditEvent{
			Type: "pin_rotation", Target: target.id, ClientID: hexID(clientID), Principal: identity.Principal, Code: code,
		})
	}()
	// Rotation affects every client sharing the token. Check permission before
	// clearing their state or logging out. The replacement activation is already
	// authorized here and must not ask the authorizer a second time.
	if err := target.authorizeOperation(ctx, identity, clientID, AuthorizationOperationRotatePIN, false); err != nil {
		return err
	}
	if err := target.authorizeOperation(ctx, identity, clientID, AuthorizationOperationActivateTarget, true); err != nil {
		return err
	}
	cleanupErr := target.clearPINRotationState(ctx)
	logoutErr := target.callControl(ctx, "proxy-pin-rotation-logout", false, func(module raw.Module, session raw.SessionHandle) error {
		return module.Logout(session)
	})
	if raw.IsError(logoutErr, raw.CKR_USER_NOT_LOGGED_IN) {
		logoutErr = nil
	}
	target.invalidatePhysicalLogin()
	if _, err := target.ensurePhysicalLogin(ctx, identity, clientID, target.physicalUserType, target.physicalUsername, pin, true, false); err != nil {
		return errors.Join(err, logoutErr, cleanupErr)
	}
	return errors.Join(logoutErr, cleanupErr)
}

func (client *logicalClient) logicalLogout(ctx context.Context, target *brokerTarget) error {
	if !client.authenticated() {
		client.stateMu.Lock()
		client.grants = make(map[string]loginGrant)
		client.stateMu.Unlock()
		return raw.Error(raw.CKR_USER_NOT_LOGGED_IN)
	}
	client.stateMu.Lock()
	client.grants = make(map[string]loginGrant)
	client.stateMu.Unlock()
	target.obs.emitAudit(ctx, AuditEvent{Type: "logout", Target: target.id, ClientID: hexID(client.id), Principal: client.principal})

	return client.cleanupLoginState(ctx, target)
}

func (target *brokerTarget) allowedUserType(userType uint) bool {
	allowed := target.login.AllowedUserTypes
	if len(allowed) == 0 {
		return userType == target.physicalUserType
	}
	return slices.Contains(allowed, userType)
}

// ensurePhysicalLogin establishes or joins one target-wide activation attempt.
// suppliedAvailable distinguishes an unavailable credential from a legitimate
// zero-length PIN. authorizeActivation is false for broker-internal recovery and
// eager startup, or for a rotation authorized before the token-wide logout.
func (target *brokerTarget) ensurePhysicalLogin(
	ctx context.Context,
	identity RequestIdentity,
	clientID [16]byte,
	userType uint,
	username string,
	supplied []byte,
	suppliedAvailable bool,
	authorizeActivation bool,
) (uint64, error) {
	if userType != target.physicalUserType || username != target.physicalUsername {
		return 0, raw.Error(raw.CKR_USER_ANOTHER_ALREADY_LOGGED_IN)
	}
	var authorizeLeader func() error
	if authorizeActivation {
		authorizeLeader = func() error {
			return target.authorizeOperation(ctx, identity, clientID, AuthorizationOperationActivateTarget, true)
		}
	}
	generation, err := target.activation.ensure(
		ctx,
		identity.Principal,
		target.login.ActivationFailureCooldown,
		authorizeLeader,
		func() error {
			// The perform closure runs only on the leader's physical PIN
			// attempt, so the audit event corresponds to exactly one device
			// login try — followers wait for the shared result instead.
			performErr := target.performPhysicalLogin(ctx, supplied, suppliedAvailable)
			// Only an actual HSM credential rejection can disarm the accepted PIN.
			// A wrong replacement, cooldown result, policy denial, or transient
			// device failure must leave the old gate in place.
			if suppliedAvailable && physicalPINRejected(performErr) {
				if armed, matched := target.pinVerifier.verifyArmed(supplied); armed && matched {
					target.pinVerifier.clear()
				}
			}
			eventType := "activation"
			if performErr != nil {
				eventType = "activation_failure"
			}
			target.obs.emitAudit(ctx, AuditEvent{Type: eventType, Target: target.id, ClientID: hexID(clientID), Principal: identity.Principal})
			return performErr
		},
		func(generation uint64) {
			// Arms only on the leader's successful physical attempt: the digest
			// of the PIN the HSM just accepted becomes the PIN every later
			// logical login must match, bound to this activation generation.
			if suppliedAvailable {
				target.pinVerifier.arm(supplied, generation)
			}
		},
	)
	if err != nil && target.login.Mode == PhysicalLoginClientActivated && raw.IsError(err, raw.CKR_USER_NOT_LOGGED_IN) && !errors.Is(err, ErrActivationRequired) {
		err = errors.Join(ErrActivationRequired, err)
	}
	return generation, err
}

func (target *brokerTarget) performPhysicalLogin(ctx context.Context, supplied []byte, suppliedAvailable bool) error {
	var (
		secret pkcs11.Secret
		err    error
	)
	switch target.login.Mode {
	case PhysicalLoginClientActivated:
		if !suppliedAvailable {
			return activationRequiredError()
		}
		secret = pkcs11.NewSecret(supplied)
	case PhysicalLoginServerManaged, PhysicalLoginProtectedPath:
		secret, err = target.physicalSecret(ctx, pkcs11.PINPurposeLogin, target.physicalUserType, target.physicalUsername)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("pkcs11 proxy: unresolved physical login mode %q", target.login.Mode)
	}
	defer secret.Destroy()

	// A client-supplied PIN is never retried automatically on a replacement
	// control session. The caller's audit event corresponds to one physical PIN
	// attempt; an ambiguous device/session failure requires a fresh audited login.
	retryControl := target.login.Mode != PhysicalLoginClientActivated
	loginErr := target.callControl(ctx, "proxy-physical-login", retryControl, func(module raw.Module, session raw.SessionHandle) error {
		if target.physicalUsername != "" {
			return module.LoginUser(session, target.physicalUserType, secret, target.physicalUsername)
		}
		return module.Login(session, target.physicalUserType, secret)
	})
	if raw.IsError(loginErr, raw.CKR_USER_ALREADY_LOGGED_IN) {
		if target.login.Mode == PhysicalLoginClientActivated {
			// The HSM did not verify the supplied value, so knowledge of the PIN is
			// unproven. Do not create an activation grant from this response.
			return activationInconclusiveError()
		}
		loginErr = nil
	}
	if loginErr != nil {
		return loginErr
	}

	if target.login.Mode == PhysicalLoginClientActivated {
		if err := target.verifyClientActivatedTokenWideLogin(ctx); err != nil {
			// Best-effort rollback. No other request can observe ActivationActive
			// until this function returns successfully.
			logoutErr := target.callControl(ctx, "proxy-client-activation-rollback", false, func(module raw.Module, session raw.SessionHandle) error {
				return module.Logout(session)
			})
			if raw.IsError(logoutErr, raw.CKR_USER_NOT_LOGGED_IN) {
				logoutErr = nil
			}
			return errors.Join(err, logoutErr)
		}
	}
	return nil
}

// verifyClientActivatedTokenWideLogin proves that a newly opened worker session
// observes the control session's login. Without this check, an adapter left in
// LoginScopeAuto could actually require a PIN per native session, which cannot
// be supported without retaining the client credential.
func (target *brokerTarget) verifyClientActivatedTokenWideLogin(ctx context.Context) error {
	if target.loginScope == pkcs11.LoginScopeToken {
		return nil
	}
	if target.loginScope == pkcs11.LoginScopeSession {
		return clientActivationUnsupportedError("selected vendor requires per-session physical login")
	}
	client := target.currentClient()
	if client == nil {
		return raw.ErrClosed
	}
	lease, err := client.AcquireRawSession(ctx, pkcs11.RawSessionOptions{
		ReadWrite: target.physicalUserType == raw.CKU_SO,
		Operation: "proxy-client-activation-scope-probe",
	})
	if err != nil {
		return err
	}
	defer func() { _ = lease.Close(ctx) }()
	var info raw.SessionInfo
	err = lease.Call(ctx, "proxy-client-activation-scope-probe", func(module raw.Module, session raw.SessionHandle) error {
		var callErr error
		info, callErr = module.GetSessionInfo(session)
		return callErr
	})
	if err != nil {
		return err
	}
	if physicalSessionStateAuthenticated(info.State, target.physicalUserType) {
		return nil
	}
	return clientActivationUnsupportedError("a new physical session did not inherit the control session login; client-activated mode would require retaining the PIN")
}

func physicalSessionStateAuthenticated(state raw.State, userType uint) bool {
	if userType == raw.CKU_SO {
		return state == raw.State(raw.CKS_RW_SO_FUNCTIONS)
	}
	return state == raw.State(raw.CKS_RO_USER_FUNCTIONS) || state == raw.State(raw.CKS_RW_USER_FUNCTIONS)
}

func (target *brokerTarget) physicalSecret(ctx context.Context, purpose pkcs11.PINPurpose, userType uint, username string) (pkcs11.Secret, error) {
	client := target.currentClient()
	if client == nil {
		return nil, raw.ErrClosed
	}
	device := client.Device()
	switch target.login.Mode {
	case PhysicalLoginServerManaged:
		if target.login.PhysicalPIN == nil {
			return nil, raw.Error(raw.CKR_USER_NOT_LOGGED_IN)
		}
		secret, err := target.login.PhysicalPIN(ctx, pkcs11.PINRequest{
			Purpose: purpose, SlotID: device.Fingerprint.SlotID, Token: device.Fingerprint.Token,
			UserType: userType, Attempt: 1, Username: username,
		})
		if err != nil {
			return nil, err
		}
		return secret, nil
	case PhysicalLoginProtectedPath:
		if device.Fingerprint.Token.Flags&raw.CKF_PROTECTED_AUTHENTICATION_PATH == 0 {
			return nil, raw.Error(raw.CKR_USER_NOT_LOGGED_IN)
		}
		return nil, nil
	case PhysicalLoginClientActivated:
		return nil, activationRequiredError()
	default:
		return nil, fmt.Errorf("pkcs11 proxy: unresolved physical login mode %q", target.login.Mode)
	}
}

func (target *brokerTarget) loginPhysicalLease(ctx context.Context, lease *pkcs11.RawSessionLease) error {
	if target.login.Mode == PhysicalLoginClientActivated {
		return clientActivationUnsupportedError("per-session login cannot be recovered without retaining the client PIN")
	}
	identity := fmt.Sprintf("proxy:%x:%d:%s", target.currentEpoch(), target.physicalUserType, target.physicalUsername)
	return lease.EnsureAuthentication(ctx, identity, func(module raw.Module, session raw.SessionHandle) error {
		secret, err := target.physicalSecret(ctx, pkcs11.PINPurposeLogin, target.physicalUserType, target.physicalUsername)
		if err != nil {
			return err
		}
		defer secret.Destroy()
		var loginErr error
		if target.physicalUsername != "" {
			loginErr = module.LoginUser(session, target.physicalUserType, secret, target.physicalUsername)
		} else {
			loginErr = module.Login(session, target.physicalUserType, secret)
		}
		if raw.IsError(loginErr, raw.CKR_USER_ALREADY_LOGGED_IN) {
			return nil
		}
		return loginErr
	})
}

func (target *brokerTarget) invalidatePhysicalLogin() {
	target.activation.invalidate(target.login.Mode == PhysicalLoginClientActivated)
	// With rotation enabled, the PIN gate outlives physical activation, including
	// indirect invalidation by control-session recovery. Otherwise a failed
	// replacement PIN could consume an HSM retry on every cooldown.
	if target.login.PINRotationInterval <= 0 {
		target.pinVerifier.clear()
	}
}

// physicalPINRejected distinguishes an unusable credential from a transient
// transport, session, or device failure. It is used only after a physical call,
// never for a cached activation failure or a logical authentication callback.
func physicalPINRejected(err error) bool {
	return raw.IsError(err, raw.CKR_PIN_INCORRECT) ||
		raw.IsError(err, raw.CKR_PIN_INVALID) ||
		raw.IsError(err, raw.CKR_PIN_LEN_RANGE) ||
		raw.IsError(err, raw.CKR_PIN_EXPIRED) ||
		raw.IsError(err, raw.CKR_PIN_LOCKED) ||
		raw.IsError(err, raw.CKR_USER_PIN_NOT_INITIALIZED)
}

func (target *brokerTarget) ensureLeaseAuthenticated(ctx context.Context, client *logicalClient, lease *pkcs11.RawSessionLease) error {
	if client == nil || !client.authenticated() {
		return nil
	}
	if _, active := target.activation.activeGeneration(); !active {
		if _, err := target.ensurePhysicalLogin(ctx, RequestIdentity{Principal: "proxy-recovery", Target: target.id, Revision: target.revision}, client.id, target.physicalUserType, target.physicalUsername, nil, false, false); err != nil {
			return err
		}
	}
	if target.loginScope == pkcs11.LoginScopeSession {
		return target.loginPhysicalLease(ctx, lease)
	}
	return nil
}

func (target *brokerTarget) contextLogin(ctx context.Context, identity RequestIdentity, client *logicalClient, lease *pkcs11.RawSessionLease, userType uint, username string, supplied []byte) error {
	if userType != raw.CKU_CONTEXT_SPECIFIC {
		return raw.Error(raw.CKR_USER_TYPE_INVALID)
	}
	if client == nil {
		return raw.Error(raw.CKR_USER_NOT_LOGGED_IN)
	}
	if !client.authenticated() {
		return client.authenticationRequiredError()
	}
	if username != target.physicalUsername {
		return raw.Error(raw.CKR_USER_ANOTHER_ALREADY_LOGGED_IN)
	}
	if err := target.authenticateLogical(ctx, identity, userType, username, supplied); err != nil {
		return err
	}
	// Context-specific authentication can only prove the armed PIN. It must not
	// start a token-wide rotation, even when the rotation interval has elapsed.
	if armed, matched := target.pinVerifier.verifyArmed(supplied); armed && !matched {
		return raw.Error(raw.CKR_PIN_INCORRECT)
	}
	var (
		secret pkcs11.Secret
		err    error
	)
	if target.login.Mode == PhysicalLoginClientActivated {
		secret = pkcs11.NewSecret(supplied)
	} else {
		secret, err = target.physicalSecret(ctx, pkcs11.PINPurposeContextSpecific, userType, username)
		if err != nil {
			return err
		}
	}
	defer secret.Destroy()
	return lease.Call(ctx, "proxy-context-login", func(module raw.Module, session raw.SessionHandle) error {
		if username != "" {
			return module.LoginUser(session, userType, secret, username)
		}
		return module.Login(session, userType, secret)
	})
}

func wipe(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
