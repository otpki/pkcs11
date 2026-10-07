// Package testmock provides the in-memory PKCS #11 module used by proxy test
// mode and tests that do not have a native HSM module. It implements a small
// useful subset of Cryptoki and returns CKR_FUNCTION_NOT_SUPPORTED for the rest.
//
// This is test infrastructure, not a security boundary. Keys are ordinary Go
// values in process memory.
package testmock

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"maps"
	"math/big"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/otpki/pkcs11/raw"
)

// DefaultPIN is the user PIN accepted by Login. It is public on purpose: the
// test module protects nothing.
const DefaultPIN = "1234"

var (
	errUnsupported = raw.Error(raw.CKR_FUNCTION_NOT_SUPPORTED)

	// ecParamsP256 is the DER object identifier for NIST P-256.
	ecParamsP256 = []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}
)

// Source adapts Module to pkcs11.ModuleSource. Sources with equal Name and
// Tokens share one registry identity, so two proxy routes configured with the
// same source see the same virtual HSM — mirroring one middleware library that
// reports several tokens.
type Source struct {
	// Name is the virtual HSM identity; it prefixes token labels and serials.
	Name string
	// Tokens is the number of token-present slots to report (1 or more).
	Tokens int
}

// OpenModule returns a fresh module instance; the managed registry shares it
// with every caller that presents the same RegistryKey.
func (s Source) OpenModule(context.Context) (raw.Module, error) {
	return New(s.Name, s.Tokens), nil
}

// RegistryKey is the process-wide sharing identity for the virtual HSM.
func (s Source) RegistryKey() string {
	return fmt.Sprintf("testmock:%s:%d", s.Name, s.Tokens)
}

// String is a human-readable module identity shown in logs and fingerprints.
func (s Source) String() string { return "testmock://" + s.Name }

// SharedSource adapts one caller-owned Module to pkcs11.ModuleSource. Unlike
// Source it returns the same instance from every OpenModule call, so a test
// can mutate the very module the managed registry hands to proxy targets:
// AddToken and RemoveToken change the next enumeration, SetSlotFault injects
// per-slot read failures, SetGate suspends an operation mid-flight, and
// SlotListCalls counts enumerations. The module survives registry release —
// Destroy marks it dead only until the next acquisition re-initializes it.
type SharedSource struct {
	// Name is the virtual HSM identity in registry keys and logs.
	Name string
	// Module is the instance every acquisition shares; must not be nil.
	Module *Module
}

// OpenModule marks the shared instance revivable and returns it.
func (s SharedSource) OpenModule(context.Context) (raw.Module, error) {
	if s.Module == nil {
		return nil, fmt.Errorf("testmock: shared source %q has no module", s.Name)
	}
	s.Module.mu.Lock()
	s.Module.revivable = true
	s.Module.mu.Unlock()
	return s.Module, nil
}

// RegistryKey is the process-wide sharing identity for the virtual HSM.
func (s SharedSource) RegistryKey() string {
	name := s.Name
	if name == "" && s.Module != nil {
		name = s.Module.name
	}
	return "testmock:shared:" + name
}

// String is a human-readable module identity shown in logs and fingerprints.
func (s SharedSource) String() string {
	if s.Name != "" {
		return "testmock://" + s.Name
	}
	if s.Module != nil {
		return "testmock://" + s.Module.name
	}
	return "testmock://"
}

// Gate suspends one module operation so a test can observe calls in flight.
// The first invocation of the gated operation closes Entered and blocks until
// Open is called; later invocations pass through. Install with SetGate.
type Gate struct {
	// Entered closes when a call reaches the gate.
	Entered  chan struct{}
	release  chan struct{}
	opened   atomic.Bool
	enterOne sync.Once
}

// NewGate returns a closed gate.
func NewGate() *Gate {
	return &Gate{Entered: make(chan struct{}), release: make(chan struct{})}
}

// wait parks the caller until Open. The Entered signal fires once per gate.
func (g *Gate) wait() {
	if g.opened.Load() {
		return
	}
	g.enterOne.Do(func() { close(g.Entered) })
	<-g.release
}

// Open releases the gated call and makes the gate inert.
func (g *Gate) Open() {
	if g.opened.CompareAndSwap(false, true) {
		close(g.release)
	}
}

// Module is an in-memory raw.Module implementation. See the package doc for
// the supported operation set.
type Module struct {
	mu           sync.Mutex
	name         string
	initialized  bool
	destroyed    bool
	revivable    bool // SharedSource modules come back on next Initialize
	sessions     map[raw.SessionHandle]*session
	nextSession  raw.SessionHandle
	tokens       []*token // index = slot - 1
	policy       raw.OutputBufferPolicy
	slotFaults   map[raw.SlotID]error
	opFaults     map[string]error
	slotListCall int
	gates        map[string]*Gate
}

var _ raw.Module = (*Module)(nil)

type token struct {
	slot     raw.SlotID
	label    string
	serial   string
	pin      []byte
	loggedIn bool
	absent   bool // hot-unplugged: unlisted, unopenable, live sessions survive
	objects  map[raw.ObjectHandle]*object
	nextObj  raw.ObjectHandle
}

type object struct {
	attrs map[uint][]byte
	// key holds live key material that is never exported as an attribute.
	key any
	// owner is nonzero for session objects (CKA_TOKEN=false).
	owner raw.SessionHandle
}

type session struct {
	slot       raw.SlotID
	flags      uint
	find       []raw.ObjectHandle
	digest     hash.Hash
	signKey    *object
	signMech   uint
	verify     *object
	verifyMech uint
	cipher     *cipherState
	decrypt    *cipherState
}

type cipherState struct {
	block cipher.Block
	iv    []byte
}

// New returns a module that reports tokens token-present slots numbered 1..N.
// Each token is labeled "<name>-token-<slot>" so it can be selected by label or
// slot ID, and accepts DefaultPIN for user login.
func New(name string, tokens int) *Module {
	if strings.TrimSpace(name) == "" {
		name = "test"
	}
	if tokens < 1 {
		tokens = 1
	}
	m := &Module{
		name:        name,
		sessions:    make(map[raw.SessionHandle]*session),
		nextSession: 1,
	}
	for i := 1; i <= tokens; i++ {
		t := &token{
			slot:    raw.SlotID(i),
			label:   fmt.Sprintf("%s-token-%d", name, i),
			serial:  fmt.Sprintf("TEST-%s-%04d", strings.ToUpper(name), i),
			pin:     []byte(DefaultPIN),
			objects: make(map[raw.ObjectHandle]*object),
		}
		t.objects[1] = &object{attrs: map[uint][]byte{
			raw.CKA_CLASS: raw.NewAttribute(raw.CKA_CLASS, raw.CKO_DATA).Value,
			raw.CKA_LABEL: []byte("testmode-info"),
			raw.CKA_VALUE: []byte("testmock in-memory token; not a security boundary"),
			raw.CKA_TOKEN: {1},
		}}
		t.nextObj = 2
		m.tokens = append(m.tokens, t)
	}
	return m
}

func (m *Module) require() error {
	if m.destroyed || !m.initialized {
		return raw.Error(raw.CKR_CRYPTOKI_NOT_INITIALIZED)
	}
	return nil
}

// AddToken inserts a new token-present slot carrying the given label and
// serial and returns its slot ID. The token accepts DefaultPIN for login.
// Slot numbers are never reused: a re-added token lands on a fresh slot even
// when an earlier token was removed.
func (m *Module) AddToken(label, serial string) raw.SlotID {
	m.mu.Lock()
	defer m.mu.Unlock()
	slot := raw.SlotID(len(m.tokens) + 1)
	t := &token{
		slot:    slot,
		label:   label,
		serial:  serial,
		pin:     []byte(DefaultPIN),
		objects: make(map[raw.ObjectHandle]*object),
		nextObj: 1,
	}
	m.tokens = append(m.tokens, t)
	return slot
}

// RemoveToken ejects the token at slot: it disappears from token-present slot
// listings, GetTokenInfo reports CKR_TOKEN_NOT_PRESENT, and new sessions are
// refused, while sessions already open keep working — matching a token
// hot-unplugged from a physical slot. The slot ID stays reserved.
func (m *Module) RemoveToken(slot raw.SlotID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if slot < 1 || int(slot) > len(m.tokens) {
		return raw.Error(raw.CKR_SLOT_ID_INVALID)
	}
	m.tokens[slot-1].absent = true
	return nil
}

// SetSlotFault makes GetSlotInfo and GetTokenInfo return err for the slot,
// simulating a token whose metadata cannot be read; a nil err clears it.
func (m *Module) SetSlotFault(slot raw.SlotID, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.slotFaults == nil {
		m.slotFaults = make(map[raw.SlotID]error)
	}
	if err == nil {
		delete(m.slotFaults, slot)
		return
	}
	m.slotFaults[slot] = err
}

// SlotListCalls reports how many GetSlotList calls the module has answered.
// Reconciliation tests use it to prove concurrent route listings share one
// enumeration.
func (m *Module) SlotListCalls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.slotListCall
}

// SessionCount reports the number of live sessions across all slots, for
// asserting that retired targets release their physical sessions.
func (m *Module) SessionCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sessions)
}

// SetGate installs a gate that suspends the named operation ("GetSlotList" or
// "GenerateRandom") until Gate.Open; a nil gate clears it.
func (m *Module) SetGate(operation string, gate *Gate) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.gates == nil {
		m.gates = make(map[string]*Gate)
	}
	if gate == nil {
		delete(m.gates, operation)
		return
	}
	m.gates[operation] = gate
}

// operationGate blocks the caller while a gate is installed for operation.
// It runs outside m.mu so a parked call does not stall the whole module.
func (m *Module) operationGate(operation string) {
	m.mu.Lock()
	gate := m.gates[operation]
	m.mu.Unlock()
	if gate != nil {
		gate.wait()
	}
}

// SetFault installs a fault that fails the named operation (e.g. "GetSlotList")
// with err, for exercising whole-module failure paths; a nil error clears it.
func (m *Module) SetFault(operation string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.opFaults == nil {
		m.opFaults = make(map[string]error)
	}
	if err == nil {
		delete(m.opFaults, operation)
		return
	}
	m.opFaults[operation] = err
}

// operationFault reports the fault installed for operation, or nil.
func (m *Module) operationFault(operation string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.opFaults[operation]
}

func (m *Module) lookup(slot raw.SlotID) (*token, error) {
	if err := m.require(); err != nil {
		return nil, err
	}
	if slot < 1 || int(slot) > len(m.tokens) {
		return nil, raw.Error(raw.CKR_SLOT_ID_INVALID)
	}
	return m.tokens[slot-1], nil
}

func (m *Module) lookupSession(handle raw.SessionHandle) (*session, *token, error) {
	if err := m.require(); err != nil {
		return nil, nil, err
	}
	s, ok := m.sessions[handle]
	if !ok {
		return nil, nil, raw.Error(raw.CKR_SESSION_HANDLE_INVALID)
	}
	return s, m.tokens[s.slot-1], nil
}

func (t *token) sessionCount(sessions map[raw.SessionHandle]*session, rw bool) uint {
	var count uint
	for _, s := range sessions {
		if s.slot != t.slot {
			continue
		}
		if !rw || s.flags&raw.CKF_RW_SESSION != 0 {
			count++
		}
	}
	return count
}

func (t *token) hasSessions(sessions map[raw.SessionHandle]*session) bool {
	return t.sessionCount(sessions, false) > 0
}

func (s *session) clearOperations() {
	s.find, s.digest = nil, nil
	s.signKey, s.verify = nil, nil
	s.cipher, s.decrypt = nil, nil
}

func attr(attrs []*raw.Attribute, typ uint) []byte {
	for _, a := range attrs {
		if a != nil && a.Type == typ {
			return a.Value
		}
	}
	return nil
}

func attrULong(attrs []*raw.Attribute, typ uint) (uint, bool) {
	if v := attr(attrs, typ); v != nil {
		return raw.ULong(v)
	}
	return 0, false
}

func attrBool(attrs []*raw.Attribute, typ uint, fallback bool) bool {
	if v := attr(attrs, typ); v != nil {
		if b, ok := raw.Bool(v); ok {
			return b
		}
	}
	return fallback
}

func attrMap(attrs []*raw.Attribute) map[uint][]byte {
	out := make(map[uint][]byte, len(attrs))
	for _, a := range attrs {
		if a == nil {
			continue
		}
		out[a.Type] = slices.Clone(a.Value)
	}
	return out
}

// Path is the synthetic module identity; there is no filesystem backing.
func (m *Module) Path() string { return "testmock://" + m.name }

// Interface reports a standard Cryptoki 2.40 interface.
func (m *Module) Interface() raw.InterfaceInfo {
	return raw.InterfaceInfo{Name: "PKCS 11", Version: raw.Version{Major: 2, Minor: 40}}
}

// Version reports Cryptoki 2.40.
func (m *Module) Version() raw.Version { return raw.Version{Major: 2, Minor: 40} }

// Supports reports Cryptoki versions up to 2.40.
func (m *Module) Supports(v raw.Version) bool { return m.Version().AtLeast(v) }

// SetOutputBufferPolicy records the compatibility policy; the fake has no
// native buffers to bound.
func (m *Module) SetOutputBufferPolicy(policy raw.OutputBufferPolicy) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.policy = policy
}

// Destroy releases the module; all later calls report CKR_CRYPTOKI_NOT_INITIALIZED.
// A module owned by a SharedSource survives: the next Initialize revives it,
// mirroring a library the registry unloads and reloads.
func (m *Module) Destroy() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.destroyed = true
	m.initialized = false
	m.sessions = nil
	for _, t := range m.tokens {
		t.loggedIn = false
	}
}

// Initialize marks the module ready; a second call reports
// CKR_CRYPTOKI_ALREADY_INITIALIZED as real modules do. A destroyed module
// returns CKR_CRYPTOKI_NOT_INITIALIZED unless it is revivable (SharedSource),
// in which case it comes back empty like a freshly dlopen'ed library.
func (m *Module) Initialize() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.destroyed {
		if !m.revivable {
			return raw.Error(raw.CKR_CRYPTOKI_NOT_INITIALIZED)
		}
		m.destroyed = false
		m.sessions = make(map[raw.SessionHandle]*session)
	}
	if m.initialized {
		return raw.Error(raw.CKR_CRYPTOKI_ALREADY_INITIALIZED)
	}
	m.initialized = true
	return nil
}

// InitializeLegacy mirrors Initialize; the fake accepts either form.
func (m *Module) InitializeLegacy() error { return m.Initialize() }

// InitializeWithFlags mirrors Initialize; OS-locking flags are a no-op here.
func (m *Module) InitializeWithFlags(uint) error { return m.Initialize() }

// Finalize closes every session and clears login state.
func (m *Module) Finalize() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.initialized || m.destroyed {
		return raw.Error(raw.CKR_CRYPTOKI_NOT_INITIALIZED)
	}
	m.initialized = false
	m.sessions = make(map[raw.SessionHandle]*session)
	for _, t := range m.tokens {
		t.loggedIn = false
	}
	return nil
}

// GetInfo reports the module-level identity.
func (m *Module) GetInfo() (raw.Info, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.require(); err != nil {
		return raw.Info{}, err
	}
	return raw.Info{
		CryptokiVersion:    raw.Version{Major: 2, Minor: 40},
		ManufacturerID:     "OTPKI Test",
		LibraryDescription: "OTPKI in-memory test module",
		LibraryVersion:     raw.Version{Major: 1, Minor: 0},
	}, nil
}

// GetFunctionList reports the interface table identity; Pointer is zero
// because no native function table exists.
func (m *Module) GetFunctionList() (raw.FunctionListInfo, error) {
	return raw.FunctionListInfo{InterfaceInfo: m.Interface()}, nil
}

// GetInterface returns the single "PKCS 11" interface when name and version
// match, else CKR_ARGUMENTS_BAD.
func (m *Module) GetInterface(name string, version *raw.Version, _ uint) (raw.FunctionListInfo, error) {
	iface := m.Interface()
	if name != "" && name != iface.Name {
		return raw.FunctionListInfo{}, raw.Error(raw.CKR_ARGUMENTS_BAD)
	}
	if version != nil && *version != iface.Version {
		return raw.FunctionListInfo{}, raw.Error(raw.CKR_ARGUMENTS_BAD)
	}
	return raw.FunctionListInfo{InterfaceInfo: iface}, nil
}

// GetInterfaceList returns the single supported interface.
func (m *Module) GetInterfaceList() ([]raw.InterfaceInfo, error) {
	return []raw.InterfaceInfo{m.Interface()}, nil
}

// GetSlotList returns slot IDs. With tokenPresent set only slots whose token
// has not been removed are listed; the physical slot numbers stay stable, so
// removing slot 1 of 3 leaves {2, 3}. Each call is counted by SlotListCalls.
func (m *Module) GetSlotList(tokenPresent bool) ([]raw.SlotID, error) {
	m.operationGate("GetSlotList")
	if err := m.operationFault("GetSlotList"); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.slotListCall++
	if err := m.require(); err != nil {
		return nil, err
	}
	var slots []raw.SlotID
	for _, t := range m.tokens {
		if tokenPresent && t.absent {
			continue
		}
		slots = append(slots, t.slot)
	}
	return slots, nil
}

// GetSlotInfo reports a removable slot; a removed token clears TOKEN_PRESENT.
func (m *Module) GetSlotInfo(slot raw.SlotID) (raw.SlotInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if fault := m.slotFaults[slot]; fault != nil {
		return raw.SlotInfo{}, fault
	}
	t, err := m.lookup(slot)
	if err != nil {
		return raw.SlotInfo{}, err
	}
	flags := raw.CKF_REMOVABLE_DEVICE
	if !t.absent {
		flags |= raw.CKF_TOKEN_PRESENT
	}
	return raw.SlotInfo{
		SlotDescription: fmt.Sprintf("%s slot %d", m.name, t.slot),
		ManufacturerID:  "OTPKI Test",
		Flags:           flags,
		HardwareVersion: raw.Version{Major: 1},
		FirmwareVersion: raw.Version{Major: 1},
	}, nil
}

// GetTokenInfo reports the token identity, live session counts, and login flags.
func (m *Module) GetTokenInfo(slot raw.SlotID) (raw.TokenInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if fault := m.slotFaults[slot]; fault != nil {
		return raw.TokenInfo{}, fault
	}
	t, err := m.lookup(slot)
	if err != nil {
		return raw.TokenInfo{}, err
	}
	if t.absent {
		return raw.TokenInfo{}, raw.Error(raw.CKR_TOKEN_NOT_PRESENT)
	}
	count := t.sessionCount(m.sessions, false)
	return raw.TokenInfo{
		Label:          t.label,
		ManufacturerID: "OTPKI Test",
		Model:          "TEST-1",
		SerialNumber:   t.serial,
		Flags: raw.CKF_RNG | raw.CKF_LOGIN_REQUIRED | raw.CKF_USER_PIN_INITIALIZED |
			raw.CKF_TOKEN_INITIALIZED | raw.CKF_SIGN | raw.CKF_DECRYPT,
		MaxSessionCount:    64,
		SessionCount:       count,
		MaxRwSessionCount:  64,
		RwSessionCount:     t.sessionCount(m.sessions, true),
		MaxPinLen:          64,
		MinPinLen:          1,
		TotalPublicMemory:  raw.CK_UNAVAILABLE_INFORMATION,
		FreePublicMemory:   raw.CK_UNAVAILABLE_INFORMATION,
		TotalPrivateMemory: raw.CK_UNAVAILABLE_INFORMATION,
		FreePrivateMemory:  raw.CK_UNAVAILABLE_INFORMATION,
		HardwareVersion:    raw.Version{Major: 1},
		FirmwareVersion:    raw.Version{Major: 1},
		UTCTime:            "2026010100000000",
	}, nil
}

var mechanismInfos = map[raw.MechanismType]raw.MechanismInfo{
	raw.MechanismType(raw.CKM_SHA256):                {Flags: raw.CKF_DIGEST},
	raw.MechanismType(raw.CKM_SHA384):                {Flags: raw.CKF_DIGEST},
	raw.MechanismType(raw.CKM_SHA512):                {Flags: raw.CKF_DIGEST},
	raw.MechanismType(raw.CKM_EC_KEY_PAIR_GEN):       {MinKeySize: 256, MaxKeySize: 256, Flags: raw.CKF_GENERATE_KEY_PAIR},
	raw.MechanismType(raw.CKM_ECDSA):                 {MinKeySize: 256, MaxKeySize: 256, Flags: raw.CKF_SIGN | raw.CKF_VERIFY},
	raw.MechanismType(raw.CKM_RSA_PKCS_KEY_PAIR_GEN): {MinKeySize: 2048, MaxKeySize: 4096, Flags: raw.CKF_GENERATE_KEY_PAIR},
	raw.MechanismType(raw.CKM_RSA_PKCS):              {MinKeySize: 2048, MaxKeySize: 4096, Flags: raw.CKF_SIGN | raw.CKF_VERIFY},
	raw.MechanismType(raw.CKM_SHA256_RSA_PKCS):       {MinKeySize: 2048, MaxKeySize: 4096, Flags: raw.CKF_SIGN | raw.CKF_VERIFY},
	raw.MechanismType(raw.CKM_AES_KEY_GEN):           {MinKeySize: 16, MaxKeySize: 32, Flags: raw.CKF_GENERATE},
	raw.MechanismType(raw.CKM_AES_CBC):               {MinKeySize: 16, MaxKeySize: 32, Flags: raw.CKF_ENCRYPT | raw.CKF_DECRYPT},
}

// GetMechanismList returns the supported mechanism table for the slot.
func (m *Module) GetMechanismList(slot raw.SlotID) ([]raw.MechanismType, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, err := m.lookup(slot); err != nil {
		return nil, err
	}
	list := make([]raw.MechanismType, 0, len(mechanismInfos))
	for mech := range mechanismInfos {
		list = append(list, mech)
	}
	return list, nil
}

// GetMechanismInfo reports per-mechanism capability metadata.
func (m *Module) GetMechanismInfo(slot raw.SlotID, mechanism raw.MechanismType) (raw.MechanismInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, err := m.lookup(slot); err != nil {
		return raw.MechanismInfo{}, err
	}
	info, ok := mechanismInfos[mechanism]
	if !ok {
		return raw.MechanismInfo{}, raw.Error(raw.CKR_MECHANISM_INVALID)
	}
	return info, nil
}

// OpenSession creates a session on the slot; CKF_SERIAL_SESSION is required
// like any standard module. A removed token refuses new sessions.
func (m *Module) OpenSession(slot raw.SlotID, flags uint) (raw.SessionHandle, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, err := m.lookup(slot)
	if err != nil {
		return 0, err
	}
	if t.absent {
		return 0, raw.Error(raw.CKR_TOKEN_NOT_PRESENT)
	}
	if flags&raw.CKF_SERIAL_SESSION == 0 {
		return 0, raw.Error(raw.CKR_SESSION_PARALLEL_NOT_SUPPORTED)
	}
	handle := m.nextSession
	m.nextSession++
	m.sessions[handle] = &session{slot: slot, flags: flags}
	return handle, nil
}

// CloseSession destroys the session and any session objects it owns. Closing
// the token's last session also logs the application out.
func (m *Module) CloseSession(handle raw.SessionHandle) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, t, err := m.lookupSession(handle)
	if err != nil {
		return err
	}
	for h, o := range t.objects {
		if o.owner == handle {
			delete(t.objects, h)
		}
	}
	delete(m.sessions, handle)
	if !t.hasSessions(m.sessions) {
		t.loggedIn = false
	}
	return nil
}

// CloseAllSessions destroys every session on the slot and logs the application
// out.
func (m *Module) CloseAllSessions(slot raw.SlotID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, err := m.lookup(slot)
	if err != nil {
		return err
	}
	for h, s := range m.sessions {
		if s.slot == slot {
			delete(m.sessions, h)
		}
	}
	t.loggedIn = false
	return nil
}

// GetSessionInfo reports the session's slot, flags, and login-derived state.
func (m *Module) GetSessionInfo(handle raw.SessionHandle) (raw.SessionInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, t, err := m.lookupSession(handle)
	if err != nil {
		return raw.SessionInfo{}, err
	}
	var state raw.State
	switch {
	case t.loggedIn && s.flags&raw.CKF_RW_SESSION != 0:
		state = raw.State(raw.CKS_RW_USER_FUNCTIONS)
	case t.loggedIn:
		state = raw.State(raw.CKS_RO_USER_FUNCTIONS)
	case s.flags&raw.CKF_RW_SESSION != 0:
		state = raw.State(raw.CKS_RW_PUBLIC_SESSION)
	default:
		state = raw.State(raw.CKS_RO_PUBLIC_SESSION)
	}
	return raw.SessionInfo{SlotID: s.slot, State: state, Flags: s.flags}, nil
}

// Login performs a token-scope user login; DefaultPIN is the accepted PIN.
func (m *Module) Login(handle raw.SessionHandle, userType uint, pin []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, t, err := m.lookupSession(handle)
	if err != nil {
		return err
	}
	if userType != raw.CKU_USER {
		return raw.Error(raw.CKR_USER_TYPE_INVALID)
	}
	if t.loggedIn {
		return raw.Error(raw.CKR_USER_ALREADY_LOGGED_IN)
	}
	if len(pin) < 1 || len(pin) > 64 {
		return raw.Error(raw.CKR_PIN_LEN_RANGE)
	}
	if string(pin) != string(t.pin) {
		return raw.Error(raw.CKR_PIN_INCORRECT)
	}
	t.loggedIn = true
	return nil
}

// LoginUser mirrors Login; the fake has no per-user identities.
func (m *Module) LoginUser(handle raw.SessionHandle, userType uint, pin []byte, _ string) error {
	return m.Login(handle, userType, pin)
}

// Logout clears the token's login state.
func (m *Module) Logout(handle raw.SessionHandle) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, t, err := m.lookupSession(handle)
	if err != nil {
		return err
	}
	if !t.loggedIn {
		return raw.Error(raw.CKR_USER_NOT_LOGGED_IN)
	}
	t.loggedIn = false
	return nil
}

// SetPIN changes the user PIN after verifying the current one.
func (m *Module) SetPIN(handle raw.SessionHandle, oldPIN, newPIN []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, t, err := m.lookupSession(handle)
	if err != nil {
		return err
	}
	if string(oldPIN) != string(t.pin) {
		return raw.Error(raw.CKR_PIN_INCORRECT)
	}
	if len(newPIN) < 1 || len(newPIN) > 64 {
		return raw.Error(raw.CKR_PIN_LEN_RANGE)
	}
	t.pin = append(t.pin[:0], newPIN...)
	return nil
}

// SessionCancel aborts all in-progress operations on the session.
func (m *Module) SessionCancel(handle raw.SessionHandle, _ uint) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, _, err := m.lookupSession(handle)
	if err != nil {
		return err
	}
	s.clearOperations()
	return nil
}

// WaitForSlotEvent reports no events; the fixture is static.
func (m *Module) WaitForSlotEvent(uint) (raw.SlotID, error) {
	return 0, raw.Error(raw.CKR_NO_EVENT)
}

// CreateObject stores a session or token object on the session's token.
func (m *Module) CreateObject(handle raw.SessionHandle, attributes []*raw.Attribute) (raw.ObjectHandle, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, t, err := m.lookupSession(handle)
	if err != nil {
		return 0, err
	}
	if attr(attributes, raw.CKA_CLASS) == nil {
		return 0, raw.Error(raw.CKR_TEMPLATE_INCOMPLETE)
	}
	if !t.loggedIn && attrBool(attributes, raw.CKA_PRIVATE, false) {
		return 0, raw.Error(raw.CKR_USER_NOT_LOGGED_IN)
	}
	obj := &object{attrs: attrMap(attributes)}
	if !attrBool(attributes, raw.CKA_TOKEN, false) {
		obj.owner = handle
	}
	h := t.nextObj
	t.nextObj++
	t.objects[h] = obj
	return h, nil
}

// CopyObject duplicates an object and applies template overrides.
func (m *Module) CopyObject(handle raw.SessionHandle, objHandle raw.ObjectHandle, attributes []*raw.Attribute) (raw.ObjectHandle, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, t, err := m.lookupSession(handle)
	if err != nil {
		return 0, err
	}
	src, ok := t.objects[objHandle]
	if !ok {
		return 0, raw.Error(raw.CKR_OBJECT_HANDLE_INVALID)
	}
	clone := &object{key: src.key}
	clone.attrs = attrMap(nil)
	for k, v := range src.attrs {
		clone.attrs[k] = slices.Clone(v)
	}
	maps.Copy(clone.attrs, attrMap(attributes))
	if !attrBool(attributes, raw.CKA_TOKEN, src.owner == 0) {
		clone.owner = handle
	}
	h := t.nextObj
	t.nextObj++
	t.objects[h] = clone
	return h, nil
}

// DestroyObject removes one object.
func (m *Module) DestroyObject(handle raw.SessionHandle, objHandle raw.ObjectHandle) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, t, err := m.lookupSession(handle)
	if err != nil {
		return err
	}
	if _, ok := t.objects[objHandle]; !ok {
		return raw.Error(raw.CKR_OBJECT_HANDLE_INVALID)
	}
	delete(t.objects, objHandle)
	return nil
}

// GetObjectSize returns the sum of attribute value lengths.
func (m *Module) GetObjectSize(handle raw.SessionHandle, objHandle raw.ObjectHandle) (uint, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, t, err := m.lookupSession(handle)
	if err != nil {
		return 0, err
	}
	obj, ok := t.objects[objHandle]
	if !ok {
		return 0, raw.Error(raw.CKR_OBJECT_HANDLE_INVALID)
	}
	var size uint
	for _, v := range obj.attrs {
		size += uint(len(v))
	}
	return size, nil
}

// GetAttributeValue fills each template attribute's Value; a missing attribute
// reports CKR_ATTRIBUTE_TYPE_INVALID.
func (m *Module) GetAttributeValue(handle raw.SessionHandle, objHandle raw.ObjectHandle, attributes []*raw.Attribute) ([]*raw.Attribute, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, t, err := m.lookupSession(handle)
	if err != nil {
		return nil, err
	}
	obj, ok := t.objects[objHandle]
	if !ok {
		return nil, raw.Error(raw.CKR_OBJECT_HANDLE_INVALID)
	}
	missing := false
	for _, a := range attributes {
		if a == nil {
			continue
		}
		if v, ok := obj.attrs[a.Type]; ok {
			a.Value = append(a.Value[:0], v...)
		} else {
			a.Value = nil
			missing = true
		}
	}
	if missing {
		return attributes, raw.Error(raw.CKR_ATTRIBUTE_TYPE_INVALID)
	}
	return attributes, nil
}

// SetAttributeValue merges template values into the object.
func (m *Module) SetAttributeValue(handle raw.SessionHandle, objHandle raw.ObjectHandle, attributes []*raw.Attribute) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, t, err := m.lookupSession(handle)
	if err != nil {
		return err
	}
	obj, ok := t.objects[objHandle]
	if !ok {
		return raw.Error(raw.CKR_OBJECT_HANDLE_INVALID)
	}
	maps.Copy(obj.attrs, attrMap(attributes))
	return nil
}

// FindObjectsInit snapshots all objects matching the template.
func (m *Module) FindObjectsInit(handle raw.SessionHandle, attributes []*raw.Attribute) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, t, err := m.lookupSession(handle)
	if err != nil {
		return err
	}
	if s.find != nil {
		return raw.Error(raw.CKR_OPERATION_ACTIVE)
	}
	var matches []raw.ObjectHandle
	for h, o := range t.objects {
		if o.owner != 0 && o.owner != handle {
			continue
		}
		if objectMatches(o, attributes) {
			matches = append(matches, h)
		}
	}
	s.find = matches
	return nil
}

func objectMatches(o *object, template []*raw.Attribute) bool {
	for _, a := range template {
		if a == nil {
			continue
		}
		v, ok := o.attrs[a.Type]
		if !ok || string(v) != string(a.Value) {
			return false
		}
	}
	return true
}

// FindObjects drains up to maxObjects handles from the active find; bool reports more.
func (m *Module) FindObjects(handle raw.SessionHandle, maxObjects int) ([]raw.ObjectHandle, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, _, err := m.lookupSession(handle)
	if err != nil {
		return nil, false, err
	}
	if s.find == nil {
		return nil, false, raw.Error(raw.CKR_OPERATION_NOT_INITIALIZED)
	}
	n := min(maxObjects, len(s.find))
	out := slices.Clone(s.find[:n])
	s.find = s.find[n:]
	return out, len(s.find) > 0, nil
}

// FindObjectsFinal clears the active find state.
func (m *Module) FindObjectsFinal(handle raw.SessionHandle) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, _, err := m.lookupSession(handle)
	if err != nil {
		return err
	}
	s.find = nil
	return nil
}

// FindAllObjects is the convenience batch form of Init/Find/Final.
func (m *Module) FindAllObjects(handle raw.SessionHandle, attributes []*raw.Attribute, batchSize int) ([]raw.ObjectHandle, error) {
	if err := m.FindObjectsInit(handle, attributes); err != nil {
		return nil, err
	}
	defer func() { _ = m.FindObjectsFinal(handle) }()
	var out []raw.ObjectHandle
	for {
		batch, more, err := m.FindObjects(handle, batchSize)
		if err != nil {
			return out, err
		}
		out = append(out, batch...)
		if !more {
			return out, nil
		}
	}
}

func hashFor(mechanism uint) hash.Hash {
	switch raw.MechanismType(mechanism) {
	case raw.MechanismType(raw.CKM_SHA256):
		return sha256.New()
	case raw.MechanismType(raw.CKM_SHA384):
		return sha512.New384()
	case raw.MechanismType(raw.CKM_SHA512):
		return sha512.New()
	}
	return nil
}

// DigestInit starts a real SHA-2 digest on the session.
func (m *Module) DigestInit(handle raw.SessionHandle, mechanisms []*raw.Mechanism) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, _, err := m.lookupSession(handle)
	if err != nil {
		return err
	}
	if s.digest != nil {
		return raw.Error(raw.CKR_OPERATION_ACTIVE)
	}
	if len(mechanisms) == 0 || mechanisms[0] == nil {
		return raw.Error(raw.CKR_MECHANISM_INVALID)
	}
	h := hashFor(mechanisms[0].Mechanism)
	if h == nil {
		return raw.Error(raw.CKR_MECHANISM_INVALID)
	}
	s.digest = h
	return nil
}

// Digest completes the active digest operation over data, as C_Digest does.
func (m *Module) Digest(handle raw.SessionHandle, data []byte) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, _, err := m.lookupSession(handle)
	if err != nil {
		return nil, err
	}
	if s.digest == nil {
		return nil, raw.Error(raw.CKR_OPERATION_NOT_INITIALIZED)
	}
	s.digest.Write(data)
	sum := s.digest.Sum(nil)
	s.digest = nil
	return sum, nil
}

// DigestUpdate feeds data into the active digest.
func (m *Module) DigestUpdate(handle raw.SessionHandle, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, _, err := m.lookupSession(handle)
	if err != nil {
		return err
	}
	if s.digest == nil {
		return raw.Error(raw.CKR_OPERATION_NOT_INITIALIZED)
	}
	s.digest.Write(data)
	return nil
}

// DigestFinal completes the active digest.
func (m *Module) DigestFinal(handle raw.SessionHandle) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, _, err := m.lookupSession(handle)
	if err != nil {
		return nil, err
	}
	if s.digest == nil {
		return nil, raw.Error(raw.CKR_OPERATION_NOT_INITIALIZED)
	}
	sum := s.digest.Sum(nil)
	s.digest = nil
	return sum, nil
}

// signKey resolves an object carrying private key material.
func (t *token) signKey(objHandle raw.ObjectHandle) (*object, error) {
	obj, ok := t.objects[objHandle]
	if !ok {
		return nil, raw.Error(raw.CKR_KEY_HANDLE_INVALID)
	}
	if obj.key == nil {
		return nil, raw.Error(raw.CKR_KEY_TYPE_INCONSISTENT)
	}
	return obj, nil
}

// SignInit starts an ECDSA or RSA signature over the session.
func (m *Module) SignInit(handle raw.SessionHandle, mechanisms []*raw.Mechanism, key raw.ObjectHandle) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, t, err := m.lookupSession(handle)
	if err != nil {
		return err
	}
	if len(mechanisms) == 0 || mechanisms[0] == nil {
		return raw.Error(raw.CKR_MECHANISM_INVALID)
	}
	mech := mechanisms[0].Mechanism
	obj, err := t.signKey(key)
	if err != nil {
		return err
	}
	switch raw.MechanismType(mech) {
	case raw.MechanismType(raw.CKM_ECDSA):
		if _, ok := obj.key.(*ecdsa.PrivateKey); !ok {
			return raw.Error(raw.CKR_KEY_TYPE_INCONSISTENT)
		}
	case raw.MechanismType(raw.CKM_RSA_PKCS), raw.MechanismType(raw.CKM_SHA256_RSA_PKCS):
		if _, ok := obj.key.(*rsa.PrivateKey); !ok {
			return raw.Error(raw.CKR_KEY_TYPE_INCONSISTENT)
		}
	default:
		return raw.Error(raw.CKR_MECHANISM_INVALID)
	}
	s.signKey, s.signMech = obj, mech
	return nil
}

// Sign returns a real signature: ECDSA as the fixed-width r||s pair required
// by CKM_ECDSA over the caller-supplied digest, or RSA PKCS#1 v1.5 over
// SHA-256 of the data.
func (m *Module) Sign(handle raw.SessionHandle, data []byte) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, t, err := m.lookupSession(handle)
	if err != nil {
		return nil, err
	}
	obj := s.signKey
	if obj == nil {
		return nil, raw.Error(raw.CKR_OPERATION_NOT_INITIALIZED)
	}
	if !t.loggedIn {
		return nil, raw.Error(raw.CKR_USER_NOT_LOGGED_IN)
	}
	s.signKey = nil
	switch key := obj.key.(type) {
	case *ecdsa.PrivateKey:
		digest := sha256.Sum256(data)
		r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
		if err != nil {
			return nil, err
		}
		size := (key.Params().N.BitLen() + 7) / 8
		out := make([]byte, size*2)
		r.FillBytes(out[:size])
		s.FillBytes(out[size:])
		return out, nil
	case *rsa.PrivateKey:
		digest := sha256.Sum256(data)
		return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	}
	return nil, raw.Error(raw.CKR_KEY_TYPE_INCONSISTENT)
}

// VerifyInit starts a verify operation against a public-key object.
func (m *Module) VerifyInit(handle raw.SessionHandle, mechanisms []*raw.Mechanism, key raw.ObjectHandle) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, t, err := m.lookupSession(handle)
	if err != nil {
		return err
	}
	if len(mechanisms) == 0 || mechanisms[0] == nil {
		return raw.Error(raw.CKR_MECHANISM_INVALID)
	}
	obj, ok := t.objects[key]
	if !ok {
		return raw.Error(raw.CKR_KEY_HANDLE_INVALID)
	}
	mech := mechanisms[0].Mechanism
	s.verify, s.verifyMech = obj, mech
	return nil
}

// Verify checks a signature produced by Sign.
func (m *Module) Verify(handle raw.SessionHandle, data, signature []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, _, err := m.lookupSession(handle)
	if err != nil {
		return err
	}
	obj := s.verify
	mech := s.verifyMech
	s.verify = nil
	if obj == nil {
		return raw.Error(raw.CKR_OPERATION_NOT_INITIALIZED)
	}
	digest := sha256.Sum256(data)
	pub, err := publicKeyFor(obj)
	if err != nil {
		return err
	}
	switch raw.MechanismType(mech) {
	case raw.MechanismType(raw.CKM_ECDSA):
		key, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return raw.Error(raw.CKR_KEY_TYPE_INCONSISTENT)
		}
		size := (key.Params().N.BitLen() + 7) / 8
		if len(signature) == size*2 {
			r := new(big.Int).SetBytes(signature[:size])
			s := new(big.Int).SetBytes(signature[size:])
			if !ecdsa.Verify(key, digest[:], r, s) {
				return raw.Error(raw.CKR_SIGNATURE_INVALID)
			}
			return nil
		}
		if !ecdsa.VerifyASN1(key, digest[:], signature) {
			return raw.Error(raw.CKR_SIGNATURE_INVALID)
		}
		return nil
	case raw.MechanismType(raw.CKM_RSA_PKCS), raw.MechanismType(raw.CKM_SHA256_RSA_PKCS):
		key, ok := pub.(*rsa.PublicKey)
		if !ok {
			return raw.Error(raw.CKR_KEY_TYPE_INCONSISTENT)
		}
		if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature); err != nil {
			return raw.Error(raw.CKR_SIGNATURE_INVALID)
		}
		return nil
	}
	return raw.Error(raw.CKR_MECHANISM_INVALID)
}

// publicKeyFor reconstructs the public half for a stored key object.
func publicKeyFor(obj *object) (any, error) {
	switch key := obj.key.(type) {
	case *ecdsa.PrivateKey:
		return &key.PublicKey, nil
	case *rsa.PrivateKey:
		return &key.PublicKey, nil
	}
	if point := obj.attrs[raw.CKA_EC_POINT]; len(point) > 2 {
		//nolint:staticcheck // CKA_EC_POINT is a raw uncompressed point; crypto/ecdh has no coordinate decode.
		x, y := elliptic.Unmarshal(elliptic.P256(), point[2:])
		if x != nil {
			//nolint:staticcheck // Test key material needs the coordinate form.
			return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
		}
	}
	if modulus := obj.attrs[raw.CKA_MODULUS]; len(modulus) > 0 {
		n := new(big.Int).SetBytes(modulus)
		e := 0
		for _, b := range obj.attrs[raw.CKA_PUBLIC_EXPONENT] {
			e = e<<8 | int(b)
		}
		return &rsa.PublicKey{N: n, E: e}, nil
	}
	return nil, raw.Error(raw.CKR_KEY_TYPE_INCONSISTENT)
}

// GenerateKey creates an AES secret key with real random key material.
func (m *Module) GenerateKey(handle raw.SessionHandle, mechanisms []*raw.Mechanism, attributes []*raw.Attribute) (raw.ObjectHandle, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, t, err := m.lookupSession(handle)
	if err != nil {
		return 0, err
	}
	if len(mechanisms) == 0 || mechanisms[0] == nil || raw.MechanismType(mechanisms[0].Mechanism) != raw.MechanismType(raw.CKM_AES_KEY_GEN) {
		return 0, raw.Error(raw.CKR_MECHANISM_INVALID)
	}
	length := uint(32)
	if v, ok := attrULong(attributes, raw.CKA_VALUE_LEN); ok && v > 0 {
		length = v
	}
	if length != 16 && length != 24 && length != 32 {
		return 0, raw.Error(raw.CKR_KEY_SIZE_RANGE)
	}
	secret := make([]byte, length)
	if _, err := rand.Read(secret); err != nil {
		return 0, raw.Error(raw.CKR_DEVICE_ERROR)
	}
	attrs := attrMap(attributes)
	attrs[raw.CKA_CLASS] = raw.NewAttribute(raw.CKA_CLASS, raw.CKO_SECRET_KEY).Value
	attrs[raw.CKA_KEY_TYPE] = raw.NewAttribute(raw.CKA_KEY_TYPE, raw.CKK_AES).Value
	attrs[raw.CKA_VALUE] = secret
	obj := &object{attrs: attrs}
	if !attrBool(attributes, raw.CKA_TOKEN, false) {
		obj.owner = handle
	}
	h := t.nextObj
	t.nextObj++
	t.objects[h] = obj
	return h, nil
}

// GenerateKeyPair creates an ECDSA P-256 or RSA-2048 key pair. Private key
// material is kept off the attribute store like a real token.
func (m *Module) GenerateKeyPair(handle raw.SessionHandle, mechanisms []*raw.Mechanism, publicAttributes, privateAttributes []*raw.Attribute) (raw.ObjectHandle, raw.ObjectHandle, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, t, err := m.lookupSession(handle)
	if err != nil {
		return 0, 0, err
	}
	if len(mechanisms) == 0 || mechanisms[0] == nil {
		return 0, 0, raw.Error(raw.CKR_MECHANISM_INVALID)
	}
	pubAttrs := attrMap(publicAttributes)
	privAttrs := attrMap(privateAttributes)
	var pub, priv *object
	switch raw.MechanismType(mechanisms[0].Mechanism) {
	case raw.MechanismType(raw.CKM_EC_KEY_PAIR_GEN):
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return 0, 0, raw.Error(raw.CKR_DEVICE_ERROR)
		}
		ecdhPub, err := key.PublicKey.ECDH()
		if err != nil {
			return 0, 0, raw.Error(raw.CKR_DEVICE_ERROR)
		}
		point := ecdhPub.Bytes()
		pubAttrs[raw.CKA_EC_PARAMS] = ecParamsP256
		pubAttrs[raw.CKA_EC_POINT] = append([]byte{0x04, byte(len(point))}, point...)
		priv = &object{attrs: privAttrs, key: key}
		pub = &object{attrs: pubAttrs}
	case raw.MechanismType(raw.CKM_RSA_PKCS_KEY_PAIR_GEN):
		bits := uint(2048)
		if v, ok := attrULong(publicAttributes, raw.CKA_MODULUS_BITS); ok && v > 0 {
			bits = v
		}
		if bits < 2048 || bits > 4096 {
			return 0, 0, raw.Error(raw.CKR_KEY_SIZE_RANGE)
		}
		key, err := rsa.GenerateKey(rand.Reader, int(bits))
		if err != nil {
			return 0, 0, raw.Error(raw.CKR_DEVICE_ERROR)
		}
		pubAttrs[raw.CKA_MODULUS] = key.N.Bytes()
		pubAttrs[raw.CKA_PUBLIC_EXPONENT] = big.NewInt(int64(key.PublicKey.E)).Bytes()
		priv = &object{attrs: privAttrs, key: key}
		pub = &object{attrs: pubAttrs}
	default:
		return 0, 0, raw.Error(raw.CKR_MECHANISM_INVALID)
	}
	pub.attrs[raw.CKA_CLASS] = raw.NewAttribute(raw.CKA_CLASS, raw.CKO_PUBLIC_KEY).Value
	priv.attrs[raw.CKA_CLASS] = raw.NewAttribute(raw.CKA_CLASS, raw.CKO_PRIVATE_KEY).Value
	if !attrBool(publicAttributes, raw.CKA_TOKEN, false) {
		pub.owner = handle
	}
	if !attrBool(privateAttributes, raw.CKA_TOKEN, false) {
		priv.owner = handle
	}
	pubHandle := t.nextObj
	t.nextObj++
	t.objects[pubHandle] = pub
	privHandle := t.nextObj
	t.nextObj++
	t.objects[privHandle] = priv
	return pubHandle, privHandle, nil
}

// EncryptInit starts AES-CBC encryption; the mechanism parameter is the IV.
func (m *Module) EncryptInit(handle raw.SessionHandle, mechanisms []*raw.Mechanism, key raw.ObjectHandle) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, t, err := m.lookupSession(handle)
	if err != nil {
		return err
	}
	state, err := aesCBCState(t, mechanisms, key)
	if err != nil {
		return err
	}
	s.cipher = state
	return nil
}

// Encrypt performs single-shot AES-CBC with PKCS#7 padding.
func (m *Module) Encrypt(handle raw.SessionHandle, plaintext []byte) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, _, err := m.lookupSession(handle)
	if err != nil {
		return nil, err
	}
	state := s.cipher
	s.cipher = nil
	if state == nil {
		return nil, raw.Error(raw.CKR_OPERATION_NOT_INITIALIZED)
	}
	return cbcEncrypt(state.block, state.iv, plaintext)
}

// DecryptInit starts AES-CBC decryption; the mechanism parameter is the IV.
func (m *Module) DecryptInit(handle raw.SessionHandle, mechanisms []*raw.Mechanism, key raw.ObjectHandle) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, t, err := m.lookupSession(handle)
	if err != nil {
		return err
	}
	state, err := aesCBCState(t, mechanisms, key)
	if err != nil {
		return err
	}
	s.decrypt = state
	return nil
}

// Decrypt performs single-shot AES-CBC and strips PKCS#7 padding.
func (m *Module) Decrypt(handle raw.SessionHandle, ciphertext []byte) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, _, err := m.lookupSession(handle)
	if err != nil {
		return nil, err
	}
	state := s.decrypt
	s.decrypt = nil
	if state == nil {
		return nil, raw.Error(raw.CKR_OPERATION_NOT_INITIALIZED)
	}
	return cbcDecrypt(state.block, state.iv, ciphertext)
}

func aesCBCState(t *token, mechanisms []*raw.Mechanism, key raw.ObjectHandle) (*cipherState, error) {
	if len(mechanisms) == 0 || mechanisms[0] == nil || raw.MechanismType(mechanisms[0].Mechanism) != raw.MechanismType(raw.CKM_AES_CBC) {
		return nil, raw.Error(raw.CKR_MECHANISM_INVALID)
	}
	obj, ok := t.objects[key]
	if !ok {
		return nil, raw.Error(raw.CKR_KEY_HANDLE_INVALID)
	}
	secret := obj.attrs[raw.CKA_VALUE]
	if len(secret) != 16 && len(secret) != 24 && len(secret) != 32 {
		return nil, raw.Error(raw.CKR_KEY_TYPE_INCONSISTENT)
	}
	iv, _ := mechanisms[0].Parameter.([]byte)
	if len(iv) != aes.BlockSize {
		return nil, raw.Error(raw.CKR_MECHANISM_PARAM_INVALID)
	}
	block, err := aes.NewCipher(secret)
	if err != nil {
		return nil, raw.Error(raw.CKR_KEY_TYPE_INCONSISTENT)
	}
	return &cipherState{block: block, iv: slices.Clone(iv)}, nil
}

func cbcEncrypt(block cipher.Block, iv, plaintext []byte) ([]byte, error) {
	pad := block.BlockSize() - len(plaintext)%block.BlockSize()
	data := make([]byte, len(plaintext)+pad)
	copy(data, plaintext)
	for i := len(plaintext); i < len(data); i++ {
		data[i] = byte(pad)
	}
	out := make([]byte, len(data))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, data)
	return out, nil
}

func cbcDecrypt(block cipher.Block, iv, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) == 0 || len(ciphertext)%block.BlockSize() != 0 {
		return nil, raw.Error(raw.CKR_ENCRYPTED_DATA_LEN_RANGE)
	}
	out := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, ciphertext)
	pad := int(out[len(out)-1])
	if pad < 1 || pad > block.BlockSize() {
		return nil, raw.Error(raw.CKR_ENCRYPTED_DATA_INVALID)
	}
	for i := len(out) - pad; i < len(out); i++ {
		if out[i] != byte(pad) {
			return nil, raw.Error(raw.CKR_ENCRYPTED_DATA_INVALID)
		}
	}
	return out[:len(out)-pad], nil
}

// SeedRandom absorbs entropy input as a no-op, matching real modules.
func (m *Module) SeedRandom(handle raw.SessionHandle, _ []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, _, err := m.lookupSession(handle)
	return err
}

// GenerateRandom returns real cryptographic randomness.
func (m *Module) GenerateRandom(handle raw.SessionHandle, length int) ([]byte, error) {
	m.operationGate("GenerateRandom")
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, _, err := m.lookupSession(handle); err != nil {
		return nil, err
	}
	if length < 0 {
		return nil, raw.Error(raw.CKR_ARGUMENTS_BAD)
	}
	out := make([]byte, length)
	if _, err := rand.Read(out); err != nil {
		return nil, raw.Error(raw.CKR_DEVICE_ERROR)
	}
	return out, nil
}
