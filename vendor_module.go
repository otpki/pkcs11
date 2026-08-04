package pkcs11

import (
	"context"
	"crypto"
	"fmt"
	"runtime"
	"sort"
	"strings"

	"github.com/otpki/pkcs11/raw"
)

// VendorModule is the only extension interface between the vendor-neutral
// driver and an HSM-specific implementation.
//
// A module owns every provider-specific concern:
//   - discovery filenames, environment variables, and installation paths;
//   - fingerprint matching and product-variant selection;
//   - proprietary mechanism, key-type, attribute, and parameter-set IDs;
//   - native lifecycle, session, login, buffer, and recovery constraints;
//   - mechanism and object-template normalization;
//   - exceptional object models and operations that standard PKCS #11 cannot
//     represent directly; and
//   - conformance runtime metadata.
//
// The root package imports no concrete vendor package. Applications select the
// integrations they trust by passing implementations through Config.Vendors.
// Implementations may live under this repository's vendors tree, in another Go
// module, or in the consuming application.
//
// Most modules should embed VendorBase and override only the methods required by
// the provider. Implementations must be safe for concurrent use and should be
// immutable after they are supplied to Config.
type VendorModule interface {
	Definition() VendorDefinition

	// AdaptRoute translates a vendor-neutral route after standard PKCS #11
	// routing has been attempted. The root driver always prefers an advertised
	// standard mechanism unless the caller explicitly supplied an override.
	AdaptRoute(Device, Route) (Route, error)

	// NormalizeMechanism and NormalizeTemplate run immediately before data
	// crosses the raw ABI boundary. Implementations must not mutate caller-owned
	// values and should return independent copies.
	NormalizeMechanism(VendorMechanismContext, *raw.Mechanism) (*raw.Mechanism, error)
	NormalizeTemplate(VendorTemplateContext, []*raw.Attribute) ([]*raw.Attribute, error)

	// ClassifyError may strengthen the conservative standard recovery action.
	// It must never weaken a non-zero StandardAction.
	ClassifyError(VendorErrorContext, error) RecoveryAction

	// ObjectAttributes lists proprietary attributes needed for object discovery
	// or algorithm inference. The root driver requests them alongside standard
	// metadata and tolerates normal unsupported/sensitive-attribute responses.
	ObjectAttributes() []uint
	InferAlgorithm(VendorObjectMetadata) (Algorithm, bool)

	// KeyPairModel describes providers that represent a logical key pair using a
	// nonstandard object model, such as one stateful secret object.
	KeyPairModel(Algorithm, Route) (VendorKeyPairModel, bool)

	// The following hooks implement operations whose lifecycle or object model
	// cannot be expressed by the generic path. handled=false asks the root driver
	// to continue with ordinary PKCS #11 behavior.
	GenerateSecretKey(context.Context, VendorSession, Route, SecretKeyOptions) (ObjectRef, bool, error)
	GenerateKeyPair(context.Context, VendorSession, Route, KeyPairOptions) (KeyPair, bool, error)
	LoadPublicKey(context.Context, VendorSession, ObjectRef, Algorithm) (crypto.PublicKey, bool, error)
	Sign(context.Context, VendorSession, ObjectRef, Route, []byte) ([]byte, bool, error)
	Verify(context.Context, VendorSession, ObjectRef, Route, []byte, []byte) (bool, error)
	Encapsulate(context.Context, VendorSession, ObjectRef, Route, KEMOptions, []*raw.Attribute) (KEMResult, bool, error)
	Decapsulate(context.Context, VendorSession, ObjectRef, []byte, Route, KEMOptions, []*raw.Attribute) (ObjectRef, bool, error)

	// FinalizeEncryption translates provider-specific output conventions, such
	// as an HSM-generated IV prepended to ciphertext.
	FinalizeEncryption(VendorCipherContext, EncryptionResult) (EncryptionResult, error)

	// AugmentCapabilities adds operations implemented through proprietary
	// mechanisms after the root driver derives standard capabilities.
	AugmentCapabilities(Fingerprint, *Capabilities)
}

// VendorBase supplies conservative no-op implementations of VendorModule.
// Embed it in a concrete module and implement Definition plus only the hooks the
// provider actually needs. VendorBase intentionally does not implement
// Definition, so it cannot accidentally become a selectable anonymous module.
type VendorBase struct{}

// AdaptRoute returns the standard route unchanged.
func (VendorBase) AdaptRoute(_ Device, route Route) (Route, error) { return route, nil }

// NormalizeMechanism returns a shallow mechanism copy without vendor translation.
func (VendorBase) NormalizeMechanism(_ VendorMechanismContext, mechanism *raw.Mechanism) (*raw.Mechanism, error) {
	return cloneMechanism(mechanism), nil
}

// NormalizeTemplate returns a deep copy of attributes without vendor translation.
func (VendorBase) NormalizeTemplate(_ VendorTemplateContext, attributes []*raw.Attribute) ([]*raw.Attribute, error) {
	return cloneAttributeTemplate(attributes), nil
}

// ClassifyError preserves the recovery action selected by the vendor-neutral driver.
func (VendorBase) ClassifyError(context VendorErrorContext, _ error) RecoveryAction {
	return context.StandardAction
}

// ObjectAttributes requests no proprietary attributes.
func (VendorBase) ObjectAttributes() []uint { return nil }

// InferAlgorithm declines vendor-specific algorithm inference.
func (VendorBase) InferAlgorithm(VendorObjectMetadata) (Algorithm, bool) { return "", false }

// KeyPairModel declines a nonstandard key-pair object model.
func (VendorBase) KeyPairModel(Algorithm, Route) (VendorKeyPairModel, bool) {
	return VendorKeyPairModel{}, false
}

// GenerateSecretKey declines custom secret-key generation.
func (VendorBase) GenerateSecretKey(context.Context, VendorSession, Route, SecretKeyOptions) (ObjectRef, bool, error) {
	return ObjectRef{}, false, nil
}

// GenerateKeyPair declines custom key-pair generation.
func (VendorBase) GenerateKeyPair(context.Context, VendorSession, Route, KeyPairOptions) (KeyPair, bool, error) {
	return KeyPair{}, false, nil
}

// LoadPublicKey declines custom public-key extraction.
func (VendorBase) LoadPublicKey(context.Context, VendorSession, ObjectRef, Algorithm) (crypto.PublicKey, bool, error) {
	return nil, false, nil
}

// Sign declines custom signing.
func (VendorBase) Sign(context.Context, VendorSession, ObjectRef, Route, []byte) ([]byte, bool, error) {
	return nil, false, nil
}

// Verify declines custom verification.
func (VendorBase) Verify(context.Context, VendorSession, ObjectRef, Route, []byte, []byte) (bool, error) {
	return false, nil
}

// Encapsulate declines custom KEM encapsulation.
func (VendorBase) Encapsulate(context.Context, VendorSession, ObjectRef, Route, KEMOptions, []*raw.Attribute) (KEMResult, bool, error) {
	return KEMResult{}, false, nil
}

// Decapsulate declines custom KEM decapsulation.
func (VendorBase) Decapsulate(context.Context, VendorSession, ObjectRef, []byte, Route, KEMOptions, []*raw.Attribute) (ObjectRef, bool, error) {
	return ObjectRef{}, false, nil
}

// FinalizeEncryption returns the generic encryption result unchanged.
func (VendorBase) FinalizeEncryption(_ VendorCipherContext, result EncryptionResult) (EncryptionResult, error) {
	return result, nil
}

// AugmentCapabilities leaves derived capabilities unchanged.
func (VendorBase) AugmentCapabilities(Fingerprint, *Capabilities) {}

// VendorDefinition is the immutable static description of one VendorModule.
type VendorDefinition struct {
	// ID is the stable machine-readable identifier used by diagnostics,
	// conformance tests, forced selection, and preferred-family filters.
	ID AdapterFamily
	// Name is the default operator-facing product or provider name.
	Name string
	// Priority breaks ties between equally strong matches. Detection evidence
	// should carry most of the score; use priority mainly for specific variants.
	Priority int
	// Source records the documentation, public header, licensed SDK, or clean-room
	// evidence used to implement the module.
	Source string

	// Match contains declarative fingerprint rules. MatchFunc, when non-nil,
	// replaces the generic scorer and can describe unusual provider metadata.
	Match     VendorMatchSpec
	MatchFunc VendorMatchFunc
	// Discovery owns every vendor-specific library name and installation hint.
	Discovery VendorDiscovery
	// Catalog exposes proprietary numeric values under stable semantic aliases.
	Catalog VendorCatalog
	// Behavior contains low-level execution facts consumed before hooks run.
	Behavior VendorBehavior
	// PreferVendorIdentifiers requests a proprietary route even when an
	// advertised standard mechanism exists. It should be rare and justified by
	// a documented provider incompatibility.
	PreferVendorIdentifiers bool
	// Conformance records whether and how the module is tested live.
	Conformance VendorConformance
}

// VendorMatch is the result of comparing a fingerprint with a vendor module.
type VendorMatch struct {
	// Matched reports whether this module recognizes the fingerprint. A false
	// result excludes the module regardless of Score.
	Matched bool
	// Score ranks this result against other matching modules. It is added to the
	// definition priority; stronger, more specific evidence should score higher.
	Score int
	// Name optionally replaces VendorDefinition.Name for a detected product
	// variant while preserving the stable module ID.
	Name string
	// Variant is a stable product/model distinction within the module. It is
	// diagnostic metadata and is not used as an adapter ID.
	Variant string
	// Reasons explains the evidence that produced the match. Keep entries
	// operator-readable and free of secrets.
	Reasons []string
}

// VendorMatchFunc performs custom, side-effect-free fingerprint matching. It
// must not call the native module or mutate global state.
type VendorMatchFunc func(Fingerprint) VendorMatch

// VendorMatchSpec describes how the generic selector scores a fingerprint.
type VendorMatchSpec struct {
	// Manufacturers are case-insensitive substrings matched against module, slot,
	// and token manufacturer fields.
	Manufacturers []string
	// LibraryDescriptions are case-insensitive substrings matched against
	// CK_INFO.libraryDescription.
	LibraryDescriptions []string
	// ModulePaths are case-insensitive substrings matched against the canonical
	// shared-library path. Use filenames or distinctive path components rather
	// than machine-specific absolute paths.
	ModulePaths []string
	// Models are case-insensitive substrings matched against CK_TOKEN_INFO.model.
	Models []string
	// SlotDescriptions are case-insensitive substrings matched against
	// CK_SLOT_INFO.slotDescription.
	SlotDescriptions []string
	// RequiredMechanisms must all be present before the module can match. Use this
	// only for mechanisms that uniquely identify the provider or product variant.
	RequiredMechanisms []NumericID
	// MinimumTextMatches overrides the default requirement of one matching text
	// category. It is useful when common names such as "cryptoki" are ambiguous.
	MinimumTextMatches int
	// MatchAllText requires every configured text category to match. Required
	// mechanisms are always all-or-nothing regardless of this field.
	MatchAllText bool
}

// VendorDiscovery declares safe, finite discovery hints for one provider.
type VendorDiscovery struct {
	// EnvironmentVariables are checked after generic PKCS11_MODULE variables.
	// Each value may be an OS path list.
	EnvironmentVariables []string
	// ModuleNames maps GOOS (linux, darwin, windows) to library basenames. The
	// empty string or "*" entry applies to every platform.
	ModuleNames map[string][]string
	// SearchDirectories maps GOOS to conventional installation directories. The
	// empty string or "*" entry applies to every platform.
	SearchDirectories map[string][]string
}

// Names returns module basenames applicable to goos.
func (d VendorDiscovery) Names(goos string) []string {
	result := append([]string(nil), d.ModuleNames[""]...)
	result = append(result, d.ModuleNames["*"]...)
	result = append(result, d.ModuleNames[goos]...)
	return result
}

// Directories returns installation directories applicable to goos.
func (d VendorDiscovery) Directories(goos string) []string {
	result := append([]string(nil), d.SearchDirectories[""]...)
	result = append(result, d.SearchDirectories["*"]...)
	result = append(result, d.SearchDirectories[goos]...)
	return result
}

// CatalogLevel describes the provenance and completeness of proprietary ABI
// information compiled into a module.
type CatalogLevel string

const (
	// CatalogPublic means the module includes proprietary identifiers whose
	// provenance permits distribution in this package.
	CatalogPublic CatalogLevel = "public"
	// CatalogStandardOnly means the module supplies detection/behavior but no
	// proprietary numeric ABI definitions.
	CatalogStandardOnly CatalogLevel = "standard-only"
	// CatalogVendorSDKRequired means additional proprietary identifiers require a
	// separately licensed SDK or consumer-provided decorated module.
	CatalogVendorSDKRequired CatalogLevel = "vendor-sdk-required"
)

// VendorCatalog maps stable semantic names to provider numeric identifiers.
// Maps are cloned and aliases are normalized when a Client is opened.
type VendorCatalog struct {
	// Level summarizes the provenance/completeness of the proprietary values.
	Level CatalogLevel
	// Source identifies the public header, SDK version, or other reviewed source.
	Source string
	// Mechanisms maps normalized semantic aliases to CK_MECHANISM_TYPE values.
	Mechanisms map[string]NumericID
	// KeyTypes maps normalized semantic aliases to CK_KEY_TYPE values.
	KeyTypes map[string]NumericID
	// Attributes maps normalized semantic aliases to CK_ATTRIBUTE_TYPE values.
	Attributes map[string]NumericID
	// ParameterSets maps normalized semantic aliases to provider parameter-set IDs.
	ParameterSets map[string]NumericID
}

// VendorLoginScope describes the authentication scope a module expects.
type VendorLoginScope uint8

const (
	// VendorLoginAuto uses standard token-wide application login semantics and
	// lets ordinary recovery handle modules that do not preserve that state.
	VendorLoginAuto VendorLoginScope = iota
	// VendorLoginToken coordinates one login state per slot/user identity.
	VendorLoginToken
	// VendorLoginSession performs a login on every newly opened native session.
	VendorLoginSession
)

// VendorGCMIVMode describes who creates an AES-GCM IV and how it is returned.
type VendorGCMIVMode string

const (
	// VendorGCMIVCaller means the application/driver supplies the IV before the
	// operation, which is the standard PKCS #11 behavior.
	VendorGCMIVCaller VendorGCMIVMode = "caller"
	// VendorGCMIVParameter means the provider writes a generated IV back through
	// the mechanism parameter structure.
	VendorGCMIVParameter VendorGCMIVMode = "parameter"
	// VendorGCMIVCiphertextPrefix means the provider prefixes its generated IV to
	// ciphertext and consumes the same combined form for decryption.
	VendorGCMIVCiphertextPrefix VendorGCMIVMode = "ciphertext-prefix"
)

// VendorBehavior contains low-level constraints that must be known before the
// driver invokes a provider. These are implementation facts, not application
// tuning knobs.
type VendorBehavior struct {
	// SerializeCalls places one process-wide mutex around calls into the module.
	SerializeCalls bool
	// LegacyInitialize uses C_Initialize(NULL) instead of CKF_OS_LOCKING_OK. Calls
	// are serialized automatically when this mode is active.
	LegacyInitialize bool
	// SkipFinalize avoids C_Finalize for modules known to own unsafe background
	// state. The dynamic library is still released when the final client closes.
	SkipFinalize bool
	// ForceSerialSessions caps each pool at one CKF_SERIAL_SESSION.
	ForceSerialSessions bool
	// LockSessionToOSThread executes every operation for a native session on one
	// permanently locked OS thread.
	LockSessionToOSThread bool
	// ReadWriteSessionsOnly makes even read operations use the read/write pool.
	ReadWriteSessionsOnly bool
	// MaxSessions is a provider-specific upper bound applied before token limits.
	// Zero means no additional module limit.
	MaxSessions int
	// LoginScope describes whether login coordination is automatic, token-wide,
	// or repeated per session.
	LoginScope VendorLoginScope
	// ProtectedPathOnEmptyPIN allows an empty PIN to select a protected
	// authentication path even when token metadata is incomplete.
	ProtectedPathOnEmptyPIN bool
	// RejectNullOutputProbe enables bounded real-buffer retries for modules that
	// reject the standard nil-output length probe.
	RejectNullOutputProbe bool
	// AllowUnadvertisedMechanism permits catalog aliases that the module omits
	// from C_GetMechanismList. Use only for a documented, tested provider defect.
	AllowUnadvertisedMechanism bool
	// NetworkBacked enables conservative reconnect-oriented error handling. It
	// does not make broad CKR_GENERAL_ERROR values retryable by itself.
	NetworkBacked bool
	// GCMIVMode records the provider's generated-IV convention.
	GCMIVMode VendorGCMIVMode
	// GCMIVSize is the generated IV buffer size for VendorGCMIVParameter. Zero
	// selects the driver's conventional 12-byte GCM IV.
	GCMIVSize int
}

// VendorMechanismContext describes a mechanism about to cross the ABI boundary.
type VendorMechanismContext struct {
	// Device is a defensive snapshot of the selected token and module.
	Device Device
	// Operation is the Cryptoki function name, such as C_SignInit.
	Operation string
}

// VendorTemplateContext describes a template about to cross the ABI boundary.
type VendorTemplateContext struct {
	// Device is a defensive snapshot of the selected token and module.
	Device Device
	// Operation identifies both the Cryptoki call and, where needed, the public
	// or private side of generation (for example C_GenerateKeyPair/public).
	Operation string
}

// VendorErrorContext gives a module the portable classification and retry
// policy already selected by the core.
type VendorErrorContext struct {
	// Device identifies the selected module/token at the time of failure.
	Device Device
	// StandardAction is the recovery action already derived from standard CKR_*
	// values. A module must return this value unchanged when it is non-zero.
	StandardAction RecoveryAction
	// RetryGeneral reports whether the caller opted into retrying otherwise broad
	// CKR_GENERAL_ERROR/CKR_FUNCTION_FAILED failures.
	RetryGeneral bool
}

// VendorObjectMetadata contains the attributes available for algorithm inference.
type VendorObjectMetadata struct {
	// Device is the selected provider snapshot.
	Device Device
	// KeyType is the decoded CKA_KEY_TYPE, which may be vendor-defined.
	KeyType uint
	// Attributes contains the standard inference attributes plus values requested
	// by VendorModule.ObjectAttributes. Values are caller-owned copies.
	Attributes []*raw.Attribute
}

// VendorKeyPairModel describes a nonstandard representation of a logical key
// pair. SingleObject makes generation and lookup use one object as both halves.
type VendorKeyPairModel struct {
	// SingleObject means one resident object is returned as both the public and
	// private logical reference.
	SingleObject bool
	// ObjectClass selects the class used to locate that resident object.
	ObjectClass uint
	// KeyType optionally narrows lookup to one provider key type.
	KeyType uint
}

// VendorCipherContext describes a completed encryption route.
type VendorCipherContext struct {
	// Device is the provider that executed the operation.
	Device Device
	// Route is an independent copy of the fully adapted encryption route.
	Route Route
}

// VendorSession is the narrow managed-session capability passed to modules. It
// exposes no pool and no reusable raw handle. Calls remain serialized,
// thread-affine, observed, and valid only for the callback duration.
type VendorSession interface {
	Context() context.Context
	Device() Device
	ReadWrite() bool
	Call(context.Context, string, func(raw.Module, raw.SessionHandle) error) error
	Resolve(ObjectRef) (raw.ObjectHandle, error)
	MarkBroken()
	InvalidateObjects()
}

// VendorConformance records the validation contract shipped with a module.
type VendorConformance struct {
	// Provider names the Testcontainers/Docker provider, when available.
	Provider string
	// Notes describes the fixture or external runtime prerequisites.
	Notes string
}

func normalizeVendorDefinition(definition VendorDefinition) (VendorDefinition, error) {
	definition.ID = normalizeAdapterFamily(definition.ID)
	definition.Name = strings.TrimSpace(definition.Name)
	definition.Source = strings.TrimSpace(definition.Source)
	if definition.ID == "" {
		return VendorDefinition{}, fmt.Errorf("vendor module ID is required")
	}
	if definition.ID == AdapterGeneric {
		return VendorDefinition{}, fmt.Errorf("vendor module ID %q is reserved", AdapterGeneric)
	}
	if definition.Name == "" {
		return VendorDefinition{}, fmt.Errorf("vendor module %q name is required", definition.ID)
	}
	if definition.MatchFunc == nil && !definition.Match.configured() {
		return VendorDefinition{}, fmt.Errorf("vendor module %q has no fingerprint matcher", definition.ID)
	}
	definition.Catalog = normalizeVendorCatalog(definition.Catalog)
	definition.Discovery = cloneVendorDiscovery(definition.Discovery)
	definition.Match = cloneVendorMatchSpec(definition.Match)
	return definition, nil
}

func (m VendorMatchSpec) configured() bool {
	return len(m.Manufacturers)+len(m.LibraryDescriptions)+len(m.ModulePaths)+len(m.Models)+len(m.SlotDescriptions)+len(m.RequiredMechanisms) != 0
}

func cloneVendorMatchSpec(value VendorMatchSpec) VendorMatchSpec {
	value.Manufacturers = append([]string(nil), value.Manufacturers...)
	value.LibraryDescriptions = append([]string(nil), value.LibraryDescriptions...)
	value.ModulePaths = append([]string(nil), value.ModulePaths...)
	value.Models = append([]string(nil), value.Models...)
	value.SlotDescriptions = append([]string(nil), value.SlotDescriptions...)
	value.RequiredMechanisms = append([]NumericID(nil), value.RequiredMechanisms...)
	return value
}

func cloneVendorDiscovery(value VendorDiscovery) VendorDiscovery {
	value.EnvironmentVariables = append([]string(nil), value.EnvironmentVariables...)
	value.ModuleNames = cloneStringSliceMap(value.ModuleNames)
	value.SearchDirectories = cloneStringSliceMap(value.SearchDirectories)
	return value
}

// CloneVendorDefinition returns an independent copy of definition. Function
// hooks are retained, while every map and slice that callers may mutate is
// cloned. VendorModule implementations that store a definition in a struct can
// use this helper from Definition to preserve the interface's immutability
// contract.
func CloneVendorDefinition(definition VendorDefinition) VendorDefinition {
	definition.Match = cloneVendorMatchSpec(definition.Match)
	definition.Discovery = cloneVendorDiscovery(definition.Discovery)
	definition.Catalog = normalizeVendorCatalog(definition.Catalog)
	return definition
}

func cloneStringSliceMap(source map[string][]string) map[string][]string {
	if len(source) == 0 {
		return nil
	}
	result := make(map[string][]string, len(source))
	for key, values := range source {
		result[key] = append([]string(nil), values...)
	}
	return result
}

func normalizeVendorCatalog(catalog VendorCatalog) VendorCatalog {
	catalog.Source = strings.TrimSpace(catalog.Source)
	catalog.Mechanisms = cloneIDs(catalog.Mechanisms)
	catalog.KeyTypes = cloneIDs(catalog.KeyTypes)
	catalog.Attributes = cloneIDs(catalog.Attributes)
	catalog.ParameterSets = cloneIDs(catalog.ParameterSets)
	if catalog.Level == "" {
		if len(catalog.Mechanisms)+len(catalog.KeyTypes)+len(catalog.Attributes)+len(catalog.ParameterSets) == 0 {
			catalog.Level = CatalogStandardOnly
		} else {
			catalog.Level = CatalogPublic
		}
	}
	return catalog
}

func validateVendorModules(modules []VendorModule) ([]VendorModule, map[AdapterFamily]VendorDefinition, error) {
	result := make([]VendorModule, 0, len(modules))
	definitions := make(map[AdapterFamily]VendorDefinition, len(modules))
	for index, module := range modules {
		if module == nil {
			return nil, nil, fmt.Errorf("vendor module %d is nil", index)
		}
		definition, err := normalizeVendorDefinition(module.Definition())
		if err != nil {
			return nil, nil, fmt.Errorf("vendor module %d: %w", index, err)
		}
		if _, exists := definitions[definition.ID]; exists {
			return nil, nil, fmt.Errorf("duplicate vendor module ID %q", definition.ID)
		}
		definitions[definition.ID] = definition
		result = append(result, module)
	}
	return result, definitions, nil
}

func sortedVendorModules(modules []VendorModule) []VendorModule {
	result := append([]VendorModule(nil), modules...)
	sort.SliceStable(result, func(i, j int) bool {
		left, right := result[i].Definition(), result[j].Definition()
		if left.Priority != right.Priority {
			return left.Priority > right.Priority
		}
		return normalizeAdapterFamily(left.ID) < normalizeAdapterFamily(right.ID)
	})
	return result
}

func cloneAttributeTemplate(attributes []*raw.Attribute) []*raw.Attribute {
	return mergeAttributes(attributes)
}

func vendorDiscoveryForOS(discovery VendorDiscovery) VendorDiscovery {
	return VendorDiscovery{
		EnvironmentVariables: append([]string(nil), discovery.EnvironmentVariables...),
		ModuleNames:          map[string][]string{"*": discovery.Names(runtime.GOOS)},
		SearchDirectories:    map[string][]string{"*": discovery.Directories(runtime.GOOS)},
	}
}
