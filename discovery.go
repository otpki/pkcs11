package pkcs11

import (
	"context"
	"fmt"
	"maps"
	"sort"

	"github.com/otpki/pkcs11/raw"
)

// Fingerprint is the standard, vendor-neutral information used to select an
// HSM adapter. No vendor SDK calls are required for initial detection.
type Fingerprint struct {
	// ModulePath is included because vendor library filenames often provide a
	// useful secondary detection signal when metadata is generic or redacted.
	ModulePath string `json:"module_path"`
	// Interface is the selected Cryptoki interface and version.
	Interface raw.InterfaceInfo `json:"interface"`
	// Module is the standard C_GetInfo result.
	Module raw.Info `json:"module"`
	// SlotID and Slot identify the token reader or logical HSM partition.
	SlotID raw.SlotID   `json:"slot_id"`
	Slot   raw.SlotInfo `json:"slot"`
	// Token is the standard C_GetTokenInfo result for SlotID.
	Token raw.TokenInfo `json:"token"`
	// Mechanisms contains successfully queried mechanisms plus any adapter-owned
	// proprietary mechanisms discovered through narrow post-detection probes.
	Mechanisms map[raw.MechanismType]raw.MechanismInfo `json:"mechanisms"`
}

// AlgorithmCapability describes which high-level operations can be routed for one algorithm.
type AlgorithmCapability struct {
	// KeyGeneration reports whether a routed key-generation operation exists.
	KeyGeneration bool `json:"key_generation"`
	// Sign and Verify report signature operation availability.
	Sign   bool `json:"sign"`
	Verify bool `json:"verify"`
	// Encrypt and Decrypt report conventional encryption operation availability.
	Encrypt bool `json:"encrypt"`
	Decrypt bool `json:"decrypt"`
	// Wrap and Unwrap report key transport operation availability.
	Wrap   bool `json:"wrap"`
	Unwrap bool `json:"unwrap"`
	// Derive reports generic key-derivation availability.
	Derive bool `json:"derive"`
	// Encapsulate and Decapsulate include both native PKCS #11 3.2 KEM calls and
	// adapter-owned derive-based KEM routes.
	Encapsulate bool `json:"encapsulate"`
	Decapsulate bool `json:"decapsulate"`
}

// Capabilities is derived from interface version, token flags, mechanism
// presence, and mechanism flags. Runtime fallback still handles modules that
// advertise more or less than they actually implement.
type Capabilities struct {
	// InterfaceVersion is the selected Cryptoki interface version.
	InterfaceVersion raw.Version `json:"interface_version"`
	// AsyncSessions reflects CKF_ASYNC_SESSION_SUPPORTED on the token.
	AsyncSessions bool `json:"async_sessions"`
	// MessageAPI reports availability by interface version; individual mechanism
	// support still determines whether a concrete message operation can run.
	MessageAPI bool `json:"message_api"`
	// PQC and the family flags summarize the operation-level Algorithms matrix.
	PQC    bool `json:"pqc"`
	MLDSA  bool `json:"ml_dsa"`
	MLKEM  bool `json:"ml_kem"`
	SLHDSA bool `json:"slh_dsa"`
	HSS    bool `json:"hss"`
	XMSS   bool `json:"xmss"`
	XMSSMT bool `json:"xmss_mt"`
	// AuthenticatedWrap reports PKCS #11 3.2 interface availability. Concrete
	// mechanism support is still validated when routing an operation.
	AuthenticatedWrap bool `json:"authenticated_wrap"`
	// Mechanisms is an independent snapshot of discovered mechanism metadata.
	Mechanisms map[raw.MechanismType]raw.MechanismInfo `json:"mechanisms"`
	// Algorithms describes the high-level operations the driver can route,
	// including approved vendor fallbacks.
	Algorithms map[Algorithm]AlgorithmCapability `json:"algorithms"`
}

// HasMechanism reports whether discovery found a mechanism identifier. The map
// can include a proprietary mechanism obtained through a narrow adapter-owned
// C_GetMechanismInfo probe even when it was omitted from C_GetMechanismList.
func (capabilities Capabilities) HasMechanism(mechanism uint) bool {
	_, ok := capabilities.Mechanisms[raw.MechanismType(mechanism)]
	return ok
}

// Supports reports whether a discovered mechanism includes the requested CKF_*
// flag. It applies strict standard semantics and does not use the zero-flag vendor
// compatibility exception used internally for known proprietary aliases.
func (capabilities Capabilities) Supports(mechanism, flag uint) bool {
	info, ok := capabilities.Mechanisms[raw.MechanismType(mechanism)]
	return ok && info.Flags&flag != 0
}

func supportsMechanism(capabilities Capabilities, mechanism, flag uint, vendorAlias bool) bool {
	info, ok := capabilities.Mechanisms[raw.MechanismType(mechanism)]
	if !ok {
		return false
	}
	if flag == 0 || info.Flags&flag != 0 {
		return true
	}
	// A few proprietary modules advertise vendor mechanisms with a zero flag
	// mask even though the operation is implemented. Only an adapter-owned
	// alias receives this compatibility treatment; standard mechanisms remain
	// subject to their normative CKF_* capability flags.
	return vendorAlias && info.Flags == 0
}

// Device is one token-bearing slot and its automatically selected vendor
// adapter. Internal compatibility behavior is deliberately not public.
type Device struct {
	// Fingerprint contains the standard metadata used for detection.
	Fingerprint Fingerprint `json:"fingerprint"`
	// Adapter describes the selected built-in HSM family and detection evidence.
	Adapter AdapterInfo `json:"adapter"`
	// Capabilities contains both raw mechanism metadata and routed operations.
	Capabilities Capabilities `json:"capabilities"`
	// Warnings records non-fatal discovery failures, such as one mechanism whose
	// C_GetMechanismInfo query failed.
	Warnings []string `json:"warnings,omitempty"`

	definition adapterDefinition
	plan       behaviorPlan
	vendor     VendorModule
}

func cloneMechanismInfoMap(source map[raw.MechanismType]raw.MechanismInfo) map[raw.MechanismType]raw.MechanismInfo {
	if source == nil {
		return nil
	}
	result := make(map[raw.MechanismType]raw.MechanismInfo, len(source))
	maps.Copy(result, source)
	return result
}

func cloneAlgorithmCapabilityMap(source map[Algorithm]AlgorithmCapability) map[Algorithm]AlgorithmCapability {
	if source == nil {
		return nil
	}
	result := make(map[Algorithm]AlgorithmCapability, len(source))
	maps.Copy(result, source)
	return result
}

func cloneFingerprint(fingerprint Fingerprint) Fingerprint {
	fingerprint.Mechanisms = cloneMechanismInfoMap(fingerprint.Mechanisms)
	return fingerprint
}

func cloneCapabilities(capabilities Capabilities) Capabilities {
	capabilities.Mechanisms = cloneMechanismInfoMap(capabilities.Mechanisms)
	capabilities.Algorithms = cloneAlgorithmCapabilityMap(capabilities.Algorithms)
	return capabilities
}

func cloneAdapterInfo(adapter AdapterInfo) AdapterInfo {
	adapter.DetectionReasons = append([]string(nil), adapter.DetectionReasons...)
	return adapter
}

// cloneDevice returns diagnostics that can be safely mutated by the caller
// without changing the driver's selected adapter or runtime capabilities.
// The private adapter plan is copied by value so the result remains usable by
// helpers such as ResolveRoute.
func cloneDevice(device Device) Device {
	device.Fingerprint = cloneFingerprint(device.Fingerprint)
	device.Adapter = cloneAdapterInfo(device.Adapter)
	device.Capabilities = cloneCapabilities(device.Capabilities)
	device.Warnings = append([]string(nil), device.Warnings...)
	return device
}

// deriveCapabilities converts raw mechanism metadata into application-level
// operation support. It does not invoke the HSM; all decisions are deterministic
// from the fingerprint and already-selected adapter catalog.
func deriveCapabilities(fingerprint Fingerprint, definition adapterDefinition) Capabilities {
	capabilities := Capabilities{
		InterfaceVersion:  fingerprint.Interface.Version,
		AsyncSessions:     fingerprint.Token.Flags&raw.CKF_ASYNC_SESSION_SUPPORTED != 0,
		MessageAPI:        fingerprint.Interface.Version.AtLeast(raw.Version{Major: 3, Minor: 0}),
		AuthenticatedWrap: fingerprint.Interface.Version.AtLeast(raw.Version{Major: 3, Minor: 2}),
		Mechanisms:        fingerprint.Mechanisms,
		Algorithms:        make(map[Algorithm]AlgorithmCapability),
	}
	for _, algorithm := range AllAlgorithms() {
		capabilities.Algorithms[algorithm] = deriveAlgorithmCapability(algorithm, capabilities, definition)
	}

	// Prefer the operation-level capability matrix over a simple mechanism-name
	// check. Vendor adapters can implement a standard algorithm through a
	// proprietary mechanism supplied by a selected vendor module, so
	// the high-level capability flags must reflect the route the driver can
	// actually execute.
	for _, algorithm := range []Algorithm{AlgorithmMLDSA44, AlgorithmMLDSA65, AlgorithmMLDSA87} {
		capability := capabilities.Algorithms[algorithm]
		capabilities.MLDSA = capabilities.MLDSA || capability.KeyGeneration || capability.Sign || capability.Verify
	}
	for _, algorithm := range []Algorithm{AlgorithmMLKEM512, AlgorithmMLKEM768, AlgorithmMLKEM1024} {
		capability := capabilities.Algorithms[algorithm]
		capabilities.MLKEM = capabilities.MLKEM || capability.KeyGeneration || capability.Encapsulate || capability.Decapsulate
	}
	capabilities.SLHDSA = capabilities.HasMechanism(raw.CKM_SLH_DSA) || capabilities.HasMechanism(raw.CKM_SLH_DSA_KEY_PAIR_GEN)
	capabilities.HSS = capabilities.HasMechanism(raw.CKM_HSS) || capabilities.HasMechanism(raw.CKM_HSS_KEY_PAIR_GEN)
	capabilities.XMSS = capabilities.HasMechanism(raw.CKM_XMSS) || capabilities.HasMechanism(raw.CKM_XMSS_KEY_PAIR_GEN)
	capabilities.XMSSMT = capabilities.HasMechanism(raw.CKM_XMSSMT) || capabilities.HasMechanism(raw.CKM_XMSSMT_KEY_PAIR_GEN)
	capabilities.PQC = capabilities.MLDSA || capabilities.MLKEM || capabilities.SLHDSA || capabilities.HSS || capabilities.XMSS || capabilities.XMSSMT
	return capabilities
}

func capabilityAlias(definition adapterDefinition, alias string) (uint, bool) {
	if alias == "" || definition.identifiers.mechanisms == nil {
		return 0, false
	}
	value, ok := definition.identifiers.mechanisms[normalizeAlias(alias)]
	return uint(value), ok
}

func deriveAlgorithmCapability(algorithm Algorithm, capabilities Capabilities, definition adapterDefinition) AlgorithmCapability {
	spec, ok := algorithmSpecs[algorithm]
	if !ok {
		return AlgorithmCapability{}
	}
	result := AlgorithmCapability{}
	if spec.KeyPair {
		if spec.KeyPairMechanismSet {
			result.KeyGeneration = supportsMechanism(capabilities, spec.KeyPairMechanism, raw.CKF_GENERATE_KEY_PAIR, false)
		}
		if mechanism, ok := capabilityAlias(definition, spec.KeyPairAlias); ok {
			result.KeyGeneration = result.KeyGeneration || supportsMechanism(capabilities, mechanism, raw.CKF_GENERATE_KEY_PAIR, true)
		}
	}
	if spec.Secret {
		if spec.SecretKeyMechanismSet {
			result.KeyGeneration = result.KeyGeneration || supportsMechanism(capabilities, spec.SecretKeyMechanism, raw.CKF_GENERATE, false)
		}
		if mechanism, ok := capabilityAlias(definition, spec.SecretKeyAlias); ok {
			result.KeyGeneration = result.KeyGeneration || supportsMechanism(capabilities, mechanism, raw.CKF_GENERATE, true)
		}
	}
	for _, mechanism := range spec.SignMechanisms {
		result.Sign = result.Sign || capabilities.Supports(mechanism, raw.CKF_SIGN)
		result.Verify = result.Verify || capabilities.Supports(mechanism, raw.CKF_VERIFY)
	}
	if spec.SignAlias != "" {
		if mechanism, ok := capabilityAlias(definition, spec.SignAlias); ok {
			result.Sign = result.Sign || supportsMechanism(capabilities, mechanism, raw.CKF_SIGN, true)
			result.Verify = result.Verify || supportsMechanism(capabilities, mechanism, raw.CKF_VERIFY, true)
		}
	}
	// Standard ML-DSA specs use the standard mechanism list rather than a
	// SignAlias. Some vendor modules expose separate sign and verify mechanism IDs,
	// so include those operation-specific aliases in the same generic matrix.
	if algorithm == AlgorithmMLDSA44 || algorithm == AlgorithmMLDSA65 || algorithm == AlgorithmMLDSA87 {
		if mechanism, ok := capabilityAlias(definition, "ml-dsa"); ok {
			result.Sign = result.Sign || supportsMechanism(capabilities, mechanism, raw.CKF_SIGN, true)
		}
		if mechanism, ok := capabilityAlias(definition, "ml-dsa-verify"); ok {
			result.Verify = result.Verify || supportsMechanism(capabilities, mechanism, raw.CKF_VERIFY, true)
		}
	}
	for _, mechanism := range spec.EncryptionMechanisms {
		result.Encrypt = result.Encrypt || capabilities.Supports(mechanism, raw.CKF_ENCRYPT)
		result.Decrypt = result.Decrypt || capabilities.Supports(mechanism, raw.CKF_DECRYPT)
		result.Wrap = result.Wrap || capabilities.Supports(mechanism, raw.CKF_WRAP)
		result.Unwrap = result.Unwrap || capabilities.Supports(mechanism, raw.CKF_UNWRAP)
	}
	for _, mechanism := range spec.DeriveMechanisms {
		result.Derive = result.Derive || capabilities.Supports(mechanism, raw.CKF_DERIVE)
	}
	for _, mechanism := range spec.KEMMechanisms {
		result.Encapsulate = result.Encapsulate || capabilities.Supports(mechanism, raw.CKF_ENCAPSULATE)
		result.Decapsulate = result.Decapsulate || capabilities.Supports(mechanism, raw.CKF_DECAPSULATE)
	}
	if spec.KEMAlias != "" {
		if mechanism, ok := capabilityAlias(definition, spec.KEMAlias); ok {
			result.Encapsulate = result.Encapsulate || supportsMechanism(capabilities, mechanism, raw.CKF_ENCAPSULATE, true) || supportsMechanism(capabilities, mechanism, raw.CKF_DERIVE, true)
			result.Decapsulate = result.Decapsulate || supportsMechanism(capabilities, mechanism, raw.CKF_DECAPSULATE, true) || supportsMechanism(capabilities, mechanism, raw.CKF_DERIVE, true)
		}
	}
	if algorithm == AlgorithmMLKEM512 || algorithm == AlgorithmMLKEM768 || algorithm == AlgorithmMLKEM1024 {
		if mechanism, ok := capabilityAlias(definition, "ml-kem-encapsulate"); ok {
			result.Encapsulate = result.Encapsulate || supportsMechanism(capabilities, mechanism, raw.CKF_ENCAPSULATE, true) || supportsMechanism(capabilities, mechanism, raw.CKF_DERIVE, true)
		}
		if mechanism, ok := capabilityAlias(definition, "ml-kem-decapsulate"); ok {
			result.Decapsulate = result.Decapsulate || supportsMechanism(capabilities, mechanism, raw.CKF_DECAPSULATE, true) || supportsMechanism(capabilities, mechanism, raw.CKF_DERIVE, true)
		}
	}
	return result
}

// Discover enumerates token-present slots using automatic VendorModule selection.
// module must already be opened and initialized. Discover does not take ownership
// of module and does not finalize or destroy it.
func Discover(module raw.Module, vendors ...VendorModule) ([]Device, error) {
	validated, _, err := validateVendorModules(vendors)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: %w", err)
	}
	return discover(module, CompatibilityConfig{}, validated)
}

// DiscoverWithCompatibility is the expert form of Discover.
func DiscoverWithCompatibility(module raw.Module, compatibility CompatibilityConfig, vendors ...VendorModule) ([]Device, error) {
	config := Config{Compatibility: compatibility, Vendors: vendors}
	if err := config.validate(); err != nil {
		return nil, err
	}
	return discover(module, compatibility, vendors)
}

func discover(module raw.Module, compatibility CompatibilityConfig, vendors []VendorModule) ([]Device, error) {
	if module == nil {
		return nil, fmt.Errorf("pkcs11: module is nil")
	}
	moduleInfo, err := module.GetInfo()
	if err != nil {
		return nil, fmt.Errorf("pkcs11: get module info: %w", err)
	}
	slots, err := module.GetSlotList(true)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: list token slots: %w", err)
	}
	devices := make([]Device, 0, len(slots))
	for _, slotID := range slots {
		slotInfo, err := module.GetSlotInfo(slotID)
		if err != nil {
			return nil, fmt.Errorf("pkcs11: slot %d info: %w", slotID, err)
		}
		tokenInfo, err := module.GetTokenInfo(slotID)
		if err != nil {
			return nil, fmt.Errorf("pkcs11: token %d info: %w", slotID, err)
		}
		mechanismList, err := module.GetMechanismList(slotID)
		if err != nil {
			return nil, fmt.Errorf("pkcs11: slot %d mechanisms: %w", slotID, err)
		}
		mechanisms := make(map[raw.MechanismType]raw.MechanismInfo, len(mechanismList))
		var warnings []string
		for _, mechanism := range mechanismList {
			info, infoErr := module.GetMechanismInfo(slotID, mechanism)
			if infoErr != nil {
				warnings = append(warnings, fmt.Sprintf("mechanism 0x%x info: %v", uint(mechanism), infoErr))
				mechanisms[mechanism] = raw.MechanismInfo{}
				continue
			}
			mechanisms[mechanism] = info
		}
		fingerprint := Fingerprint{
			ModulePath: module.Path(), Interface: module.Interface(), Module: moduleInfo,
			SlotID: slotID, Slot: slotInfo, Token: tokenInfo, Mechanisms: mechanisms,
		}
		selection, err := selectAdapter(fingerprint, compatibility, vendors)
		if err != nil {
			return nil, err
		}
		if !compatibility.StrictStandard {
			// A selected module may declare proprietary mechanisms that its native
			// C_GetMechanismList omits. Probe only that finite catalog.
			for _, numeric := range selection.definition.identifiers.mechanisms {
				mechanism := raw.MechanismType(numeric)
				if _, exists := fingerprint.Mechanisms[mechanism]; exists {
					continue
				}
				if info, probeErr := module.GetMechanismInfo(slotID, mechanism); probeErr == nil {
					fingerprint.Mechanisms[mechanism] = info
				}
			}
			selection, err = selectAdapter(fingerprint, compatibility, vendors)
			if err != nil {
				return nil, err
			}
		}
		capabilities := deriveCapabilities(fingerprint, selection.definition)
		if selection.definition.module != nil {
			selection.definition.module.AugmentCapabilities(cloneFingerprint(fingerprint), &capabilities)
		}
		devices = append(devices, Device{
			Fingerprint: fingerprint, Adapter: selection.adapterInfo(),
			Capabilities: capabilities,
			Warnings:     warnings, definition: selection.definition, plan: selection.plan,
			vendor: selection.definition.module,
		})
	}
	sort.Slice(devices, func(i, j int) bool { return devices[i].Fingerprint.SlotID < devices[j].Fingerprint.SlotID })
	return devices, nil
}

func discoverManaged(module *moduleRef, compatibility CompatibilityConfig, vendors []VendorModule) ([]Device, error) {
	return discoverManagedWithPlan(module, behaviorPlan{}, compatibility, vendors)
}

func discoverManagedWithPlan(module *moduleRef, plan behaviorPlan, compatibility CompatibilityConfig, vendors []VendorModule) (devices []Device, err error) {
	if module == nil {
		return nil, fmt.Errorf("pkcs11: module is closed")
	}
	err = module.execute(context.Background(), plan, func(ctx raw.Module) error {
		devices, err = discover(ctx, compatibility, vendors)
		return err
	})
	return devices, err
}
