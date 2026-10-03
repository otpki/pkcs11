package pkcs11

import (
	"cmp"
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"

	"github.com/otpki/pkcs11/raw"
)

// NumericID is a standard or vendor-defined PKCS #11 numeric identifier.
// JSON accepts either a number or a decimal/0x-prefixed string.
type NumericID uint

// UnmarshalJSON accepts a JSON number or a quoted integer understood by
// strconv.ParseUint with base zero.
func (id *NumericID) UnmarshalJSON(data []byte) error {
	var number uint64
	if len(data) > 0 && data[0] == '"' {
		var value string
		if err := json.Unmarshal(data, &value); err != nil {
			return err
		}
		parsed, err := strconv.ParseUint(value, 0, 64)
		if err != nil {
			return fmt.Errorf("invalid PKCS #11 id %q: %w", value, err)
		}
		number = parsed
	} else if err := json.Unmarshal(data, &number); err != nil {
		return err
	}
	if number > math.MaxUint {
		return fmt.Errorf("invalid PKCS #11 id %d: overflows uint", number)
	}
	*id = NumericID(number)
	return nil
}

// MarshalJSON renders an identifier as a fixed-width hexadecimal string.
func (id NumericID) MarshalJSON() ([]byte, error) {
	return json.Marshal(fmt.Sprintf("0x%08x", uint(id)))
}

// AdapterFamily is the stable ID of a VendorModule. Concrete vendor packages
// define their own IDs; the root package reserves only AdapterGeneric.
type AdapterFamily string

// AdapterGeneric identifies the vendor-neutral standards-only fallback.
const AdapterGeneric AdapterFamily = "generic"

// AdapterInfo is the read-only result of dynamic VendorModule selection.
type AdapterInfo struct {
	Name             string            `json:"name"`
	Family           AdapterFamily     `json:"family"`
	Variant          string            `json:"variant,omitempty"`
	Source           string            `json:"source,omitempty"`
	CatalogLevel     CatalogLevel      `json:"catalog_level"`
	DetectionScore   int               `json:"detection_score,omitempty"`
	DetectionReasons []string          `json:"detection_reasons,omitempty"`
	StrictStandard   bool              `json:"strict_standard,omitempty"`
	Conformance      VendorConformance `json:"conformance"`
}

type loginScope uint8

const (
	loginScopeAuto loginScope = iota
	loginScopeToken
	loginScopeSession
)

type moduleBehavior struct {
	serializeCalls bool
	legacyInit     bool
	skipFinalize   bool
}

type sessionBehavior struct {
	forceSerial   bool
	lockOSThread  bool
	readWriteOnly bool
	max           int
}

type loginBehavior struct {
	scope                   loginScope
	protectedPathOnEmptyPIN bool
}

type (
	bufferBehavior    struct{ rejectNullProbe bool }
	mechanismBehavior struct{ allowUnadvertisedAliases bool }
	recoveryBehavior  struct{ networkBacked bool }
	cipherBehavior    struct {
		gcmIVMode VendorGCMIVMode
		gcmIVSize int
	}
)

// behaviorPlan is private runtime state derived from standard flags and the
// selected VendorModule. Applications cannot tune individual workarounds.
type behaviorPlan struct {
	module     moduleBehavior
	sessions   sessionBehavior
	login      loginBehavior
	buffers    bufferBehavior
	mechanisms mechanismBehavior
	recovery   recoveryBehavior
	cipher     cipherBehavior
}

func standardBehavior(fingerprint Fingerprint) behaviorPlan {
	return behaviorPlan{
		login: loginBehavior{
			scope:                   loginScopeAuto,
			protectedPathOnEmptyPIN: fingerprint.Token.Flags&raw.CKF_PROTECTED_AUTHENTICATION_PATH != 0,
		},
		cipher: cipherBehavior{gcmIVMode: VendorGCMIVCaller, gcmIVSize: 12},
	}
}

func behaviorFromVendor(value VendorBehavior) behaviorPlan {
	scope := loginScopeAuto
	switch value.LoginScope {
	case VendorLoginToken:
		scope = loginScopeToken
	case VendorLoginSession:
		scope = loginScopeSession
	}
	mode := value.GCMIVMode
	if mode == "" {
		mode = VendorGCMIVCaller
	}
	size := value.GCMIVSize
	if size <= 0 {
		size = 12
	}
	return behaviorPlan{
		module: moduleBehavior{
			serializeCalls: value.SerializeCalls,
			legacyInit:     value.LegacyInitialize,
			skipFinalize:   value.SkipFinalize,
		},
		sessions: sessionBehavior{
			forceSerial:   value.ForceSerialSessions,
			lockOSThread:  value.LockSessionToOSThread,
			readWriteOnly: value.ReadWriteSessionsOnly,
			max:           value.MaxSessions,
		},
		login: loginBehavior{
			scope:                   scope,
			protectedPathOnEmptyPIN: value.ProtectedPathOnEmptyPIN,
		},
		buffers:    bufferBehavior{rejectNullProbe: value.RejectNullOutputProbe},
		mechanisms: mechanismBehavior{allowUnadvertisedAliases: value.AllowUnadvertisedMechanism},
		recovery:   recoveryBehavior{networkBacked: value.NetworkBacked},
		cipher:     cipherBehavior{gcmIVMode: mode, gcmIVSize: size},
	}
}

func mergeBehavior(base, vendor behaviorPlan) behaviorPlan {
	result := base
	result.module.serializeCalls = result.module.serializeCalls || vendor.module.serializeCalls
	result.module.legacyInit = result.module.legacyInit || vendor.module.legacyInit
	result.module.skipFinalize = result.module.skipFinalize || vendor.module.skipFinalize
	result.sessions.forceSerial = result.sessions.forceSerial || vendor.sessions.forceSerial
	result.sessions.lockOSThread = result.sessions.lockOSThread || vendor.sessions.lockOSThread
	result.sessions.readWriteOnly = result.sessions.readWriteOnly || vendor.sessions.readWriteOnly
	if vendor.sessions.max > 0 && (result.sessions.max == 0 || vendor.sessions.max < result.sessions.max) {
		result.sessions.max = vendor.sessions.max
	}
	if vendor.login.scope != loginScopeAuto {
		result.login.scope = vendor.login.scope
	}
	result.login.protectedPathOnEmptyPIN = result.login.protectedPathOnEmptyPIN || vendor.login.protectedPathOnEmptyPIN
	result.buffers.rejectNullProbe = result.buffers.rejectNullProbe || vendor.buffers.rejectNullProbe
	result.mechanisms.allowUnadvertisedAliases = result.mechanisms.allowUnadvertisedAliases || vendor.mechanisms.allowUnadvertisedAliases
	result.recovery.networkBacked = result.recovery.networkBacked || vendor.recovery.networkBacked
	if vendor.cipher.gcmIVMode != "" && vendor.cipher.gcmIVMode != VendorGCMIVCaller {
		result.cipher = vendor.cipher
	}
	return result
}

type identifierAliases struct {
	mechanisms    map[string]NumericID
	keyTypes      map[string]NumericID
	attributes    map[string]NumericID
	parameterSets map[string]NumericID
}

type adapterDefinition struct {
	name                    string
	variant                 string
	family                  AdapterFamily
	priority                int
	match                   VendorMatchSpec
	matchFunc               VendorMatchFunc
	identifiers             identifierAliases
	behavior                behaviorPlan
	preferVendorIdentifiers bool
	source                  string
	catalogLevel            CatalogLevel
	conformance             VendorConformance
	module                  VendorModule
}

type adapterSelection struct {
	definition adapterDefinition
	plan       behaviorPlan
	score      int
	reasons    []string
	strict     bool
}

func definitionFromVendor(module VendorModule) (adapterDefinition, error) {
	definition, err := normalizeVendorDefinition(module.Definition())
	if err != nil {
		return adapterDefinition{}, err
	}
	catalog := definition.Catalog
	return adapterDefinition{
		name: definition.Name, family: definition.ID, priority: definition.Priority,
		match: definition.Match, matchFunc: definition.MatchFunc,
		behavior: behaviorFromVendor(definition.Behavior),
		identifiers: identifierAliases{
			mechanisms: catalog.Mechanisms, keyTypes: catalog.KeyTypes,
			attributes: catalog.Attributes, parameterSets: catalog.ParameterSets,
		},
		preferVendorIdentifiers: definition.PreferVendorIdentifiers,
		source:                  firstNonEmpty(catalog.Source, definition.Source),
		catalogLevel:            catalog.Level,
		conformance:             definition.Conformance,
		module:                  module,
	}, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func (selection adapterSelection) adapterInfo() AdapterInfo {
	return AdapterInfo{
		Name: selection.definition.name, Family: selection.definition.family,
		Variant: selection.definition.variant, Source: selection.definition.source,
		CatalogLevel: selection.definition.catalogLevel, DetectionScore: selection.score,
		DetectionReasons: slices.Clone(selection.reasons),
		StrictStandard:   selection.strict, Conformance: selection.definition.conformance,
	}
}

func normalizeAdapterFamily(family AdapterFamily) AdapterFamily {
	return AdapterFamily(normalizeAlias(string(family)))
}

func knownAdapterFamily(family AdapterFamily, modules []VendorModule) bool {
	family = normalizeAdapterFamily(family)
	if family == AdapterGeneric {
		return true
	}
	return slices.ContainsFunc(modules, func(module VendorModule) bool {
		return normalizeAdapterFamily(module.Definition().ID) == family
	})
}

// VendorModules returns diagnostic metadata for candidate vendor modules.
func VendorModules(modules ...VendorModule) ([]AdapterInfo, error) {
	validated, _, err := validateVendorModules(modules)
	if err != nil {
		return nil, err
	}
	result := []AdapterInfo{{Name: "Generic PKCS #11", Family: AdapterGeneric, Source: "PKCS #11 3.2", CatalogLevel: CatalogStandardOnly}}
	for _, module := range validated {
		definition, err := definitionFromVendor(module)
		if err != nil {
			return nil, err
		}
		result = append(result, AdapterInfo{
			Name: definition.name, Family: definition.family, Source: definition.source,
			CatalogLevel: definition.catalogLevel, Conformance: definition.conformance,
		})
	}
	slices.SortFunc(result, func(a, b AdapterInfo) int { return cmp.Compare(a.Family, b.Family) })
	return result, nil
}

func containsAny(value string, candidates []string) bool {
	value = strings.ToLower(value)
	for _, candidate := range candidates {
		if candidate != "" && strings.Contains(value, strings.ToLower(candidate)) {
			return true
		}
	}
	return false
}

func scoreDeclarativeMatch(definition adapterDefinition, fingerprint Fingerprint) VendorMatch {
	score := definition.priority
	var reasons []string
	configured, matched := 0, 0
	matches := []struct {
		name, value string
		candidates  []string
		weight      int
	}{
		{"manufacturer fingerprint", fingerprint.Module.ManufacturerID + " " + fingerprint.Token.ManufacturerID + " " + fingerprint.Slot.ManufacturerID, definition.match.Manufacturers, 100},
		{"library description", fingerprint.Module.LibraryDescription, definition.match.LibraryDescriptions, 80},
		{"module path", fingerprint.ModulePath, definition.match.ModulePaths, 90},
		{"token model", fingerprint.Token.Model, definition.match.Models, 70},
		{"slot description", fingerprint.Slot.SlotDescription, definition.match.SlotDescriptions, 40},
	}
	for _, match := range matches {
		if len(match.candidates) == 0 {
			continue
		}
		configured++
		if containsAny(match.value, match.candidates) {
			matched++
			score += match.weight
			reasons = append(reasons, match.name)
			continue
		}
		if definition.match.MatchAllText {
			return VendorMatch{}
		}
	}
	minimum := definition.match.MinimumTextMatches
	if configured > 0 && minimum == 0 {
		minimum = 1
	}
	if matched < minimum {
		return VendorMatch{}
	}
	score -= (configured - matched) * 15
	for _, numeric := range definition.match.RequiredMechanisms {
		if _, ok := fingerprint.Mechanisms[raw.MechanismType(numeric)]; !ok {
			return VendorMatch{}
		}
		score += 20
		reasons = append(reasons, fmt.Sprintf("mechanism 0x%x", uint(numeric)))
	}
	if configured == 0 && len(definition.match.RequiredMechanisms) == 0 {
		return VendorMatch{}
	}
	return VendorMatch{Matched: true, Score: score, Reasons: reasons}
}

func matchVendor(definition adapterDefinition, fingerprint Fingerprint) VendorMatch {
	if definition.matchFunc != nil {
		match := definition.matchFunc(cloneFingerprint(fingerprint))
		if match.Matched {
			match.Score += definition.priority
		}
		return match
	}
	return scoreDeclarativeMatch(definition, fingerprint)
}

// MatchVendorModule evaluates one VendorModule against a defensive fingerprint
// snapshot without loading an HSM or mutating driver state. Provider packages
// can use it in unit tests to verify declarative and custom matching rules. The
// returned score includes VendorDefinition.Priority, exactly as live selection
// does.
func MatchVendorModule(module VendorModule, fingerprint Fingerprint) (VendorMatch, error) {
	validated, _, err := validateVendorModules([]VendorModule{module})
	if err != nil {
		return VendorMatch{}, err
	}
	definition, err := definitionFromVendor(validated[0])
	if err != nil {
		return VendorMatch{}, err
	}
	match := matchVendor(definition, cloneFingerprint(fingerprint))
	match.Reasons = slices.Clone(match.Reasons)
	return match, nil
}

func genericDefinition() adapterDefinition {
	return adapterDefinition{
		name: "Generic PKCS #11", family: AdapterGeneric, priority: -1000,
		source: "PKCS #11 3.2", catalogLevel: CatalogStandardOnly,
	}
}

func selectAdapter(fingerprint Fingerprint, compatibility CompatibilityConfig, modules []VendorModule) (adapterSelection, error) {
	definitions := make([]adapterDefinition, 0, len(modules))
	for _, module := range modules {
		definition, err := definitionFromVendor(module)
		if err != nil {
			return adapterSelection{}, err
		}
		definitions = append(definitions, definition)
	}

	forced := normalizeAdapterFamily(compatibility.AdapterFamily)
	if forced != "" {
		if forced == AdapterGeneric {
			generic := genericDefinition()
			return adapterSelection{definition: generic, plan: standardBehavior(fingerprint), score: 1_000_000, reasons: []string{"forced generic standards mode"}}, nil
		}
		for _, definition := range definitions {
			if definition.family == forced {
				definition.variant = "forced"
				return adapterSelection{
					definition: definition,
					plan:       mergeBehavior(standardBehavior(fingerprint), definition.behavior),
					score:      1_000_000,
					reasons:    []string{"forced by CompatibilityConfig.AdapterFamily"},
				}, nil
			}
		}
		return adapterSelection{}, fmt.Errorf("pkcs11: unknown adapter family %q", compatibility.AdapterFamily)
	}

	best := adapterSelection{definition: genericDefinition(), score: -1000, reasons: []string{"generic fallback"}}
	for _, definition := range definitions {
		match := matchVendor(definition, fingerprint)
		if !match.Matched || match.Score < best.score {
			continue
		}
		if strings.TrimSpace(match.Name) != "" {
			definition.name = strings.TrimSpace(match.Name)
		}
		definition.variant = strings.TrimSpace(match.Variant)
		best = adapterSelection{definition: definition, score: match.Score, reasons: slices.Clone(match.Reasons)}
	}
	best.plan = mergeBehavior(standardBehavior(fingerprint), best.definition.behavior)
	if compatibility.StrictStandard {
		best.plan = standardBehavior(fingerprint)
		best.definition.identifiers = identifierAliases{}
		best.definition.preferVendorIdentifiers = false
		best.definition.source = "PKCS #11 3.2 strict-standard mode"
		best.definition.catalogLevel = CatalogStandardOnly
		best.definition.module = nil
		best.strict = true
	}
	return best, nil
}
