package conformance

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/raw"
)

// Requirement controls how a test result affects the conformance verdict.
type Requirement string

const (
	Required  Requirement = "required"
	Optional  Requirement = "optional"
	Forbidden Requirement = "forbidden"
	Disabled  Requirement = "disabled"
)

var knownCaseKinds = map[string]struct{}{
	"runtime":                {},
	"random":                 {},
	"session":                {},
	"digest":                 {},
	"concurrency":            {},
	"generate":               {},
	"sign":                   {},
	"hmac":                   {},
	"encrypt":                {},
	"wrap":                   {},
	"authenticated-wrap":     {},
	"derive-ecdh":            {},
	"derive-hash":            {},
	"derive-hkdf":            {},
	"derive-ike":             {},
	"import-secret":          {},
	"message-sign":           {},
	"signature-first-verify": {},
	"session-validation":     {},
	"kem":                    {},
	"object-lifecycle":       {},
	"trust-object":           {},
	"validation-object":      {},
	"message-aead":           {},
	"certificate":            {},
	"idle-recovery":          {},
	"dsa":                    {},
	"parameter-gen":          {},
	"derive-dh":              {},
	"derive-montgomery":      {},
	"mac":                    {},
	"derive-encrypt":         {},
	"derive-concatenate":     {},
	"derive-extract":         {},
	"rsa-aes-wrap":           {},
	"derive-sp800":           {},
	"derive-tls":             {},
	"tls-mac":                {},
	"hotp":                   {},
	"pbkdf2":                 {},
	"pub-key-from-priv":      {},
	"hmac-keygen":            {},
	"des":                    {},
	"token-prehash":          {},
	"derive-ike1-prf":        {},
	"derive-ike2-prf-plus":   {},
	"derive-ike1-extended":   {},
	"profile-object":         {},
}

// NumericID is a mechanism or parameter-set identifier used by a test case.
type NumericID uint64

type TokenProfile struct {
	SlotID       *uint64
	SlotIndex    *int
	Label        string
	SerialNumber string
	Model        string
}

type LoginProfile struct {
	Mode     pkcs11.LoginMode
	Role     pkcs11.UserRole
	Username string
	PINEnv   string
}

type SessionProfile struct {
	Min         int
	Max         int
	IdleTimeout time.Duration
	Async       bool
}

type ExpectedProfile struct {
	Adapter            pkcs11.AdapterFamily
	MinimumInterface   string
	RequiredMechanisms []NumericID
}

type SuiteProfile struct {
	Timeout     time.Duration
	CaseTimeout time.Duration
	Cleanup     bool
	Prefix      string
	Concurrency int
	Iterations  int
}

type HSSProfile struct {
	Levels     uint
	LMSTypes   []NumericID
	LMOTSTypes []NumericID
}

// Case describes one portable or vendor-specific conformance operation.
type Case struct {
	Name           string
	Kind           string
	Requirement    Requirement
	Algorithm      pkcs11.Algorithm
	Variant        string
	Hash           string
	RSABits        uint
	ParameterSet   NumericID
	HSS            *HSSProfile
	MessageBytes   int
	Concurrency    int
	Iterations     int
	IdleFor        time.Duration
	ExpectRecovery *bool
	Context        string
	Verify         *bool
	// PublicAttributes and PrivateAttributes merge raw attributes into the
	// generated key-pair templates last, overriding policy-derived defaults.
	PublicAttributes  []*raw.Attribute
	PrivateAttributes []*raw.Attribute
	Notes             string
}

// Profile is a Go-native HSM conformance plan.
type Profile struct {
	Module         string
	Token          TokenProfile
	Login          LoginProfile
	Sessions       SessionProfile
	Expected       ExpectedProfile
	Suite          SuiteProfile
	ForceAdapter   pkcs11.AdapterFamily
	StrictStandard bool
	Cases          []Case
}

func (p Profile) Validate(extensions ...CaseExtension) error {
	registry, registryErr := buildExtensionRegistry(extensions)
	var errs []error
	if registryErr != nil {
		errs = append(errs, registryErr)
	}
	if len(p.Cases) == 0 {
		errs = append(errs, errors.New("at least one case is required"))
	}
	seen := make(map[string]struct{}, len(p.Cases))
	for i, testCase := range p.Cases {
		if testCase.Name == "" {
			errs = append(errs, fmt.Errorf("case %d has no name", i))
		}
		requirement := testCase.Requirement
		if requirement == "" {
			requirement = Required
		}
		kind := strings.ToLower(strings.TrimSpace(testCase.Kind))
		if kind == "" {
			errs = append(errs, fmt.Errorf("case %q has no kind", testCase.Name))
		} else if _, portable := knownCaseKinds[kind]; !portable {
			_, extended := registry.byKind[kind]
			if !extended && requirement != Disabled {
				errs = append(errs, fmt.Errorf("case %q has unknown kind %q; install its CaseExtension or keep it disabled", testCase.Name, testCase.Kind))
			}
		}
		if _, ok := seen[testCase.Name]; ok {
			errs = append(errs, fmt.Errorf("duplicate case name %q", testCase.Name))
		}
		seen[testCase.Name] = struct{}{}
		switch requirement {
		case Required, Optional, Forbidden, Disabled:
		default:
			errs = append(errs, fmt.Errorf("case %q has invalid requirement %q", testCase.Name, requirement))
		}
	}
	return errors.Join(errs...)
}

func (p Profile) normalizedCase(testCase Case) Case {
	if testCase.Requirement == "" {
		testCase.Requirement = Required
	}
	if testCase.MessageBytes <= 0 {
		testCase.MessageBytes = 128
	}
	if testCase.Concurrency <= 0 {
		testCase.Concurrency = p.Suite.Concurrency
	}
	if testCase.Concurrency <= 0 {
		testCase.Concurrency = 8
	}
	if testCase.Iterations <= 0 {
		testCase.Iterations = p.Suite.Iterations
	}
	if testCase.Iterations <= 0 {
		testCase.Iterations = 25
	}
	return testCase
}

func (p Profile) caseTimeout() time.Duration {
	if p.Suite.CaseTimeout > 0 {
		return p.Suite.CaseTimeout
	}
	return 2 * time.Minute
}

func (p Profile) suiteTimeout() time.Duration {
	if p.Suite.Timeout > 0 {
		return p.Suite.Timeout
	}
	return 30 * time.Minute
}

func (p Profile) clientConfig(vendors []pkcs11.VendorModule, sources ...pkcs11.ModuleSource) (pkcs11.Config, error) {
	var module pkcs11.ModuleSource
	if len(sources) != 0 {
		module = sources[0]
	}
	if module == nil {
		if strings.TrimSpace(p.Module) == "" || strings.Contains(p.Module, "${") {
			return pkcs11.Config{}, errors.New("conformance: module path is empty or contains an unresolved environment variable")
		}
		module = pkcs11.LocalModule(p.Module)
	}
	selector := pkcs11.TokenSelector{
		SlotIndex:    p.Token.SlotIndex,
		Label:        p.Token.Label,
		SerialNumber: p.Token.SerialNumber,
		Model:        p.Token.Model,
	}
	if p.Token.SlotID != nil {
		slot := raw.SlotID(*p.Token.SlotID)
		selector.SlotID = &slot
	}
	mode := p.Login.Mode
	if mode == "" {
		mode = pkcs11.LoginNone
	}
	role := p.Login.Role
	if role == "" {
		role = pkcs11.UserRoleUser
	}
	config := pkcs11.Config{
		Module: module,
		Token:  selector,
		Login: pkcs11.LoginConfig{
			Mode:     mode,
			Role:     role,
			Username: p.Login.Username,
		},
		Sessions: pkcs11.SessionConfig{
			Min:         p.Sessions.Min,
			Max:         p.Sessions.Max,
			IdleTimeout: p.Sessions.IdleTimeout,
			Async:       p.Sessions.Async,
		},
		Vendors: append([]pkcs11.VendorModule(nil), vendors...),
		Compatibility: pkcs11.CompatibilityConfig{
			StrictStandard: p.StrictStandard,
			AdapterFamily:  p.ForceAdapter,
		},
	}
	if mode != pkcs11.LoginNone {
		if p.Login.PINEnv == "" {
			return pkcs11.Config{}, errors.New("conformance: login.pin_env is required when login is enabled")
		}
		pin, ok := os.LookupEnv(p.Login.PINEnv)
		if !ok || pin == "" {
			return pkcs11.Config{}, fmt.Errorf("conformance: environment variable %s is empty", p.Login.PINEnv)
		}
		config.PIN = pkcs11.StaticPIN(pin)
	}
	return config, nil
}
