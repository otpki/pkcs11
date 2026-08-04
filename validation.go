package pkcs11

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/otpki/pkcs11/raw"
)

// ValidationLevel describes how far a live module/token validation progressed.
// It intentionally does not claim vendor certification or laboratory testing.
type ValidationLevel string

const (
	// ValidationIdentified means the module loaded and a token was identified.
	ValidationIdentified ValidationLevel = "identified"
	// ValidationMechanisms means every advertised mechanism was enumerated and
	// its CK_MECHANISM_INFO record was read successfully.
	ValidationMechanisms ValidationLevel = "mechanisms"
	// ValidationSession means the managed client successfully acquired and
	// inspected a session in addition to completing discovery checks.
	ValidationSession ValidationLevel = "session"
	// ValidationOperational means the requested live, non-destructive operation
	// probe succeeded. At present that probe is C_GenerateRandom.
	ValidationOperational ValidationLevel = "operational"
	// ValidationCryptographic means the caller-supplied cryptographic probe
	// completed successfully against an existing key.
	ValidationCryptographic ValidationLevel = "cryptographically-validated"
	// ValidationHardwareAttested means signed external evidence matched this
	// exact runtime module, mechanism inventory, token, firmware, and adapter.
	ValidationHardwareAttested ValidationLevel = "hardware-attested"
)

// RuntimeValidationOptions controls non-destructive validation against the
// module and token that are actually loaded in this process.
type RuntimeValidationOptions struct {
	// Refresh re-enumerates slots and re-runs adapter selection before probing.
	Refresh bool
	// CheckRandom performs a live C_GenerateRandom operation. It never creates a
	// test key and is the only operation probe enabled by this type.
	CheckRandom bool
	// RandomBytes is the requested C_GenerateRandom output length. Values less
	// than or equal to zero use the health check's conservative default.
	RandomBytes int
	// ReadWrite also verifies that a read/write session can be acquired.
	ReadWrite bool
	// CryptographicProbe exercises a caller-selected existing key. The driver
	// never creates a persistent test key as part of validation.
	CryptographicProbe func(context.Context, *Client) error
}

// MechanismValidation is live evidence for one advertised mechanism.
type MechanismValidation struct {
	// Mechanism is the numeric CK_MECHANISM_TYPE returned by the token.
	Mechanism raw.MechanismType `json:"mechanism"`
	// Info is the live CK_MECHANISM_INFO value. It is zero when the module
	// advertised the mechanism but failed to return its information record.
	Info raw.MechanismInfo `json:"info"`
	// Error is a serialization-friendly copy of the mechanism-info failure.
	Error string `json:"error,omitempty"`
}

// RuntimeValidationReport records live, non-destructive evidence collected
// from the selected module and token. RuntimeProbed means the calls were made
// against the loaded PKCS #11 module; it is not a claim that this project has
// independently certified the HSM model or firmware.
type RuntimeValidationReport struct {
	// Level is the strongest validation stage completed successfully. Stages are
	// cumulative, but a report can still contain warnings from optional checks.
	Level ValidationLevel `json:"level"`
	// RuntimeProbed distinguishes live evidence from a report value that was
	// merely decoded or constructed by an application.
	RuntimeProbed bool `json:"runtime_probed"`
	// ValidatedAt is captured immediately before the first validation step.
	ValidatedAt time.Time `json:"validated_at"`
	// Duration is the total wall-clock time spent collecting the report.
	Duration time.Duration `json:"duration"`
	// ModulePath is the canonical native library path owned by the client.
	ModulePath string `json:"module_path"`
	// ModuleSHA256 identifies the module file bytes when the file can be read. A
	// missing digest is reported as a warning rather than failing live probing.
	ModuleSHA256 string `json:"module_sha256,omitempty"`
	// MechanismSHA256 fingerprints the sorted mechanism ID, key-size range, and
	// capability flags observed during this validation run.
	MechanismSHA256 string `json:"mechanism_sha256,omitempty"`
	// Interface is the Cryptoki interface selected by raw.Open.
	Interface raw.InterfaceInfo `json:"interface"`
	// Device is a defensive snapshot of the selected slot, token, capabilities,
	// and automatically detected adapter.
	Device Device `json:"device"`
	// Mechanisms contains one record for every ID returned by C_GetMechanismList.
	Mechanisms []MechanismValidation `json:"mechanisms"`
	// Health contains the module, token, session, and optional RNG checks used to
	// establish the session or operational validation levels.
	Health HealthReport `json:"health"`
	// Warnings record non-fatal evidence gaps and adapter/catalog discrepancies.
	Warnings []string `json:"warnings,omitempty"`
	// AttestationLab is populated only after VerifyHardwareEvidence succeeds.
	AttestationLab string `json:"attestation_lab,omitempty"`
}

// ValidateRuntime re-runs dynamic adapter detection and collects live evidence
// from the loaded module. The probe is non-destructive and never requires a
// configured test key.
func (c *Client) ValidateRuntime(ctx context.Context, options RuntimeValidationOptions) (RuntimeValidationReport, error) {
	start := time.Now()
	report := RuntimeValidationReport{Level: ValidationIdentified, ValidatedAt: start}
	if c == nil || c.closed.Load() || c.module == nil {
		err := errors.New("pkcs11: client is closed")
		return report, err
	}
	if options.Refresh {
		if err := c.Refresh(ctx); err != nil {
			return report, fmt.Errorf("pkcs11: refresh before runtime validation: %w", err)
		}
	}
	report.RuntimeProbed = true
	report.ModulePath = c.ModulePath()
	// Hash the library bytes rather than metadata such as path or mtime. The
	// digest is an evidence-binding input, but inability to read a loaded module
	// must not turn otherwise useful runtime diagnostics into a hard failure.
	if data, readErr := os.ReadFile(report.ModulePath); readErr == nil {
		digest := sha256.Sum256(data)
		report.ModuleSHA256 = hex.EncodeToString(digest[:])
	} else {
		report.Warnings = append(report.Warnings, "module digest unavailable: "+readErr.Error())
	}
	report.Interface = c.Interface()
	report.Device = c.Device()

	mechanisms, err := c.getMechanismList(ctx, report.Device.Fingerprint.SlotID)
	if err != nil {
		report.Duration = time.Since(start)
		return report, fmt.Errorf("pkcs11: runtime mechanism list: %w", err)
	}
	// Stable ordering makes both the JSON evidence and the mechanism fingerprint
	// independent of a vendor module's enumeration order.
	slices.Sort(mechanisms)
	var mechanismErrs []error
	for _, mechanism := range mechanisms {
		info, infoErr := c.getMechanismInfo(ctx, report.Device.Fingerprint.SlotID, mechanism)
		validation := MechanismValidation{Mechanism: mechanism, Info: info}
		if infoErr != nil {
			validation.Error = infoErr.Error()
			mechanismErrs = append(mechanismErrs, fmt.Errorf("mechanism 0x%x: %w", uint(mechanism), infoErr))
		}
		report.Mechanisms = append(report.Mechanisms, validation)
	}
	// Use fixed-width hexadecimal fields to avoid ambiguous concatenation and to
	// keep the fingerprint stable across platforms with different native CK_ULONG
	// widths in their textual formatting.
	mechanismHash := sha256.New()
	for _, validation := range report.Mechanisms {
		fmt.Fprintf(mechanismHash, "%016x:%016x:%016x:%016x\n", uint(validation.Mechanism), validation.Info.MinKeySize, validation.Info.MaxKeySize, validation.Info.Flags)
	}
	report.MechanismSHA256 = hex.EncodeToString(mechanismHash.Sum(nil))
	if len(report.Mechanisms) == 0 {
		mechanismErrs = append(mechanismErrs, errors.New("pkcs11: token advertises no mechanisms"))
	}
	if len(mechanismErrs) == 0 {
		report.Level = ValidationMechanisms
	}

	// Validation levels advance monotonically. Mechanism-detail failures remain
	// part of the returned joined error even when later, independent health checks
	// succeed and provide useful evidence.
	health, healthErr := c.Health(ctx, HealthOptions{CheckRandom: options.CheckRandom, RandomBytes: options.RandomBytes, ReadWrite: options.ReadWrite})
	report.Health = health
	if health.Status != HealthUnhealthy {
		report.Level = ValidationSession
		if options.CheckRandom {
			report.Level = ValidationOperational
		}
	}
	if options.CryptographicProbe != nil && health.Status != HealthUnhealthy {
		if probeErr := options.CryptographicProbe(ctx, c); probeErr != nil {
			mechanismErrs = append(mechanismErrs, fmt.Errorf("cryptographic validation: %w", probeErr))
		} else {
			report.Level = ValidationCryptographic
		}
	}
	report.Warnings = append(report.Warnings, report.Device.Warnings...)
	for name, id := range report.Device.definition.identifiers.mechanisms {
		if !mechanismAdvertised(report.Device, uint(id)) {
			report.Warnings = append(report.Warnings, fmt.Sprintf("adapter alias %q (0x%x) is not advertised by this token", name, uint(id)))
		}
	}
	report.Duration = time.Since(start)
	return report, errors.Join(errors.Join(mechanismErrs...), healthErr)
}

// HardwareEvidence is a signed, externally produced lab record. The driver
// never upgrades a runtime probe to hardware validation without this evidence.
type HardwareEvidence struct {
	// Version identifies the evidence schema. Sign sets version 1 when zero.
	Version uint `json:"version"`
	// AdapterFamily is the driver adapter family observed by the lab.
	AdapterFamily string `json:"adapter_family"`
	// ModuleSHA256 binds the evidence to the exact tested PKCS #11 library bytes.
	ModuleSHA256 string `json:"module_sha256"`
	// MechanismSHA256 binds the evidence to the tested mechanism inventory.
	MechanismSHA256 string `json:"mechanism_sha256"`
	// TokenSerial identifies the physical or virtual token instance tested.
	TokenSerial string `json:"token_serial"`
	// Manufacturer is the token manufacturer string reported by Cryptoki.
	Manufacturer string `json:"manufacturer"`
	// Model is the token model string reported by Cryptoki.
	Model string `json:"model"`
	// Firmware is the token firmware version reported by Cryptoki.
	Firmware raw.Version `json:"firmware"`
	// ValidatedAt records when the external validation was performed.
	ValidatedAt time.Time `json:"validated_at"`
	// Lab identifies the external organization or controlled test environment.
	Lab string `json:"lab"`
	// Checks names the conformance or cryptographic cases covered by the record.
	Checks []string `json:"checks"`
	// Signature is an Ed25519 signature over the JSON representation with this
	// field omitted. VerifyHardwareEvidence still performs runtime matching.
	Signature []byte `json:"signature,omitempty"`
}

// signingBytes returns the deterministic payload used by Sign and Verify. JSON
// struct-field order is stable, and clearing Signature prevents self-reference.
func (e HardwareEvidence) signingBytes() ([]byte, error) {
	e.Signature = nil
	return json.Marshal(e)
}

// Sign binds the evidence fields to an Ed25519 signature.
func (e *HardwareEvidence) Sign(privateKey ed25519.PrivateKey) error {
	if e == nil {
		return errors.New("pkcs11: nil hardware evidence")
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return errors.New("pkcs11: invalid evidence private key")
	}
	if e.Version == 0 {
		e.Version = 1
	}
	payload, err := e.signingBytes()
	if err != nil {
		return err
	}
	e.Signature = ed25519.Sign(privateKey, payload)
	return nil
}

// Verify authenticates the evidence signature without comparing it to a runtime report.
func (e HardwareEvidence) Verify(publicKey ed25519.PublicKey) error {
	if len(publicKey) != ed25519.PublicKeySize || len(e.Signature) != ed25519.SignatureSize {
		return errors.New("pkcs11: invalid or unsigned hardware evidence")
	}
	payload, err := e.signingBytes()
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, payload, e.Signature) {
		return errors.New("pkcs11: invalid hardware evidence signature")
	}
	return nil
}

// VerifyHardwareEvidence binds a signed lab record to the exact module binary,
// mechanism inventory, token identity, firmware and selected adapter observed
// by this runtime report.
func (r *RuntimeValidationReport) VerifyHardwareEvidence(e HardwareEvidence, publicKey ed25519.PublicKey) error {
	if r == nil {
		return errors.New("pkcs11: nil runtime validation report")
	}
	if err := e.Verify(publicKey); err != nil {
		return err
	}
	// The signature authenticates the lab record; these comparisons bind that
	// authenticated record to what this process actually loaded and discovered.
	checks := []struct{ name, have, want string }{
		{"adapter family", e.AdapterFamily, string(r.Device.Adapter.Family)},
		{"module SHA-256", strings.ToLower(e.ModuleSHA256), strings.ToLower(r.ModuleSHA256)},
		{"mechanism SHA-256", strings.ToLower(e.MechanismSHA256), strings.ToLower(r.MechanismSHA256)},
		{"token serial", e.TokenSerial, r.Device.Fingerprint.Token.SerialNumber},
		{"manufacturer", e.Manufacturer, r.Device.Fingerprint.Token.ManufacturerID},
		{"model", e.Model, r.Device.Fingerprint.Token.Model},
	}
	for _, check := range checks {
		if check.have != check.want {
			return fmt.Errorf("pkcs11: hardware evidence %s mismatch: %q != %q", check.name, check.have, check.want)
		}
	}
	if e.Firmware != r.Device.Fingerprint.Token.FirmwareVersion {
		return errors.New("pkcs11: hardware evidence firmware mismatch")
	}
	// Upgrade the mutable report only after every identity and firmware check has
	// succeeded. A failed comparison leaves the original runtime level intact.
	r.Level = ValidationHardwareAttested
	r.AttestationLab = e.Lab
	return nil
}
