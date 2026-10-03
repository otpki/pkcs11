package pkcs11

import (
	"testing"

	"github.com/otpki/pkcs11/raw"
)

func fingerprint(manufacturer, description, model, path string) Fingerprint {
	return Fingerprint{
		ModulePath: path,
		Module:     raw.Info{ManufacturerID: manufacturer, LibraryDescription: description},
		Slot:       raw.SlotInfo{ManufacturerID: manufacturer},
		Token:      raw.TokenInfo{ManufacturerID: manufacturer, Model: model},
		Mechanisms: map[raw.MechanismType]raw.MechanismInfo{},
	}
}

func TestVendorSelectionUsesOnlySuppliedModules(t *testing.T) {
	alpha := newTestVendor("alpha", "Alpha HSM", 10, VendorMatchSpec{Manufacturers: []string{"alpha"}})
	beta := newTestVendor("beta", "Beta HSM", 20, VendorMatchSpec{Manufacturers: []string{"beta"}})

	selection, err := selectAdapter(fingerprint("Beta Security", "", "", "/opt/beta/lib.so"), CompatibilityConfig{}, []VendorModule{alpha, beta})
	if err != nil {
		t.Fatal(err)
	}
	if got := selection.definition.family; got != "beta" {
		t.Fatalf("family = %q, want beta", got)
	}

	selection, err = selectAdapter(fingerprint("Beta Security", "", "", "/opt/beta/lib.so"), CompatibilityConfig{}, []VendorModule{alpha})
	if err != nil {
		t.Fatal(err)
	}
	if got := selection.definition.family; got != AdapterGeneric {
		t.Fatalf("unsupplied vendor selected as %q, want generic", got)
	}
}

func TestCompatibilityCanForceSuppliedModule(t *testing.T) {
	module := newTestVendor("remote-hsm", "Remote HSM", 1, VendorMatchSpec{Manufacturers: []string{"remote"}})
	module.definition.Behavior = VendorBehavior{NetworkBacked: true, ReadWriteSessionsOnly: true}
	selection, err := selectAdapter(Fingerprint{}, CompatibilityConfig{AdapterFamily: "remote-hsm"}, []VendorModule{module})
	if err != nil {
		t.Fatal(err)
	}
	if selection.definition.family != "remote-hsm" || !selection.plan.recovery.networkBacked || !selection.plan.sessions.readWriteOnly {
		t.Fatalf("forced module did not retain behavior: %#v", selection)
	}
}

func TestCompatibilityRejectsUnsuppliedModule(t *testing.T) {
	_, err := selectAdapter(Fingerprint{}, CompatibilityConfig{AdapterFamily: "missing"}, nil)
	if err == nil {
		t.Fatal("expected unknown forced module error")
	}
}

func TestStrictStandardRetainsIdentityButDisablesModuleBehavior(t *testing.T) {
	module := newTestVendor("remote-hsm", "Remote HSM", 1, VendorMatchSpec{Manufacturers: []string{"remote"}})
	module.definition.Behavior = VendorBehavior{NetworkBacked: true, ReadWriteSessionsOnly: true, GCMIVMode: VendorGCMIVCiphertextPrefix}
	module.definition.Catalog = VendorCatalog{Level: CatalogPublic, Source: "test", Mechanisms: map[string]NumericID{"vendor-mechanism": 0x80000001}}
	selection, err := selectAdapter(fingerprint("Remote", "", "", ""), CompatibilityConfig{StrictStandard: true}, []VendorModule{module})
	if err != nil {
		t.Fatal(err)
	}
	if selection.definition.family != "remote-hsm" || !selection.strict {
		t.Fatalf("strict selection = %#v", selection)
	}
	if selection.definition.module != nil || selection.plan.recovery.networkBacked || selection.plan.sessions.readWriteOnly || selection.plan.cipher.gcmIVMode != VendorGCMIVCaller {
		t.Fatalf("strict-standard mode retained vendor behavior: %#v", selection.plan)
	}
	if len(selection.definition.identifiers.mechanisms) != 0 {
		t.Fatal("strict-standard mode retained vendor identifiers")
	}
}

func TestClientDiagnosticsAreIndependentSnapshots(t *testing.T) {
	module := newTestVendor("diagnostic", "Diagnostic HSM", 1, VendorMatchSpec{Manufacturers: []string{"diagnostic"}})
	mechanism := raw.MechanismType(raw.CKM_RSA_PKCS)
	device := deviceForVendor(t, module, map[raw.MechanismType]raw.MechanismInfo{mechanism: {Flags: raw.CKF_SIGN}})
	device.Warnings = []string{"original"}
	device.Adapter.DetectionReasons = []string{"manufacturer fingerprint"}
	client := &Client{device: device}

	snapshot := client.Device()
	delete(snapshot.Fingerprint.Mechanisms, mechanism)
	delete(snapshot.Capabilities.Mechanisms, mechanism)
	delete(snapshot.Capabilities.Algorithms, AlgorithmRSA)
	snapshot.Warnings[0] = "mutated"
	snapshot.Adapter.DetectionReasons[0] = "mutated"

	current := client.currentDevice()
	if _, ok := current.Fingerprint.Mechanisms[mechanism]; !ok {
		t.Fatal("mutating Device fingerprint changed internal state")
	}
	if _, ok := current.Capabilities.Mechanisms[mechanism]; !ok {
		t.Fatal("mutating Device capabilities changed internal state")
	}
	if _, ok := current.Capabilities.Algorithms[AlgorithmRSA]; !ok {
		t.Fatal("mutating Device algorithm map changed internal state")
	}
	if current.Warnings[0] != "original" || current.Adapter.DetectionReasons[0] != "manufacturer fingerprint" {
		t.Fatal("mutating Device slices changed internal state")
	}
}
