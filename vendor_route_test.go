package pkcs11

import (
	"testing"

	"github.com/otpki/pkcs11/raw"
)

func TestStandardMechanismWinsBeforeVendorFallback(t *testing.T) {
	const vendorMechanism = 0x80000100
	module := newTestVendor("route-vendor", "Route Vendor", 1, VendorMatchSpec{Manufacturers: []string{"route"}})
	module.definition.Catalog = VendorCatalog{Level: CatalogPublic, Source: "test", Mechanisms: map[string]NumericID{"ml-dsa": vendorMechanism}}
	device := deviceForVendor(t, module, map[raw.MechanismType]raw.MechanismInfo{
		raw.MechanismType(raw.CKM_ML_DSA):  {Flags: raw.CKF_SIGN},
		raw.MechanismType(vendorMechanism): {Flags: raw.CKF_SIGN},
	})
	route, err := ResolveRoute(device, Intent{Operation: OperationSign, Algorithm: AlgorithmMLDSA65})
	if err != nil {
		t.Fatal(err)
	}
	if route.Mechanism.Mechanism != raw.CKM_ML_DSA || route.MechanismSource != "pkcs11-standard" {
		t.Fatalf("route = %#v", route)
	}
}

func TestVendorModuleAdaptsFallbackRoute(t *testing.T) {
	const vendorMechanism = 0x80000100
	module := newTestVendor("route-vendor", "Route Vendor", 1, VendorMatchSpec{Manufacturers: []string{"route"}})
	module.definition.Catalog = VendorCatalog{Level: CatalogPublic, Source: "test", Mechanisms: map[string]NumericID{"ml-dsa": vendorMechanism}}
	module.adaptRoute = func(_ Device, route Route) (Route, error) {
		route.VendorData = "adapted"
		route.Reasons = append(route.Reasons, "test vendor adapted route")
		return route, nil
	}
	device := deviceForVendor(t, module, map[raw.MechanismType]raw.MechanismInfo{
		raw.MechanismType(vendorMechanism): {Flags: raw.CKF_SIGN},
	})
	route, err := ResolveRoute(device, Intent{Operation: OperationSign, Algorithm: AlgorithmMLDSA65})
	if err != nil {
		t.Fatal(err)
	}
	if route.Mechanism.Mechanism != vendorMechanism || route.MechanismSource != "vendor-adapter" || route.VendorData != "adapted" {
		t.Fatalf("route = %#v", route)
	}
}

func TestConsumerModuleCanDefineLegacyAlgorithmCatalog(t *testing.T) {
	const (
		keyType   = 0x80001001
		keygen    = 0x80001002
		parameter = 0x80001003
	)
	module := newTestVendor("legacy-pqc", "Legacy PQC", 1, VendorMatchSpec{Manufacturers: []string{"legacy"}})
	module.definition.Catalog = VendorCatalog{
		Level: pkcs11CatalogPublicForTest(), Source: "test",
		KeyTypes:      map[string]NumericID{"dilithium": keyType},
		Mechanisms:    map[string]NumericID{"dilithium-key-pair-gen": keygen},
		ParameterSets: map[string]NumericID{"dilithium-2": parameter},
	}
	device := deviceForVendor(t, module, map[raw.MechanismType]raw.MechanismInfo{raw.MechanismType(keygen): {Flags: raw.CKF_GENERATE_KEY_PAIR}})
	route, err := ResolveRoute(device, Intent{Operation: OperationGenerate, Algorithm: AlgorithmDilithium2})
	if err != nil {
		t.Fatal(err)
	}
	if route.KeyType != keyType || route.ParameterSet != parameter || route.Mechanism.Mechanism != keygen {
		t.Fatalf("route = %#v", route)
	}
}

// Keep this tiny helper local so the test reads naturally without shadowing a
// public identifier in table literals.
func pkcs11CatalogPublicForTest() CatalogLevel { return CatalogPublic }
