package pkcs11

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otpki/pkcs11/internal/testmock"
	"github.com/otpki/pkcs11/raw"
)

func TestDefaultAttributeCachePolicy(t *testing.T) {
	allowed := []uint{raw.CKA_CLASS, raw.CKA_LABEL, raw.CKA_ID, raw.CKA_UNIQUE_ID, raw.CKA_PUBLIC_KEY_INFO}
	for _, attributeType := range allowed {
		if !DefaultAttributeCachePolicy(attributeType) {
			t.Errorf("attribute %#x should be cacheable", attributeType)
		}
	}

	blocked := []uint{
		raw.CKA_VALUE,
		raw.CKA_PRIVATE_EXPONENT,
		raw.CKA_PRIME_1,
		raw.CKA_PRIME_2,
		raw.CKA_EXPONENT_1,
		raw.CKA_EXPONENT_2,
		raw.CKA_COEFFICIENT,
		raw.CKA_SEED,
		raw.CKA_OTP_COUNTER,
		raw.CKA_OTP_TIME,
		raw.CKA_HSS_KEYS_REMAINING,
		raw.CKA_VENDOR_DEFINED,
		raw.CKA_VENDOR_DEFINED + 1,
	}
	for _, attributeType := range blocked {
		if DefaultAttributeCachePolicy(attributeType) {
			t.Errorf("attribute %#x must not be cached by default", attributeType)
		}
	}
}

func TestObjectCacheUsesBoundedLRU(t *testing.T) {
	cache := newTokenCache(CacheConfig{
		ObjectTTL:        time.Hour,
		AttributeTTL:     time.Hour,
		ObjectMaxEntries: 2,
	})
	cache.putObjects("a", 1, []raw.ObjectHandle{1})
	cache.putObjects("b", 1, []raw.ObjectHandle{2})
	if _, ok := cache.getObjects("a", 1); !ok {
		t.Fatal("expected cache hit for a")
	}
	cache.putObjects("c", 1, []raw.ObjectHandle{3})

	if _, ok := cache.getObjects("b", 1); ok {
		t.Fatal("least recently used entry b was not evicted")
	}
	if got, ok := cache.getObjects("a", 1); !ok || len(got) != 1 || got[0] != 1 {
		t.Fatalf("entry a = %v, %v", got, ok)
	}
	if got, ok := cache.getObjects("c", 1); !ok || len(got) != 1 || got[0] != 3 {
		t.Fatalf("entry c = %v, %v", got, ok)
	}
}

func TestAttributeCacheRejectsSensitiveAndVendorValues(t *testing.T) {
	cache := newTokenCache(CacheConfig{
		ObjectTTL:           time.Hour,
		AttributeTTL:        time.Hour,
		ObjectMaxEntries:    2,
		AttributeMaxEntries: 2,
	})

	publicRequest := []*raw.Attribute{raw.NewAttribute(raw.CKA_LABEL, nil)}
	publicValue := []*raw.Attribute{raw.NewAttribute(raw.CKA_LABEL, "key")}
	cache.putAttributes("public", 1, publicRequest, publicValue)
	if got, ok := cache.getAttributes("public", 1, publicRequest); !ok || string(got[0].Value) != "key" {
		t.Fatalf("public attributes were not cached: %v, %v", got, ok)
	}

	secretRequest := []*raw.Attribute{raw.NewAttribute(raw.CKA_VALUE, nil)}
	cache.putAttributes("secret", 1, secretRequest, []*raw.Attribute{raw.NewAttribute(raw.CKA_VALUE, []byte("secret"))})
	if _, ok := cache.getAttributes("secret", 1, secretRequest); ok {
		t.Fatal("CKA_VALUE was cached")
	}

	vendorType := raw.CKA_VENDOR_DEFINED + 42
	vendorRequest := []*raw.Attribute{raw.NewAttribute(vendorType, nil)}
	cache.putAttributes("vendor", 1, vendorRequest, []*raw.Attribute{raw.NewAttribute(vendorType, []byte("opaque"))})
	if _, ok := cache.getAttributes("vendor", 1, vendorRequest); ok {
		t.Fatal("vendor-defined attribute was cached without an explicit policy")
	}
}

func TestAttributeCachePolicyCanOptInVendorMetadata(t *testing.T) {
	vendorType := raw.CKA_VENDOR_DEFINED + 42
	cache := newTokenCache(CacheConfig{
		ObjectTTL:           time.Hour,
		AttributeTTL:        time.Hour,
		ObjectMaxEntries:    2,
		AttributeMaxEntries: 2,
		AttributePolicy: func(attributeType uint) bool {
			return attributeType == vendorType
		},
	})
	request := []*raw.Attribute{raw.NewAttribute(vendorType, nil)}
	cache.putAttributes("vendor", 1, request, []*raw.Attribute{raw.NewAttribute(vendorType, []byte("metadata"))})
	if got, ok := cache.getAttributes("vendor", 1, request); !ok || string(got[0].Value) != "metadata" {
		t.Fatalf("opted-in vendor attribute was not cached: %v, %v", got, ok)
	}
}

type findCountingModule struct {
	*testmock.Module
	finds atomic.Int32
}

func (m *findCountingModule) FindAllObjects(handle raw.SessionHandle, attributes []*raw.Attribute, batchSize int) ([]raw.ObjectHandle, error) {
	m.finds.Add(1)
	return m.Module.FindAllObjects(handle, attributes, batchSize)
}

type sharedModuleSource struct {
	name   string
	module raw.Module
}

func (s sharedModuleSource) OpenModule(context.Context) (raw.Module, error) { return s.module, nil }
func (s sharedModuleSource) RegistryKey() string                            { return "test/" + s.name }

func (s sharedModuleSource) String() string { return "test:" + s.name }

func TestResolveObjectReusesFindResults(t *testing.T) {
	module := &findCountingModule{Module: testmock.New("resolve-cache", 1)}
	ctx := context.Background()
	client, err := Open(ctx, Config{
		Module: sharedModuleSource{name: "resolve-cache", module: module},
		PIN:    StaticPIN(testmock.DefaultPIN),
		Login:  LoginConfig{Mode: LoginEager},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close(ctx) }()

	if _, err := client.GenerateKeyPair(ctx, KeyPairOptions{
		Algorithm: AlgorithmRSA,
		Label:     "cached-pair",
		ID:        []byte{0x2a},
	}); err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	module.finds.Store(0)
	pair, err := client.FindKeyPair(ctx, KeyLocator{Label: "cached-pair", Algorithm: AlgorithmRSA})
	if err != nil {
		t.Fatalf("FindKeyPair: %v", err)
	}
	if finds := module.finds.Load(); finds != 1 {
		t.Fatalf("FindKeyPair performed %d finds, want 1", finds)
	}

	// Resolving the same pair must reuse the cached find results instead of
	// paying for another enumeration — remote backends charge seconds each.
	// CKA_SIGN is outside the find attribute sweep so these reads must resolve
	// a handle against the refs cache rather than a cached attribute set.
	if _, err := client.Attributes(ctx, pair.Private, raw.NewAttribute(raw.CKA_SIGN, nil)); err != nil {
		t.Fatalf("Attributes(private): %v", err)
	}
	if _, err := client.Attributes(ctx, pair.Public, raw.NewAttribute(raw.CKA_VERIFY, nil)); err != nil {
		t.Fatalf("Attributes(public): %v", err)
	}
	if got := module.finds.Load(); got != 1 {
		t.Fatalf("resolve performed %d total finds, want 1", got)
	}
}
