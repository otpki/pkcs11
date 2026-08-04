package pkcs11

import (
	"github.com/otpki/pkcs11/raw"
	"testing"
	"time"
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
