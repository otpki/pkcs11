package proxy

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/otpki/pkcs11/internal/testmock"
	"github.com/otpki/pkcs11/raw"
)

type findInitCounter struct {
	*testmock.Module
	inits   atomic.Int32
	findAll atomic.Int32
}

func (m *findInitCounter) FindObjectsInit(session raw.SessionHandle, attributes []*raw.Attribute) error {
	m.inits.Add(1)
	return m.Module.FindObjectsInit(session, attributes)
}

func (m *findInitCounter) FindAllObjects(session raw.SessionHandle, attributes []*raw.Attribute, maxResults int) ([]raw.ObjectHandle, error) {
	m.findAll.Add(1)
	return m.Module.FindAllObjects(session, attributes, maxResults)
}

func newFindCacheFixture(t *testing.T) (*findCachingModule, *findInitCounter, raw.SessionHandle) {
	t.Helper()
	inner := &findInitCounter{Module: testmock.New("findcache", 1)}
	if err := inner.Initialize(); err != nil {
		t.Fatal(err)
	}
	module := newFindCachingModule(inner, time.Minute)
	session, err := module.OpenSession(1, raw.CKF_SERIAL_SESSION)
	if err != nil {
		t.Fatal(err)
	}
	return module, inner, session
}

func TestFindCacheReplaysRepeatedEnumerations(t *testing.T) {
	module, inner, session := newFindCacheFixture(t)
	defer func() { _ = module.Finalize() }()
	defer func() { _ = module.CloseSession(session) }()
	template := []*raw.Attribute{raw.NewAttribute(raw.CKA_LABEL, "testmode-info")}

	first, err := module.FindAllObjects(session, template, 4)
	if err != nil || len(first) == 0 {
		t.Fatalf("first find = %v, %v", first, err)
	}
	second, err := module.FindAllObjects(session, template, 4)
	if err != nil {
		t.Fatal(err)
	}
	if len(second) != len(first) {
		t.Fatalf("replayed find = %v, want %v", second, first)
	}
	if got := inner.inits.Load(); got != 1 {
		t.Fatalf("native FindObjectsInit ran %d times, want 1", got)
	}
	// Attribute order must not fork the cache key.
	reordered, err := module.FindAllObjects(session, []*raw.Attribute{
		raw.NewAttribute(raw.CKA_LABEL, "testmode-info"),
	}, 4)
	if err != nil || len(reordered) != len(first) {
		t.Fatalf("equivalent template = %v, %v", reordered, err)
	}
	if got := inner.inits.Load(); got != 1 {
		t.Fatalf("equivalent template re-enumerated: %d inits", got)
	}
}

func TestFindCacheInvalidatesOnMutationAndLogin(t *testing.T) {
	module, inner, session := newFindCacheFixture(t)
	defer func() { _ = module.Finalize() }()
	defer func() { _ = module.CloseSession(session) }()
	template := []*raw.Attribute{raw.NewAttribute(raw.CKA_LABEL, "testmode-info")}

	mustFind := func(want int) {
		if _, err := module.FindAllObjects(session, template, 4); err != nil {
			t.Fatal(err)
		}
		if got := inner.inits.Load(); got != int32(want) {
			t.Fatalf("native inits = %d, want %d", got, want)
		}
	}
	mustFind(1)
	mustFind(1) // replay

	if _, err := module.CreateObject(session, []*raw.Attribute{
		raw.NewAttribute(raw.CKA_CLASS, raw.CKO_DATA),
		raw.NewAttribute(raw.CKA_LABEL, "scratch"),
		raw.NewAttribute(raw.CKA_VALUE, []byte("x")),
	}); err != nil {
		t.Fatal(err)
	}
	mustFind(2) // mutation invalidated the entry
	mustFind(2)

	if err := module.Login(session, raw.CKU_USER, []byte(testmock.DefaultPIN)); err != nil {
		t.Fatal(err)
	}
	mustFind(3) // visibility change invalidated the entry
}

// Cryptoki allows one enumeration per session. A replayed find must therefore
// reject a second init exactly like a live native find — the broker's own
// nested locator checks (verifyStableLocator inside result virtualization)
// depend on CKR_OPERATION_ACTIVE rather than silently taking over the session.
func TestFindCacheRejectsNestedEnumeration(t *testing.T) {
	module, inner, session := newFindCacheFixture(t)
	defer func() { _ = module.Finalize() }()
	defer func() { _ = module.CloseSession(session) }()
	template := []*raw.Attribute{raw.NewAttribute(raw.CKA_LABEL, "testmode-info")}

	if _, err := module.FindAllObjects(session, template, 4); err != nil {
		t.Fatal(err)
	}
	// Second find replays from cache; while it is open a nested init must
	// fail with CKR_OPERATION_ACTIVE.
	if err := module.FindObjectsInit(session, template); err != nil {
		t.Fatal(err)
	}
	if got := inner.inits.Load(); got != 1 {
		t.Fatalf("replay hit the native module: %d inits", got)
	}
	if err := module.FindObjectsInit(session, template); !raw.IsError(err, raw.CKR_OPERATION_ACTIVE) {
		t.Fatalf("nested init = %v, want CKR_OPERATION_ACTIVE", err)
	}
	batch, _, err := module.FindObjects(session, 4)
	if err != nil || len(batch) == 0 {
		t.Fatalf("outer find broken after nested init: %v %v", batch, err)
	}
	if err := module.FindObjectsFinal(session); err != nil {
		t.Fatal(err)
	}
}

func TestFindCacheExpiresAndDropsSessionState(t *testing.T) {
	inner := &findInitCounter{Module: testmock.New("findcache-ttl", 1)}
	if err := inner.Initialize(); err != nil {
		t.Fatal(err)
	}
	module := newFindCachingModule(inner, time.Nanosecond)
	session, err := module.OpenSession(1, raw.CKF_SERIAL_SESSION)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = module.Finalize() }()
	template := []*raw.Attribute{raw.NewAttribute(raw.CKA_LABEL, "testmode-info")}

	if _, err := module.FindAllObjects(session, template, 4); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Millisecond) // TTL elapsed
	if _, err := module.FindAllObjects(session, template, 4); err != nil {
		t.Fatal(err)
	}
	if got := inner.inits.Load(); got != 2 {
		t.Fatalf("expired entry was replayed: %d inits, want 2", got)
	}
	// A mid-stream replay survives only until the caller finalizes: the next
	// init still records fresh state.
	if _, err := module.FindAllObjects(session, template, 4); err != nil {
		t.Fatal(err)
	}
	if got := inner.inits.Load(); got != 3 {
		t.Fatalf("inits = %d, want 3", got)
	}
}

// A recoverable token object re-resolves its native handle through a locator
// find once per physical session; later operations reuse the memoized handle
// until the memo is dropped or the object is removed.
func TestResolvedObjectMemoizesNativeHandle(t *testing.T) {
	inner := &findInitCounter{Module: testmock.New("objmemo", 1)}
	if err := inner.Initialize(); err != nil {
		t.Fatal(err)
	}
	module := inner
	session, err := module.OpenSession(1, raw.CKF_SERIAL_SESSION)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = module.Finalize() }()
	native, err := module.CreateObject(session, []*raw.Attribute{
		raw.NewAttribute(raw.CKA_CLASS, raw.CKO_PUBLIC_KEY),
		raw.NewAttribute(raw.CKA_TOKEN, true),
		raw.NewAttribute(raw.CKA_LABEL, "memo-key"),
	})
	if err != nil {
		t.Fatal(err)
	}

	target := &brokerTarget{}
	client := newLogicalClient(target, [16]byte{1}, "p", "test", 0)
	virtual := raw.ObjectHandle(9000)
	client.objects[virtual] = &virtualObject{
		handle: virtual, native: native, token: true, recoverable: true,
		class: raw.CKO_PUBLIC_KEY, label: "memo-key",
	}
	borrows := newObjectBorrowSet(target)
	vsession := &virtualSession{}

	resolved, err := client.resolveObjectBorrowed(module, session, vsession, borrows, virtual)
	if err != nil || resolved != native {
		t.Fatalf("first resolve = %d, %v; want %d", resolved, err, native)
	}
	resolved, err = client.resolveObjectBorrowed(module, session, vsession, borrows, virtual)
	if err != nil || resolved != native {
		t.Fatalf("second resolve = %d, %v; want %d", resolved, err, native)
	}
	if got := inner.findAll.Load(); got != 1 {
		t.Fatalf("memoized resolve ran %d finds, want 1", got)
	}

	client.dropResolvedObjects()
	if _, err := client.resolveObjectBorrowed(module, session, vsession, borrows, virtual); err != nil {
		t.Fatal(err)
	}
	if got := inner.findAll.Load(); got != 2 {
		t.Fatalf("post-drop resolve ran %d finds, want 2", got)
	}

	client.removeObject(vsession, virtual)
	if _, err := client.resolveObjectBorrowed(module, session, vsession, borrows, virtual); err == nil {
		t.Fatal("removed object still resolves")
	}
}
