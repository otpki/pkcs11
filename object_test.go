package pkcs11

import (
	"context"
	"errors"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/otpki/pkcs11/internal/testmock"
	"github.com/otpki/pkcs11/raw"
)

func openDescribeClient(t *testing.T, name string) (*Client, *findCountingModule) {
	t.Helper()
	return openDescribeClientObservedBy(t, name, nil)
}

func openDescribeClientObservedBy(t *testing.T, name string, metrics Metrics) (*Client, *findCountingModule) {
	t.Helper()
	module := &findCountingModule{Module: testmock.New(name, 1)}
	ctx := context.Background()
	client, err := Open(ctx, Config{
		Module: sharedModuleSource{name: name, module: module},
		PIN:    StaticPIN(testmock.DefaultPIN),
		Login:  LoginConfig{Mode: LoginEager},
		Hooks:  Hooks{Metrics: metrics},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close(ctx) })
	if _, err := client.GenerateKeyPair(ctx, KeyPairOptions{
		Algorithm: AlgorithmRSA,
		Label:     "described",
		ID:        []byte{0x2a},
	}); err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	return client, module
}

func handlesOf(refs []ObjectRef) []raw.ObjectHandle {
	handles := make([]raw.ObjectHandle, len(refs))
	for i, ref := range refs {
		handles[i] = ref.Handle
	}
	return handles
}

func TestDescribeReturnsTheReferencesFindReturns(t *testing.T) {
	client, _ := openDescribeClient(t, "describe-matches-find")
	ctx := context.Background()
	found, err := client.Find(ctx, ObjectQuery{Label: "described"})
	if err != nil || len(found) != 2 {
		t.Fatalf("Find = %v, %v; want the private and the public key", found, err)
	}

	described, err := client.Describe(ctx, handlesOf(found))
	if err != nil {
		t.Fatalf("Describe: %v", err)
	}
	if !reflect.DeepEqual(described, found) {
		t.Errorf("Describe = %+v, want Find's %+v", described, found)
	}
}

func TestDescribeRefusesAnUnknownHandle(t *testing.T) {
	client, _ := openDescribeClient(t, "describe-unknown")

	_, err := client.Describe(context.Background(), []raw.ObjectHandle{0x7fff})
	if !errors.Is(err, raw.Error(raw.CKR_OBJECT_HANDLE_INVALID)) {
		t.Errorf("Describe of an unknown handle = %v, want CKR_OBJECT_HANDLE_INVALID", err)
	}
}

// replays counts the operations a client ran past their first attempt.
type replays struct{ count atomic.Int32 }

func (r *replays) ObservePKCS11(_ context.Context, event OperationEvent) {
	if event.Attempt > 1 {
		r.count.Add(1)
	}
}

func TestDescribeOfAnUnknownHandleRunsOnce(t *testing.T) {
	seen := &replays{}
	client, _ := openDescribeClientObservedBy(t, "describe-unknown-once", seen)

	if _, err := client.Describe(context.Background(), []raw.ObjectHandle{0x7fff}); err == nil {
		t.Fatal("Describe of an unknown handle succeeded")
	}
	if n := seen.count.Load(); n != 0 {
		t.Errorf("Describe of an unknown handle replayed %d operations, want none", n)
	}
}

func TestDescribeOfNoHandlesDescribesNothing(t *testing.T) {
	client, _ := openDescribeClient(t, "describe-none")

	described, err := client.Describe(context.Background(), nil)
	if err != nil || len(described) != 0 {
		t.Errorf("Describe(nil) = %v, %v; want nothing", described, err)
	}
}

func TestDescribedReferencesResolveWithoutAFind(t *testing.T) {
	client, module := openDescribeClient(t, "describe-resolve")
	ctx := context.Background()
	found, err := client.Find(ctx, ObjectQuery{Label: "described"})
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	client.cache.invalidate()

	described, err := client.Describe(ctx, handlesOf(found))
	if err != nil {
		t.Fatalf("Describe: %v", err)
	}
	module.finds.Store(0)
	for _, ref := range described {
		if _, err := client.Attributes(ctx, ref, raw.NewAttribute(raw.CKA_LABEL, nil)); err != nil {
			t.Fatalf("Attributes: %v", err)
		}
	}
	if finds := module.finds.Load(); finds != 0 {
		t.Errorf("resolving described references performed %d finds, want 0", finds)
	}
}
