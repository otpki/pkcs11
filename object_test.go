package pkcs11

import (
	"cmp"
	"context"
	"errors"
	"reflect"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otpki/pkcs11/internal/testmock"
	"github.com/otpki/pkcs11/raw"
)

// everySessionRetires closes each native session as its lease returns.
var everySessionRetires = SessionConfig{MaxLifetime: time.Nanosecond}

func openFindRawClient(t *testing.T, name string) (*Client, *findCountingModule) {
	t.Helper()
	module := &findCountingModule{Module: testmock.New(name, 1)}
	return openFindRawClientOn(t, name, module, SessionConfig{}), module
}

// openFindRawClientOn opens a client on module that holds a key pair labelled "described".
func openFindRawClientOn(t *testing.T, name string, module raw.Module, sessions SessionConfig) *Client {
	t.Helper()
	ctx := context.Background()
	client, err := Open(ctx, Config{
		Module:   sharedModuleSource{name: name, module: module},
		PIN:      StaticPIN(testmock.DefaultPIN),
		Login:    LoginConfig{Mode: LoginEager},
		Sessions: sessions,
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
	return client
}

// closeFailingModule closes a session and then fails the close once armed.
type closeFailingModule struct {
	*testmock.Module
	failNextClose atomic.Bool
}

func (m *closeFailingModule) CloseSession(handle raw.SessionHandle) error {
	if err := m.Module.CloseSession(handle); err != nil {
		return err
	}
	if m.failNextClose.CompareAndSwap(true, false) {
		return raw.Error(raw.CKR_DEVICE_ERROR)
	}
	return nil
}

func findByLabel(label string) func(raw.Module, raw.SessionHandle) ([]raw.ObjectHandle, error) {
	return func(module raw.Module, session raw.SessionHandle) ([]raw.ObjectHandle, error) {
		if err := module.FindObjectsInit(session, []*raw.Attribute{raw.NewAttribute(raw.CKA_LABEL, label)}); err != nil {
			return nil, err
		}
		defer func() { _ = module.FindObjectsFinal(session) }()
		var found []raw.ObjectHandle
		for {
			batch, more, err := module.FindObjects(session, 16)
			if err != nil {
				return nil, err
			}
			found = append(found, batch...)
			if !more {
				return found, nil
			}
		}
	}
}

func returning(handles ...raw.ObjectHandle) func(raw.Module, raw.SessionHandle) ([]raw.ObjectHandle, error) {
	return func(raw.Module, raw.SessionHandle) ([]raw.ObjectHandle, error) { return handles, nil }
}

func byHandle(refs []ObjectRef) []ObjectRef {
	return slices.SortedFunc(slices.Values(refs), func(a, b ObjectRef) int { return cmp.Compare(a.Handle, b.Handle) })
}

func TestFindRawReturnsTheReferencesFindReturns(t *testing.T) {
	client, _ := openFindRawClient(t, "find-raw-matches-find")
	ctx := context.Background()
	found, err := client.Find(ctx, ObjectQuery{Label: "described"})
	if err != nil || len(found) != 2 {
		t.Fatalf("Find = %v, %v; want the private and the public key", found, err)
	}

	described, err := client.FindRaw(ctx, RawSessionOptions{}, findByLabel("described"))
	if err != nil {
		t.Fatalf("FindRaw: %v", err)
	}
	if !reflect.DeepEqual(byHandle(described), byHandle(found)) {
		t.Errorf("FindRaw = %+v, want Find's %+v", described, found)
	}
}

func TestFindRawReferencesResolveWithoutAFind(t *testing.T) {
	client, module := openFindRawClient(t, "find-raw-resolve")
	ctx := context.Background()
	client.cache.invalidate()

	described, err := client.FindRaw(ctx, RawSessionOptions{}, findByLabel("described"))
	if err != nil || len(described) != 2 {
		t.Fatalf("FindRaw = %v, %v; want the private and the public key", described, err)
	}
	module.finds.Store(0)
	for _, ref := range described {
		if _, err := client.Attributes(ctx, ref, raw.NewAttribute(raw.CKA_LABEL, nil)); err != nil {
			t.Fatalf("Attributes: %v", err)
		}
	}
	if finds := module.finds.Load(); finds != 0 {
		t.Errorf("resolving FindRaw's references performed %d finds, want 0", finds)
	}
}

func TestFindRawDescribesASessionObjectItsSearchFinds(t *testing.T) {
	module := &findCountingModule{Module: testmock.New("find-raw-session-object", 1)}
	client := openFindRawClientOn(t, "find-raw-session-object", module, everySessionRetires)

	described, err := client.FindRaw(context.Background(), RawSessionOptions{}, func(module raw.Module, session raw.SessionHandle) ([]raw.ObjectHandle, error) {
		if _, err := module.CreateObject(session, []*raw.Attribute{
			raw.NewAttribute(raw.CKA_CLASS, raw.CKO_DATA),
			raw.NewAttribute(raw.CKA_TOKEN, false),
			raw.NewAttribute(raw.CKA_LABEL, "session object"),
		}); err != nil {
			return nil, err
		}
		return findByLabel("session object")(module, session)
	})
	if err != nil {
		t.Fatalf("FindRaw: %v", err)
	}
	if len(described) != 1 || described[0].Class != raw.CKO_DATA || described[0].Label != "session object" {
		t.Errorf("FindRaw = %+v, want the session object", described)
	}
}

func TestFindRawReturnsItsSearchError(t *testing.T) {
	client, _ := openFindRawClient(t, "find-raw-search-error")
	errSearch := errors.New("search failed")

	described, err := client.FindRaw(context.Background(), RawSessionOptions{}, func(raw.Module, raw.SessionHandle) ([]raw.ObjectHandle, error) {
		return []raw.ObjectHandle{0x7fff}, errSearch
	})
	if !errors.Is(err, errSearch) || len(described) != 0 {
		t.Errorf("FindRaw = %v, %v; want the search's error and nothing described", described, err)
	}
}

func TestAReadWriteFindRawDropsTheCacheBeforeCachingItsReferences(t *testing.T) {
	client, module := openFindRawClient(t, "find-raw-read-write")
	ctx := context.Background()
	found, err := client.Find(ctx, ObjectQuery{Label: "described"})
	if err != nil || len(found) != 2 {
		t.Fatalf("Find = %v, %v; want the private and the public key", found, err)
	}
	private, public := found[0], found[1]
	if private.Class != raw.CKO_PRIVATE_KEY {
		private, public = public, private
	}

	kept, err := client.FindRaw(ctx, RawSessionOptions{ReadWrite: true}, func(module raw.Module, session raw.SessionHandle) ([]raw.ObjectHandle, error) {
		if err := module.DestroyObject(session, private.Handle); err != nil {
			return nil, err
		}
		return []raw.ObjectHandle{public.Handle}, nil
	})
	if err != nil || len(kept) != 1 {
		t.Fatalf("FindRaw = %v, %v; want the public key", kept, err)
	}
	module.finds.Store(0)
	if _, err := client.Attributes(ctx, kept[0], raw.NewAttribute(raw.CKA_LABEL, nil)); err != nil {
		t.Fatalf("Attributes: %v", err)
	}
	if finds := module.finds.Load(); finds != 0 {
		t.Errorf("resolving FindRaw's reference performed %d finds, want 0", finds)
	}
	if after, err := client.Find(ctx, ObjectQuery{Label: "described"}); err != nil || len(after) != 1 {
		t.Errorf("Find after the search destroyed the private key = %v, %v; want only the public key", after, err)
	}
}

func TestFindRawRefusesAHandleTheTokenLacks(t *testing.T) {
	client, _ := openFindRawClient(t, "find-raw-unknown")

	_, err := client.FindRaw(context.Background(), RawSessionOptions{}, returning(0x7fff))
	if !errors.Is(err, raw.Error(raw.CKR_OBJECT_HANDLE_INVALID)) {
		t.Errorf("FindRaw of an unknown handle = %v, want CKR_OBJECT_HANDLE_INVALID", err)
	}
}

func TestFindRawSearchesOnceUnlessIdempotent(t *testing.T) {
	client, _ := openFindRawClient(t, "find-raw-once")
	searches := 0

	_, err := client.FindRaw(context.Background(), RawSessionOptions{}, func(raw.Module, raw.SessionHandle) ([]raw.ObjectHandle, error) {
		searches++
		return []raw.ObjectHandle{0x7fff}, nil
	})
	if err == nil {
		t.Fatal("FindRaw of an unknown handle succeeded")
	}
	if searches != 1 {
		t.Errorf("FindRaw searched %d times, want once", searches)
	}
}

func TestAnIdempotentFindRawSearchesAgainOnReplay(t *testing.T) {
	client, _ := openFindRawClient(t, "find-raw-replay")
	searches := 0

	described, err := client.FindRaw(context.Background(), RawSessionOptions{Idempotent: true}, func(module raw.Module, session raw.SessionHandle) ([]raw.ObjectHandle, error) {
		searches++
		if searches == 1 {
			return []raw.ObjectHandle{0x7fff}, nil
		}
		return findByLabel("described")(module, session)
	})
	if err != nil || len(described) != 2 {
		t.Fatalf("FindRaw = %v, %v; want the private and the public key", described, err)
	}
	if searches != 2 {
		t.Errorf("FindRaw searched %d times, want twice", searches)
	}
}

func TestAnIdempotentFindRawReturnsOnlyWhatItsLastSearchFound(t *testing.T) {
	module := &closeFailingModule{Module: testmock.New("find-raw-empty-replay", 1)}
	client := openFindRawClientOn(t, "find-raw-empty-replay", module, everySessionRetires)
	module.failNextClose.Store(true)
	searches := 0

	described, err := client.FindRaw(context.Background(), RawSessionOptions{Idempotent: true}, func(module raw.Module, session raw.SessionHandle) ([]raw.ObjectHandle, error) {
		searches++
		if searches == 1 {
			return findByLabel("described")(module, session)
		}
		return nil, nil
	})
	if err != nil || len(described) != 0 {
		t.Errorf("FindRaw = %v, %v; want the replay's empty result", described, err)
	}
	if searches != 2 {
		t.Errorf("FindRaw searched %d times, want twice", searches)
	}
}

func TestFindRawOfNoObjectsDescribesNothing(t *testing.T) {
	client, _ := openFindRawClient(t, "find-raw-none")

	described, err := client.FindRaw(context.Background(), RawSessionOptions{}, returning())
	if err != nil || len(described) != 0 {
		t.Errorf("FindRaw of no objects = %v, %v; want nothing", described, err)
	}
}
