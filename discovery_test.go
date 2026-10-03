package pkcs11

import (
	"errors"
	"sync/atomic"
	"testing"

	"github.com/otpki/pkcs11/internal/testmock"
	"github.com/otpki/pkcs11/raw"
)

// batchingModule wraps the in-memory module with the batcher interface the
// remote proxy implements, counting batch versus serial mechanism-info calls.
type batchingModule struct {
	*testmock.Module
	batchCalls  atomic.Int32
	serialCalls atomic.Int32
	batchErr    error
}

func (m *batchingModule) GetMechanismInfo(slot raw.SlotID, mechanism raw.MechanismType) (raw.MechanismInfo, error) {
	m.serialCalls.Add(1)
	return m.Module.GetMechanismInfo(slot, mechanism)
}

func (m *batchingModule) GetMechanismInfos(slot raw.SlotID, mechanisms []raw.MechanismType) ([]raw.MechanismInfo, []error, error) {
	m.batchCalls.Add(1)
	if m.batchErr != nil {
		return nil, nil, m.batchErr
	}
	infos := make([]raw.MechanismInfo, len(mechanisms))
	errs := make([]error, len(mechanisms))
	for i, mechanism := range mechanisms {
		infos[i], errs[i] = m.Module.GetMechanismInfo(slot, mechanism)
	}
	return infos, errs, nil
}

// Modules that can resolve mechanism info in one call — the remote proxy —
// must not pay a serial per-mechanism sweep during discovery.
func TestDiscoverUsesMechanismInfoBatching(t *testing.T) {
	module := &batchingModule{Module: testmock.New("batch", 1)}
	if err := module.Initialize(); err != nil {
		t.Fatal(err)
	}
	devices, err := Discover(module)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if len(devices) != 1 {
		t.Fatalf("devices = %d, want 1", len(devices))
	}
	if module.batchCalls.Load() == 0 {
		t.Fatal("discovery never used the batched mechanism-info call")
	}
	if module.serialCalls.Load() != 0 {
		t.Fatalf("discovery made %d serial GetMechanismInfo calls, want 0", module.serialCalls.Load())
	}
	if len(devices[0].Fingerprint.Mechanisms) == 0 {
		t.Fatal("fingerprint has no mechanisms after batched discovery")
	}
}

// A batch-level failure (transport error, older broker) falls back to the
// serial sweep so discovery still produces a complete fingerprint.
func TestDiscoverFallsBackWhenMechanismBatchFails(t *testing.T) {
	module := &batchingModule{Module: testmock.New("batchfail", 1), batchErr: errors.New("batch unsupported")}
	if err := module.Initialize(); err != nil {
		t.Fatal(err)
	}
	devices, err := Discover(module)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if len(devices) != 1 {
		t.Fatalf("devices = %d, want 1", len(devices))
	}
	if module.batchCalls.Load() == 0 {
		t.Fatal("batch call was never attempted")
	}
	if module.serialCalls.Load() == 0 {
		t.Fatal("batch failure did not fall back to serial GetMechanismInfo")
	}
	if len(devices[0].Fingerprint.Mechanisms) == 0 {
		t.Fatal("fingerprint has no mechanisms after serial fallback")
	}
}
