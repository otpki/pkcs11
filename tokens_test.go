package pkcs11

import (
	"context"
	"fmt"
	"testing"

	"github.com/otpki/pkcs11/internal/testmock"
	"github.com/otpki/pkcs11/raw"
)

// ListTokens returns one summary per token the module reports, carrying slot
// and token metadata without opening a session or reading mechanisms.
func TestListTokensReportsEachToken(t *testing.T) {
	source := testmock.SharedSource{Name: "enum", Module: testmock.New("enum", 3)}
	summaries, err := ListTokens(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	if len(summaries) != 3 {
		t.Fatalf("summaries = %d, want 3", len(summaries))
	}
	for i, summary := range summaries {
		if summary.Err != nil {
			t.Fatalf("slot %d reported error %v", summary.SlotID, summary.Err)
		}
		if summary.SlotID != raw.SlotID(i+1) {
			t.Fatalf("summaries[%d].SlotID = %d, want %d", i, summary.SlotID, i+1)
		}
		if want := fmt.Sprintf("enum-token-%d", i+1); summary.Token.Label != want {
			t.Fatalf("summaries[%d].Label = %q, want %q", i, summary.Token.Label, want)
		}
		if summary.Slot.ManufacturerID != "OTPKI Test" {
			t.Fatalf("summaries[%d].Slot.ManufacturerID = %q", i, summary.Slot.ManufacturerID)
		}
	}
}

// A slot whose metadata cannot be read comes back as a per-slot error while
// the rest of the enumeration still stands.
func TestListTokensRecordsPerSlotError(t *testing.T) {
	module := testmock.New("enum-err", 3)
	module.SetSlotFault(2, raw.Error(raw.CKR_DEVICE_ERROR))
	source := testmock.SharedSource{Name: "enum-err", Module: module}

	summaries, err := ListTokens(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	if len(summaries) != 3 {
		t.Fatalf("summaries = %d, want 3 entries including the faulted slot", len(summaries))
	}
	for _, summary := range summaries {
		switch summary.SlotID {
		case 2:
			if summary.Err == nil {
				t.Fatal("faulted slot 2 reported no error")
			}
		default:
			if summary.Err != nil {
				t.Fatalf("healthy slot %d reported %v", summary.SlotID, summary.Err)
			}
			if summary.Token.Label == "" {
				t.Fatalf("healthy slot %d has empty label", summary.SlotID)
			}
		}
	}
}

// Tokens added and removed between enumerations appear and disappear on the
// next call — the property the route reconciler relies on.
func TestListTokensTracksRuntimeMutation(t *testing.T) {
	module := testmock.New("enum-mut", 1)
	source := testmock.SharedSource{Name: "enum-mut", Module: module}

	summaries, err := ListTokens(context.Background(), source)
	if err != nil || len(summaries) != 1 {
		t.Fatalf("initial summaries = %d, %v", len(summaries), err)
	}

	module.AddToken("enum-mut-extra", "TEST-EXTRA-1")
	summaries, err = ListTokens(context.Background(), source)
	if err != nil || len(summaries) != 2 || summaries[1].Token.SerialNumber != "TEST-EXTRA-1" {
		t.Fatalf("after add summaries = %+v, %v", summaries, err)
	}

	if err := module.RemoveToken(1); err != nil {
		t.Fatal(err)
	}
	summaries, err = ListTokens(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	if len(summaries) != 1 || summaries[0].SlotID != 2 {
		t.Fatalf("after remove summaries = %+v, want only slot 2", summaries)
	}
}

// A module that cannot be opened at all fails the whole enumeration rather
// than reporting an empty list.
func TestListTokensFailsWholeEnumeration(t *testing.T) {
	_, err := ListTokens(context.Background(), LocalModule("/nonexistent/pkcs11-module.so"))
	if err == nil {
		t.Fatal("enumeration on a missing module succeeded")
	}
}
