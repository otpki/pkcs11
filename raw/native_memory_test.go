package raw

import (
	"bytes"
	"strings"
	"testing"
)

func TestNativeArenaRejectsInvalidAllocations(t *testing.T) {
	arena := &nativeArena{}
	if _, _, err := arena.alloc(-1); err == nil || !strings.Contains(err.Error(), "negative") {
		t.Fatalf("negative allocation error = %v", err)
	}
	if pointer, value, err := arena.alloc(0); err != nil || pointer != 0 || value != nil {
		t.Fatalf("zero allocation = pointer %#x value %v error %v", pointer, value, err)
	}

	arena.close()
	if _, _, err := arena.alloc(1); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("closed arena allocation error = %v", err)
	}
}

func TestNativeArenaWipesSecretBuffers(t *testing.T) {
	secret := []byte("sensitive-pin")
	released := false
	arena := &nativeArena{
		blocks: []nativeBlock{{
			bytes: secret,
			release: func() {
				released = true
				if !bytes.Equal(secret, make([]byte, len(secret))) {
					t.Fatalf("secret buffer was not wiped before release: %x", secret)
				}
			},
		}},
		secrets: [][]byte{secret},
	}

	arena.close()
	if !released {
		t.Fatal("native block was not released")
	}

	// Cleanup is deliberately idempotent because several error paths defer an
	// arena close after an explicit early close.
	arena.close()
}

func TestMarshalNativeParameterRelocationsArePinnedAndPatched(t *testing.T) {
	arena := &nativeArena{}
	defer arena.close()

	builder := NewNativeStructBuilder(HostNativeABI())
	builder.AddULong(0x1122)
	builder.AddPointer([]byte{1, 2, 3, 4})
	layout := builder.Layout()

	pointer, length, err := marshalLayout(arena, layout)
	if err != nil {
		t.Fatal(err)
	}
	if pointer == 0 || length != uint(len(layout.Root)) {
		t.Fatalf("marshalLayout pointer=%#x length=%d, want nonzero/%d", pointer, length, len(layout.Root))
	}

	root := nativeBytes(pointer, len(layout.Root))
	if got := HostNativeABI().getULong(root, 0); got != 0x1122 {
		t.Fatalf("native CK_ULONG = %#x", got)
	}
	if len(layout.Pointers) != 1 {
		t.Fatalf("relocations = %#v", layout.Pointers)
	}
	target := HostNativeABI().getPointer(root, layout.Pointers[0].Offset)
	if target == 0 || !bytes.Equal(nativeBytes(target, 4), []byte{1, 2, 3, 4}) {
		t.Fatalf("relocated data = %x", nativeBytes(target, 4))
	}
}

func TestGCMParameterSyncBackRunsBeforeRelease(t *testing.T) {
	params := &GCMParams{IV: make([]byte, 12), IVBits: 96, TagBits: 128}
	mechanism, err := marshalMechanism(NewMechanism(CKM_AES_GCM, params))
	if err != nil {
		t.Fatal(err)
	}

	layout := nativeMechanismLayout(HostNativeABI())
	parameterPointer := HostNativeABI().getPointer(mechanism.root, layout.parameter)
	gcmLayout := nativeGCMParameterLayout(HostNativeABI())
	gcm := nativeBytes(parameterPointer, gcmLayout.size)
	ivPointer := HostNativeABI().getPointer(gcm, gcmLayout.iv)
	copy(nativeBytes(ivPointer, 12), []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11})
	HostNativeABI().putULong(gcm, gcmLayout.ivLength, 12)
	HostNativeABI().putULong(gcm, gcmLayout.ivBits, 96)
	HostNativeABI().putULong(gcm, gcmLayout.tagBits, 120)

	mechanism.free()
	if !bytes.Equal(params.IV, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}) {
		t.Fatalf("synchronized IV = %x", params.IV)
	}
	if params.IVBits != 96 || params.TagBits != 120 {
		t.Fatalf("synchronized bits = IV:%d tag:%d", params.IVBits, params.TagBits)
	}

	// A second free must not run sync-back again or release twice.
	mechanism.free()
}

func TestNestedAttributeTemplateRoundTripAndUnavailableValue(t *testing.T) {
	requested := []*Attribute{
		NewAttribute(CKA_LABEL, nil),
		{
			Type: CKA_WRAP_TEMPLATE,
			Children: []*Attribute{
				NewAttribute(CKA_CLASS, nil),
				NewAttribute(CKA_ID, nil),
			},
		},
	}
	template, err := newGetTemplate(requested)
	if err != nil {
		t.Fatal(err)
	}
	defer template.free()

	layout := nativeAttributeLayout(HostNativeABI())
	HostNativeABI().putULong(template.root, layout.length, 5)
	child := template.children[0]
	HostNativeABI().putULong(child.root, layout.length, HostNativeABI().unavailableInformation())
	childIDOffset := layout.size
	HostNativeABI().putULong(child.root, childIDOffset+layout.length, 3)
	if err := template.allocateGetValues(requested); err != nil {
		t.Fatal(err)
	}
	labelPointer := HostNativeABI().getPointer(template.root, layout.value)
	copy(nativeBytes(labelPointer, 5), []byte("label"))
	idPointer := HostNativeABI().getPointer(child.root, childIDOffset+layout.value)
	copy(nativeBytes(idPointer, 3), []byte{7, 8, 9})

	values := template.copyGetValues(requested)
	if len(values) != 2 || string(values[0].Value) != "label" {
		t.Fatalf("top-level values = %#v", values)
	}
	if len(values[1].Children) != 2 {
		t.Fatalf("nested values = %#v", values[1].Children)
	}
	if values[1].Children[0].Value != nil {
		t.Fatalf("unavailable attribute unexpectedly returned %x", values[1].Children[0].Value)
	}
	if !bytes.Equal(values[1].Children[1].Value, []byte{7, 8, 9}) {
		t.Fatalf("nested CKA_ID = %x", values[1].Children[1].Value)
	}
}

func TestCheckedNativeLengthRejectsHostOverflow(t *testing.T) {
	abi := HostNativeABI()
	if _, err := abi.checkedLength(^uint(0)); err == nil && ^uint(0) > ^uint(0)>>1 {
		t.Fatal("expected a length larger than MaxInt to be rejected")
	}
}
