package raw

import (
	"errors"
	"fmt"
	"testing"
)

func TestIsErrorThroughWrappingAndJoin(t *testing.T) {
	err := errors.Join(fmt.Errorf("wrapped: %w", Error(CKR_DEVICE_ERROR)), errors.New("other"))
	if !IsError(err, CKR_DEVICE_ERROR) {
		t.Fatalf("IsError did not find wrapped CKR_DEVICE_ERROR: %v", err)
	}
	if !errors.Is(err, Error(CKR_DEVICE_ERROR)) {
		t.Fatalf("errors.Is did not match wrapped Error")
	}
}
