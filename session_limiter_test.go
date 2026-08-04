package pkcs11

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestSessionLimiterCloseWakesBlockedAcquisition(t *testing.T) {
	limiter := newSessionLimiter(1)
	if err := limiter.acquire(context.Background()); err != nil {
		t.Fatal(err)
	}

	result := make(chan error, 1)
	go func() { result <- limiter.acquire(context.Background()) }()
	select {
	case err := <-result:
		t.Fatalf("blocked acquisition returned before close: %v", err)
	case <-time.After(25 * time.Millisecond):
	}

	limiter.close()
	select {
	case err := <-result:
		if !errors.Is(err, errSessionLimiterClosed) {
			t.Fatalf("blocked acquisition error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked acquisition was not woken by close")
	}

	limiter.release()
	if limiter.used() != 0 {
		t.Fatalf("used permits after release = %d", limiter.used())
	}
}
