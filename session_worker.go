package pkcs11

import (
	"context"
	"errors"
	"runtime"
	"sync"
)

// sessionWork is one synchronous function invocation transferred to the
// goroutine that owns a session's native OS thread.
type sessionWork struct {
	call func() error
	// result is buffered so the worker can complete even if the submitting
	// context is canceled after the request has started.
	result chan error
}

// sessionWorker permanently owns one native OS thread. It is allocated only
// when an internal adapter requires OS-thread affinity, allowing a pooled
// native session to retain thread-local vendor state across independent Go callers.
type sessionWorker struct {
	// mu prevents requests from racing with closure of requests. A read lock is
	// intentionally held through call completion so close also waits for work in
	// flight before closing the channel.
	mu       sync.RWMutex
	requests chan sessionWork
	done     chan struct{}
	closed   bool
}

// newSessionWorker starts a dedicated goroutine and permanently pins it to one
// native OS thread until close is called.
func newSessionWorker() *sessionWorker {
	worker := &sessionWorker{requests: make(chan sessionWork), done: make(chan struct{})}
	go func() {
		// Vendor middleware may associate session state with a native thread rather
		// than the PKCS #11 session handle. Keep this goroutine pinned for life.
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		defer close(worker.done)
		for request := range worker.requests {
			request.result <- request.call()
			close(request.result)
		}
	}()
	return worker
}

// do starts call on the worker's pinned thread. Context cancellation can abort
// queueing, but cannot interrupt a C function after execution has begun.
func (w *sessionWorker) do(ctx context.Context, call func() error) error {
	if w == nil {
		return call()
	}
	if ctx == nil {
		ctx = context.Background()
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.closed {
		return errors.New("pkcs11: session worker is closed")
	}
	request := sessionWork{call: call, result: make(chan error, 1)}
	select {
	case w.requests <- request:
	case <-ctx.Done():
		return ctx.Err()
	}
	// Once a native call has begun it cannot be canceled portably. Wait until
	// it returns so the session cannot be reused concurrently with an in-flight
	// C operation, even if ctx is canceled meanwhile.
	return <-request.result
}

// close stops accepting work, waits for the pinned goroutine to exit, and is
// safe to call repeatedly.
func (w *sessionWorker) close() {
	if w == nil {
		return
	}
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		<-w.done
		return
	}
	w.closed = true
	close(w.requests)
	w.mu.Unlock()
	<-w.done
}
