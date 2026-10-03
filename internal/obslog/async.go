// Package obslog provides a non-blocking slog.Handler: records are queued on a
// bounded channel and written by a dedicated goroutine so a slow or blocked
// downstream writer (stderr, file, network) can never stall request paths.
package obslog

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultQueueSize bounds the records held between producers and the single
// writer goroutine when the caller does not configure one.
const DefaultQueueSize = 8192

// queuedRecord pairs a record with the handler that produced it, so
// WithAttrs/WithGroup derivations survive the queue: the writer delivers each
// record through the same delegate chain its caller saw.
type queuedRecord struct {
	record   slog.Record
	delegate slog.Handler
}

// core is shared by an AsyncHandler and every WithAttrs/WithGroup derivation:
// one queue, one writer goroutine, one drop counter.
type core struct {
	queue     chan queuedRecord
	done      chan struct{}
	wg        sync.WaitGroup
	closeOnce sync.Once
	dropped   atomic.Uint64
	flushed   atomic.Uint64
}

// AsyncHandler is a slog.Handler that never blocks in Handle beyond one
// channel send attempt. When the queue is full the record is dropped and
// counted; the writer goroutine emits a synthetic warning summarizing each
// batch of drops so loss is visible downstream instead of silent.
type AsyncHandler struct {
	core     *core
	delegate slog.Handler
}

// NewAsyncHandler wraps delegate with a bounded asynchronous queue.
// queueSize <= 0 selects DefaultQueueSize.
func NewAsyncHandler(delegate slog.Handler, queueSize int) *AsyncHandler {
	if queueSize <= 0 {
		queueSize = DefaultQueueSize
	}
	c := &core{
		queue: make(chan queuedRecord, queueSize),
		done:  make(chan struct{}),
	}
	c.wg.Go(c.run)
	return &AsyncHandler{core: c, delegate: delegate}
}

// Enabled reports whether the delegate accepts level.
func (h *AsyncHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.delegate.Enabled(ctx, level)
}

// Handle enqueues a copy of the record for the writer goroutine. It returns
// nil even when the record is dropped: logging must never fail the caller, and
// the loss is tracked by Dropped plus a downstream warning.
func (h *AsyncHandler) Handle(_ context.Context, record slog.Record) error {
	select {
	case h.core.queue <- queuedRecord{record: record.Clone(), delegate: h.delegate}:
	default:
		h.core.dropped.Add(1)
	}
	return nil
}

// WithAttrs returns a handler sharing the queue with attributes applied.
func (h *AsyncHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &AsyncHandler{core: h.core, delegate: h.delegate.WithAttrs(attrs)}
}

// WithGroup returns a handler sharing the queue with the group applied.
func (h *AsyncHandler) WithGroup(name string) slog.Handler {
	return &AsyncHandler{core: h.core, delegate: h.delegate.WithGroup(name)}
}

// Dropped returns the number of records discarded because the queue was full.
func (h *AsyncHandler) Dropped() uint64 { return h.core.dropped.Load() }

// Flushed returns the number of records the writer goroutine has delivered.
func (h *AsyncHandler) Flushed() uint64 { return h.core.flushed.Load() }

// QueueLen reports the current queue depth, for the dev UI and tests.
func (h *AsyncHandler) QueueLen() int { return len(h.core.queue) }

// QueueCap reports the configured queue bound.
func (h *AsyncHandler) QueueCap() int { return cap(h.core.queue) }

// Close stops accepting new records and blocks until the queue is flushed.
// Records enqueued after Close may still be delivered before it returns.
// Close is idempotent and safe to call from any handler sharing the core.
func (h *AsyncHandler) Close() {
	h.core.closeOnce.Do(func() {
		close(h.core.done)
	})
	h.core.wg.Wait()
}

func (c *core) run() {
	for {
		select {
		case item := <-c.queue:
			c.deliver(item)
		case <-c.done:
			for {
				select {
				case item := <-c.queue:
					c.deliver(item)
				default:
					return
				}
			}
		}
	}
}

func (c *core) deliver(item queuedRecord) {
	// The delegate must handle errors itself; async delivery cannot return them
	// to the original caller.
	_ = item.delegate.Handle(context.Background(), item.record)
	c.flushed.Add(1)
	c.reportDropped(item.delegate)
}

// reportDropped emits one synthetic warning per contiguous run of drops
// through the same delegate that just delivered, preserving its formatting.
func (c *core) reportDropped(delegate slog.Handler) {
	dropped := c.dropped.Swap(0)
	if dropped == 0 || !delegate.Enabled(context.Background(), slog.LevelWarn) {
		return
	}
	record := slog.NewRecord(time.Now(), slog.LevelWarn, "obslog: dropped log records (queue full)", 0)
	record.AddAttrs(slog.Uint64("dropped", dropped))
	_ = delegate.Handle(context.Background(), record)
}
