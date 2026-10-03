package obslog

import (
	"context"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// gateHandler blocks every Handle call until the gate channel is closed,
// letting tests prove the async wrapper never stalls producers. entered is
// closed when the first record reaches the delegate, so tests can park the
// writer goroutine inside Handle deterministically.
type gateHandler struct {
	gate    chan struct{}
	entered chan struct{}
	once    sync.Once
	mu      sync.Mutex
	records []slog.Record
	level   slog.Level
}

func newGateHandler() *gateHandler {
	return &gateHandler{gate: make(chan struct{}), entered: make(chan struct{})}
}

func (g *gateHandler) Enabled(_ context.Context, level slog.Level) bool { return level >= g.level }

func (g *gateHandler) Handle(_ context.Context, record slog.Record) error {
	g.once.Do(func() { close(g.entered) })
	<-g.gate
	g.mu.Lock()
	defer g.mu.Unlock()
	g.records = append(g.records, record)
	return nil
}

func (g *gateHandler) WithAttrs([]slog.Attr) slog.Handler { return g }
func (g *gateHandler) WithGroup(string) slog.Handler      { return g }

func (g *gateHandler) delivered() []slog.Record {
	g.mu.Lock()
	defer g.mu.Unlock()
	return slices.Clone(g.records)
}

func TestAsyncHandlerDoesNotBlockOnSaturation(t *testing.T) {
	gate := newGateHandler()
	handler := NewAsyncHandler(gate, 4)
	defer handler.Close()

	record := slog.NewRecord(time.Now(), slog.LevelInfo, "fill", 0)
	// Park the writer inside the blocked delegate so queue depth is
	// deterministic: one in-flight record, then the queue itself saturates.
	_ = handler.Handle(context.Background(), record)
	select {
	case <-gate.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("writer did not pick up the first record")
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 63 {
			_ = handler.Handle(context.Background(), record)
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Handle blocked on a full queue behind a stuck writer")
	}
	if dropped := handler.Dropped(); dropped != 59 {
		t.Fatalf("dropped = %d, want 59", dropped)
	}
	close(gate.gate)
	handler.Close()
	if delivered := len(gate.delivered()); delivered != 6 {
		// One in-flight record, four queued records, one drop warning.
		t.Fatalf("delivered = %d, want 6 (1 in-flight + 4 queued + drop warning)", delivered)
	}
	var warned bool
	for _, record := range gate.delivered() {
		if strings.Contains(record.Message, "dropped") {
			warned = true
		}
	}
	if !warned {
		t.Fatal("no downstream warning was emitted for dropped records")
	}
}

func TestAsyncHandlerPreservesOrderAndAttrs(t *testing.T) {
	buffer := &lineBuffer{}
	delegate := slog.NewTextHandler(buffer, &slog.HandlerOptions{Level: slog.LevelDebug})
	handler := NewAsyncHandler(delegate, 32)
	logger := slog.New(handler).With("component", "test").WithGroup("g")

	for i := range 8 {
		logger.Info("message", "i", i)
	}
	handler.Close()

	lines := buffer.lines()
	if len(lines) != 8 {
		t.Fatalf("delivered %d records, want 8", len(lines))
	}
	for i, line := range lines {
		want := strings.Contains(line, "component=test") && strings.Contains(line, "g.i=")
		if !want {
			t.Fatalf("line %d lost attrs/group: %q", i, line)
		}
	}
	if handler.Flushed() != 8 {
		t.Fatalf("flushed = %d, want 8", handler.Flushed())
	}
	if handler.Dropped() != 0 {
		t.Fatalf("dropped = %d, want 0", handler.Dropped())
	}
}

func TestAsyncHandlerDrainsOnClose(t *testing.T) {
	gate := newGateHandler()
	handler := NewAsyncHandler(gate, 16)
	record := slog.NewRecord(time.Now(), slog.LevelInfo, "x", 0)
	for range 8 {
		_ = handler.Handle(context.Background(), record)
	}
	close(gate.gate)
	handler.Close()
	if len(gate.delivered()) != 8 {
		t.Fatalf("delivered %d records after Close, want 8", len(gate.delivered()))
	}
}

func TestAsyncHandlerEnabledDelegates(t *testing.T) {
	gate := newGateHandler()
	gate.level = slog.LevelWarn
	handler := NewAsyncHandler(gate, 4)
	defer handler.Close()
	if handler.Enabled(context.Background(), slog.LevelInfo) {
		t.Fatal("Enabled ignored the delegate level")
	}
	if !handler.Enabled(context.Background(), slog.LevelError) {
		t.Fatal("Enabled rejected an allowed level")
	}
}

type lineBuffer struct {
	mu   sync.Mutex
	text []string
}

func (b *lineBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.text = append(b.text, string(p))
	return len(p), nil
}

func (b *lineBuffer) lines() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return slices.Clone(b.text)
}
