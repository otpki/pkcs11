package obslog

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

// gateHandler blocks every Handle call until the gate channel is closed,
// letting tests prove the async wrapper never stalls producers.
type gateHandler struct {
	gate    chan struct{}
	mu      sync.Mutex
	records []slog.Record
	level   slog.Level
}

func newGateHandler() *gateHandler { return &gateHandler{gate: make(chan struct{})} }

func (g *gateHandler) Enabled(_ context.Context, level slog.Level) bool { return level >= g.level }

func (g *gateHandler) Handle(_ context.Context, record slog.Record) error {
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
	return append([]slog.Record(nil), g.records...)
}

func TestAsyncHandlerDoesNotBlockOnSaturation(t *testing.T) {
	gate := newGateHandler()
	handler := NewAsyncHandler(gate, 4)
	defer handler.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		record := slog.NewRecord(time.Now(), slog.LevelInfo, "fill", 0)
		for range 64 {
			_ = handler.Handle(context.Background(), record)
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Handle blocked on a full queue behind a stuck writer")
	}
	if handler.Dropped() == 0 {
		t.Fatal("saturation did not count dropped records")
	}
	close(gate.gate)
	handler.Close()
	if delivered := len(gate.delivered()); delivered != 5 {
		// 4 queued records plus one synthetic drop-warning record.
		t.Fatalf("delivered = %d, want 5 (4 records + drop warning)", delivered)
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
	return append([]string(nil), b.text...)
}
