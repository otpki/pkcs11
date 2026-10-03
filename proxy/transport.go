package proxy

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/otpki/pkcs11/raw"
)

const defaultMaximumMessageSize = 64 << 20

// marshalMessage encodes one JSON message. A pooled connection can carry many
// request/response pairs, each with its own length prefix. JSON keeps the wire
// format independent of Go versions and lets the reader reject unknown fields.
// Retry fingerprints describe argument types, not secret argument values.
func marshalMessage(value any, maximum int) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	if maximum <= 0 {
		maximum = defaultMaximumMessageSize
	}
	if len(encoded) > maximum {
		wipe(encoded)
		return nil, fmt.Errorf("pkcs11 proxy: encoded message is %d bytes; maximum is %d", len(encoded), maximum)
	}
	return encoded, nil
}

func writeMessage(writer io.Writer, value any, maximum int) error {
	encoded, err := marshalMessage(value, maximum)
	if err != nil {
		return err
	}
	defer wipe(encoded)
	if uint64(len(encoded)) > uint64(^uint32(0)) {
		return errors.New("pkcs11 proxy: message exceeds uint32 framing")
	}
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(encoded))) //nolint:gosec // G115: guarded by the uint32 bound check above.
	if err := writeAll(writer, length[:]); err != nil {
		return err
	}
	return writeAll(writer, encoded)
}

func writeAll(writer io.Writer, value []byte) error {
	for len(value) != 0 {
		written, err := writer.Write(value)
		if err != nil {
			return err
		}
		if written <= 0 {
			return io.ErrShortWrite
		}
		value = value[written:]
	}
	return nil
}

// readMessage decodes one length-prefixed frame. Callers that read more than
// once from the same source must pass a persistent *bufio.Reader — wrapping a
// stream per call lets the buffer prefetch bytes belonging to the next frame,
// which are then lost when the reader is discarded.
func readMessage(reader io.Reader, value any, maximum int) error {
	if maximum <= 0 {
		maximum = defaultMaximumMessageSize
	}
	buffered, ok := reader.(*bufio.Reader)
	if !ok {
		buffered = bufio.NewReader(reader)
	}
	var length [4]byte
	if _, err := io.ReadFull(buffered, length[:]); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(length[:])
	if uint64(size) > uint64(maximum) {
		return fmt.Errorf("pkcs11 proxy: incoming message is %d bytes; maximum is %d", size, maximum)
	}
	payload := make([]byte, size)
	defer wipe(payload)
	if _, err := io.ReadFull(buffered, payload); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return fmt.Errorf("pkcs11 proxy: decode message: %w", err)
	}
	// A framed message must contain exactly one JSON value. Reject concatenated
	// data even though the outer length prefix would otherwise make it invisible.
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("pkcs11 proxy: trailing JSON value")
		}
		return fmt.Errorf("pkcs11 proxy: trailing message data: %w", err)
	}
	return nil
}

// dialContext connects to one specific proxy endpoint. Endpoint selection
// happens only while establishing a logical client; every call afterward dials
// the endpoint that client's Describe pinned.
func dialContext(ctx context.Context, target Target, endpoint string) (net.Conn, error) {
	dialer := target.Dialer
	dialer = cmp.Or(dialer, &net.Dialer{Timeout: target.ConnectTimeout})
	connection, err := dialer.DialContext(ctx, "tcp", endpoint)
	if err != nil {
		return nil, err
	}
	if target.TLS == nil {
		if !target.AllowInsecure {
			_ = connection.Close()
			return nil, errors.New("pkcs11 proxy: TLS is required unless AllowInsecure is explicitly enabled")
		}
		return connection, nil
	}
	config := target.TLS.Clone()
	if config.ServerName == "" {
		config.ServerName = target.ServerName
	}
	if config.ServerName == "" {
		host, _, splitErr := net.SplitHostPort(endpoint)
		if splitErr == nil {
			config.ServerName = host
		}
	}
	tlsConnection := tls.Client(connection, config)
	if err := tlsConnection.HandshakeContext(ctx); err != nil {
		_ = connection.Close()
		return nil, err
	}
	return tlsConnection, nil
}

func applyConnectionDeadline(ctx context.Context, connection net.Conn, fallback time.Duration) {
	deadline, ok := ctx.Deadline()
	if !ok && fallback > 0 {
		deadline, ok = time.Now().Add(fallback), true
	}
	if ok {
		_ = connection.SetDeadline(deadline)
	}
}

func closeConnectionOnContext(ctx context.Context, connection net.Conn) func() {
	if ctx == nil || connection == nil {
		return func() {}
	}
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(done)
		_ = connection.SetDeadline(time.Now())
		_ = connection.Close()
	})
	var once sync.Once
	return func() {
		once.Do(func() {
			if !stop() {
				// A running callback owns this connection until it finishes.
				// Returning sooner could let it close another request's socket.
				<-done
			}
		})
	}
}

const (
	// defaultMaxPooledConns bounds how many transport connections one logical
	// client keeps alive to its pinned endpoint. Each pooled connection serves
	// one request at a time, so the bound is also the client's maximum request
	// concurrency.
	defaultMaxPooledConns = 4
	// defaultConnIdleTimeout discards pooled connections that sit unused this
	// long. It stays under the broker's default 30s read timeout so the client
	// usually closes before the server does; a stale connection that slips
	// through simply fails its next round-trip and is discarded.
	defaultConnIdleTimeout = 25 * time.Second
)

// pooledConn is one checked-in transport connection and the time it was last
// released. Idle age beyond the pool's timeout makes it a discard candidate:
// the broker may already have timed it out server-side.
type pooledConn struct {
	conn       net.Conn
	releasedAt time.Time
}

// connPool bounds and reuses connections to one pinned endpoint. Capacity is a
// token semaphore: a connection owns its token from dial to close, so checking
// in never frees the token and checking out never takes a second one. An
// acquirer either receives a checked-in connection over the idle channel or
// takes a fresh token to dial — whichever unblocks first — and checked-out
// connections are never shared between concurrent callers.
type connPool struct {
	target      Target
	endpoint    string
	idleTimeout time.Duration
	tokens      chan struct{}
	idle        chan pooledConn
	done        chan struct{}
	closed      atomic.Bool
	// mu serializes release against close so a connection cannot be sent to
	// idle after close has drained it.
	mu sync.Mutex
}

func newConnPool(target Target, endpoint string, size int, idleTimeout time.Duration) *connPool {
	if size <= 0 {
		size = defaultMaxPooledConns
	}
	if idleTimeout <= 0 {
		idleTimeout = defaultConnIdleTimeout
	}
	return &connPool{
		target:      target,
		endpoint:    endpoint,
		idleTimeout: idleTimeout,
		tokens:      make(chan struct{}, size),
		idle:        make(chan pooledConn, size),
		done:        make(chan struct{}),
	}
}

// acquire returns a live connection to the endpoint, reusing an idle pooled
// connection when one is available and fresh enough, or dialing when capacity
// allows. The caller must pair it with release or discard.
func (p *connPool) acquire(ctx context.Context) (net.Conn, error) {
	if p == nil || p.closed.Load() {
		return nil, raw.ErrClosed
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if p.closed.Load() {
			return nil, raw.ErrClosed
		}
		// Prefer a checked-in connection; it already owns its token.
		select {
		case pooled := <-p.idle:
			if p.closed.Load() {
				p.expire(pooled)
				return nil, raw.ErrClosed
			}
			if time.Since(pooled.releasedAt) > p.idleTimeout {
				p.expire(pooled)
				continue
			}
			return pooled.conn, nil
		default:
		}
		select {
		case pooled := <-p.idle:
			if p.closed.Load() {
				p.expire(pooled)
				return nil, raw.ErrClosed
			}
			if time.Since(pooled.releasedAt) > p.idleTimeout {
				p.expire(pooled)
				continue
			}
			return pooled.conn, nil
		case p.tokens <- struct{}{}:
		case <-p.done:
			return nil, raw.ErrClosed
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if p.closed.Load() {
			p.freeToken()
			return nil, raw.ErrClosed
		}
		connection, err := dialContext(ctx, p.target, p.endpoint)
		if err != nil {
			p.freeToken()
			return nil, err
		}
		if p.closed.Load() {
			p.discard(connection)
			return nil, raw.ErrClosed
		}
		return connection, nil
	}
}

// release returns a healthy connection to the idle set, clearing the
// per-request deadline so a later checkout starts clean. When the pool is
// closed the connection is closed and its token freed instead.
func (p *connPool) release(connection net.Conn) {
	if p == nil || connection == nil {
		return
	}
	_ = connection.SetDeadline(time.Time{})
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed.Load() {
		_ = connection.Close()
		p.freeToken()
		return
	}
	// A checked-in connection always holds a token, so idle can never be full
	// here — the channel capacity equals the token bound.
	p.idle <- pooledConn{conn: connection, releasedAt: time.Now()}
}

// discard closes an unhealthy connection and frees its token.
func (p *connPool) discard(connection net.Conn) {
	if p == nil {
		return
	}
	if connection != nil {
		_ = connection.Close()
	}
	p.freeToken()
}

func (p *connPool) expire(pooled pooledConn) {
	_ = pooled.conn.Close()
	p.freeToken()
}

func (p *connPool) freeToken() {
	select {
	case <-p.tokens:
	default:
	}
}

// close wakes all waiting callers and closes idle connections. Connections
// still in use close when their callers release or discard them.
func (p *connPool) close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.closed.CompareAndSwap(false, true) {
		return
	}
	close(p.done)
	for {
		select {
		case pooled := <-p.idle:
			_ = pooled.conn.Close()
			p.freeToken()
		default:
			return
		}
	}
}
