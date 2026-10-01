package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const defaultMaximumMessageSize = 64 << 20

// marshalMessage uses a deterministic, architecture-independent JSON envelope.
// The transport is framed separately, so one connection always carries exactly
// one request and one response. JSON is intentionally preferred over gob here:
// it avoids Go-runtime-specific type metadata, produces deterministic
// envelopes, and permits strict unknown-field rejection at the trust boundary.
// The deduplication ledger fingerprints only operation schemas, never encoded
// values, so PINs and other low-entropy secrets do not become stored hashes.
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
	if len(encoded) > int(^uint32(0)) {
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

func readMessage(reader io.Reader, value any, maximum int) error {
	if maximum <= 0 {
		maximum = defaultMaximumMessageSize
	}
	buffered := bufio.NewReader(reader)
	var length [4]byte
	if _, err := io.ReadFull(buffered, length[:]); err != nil {
		return err
	}
	size := int(binary.BigEndian.Uint32(length[:]))
	if size > maximum {
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
	if dialer == nil {
		dialer = &net.Dialer{Timeout: target.ConnectTimeout}
	}
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
	go func() {
		select {
		case <-ctx.Done():
			// SetDeadline wakes both plain and TLS reads/writes before Close tears
			// down the socket. The native HSM call may still finish on the broker,
			// but the caller is never forced to wait for the request timeout.
			_ = connection.SetDeadline(time.Now())
			_ = connection.Close()
		case <-done:
		}
	}()
	var once sync.Once
	return func() { once.Do(func() { close(done) }) }
}
