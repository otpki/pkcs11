package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"
	"sync"
	"time"
)

type dedupKey struct {
	principal string
	client    [16]byte
	request   [16]byte
}

type dedupEntry struct {
	done        chan struct{}
	fingerprint [32]byte
	response    response
	completed   time.Time
	size        int
	waiters     int
	retired     bool
}

type dedupLedger struct {
	mu           sync.Mutex
	entries      map[dedupKey]*dedupEntry
	maximum      int
	maximumBytes int
	bytes        int
	ttl          time.Duration
	closed       bool
}

func newDedupLedger(maximum, maximumBytes int, ttl time.Duration) *dedupLedger {
	if maximum <= 0 {
		maximum = 4096
	}
	if maximumBytes <= 0 {
		maximumBytes = 64 << 20
	}
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	return &dedupLedger{entries: make(map[dedupKey]*dedupEntry), maximum: maximum, maximumBytes: maximumBytes, ttl: ttl}
}

// begin reserves key for a new non-idempotent request or waits for the exact
// response retained by an earlier request with the same key. A replay response
// is cloned while the ledger lock still protects the retained buffers, so a
// concurrent target reset, shutdown, or eviction can never wipe memory while a
// follower is copying it.
func (ledger *dedupLedger) begin(ctx context.Context, key dedupKey, fingerprint [32]byte) (entry *dedupEntry, leader bool, replay response, err error) {
	ledger.mu.Lock()
	ledger.pruneLocked(time.Now())
	if ledger.closed {
		ledger.mu.Unlock()
		return nil, false, response{}, errors.New("pkcs11 proxy: request ledger is closed")
	}
	if existing := ledger.entries[key]; existing != nil {
		if existing.fingerprint != fingerprint {
			ledger.mu.Unlock()
			return nil, false, response{}, &RemoteError{Code: "request_id_reuse", Message: "request ID was reused with different request contents"}
		}
		existing.waiters++
		done := existing.done
		ledger.mu.Unlock()

		select {
		case <-done:
			ledger.mu.Lock()
			replay = cloneResponse(existing.response)
			ledger.releaseWaiterLocked(existing)
			ledger.mu.Unlock()
			return nil, false, replay, nil
		case <-ctx.Done():
			ledger.mu.Lock()
			ledger.releaseWaiterLocked(existing)
			ledger.mu.Unlock()
			return nil, false, response{}, ctx.Err()
		}
	}
	if len(ledger.entries) >= ledger.maximum && !ledger.evictOldestLocked() {
		// Never exceed the configured bound merely because all entries are still
		// executing. The caller can retry later with the same request ID.
		ledger.mu.Unlock()
		return nil, false, response{}, &RemoteError{Code: "dedup_capacity", Message: "all request-ledger entries are in progress"}
	}
	entry = &dedupEntry{done: make(chan struct{}), fingerprint: fingerprint}
	ledger.entries[key] = entry
	ledger.mu.Unlock()
	return entry, true, response{}, nil
}

func (ledger *dedupLedger) releaseWaiterLocked(entry *dedupEntry) {
	if entry == nil {
		return
	}
	if entry.waiters <= 0 {
		panic("pkcs11 proxy: dedup waiter accounting underflow")
	}
	entry.waiters--
	if entry.retired && entry.waiters == 0 {
		wipeResponse(&entry.response)
	}
}

func (ledger *dedupLedger) complete(key dedupKey, entry *dedupEntry, result response) {
	ledger.mu.Lock()
	if current := ledger.entries[key]; current == entry {
		entry.response = cloneResponse(result)
		entry.completed = time.Now()
		entry.size = responseRetainedSize(entry.response)
		ledger.bytes += entry.size
		ledger.evictBytesLocked(key)
		close(entry.done)
	}
	ledger.mu.Unlock()
}

func responseRetainedSize(value response) int {
	encoded, err := marshalMessage(value, defaultMaximumMessageSize)
	if err != nil {
		return 0
	}
	size := len(encoded)
	wipe(encoded)
	return size
}

func (ledger *dedupLedger) stats() (entries, bytes int) {
	if ledger == nil {
		return 0, 0
	}
	ledger.mu.Lock()
	ledger.pruneLocked(time.Now())
	entries, bytes = len(ledger.entries), ledger.bytes
	ledger.mu.Unlock()
	return entries, bytes
}

func (ledger *dedupLedger) retireLocked(key dedupKey, entry *dedupEntry) {
	if entry == nil || entry.retired {
		delete(ledger.entries, key)
		return
	}
	entry.retired = true
	ledger.bytes -= entry.size
	if ledger.bytes < 0 {
		ledger.bytes = 0
	}
	delete(ledger.entries, key)
	if entry.waiters == 0 {
		wipeResponse(&entry.response)
	}
}

func (ledger *dedupLedger) pruneLocked(now time.Time) {
	for key, entry := range ledger.entries {
		if !entry.completed.IsZero() && now.Sub(entry.completed) > ledger.ttl {
			ledger.retireLocked(key, entry)
		}
	}
}

func (ledger *dedupLedger) evictOldestLocked() bool {
	return ledger.evictOldestExceptLocked(dedupKey{})
}

func (ledger *dedupLedger) evictOldestExceptLocked(except dedupKey) bool {
	var oldestKey dedupKey
	var oldest *dedupEntry
	for key, entry := range ledger.entries {
		if key == except || entry.completed.IsZero() {
			continue
		}
		if oldest == nil || entry.completed.Before(oldest.completed) {
			oldestKey, oldest = key, entry
		}
	}
	if oldest == nil {
		return false
	}
	ledger.retireLocked(oldestKey, oldest)
	return true
}

func (ledger *dedupLedger) evictBytesLocked(except dedupKey) {
	for ledger.bytes > ledger.maximumBytes {
		if !ledger.evictOldestExceptLocked(except) {
			// Keep the just-completed response even when it alone exceeds the byte
			// budget; otherwise a transport retry could repeat a non-idempotent HSM
			// operation. The frame limit remains the absolute upper bound.
			return
		}
	}
}

func (ledger *dedupLedger) reset(epoch [16]byte) {
	if ledger == nil {
		return
	}
	ledger.mu.Lock()
	for key, entry := range ledger.entries {
		if entry.completed.IsZero() {
			entry.response = response{Version: protocolVersion, Epoch: epoch, Error: encodeError(&RemoteError{Code: "target_epoch_mismatch", Message: "target generation changed during request"})}
			entry.completed = time.Now()
			close(entry.done)
		}
		ledger.retireLocked(key, entry)
	}
	ledger.bytes = 0
	ledger.mu.Unlock()
}

func (ledger *dedupLedger) close() {
	if ledger == nil {
		return
	}
	ledger.mu.Lock()
	if ledger.closed {
		ledger.mu.Unlock()
		return
	}
	ledger.closed = true
	for key, entry := range ledger.entries {
		if entry.completed.IsZero() {
			entry.response = response{Version: protocolVersion, Error: encodeError(rawClosedError())}
			entry.completed = time.Now()
			close(entry.done)
		}
		ledger.retireLocked(key, entry)
	}
	ledger.bytes = 0
	ledger.mu.Unlock()
}

func cloneResponse(source response) response {
	result := source
	result.Results = make([]wireValue, len(source.Results))
	for index := range source.Results {
		result.Results[index] = cloneWireValue(source.Results[index])
	}
	result.ArgumentUpdates = make([]argumentUpdate, len(source.ArgumentUpdates))
	for index := range source.ArgumentUpdates {
		result.ArgumentUpdates[index] = argumentUpdate{Index: source.ArgumentUpdates[index].Index, Value: cloneWireValue(source.ArgumentUpdates[index].Value)}
	}
	result.Updates = make([]parameterUpdate, len(source.Updates))
	for index := range source.Updates {
		result.Updates[index] = source.Updates[index]
		result.Updates[index].Parameter.Data = append([]byte(nil), source.Updates[index].Parameter.Data...)
	}
	if source.Error != nil {
		copied := *source.Error
		result.Error = &copied
	}
	return result
}

func wipeResponse(value *response) {
	if value == nil {
		return
	}
	for index := range value.Results {
		wipeWireValue(&value.Results[index])
	}
	for index := range value.ArgumentUpdates {
		wipeWireValue(&value.ArgumentUpdates[index].Value)
	}
	for index := range value.Updates {
		wipe(value.Updates[index].Parameter.Data)
		value.Updates[index] = parameterUpdate{}
	}
	*value = response{}
}

// requestFingerprint binds a request ID to one operation schema without
// retaining a hash of request values. Values may contain a low-entropy HSM PIN,
// bearer credential, key material, plaintext, labels, or vendor parameter
// payloads; hashing those bytes would create a long-lived offline verifier in
// the deduplication ledger. The key already contains principal, client ID, and
// request ID, so a same-ID retry is conservatively replayed rather than executed
// again even when the caller changes a value accidentally.
func requestFingerprint(req request) [32]byte {
	digest := sha256.New()
	writeShapeString(digest, req.Method)
	writeShapeUint64(digest, uint64(len(req.Arguments)))
	for index := range req.Arguments {
		writeWireShape(digest, req.Arguments[index])
	}
	var result [32]byte
	copy(result[:], digest.Sum(nil))
	return result
}

func writeWireShape(digest hash.Hash, value wireValue) {
	_, _ = digest.Write([]byte{byte(value.Kind)})
	switch value.Kind {
	case valueList:
		writeShapeUint64(digest, uint64(len(value.Items)))
		for index := range value.Items {
			writeWireShape(digest, value.Items[index])
		}
	case valueStruct:
		writeShapeUint64(digest, uint64(len(value.Fields)))
		for index := range value.Fields {
			writeShapeString(digest, value.Fields[index].Name)
			writeWireShape(digest, value.Fields[index].Value)
		}
	case valueParameter:
		writeShapeString(digest, value.Parameter.Kind)
		writeShapeUint64(digest, uint64(value.Parameter.CodecVersion))
		if value.Parameter.Pointer {
			_, _ = digest.Write([]byte{1})
		} else {
			_, _ = digest.Write([]byte{0})
		}
	}
}

func writeShapeString(digest hash.Hash, value string) {
	writeShapeUint64(digest, uint64(len(value)))
	_, _ = digest.Write([]byte(value))
}

func writeShapeUint64(digest hash.Hash, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	_, _ = digest.Write(encoded[:])
}

func rawClosedError() error {
	return &RemoteError{Code: "closed", Message: "target is closed"}
}
