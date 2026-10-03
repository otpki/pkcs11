package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"slices"
	"sync"
	"time"
)

type dedupKey struct {
	principal string
	client    [16]byte
	request   [16]byte
}

// dedupEntry records that one request ID was admitted. The execution record
// outlives its cached response so evicting response bytes can never make an
// already-run mutation look safe to run again.
type dedupEntry struct {
	done        chan struct{}
	fingerprint [32]byte
	epoch       [16]byte
	response    response
	hasResponse bool
	completed   time.Time
	expiresAt   time.Time
	size        int
	waiters     int
	retired     bool
}

// outcomeAvailable reports whether the retained response can still be replayed.
func (entry *dedupEntry) outcomeAvailable() bool {
	return entry.hasResponse
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

// begin admits a new non-idempotent request or waits for the result of an
// existing request with the same key. The request ID is valid only until its
// deadline or ledger TTL, whichever comes first. A stale request is rejected
// instead of being executed again after its history is pruned.
func (ledger *dedupLedger) begin(ctx context.Context, key dedupKey, fingerprint [32]byte, epoch [16]byte, deadline time.Time) (entry *dedupEntry, leader bool, replay response, err error) {
	now := time.Now()
	ledger.mu.Lock()
	ledger.pruneLocked(now)
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
		entryEpoch := existing.epoch
		ledger.mu.Unlock()

		select {
		case <-done:
			ledger.mu.Lock()
			if existing.outcomeAvailable() {
				replay = cloneResponse(existing.response)
			} else {
				// The execution history is authoritative but its result bytes
				// were discarded under memory pressure. Report an explicit
				// unknown outcome rather than re-running the mutation.
				replay = outcomeUnknownResponse(entryEpoch)
			}
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
	if !deadline.IsZero() && !now.Before(deadline) {
		ledger.mu.Unlock()
		return nil, false, response{}, &RemoteError{Code: "deadline_exceeded", Message: "request retry horizon has expired"}
	}
	if len(ledger.entries) >= ledger.maximum {
		// Completed entries stay protected until their retry horizon expires;
		// admitting over the limit would require forgetting an executed request.
		// The caller can retry the same request ID once earlier entries expire.
		ledger.mu.Unlock()
		return nil, false, response{}, &RemoteError{Code: "dedup_capacity", Message: "request-ledger capacity reached"}
	}
	expiresAt := now.Add(ledger.ttl)
	if !deadline.IsZero() && deadline.Before(expiresAt) {
		expiresAt = deadline
	}
	entry = &dedupEntry{done: make(chan struct{}), fingerprint: fingerprint, epoch: epoch, expiresAt: expiresAt}
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
		entry.hasResponse = true
		entry.completed = time.Now()
		entry.size = responseRetainedSize(entry.response)
		ledger.bytes += entry.size
		// Payload eviction removes response bytes only — never the execution
		// record — and never touches in-flight work. A retained response that
		// exceeds the budget by itself degrades to the unknown-outcome
		// tombstone, keeping the byte bound absolute.
		ledger.evictBytesLocked()
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
		if entry.completed.IsZero() {
			continue // in-progress execution records are never evicted
		}
		if !entry.expiresAt.IsZero() && !now.Before(entry.expiresAt) {
			ledger.retireLocked(key, entry)
		}
	}
}

// dropPayloadLocked releases the retained response bytes of one completed
// entry while keeping its execution record. The entry stays in the map so a
// retry observes the tombstone instead of re-executing.
func (ledger *dedupLedger) dropPayloadLocked(entry *dedupEntry) {
	if entry == nil || !entry.hasResponse {
		return
	}
	entry.hasResponse = false
	ledger.bytes -= entry.size
	if ledger.bytes < 0 {
		ledger.bytes = 0
	}
	entry.size = 0
	// Waiters copy under ledger.mu only, so wiping is always safe — a queued
	// follower observes hasResponse=false and replays the unknown-outcome
	// tombstone rather than the discarded bytes.
	wipeResponse(&entry.response)
}

func (ledger *dedupLedger) evictBytesLocked() {
	for ledger.bytes > ledger.maximumBytes {
		var oldest *dedupEntry
		for _, entry := range ledger.entries {
			if !entry.hasResponse {
				continue
			}
			if oldest == nil || entry.completed.Before(oldest.completed) {
				oldest = entry
			}
		}
		if oldest == nil {
			return
		}
		ledger.dropPayloadLocked(oldest)
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
			entry.hasResponse = true
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
			entry.hasResponse = true
			entry.completed = time.Now()
			close(entry.done)
		}
		ledger.retireLocked(key, entry)
	}
	ledger.bytes = 0
	ledger.mu.Unlock()
}

// outcomeUnknownResponse is the ledger tombstone: the execution record proves
// the request ran (or is running) but its result bytes were discarded, so the
// caller must not resubmit it as new work.
func outcomeUnknownResponse(epoch [16]byte) response {
	return response{
		Version: protocolVersion,
		Epoch:   epoch,
		Error:   encodeError(fmt.Errorf("%w: original request outcome was evicted from the deduplication ledger", ErrOutcomeUnknown)),
	}
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
		result.Updates[index].Parameter.Data = slices.Clone(source.Updates[index].Parameter.Data)
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
	for index := range value.Batch {
		batch := &value.Batch[index]
		for i := range batch.Results {
			wipeWireValue(&batch.Results[i])
		}
		for i := range batch.ArgumentUpdates {
			wipeWireValue(&batch.ArgumentUpdates[i].Value)
		}
		for i := range batch.Updates {
			wipe(batch.Updates[i].Parameter.Data)
			batch.Updates[i] = parameterUpdate{}
		}
	}
	*value = response{}
}

// requestFingerprint binds a request ID to the operation shape without hashing
// argument values. Values may contain PINs, credentials, keys, or plaintext and
// must not become long-lived offline verifiers in the deduplication ledger.
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
