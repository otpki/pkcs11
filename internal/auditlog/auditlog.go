// Package auditlog writes append-only audit records for the PKCS #11 proxy.
// Records are grouped into Merkle trees and sealed by signed checkpoints. Verify
// replays the checkpoint chain, and Prove creates an inclusion proof for one
// record.
//
// Records after the newest checkpoint are an unsealed tail. A crash may leave
// that tail unsigned, which Verify reports explicitly.
//
// Producers write through a bounded queue. If it overflows, the writer records
// an audit_gap entry so the loss is visible in the log.
package auditlog

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/otpki/pkcs11/proxy"
)

const (
	// Version is the record schema version.
	Version = 1
	// DefaultQueueSize bounds events held between producers and the writer.
	DefaultQueueSize = 4096
	// DefaultBatchSize is the number of leaf records one checkpoint seals.
	DefaultBatchSize = 64
	// DefaultCheckpointInterval bounds how long records sit unsealed when
	// event volume never reaches the batch size.
	DefaultCheckpointInterval = 30 * time.Second
	// eventGap marks a leaf inserted after drops; Dropped carries the number
	// of lost events.
	eventGap = "audit_gap"
	// typeCheckpoint is the reserved record type for Merkle checkpoint lines.
	typeCheckpoint = "checkpoint"
)

var genesis = sha256.Sum256([]byte("pkcs11-proxy-audit/v1"))

// Options tunes the writer's queue, batching, and seal cadence.
type Options struct {
	// QueueSize bounds buffered events; overflow is dropped and counted.
	QueueSize int
	// BatchSize is the number of leaf records sealed by one checkpoint.
	BatchSize int
	// CheckpointInterval seals a non-empty batch even when BatchSize is not
	// reached, bounding the unsealed window under low traffic. Zero disables.
	CheckpointInterval time.Duration
}

func (o Options) normalized() Options {
	if o.QueueSize <= 0 {
		o.QueueSize = DefaultQueueSize
	}
	if o.BatchSize <= 0 {
		o.BatchSize = DefaultBatchSize
	}
	if o.CheckpointInterval == 0 {
		o.CheckpointInterval = DefaultCheckpointInterval
	}
	return o
}

// Record is one unsigned leaf line: a decoded audit event. Field order
// defines the JSON encoding, which is the leaf-hash input byte-for-byte.
type Record struct {
	Version   int    `json:"v"`
	Seq       uint64 `json:"seq"`
	Time      string `json:"ts"`
	Type      string `json:"type"`
	Target    string `json:"target,omitempty"`
	Method    string `json:"method,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	Principal string `json:"principal,omitempty"`
	Code      string `json:"code,omitempty"`
	Dropped   uint64 `json:"dropped,omitempty"`
}

// checkpoint is the signed line sealing a batch of leaf records.
type checkpoint struct {
	Version int    `json:"v"`
	Type    string `json:"type"` // always "checkpoint"
	Start   uint64 `json:"start"`
	End     uint64 `json:"end"`
	Root    string `json:"root"` // hex Merkle root over leaf hashes Start..End
	Prev    string `json:"prev"` // hex digest of the previous checkpoint
	KeyID   string `json:"key"`
	Sig     string `json:"sig"`
}

// canonical returns the deterministic signature input: the JSON encoding of
// the checkpoint content fields in declaration order. The signature and the
// chain digest are both derived from this value.
func (c *checkpoint) canonical() ([]byte, error) {
	return json.Marshal([]any{
		c.Version, c.Type, c.Start, c.End, c.Root, c.Prev, c.KeyID,
	})
}

// leafHash is the Merkle leaf hash over the raw record line, domain-separated
// from interior nodes so a record can never masquerade as a node.
func leafHash(line []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(line)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func nodeHash(left, right [32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left[:])
	h.Write(right[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// merkleRoot reduces leaf hashes to the tree root; an odd trailing node is
// promoted unchanged rather than duplicated.
func merkleRoot(leaves [][32]byte) [32]byte {
	if len(leaves) == 0 {
		return [32]byte{}
	}
	level := leaves
	for len(level) > 1 {
		next := make([][32]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 < len(level) {
				next = append(next, nodeHash(level[i], level[i+1]))
			} else {
				next = append(next, level[i])
			}
		}
		level = next
	}
	return level[0]
}

// ProofNode is one step of a Merkle inclusion path: Position is "L" or "R" —
// which side the sibling hash sits on when recomputing toward the root.
type ProofNode struct {
	Position string `json:"pos"`
	Hash     string `json:"hash"`
}

// merklePath returns the inclusion path for leaf index within leaves.
func merklePath(leaves [][32]byte, index int) []ProofNode {
	path := []ProofNode{}
	level := leaves
	idx := index
	for len(level) > 1 {
		next := make([][32]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 < len(level) {
				next = append(next, nodeHash(level[i], level[i+1]))
			} else {
				next = append(next, level[i])
			}
		}
		var sibling [32]byte
		position := ""
		switch {
		case idx%2 == 1:
			sibling = level[idx-1]
			position = "L"
		case idx+1 < len(level):
			sibling = level[idx+1]
			position = "R"
		}
		if position != "" {
			path = append(path, ProofNode{Position: position, Hash: hex.EncodeToString(sibling[:])})
		}
		idx /= 2
		level = next
	}
	return path
}

// verifyPath recomputes a root from a leaf hash and an inclusion path.
func verifyPath(leaf [32]byte, path []ProofNode) ([32]byte, error) {
	current := leaf
	for _, node := range path {
		sibling, err := hex.DecodeString(node.Hash)
		if err != nil || len(sibling) != sha256.Size {
			return [32]byte{}, errors.New("auditlog: invalid proof hash")
		}
		var sib [32]byte
		copy(sib[:], sibling)
		switch node.Position {
		case "L":
			current = nodeHash(sib, current)
		case "R":
			current = nodeHash(current, sib)
		default:
			return [32]byte{}, fmt.Errorf("auditlog: invalid proof position %q", node.Position)
		}
	}
	return current, nil
}

// Writer appends audit records to a file and seals them with signed Merkle
// checkpoints. It implements proxy.AuditSink.
type Writer struct {
	file    *os.File
	key     ed25519.PrivateKey
	public  ed25519.PublicKey
	keyID   string
	pubPath string
	opts    Options

	mu           sync.Mutex
	seq          uint64
	prev         [32]byte // digest of the last checkpoint's canonical input
	pending      [][32]byte
	pendingStart uint64
	tail         []Record // bounded in-memory mirror for the dev UI

	queue       chan proxy.AuditEvent
	done        chan struct{}
	wg          sync.WaitGroup
	written     atomic.Uint64
	sealed      atomic.Uint64
	checkpoints atomic.Uint64
	dropped     atomic.Uint64
	failed      atomic.Uint64
}

// Open creates or resumes an audit log. Checkpoints are signed with the Ed25519 key at keyPath. A
// missing key is created with mode 0600 and its public key is written to keyPath+".pub".
func Open(path, keyPath string, opts Options) (*Writer, error) {
	opts = opts.normalized()
	key, err := loadOrCreateKey(keyPath)
	if err != nil {
		return nil, err
	}
	public, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("auditlog: key %s is not ed25519", keyPath)
	}
	if err := writePublicKey(keyPath+".pub", public); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) //nolint:gosec // G304: path is the operator-configured audit log.
	if err != nil {
		return nil, fmt.Errorf("auditlog: open %s: %w", path, err)
	}
	w := &Writer{
		file:    file,
		key:     key,
		public:  public,
		keyID:   KeyID(public),
		pubPath: keyPath + ".pub",
		opts:    opts,
		queue:   make(chan proxy.AuditEvent, opts.QueueSize),
		done:    make(chan struct{}),
		prev:    genesis,
	}
	if err := w.resume(path); err != nil {
		_ = file.Close()
		return nil, err
	}
	w.wg.Go(w.run)
	return w, nil
}

// resume continues from an existing file: the checkpoint chain restarts at the
// last checkpoint digest, the seq counter at the last leaf, and any leaves
// after the last checkpoint become pending for the next seal.
func (w *Writer) resume(path string) error {
	existing, err := os.Open(path) //nolint:gosec // G304: path is the operator-configured audit log.
	if err != nil {
		return err
	}
	defer func() { _ = existing.Close() }()
	scanner := bufio.NewScanner(existing)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var probe struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(line, &probe) != nil {
			return fmt.Errorf("auditlog: refusing to append to a corrupt log at %s", path)
		}
		if probe.Type == typeCheckpoint {
			var cp checkpoint
			if err := json.Unmarshal(line, &cp); err != nil {
				return fmt.Errorf("auditlog: refusing to append to a corrupt log at %s", path)
			}
			canonical, err := cp.canonical()
			if err != nil {
				return err
			}
			w.prev = sha256.Sum256(canonical)
			w.pending = nil
			continue
		}
		var entry Record
		if err := json.Unmarshal(line, &entry); err != nil {
			return fmt.Errorf("auditlog: refusing to append to a corrupt log at %s", path)
		}
		if len(w.pending) == 0 {
			w.pendingStart = entry.Seq
		}
		w.pending = append(w.pending, leafHash(line))
		w.tailAppend(entry)
		w.seq = entry.Seq
	}
	return scanner.Err()
}

// AuditProxy implements proxy.AuditSink. It never blocks: a full queue drops
// the event and arms an audit_gap leaf so the loss stays inside the
// verifiable record set.
func (w *Writer) AuditProxy(_ context.Context, event proxy.AuditEvent) {
	select {
	case w.queue <- event:
	default:
		w.dropped.Add(1)
	}
}

// Written returns leaf records appended and fsynced.
func (w *Writer) Written() uint64 { return w.written.Load() }

// Sealed returns leaf records covered by a committed checkpoint.
func (w *Writer) Sealed() uint64 { return w.sealed.Load() }

// Checkpoints returns signed checkpoint records committed.
func (w *Writer) Checkpoints() uint64 { return w.checkpoints.Load() }

// Pending returns leaf records written but not yet sealed by a checkpoint.
func (w *Writer) Pending() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.pending)
}

// Dropped returns events discarded because the queue was full.
func (w *Writer) Dropped() uint64 { return w.dropped.Load() }

// Failed returns records that could not be written to the file.
func (w *Writer) Failed() uint64 { return w.failed.Load() }

// KeyID returns the signing key identifier, a truncated public key digest.
func (w *Writer) KeyID() string { return w.keyID }

// PublicKey returns the verification half of the signing key.
func (w *Writer) PublicKey() ed25519.PublicKey { return w.public }

// PublicKeyPath returns the file carrying the verification public key.
func (w *Writer) PublicKeyPath() string { return w.pubPath }

// Path returns the audit log's file path.
func (w *Writer) Path() string { return w.file.Name() }

// Tail returns the most recent leaf records from the writer's bounded
// in-memory mirror — newest last — without touching the log file.
func (w *Writer) Tail(n int) []Record {
	w.mu.Lock()
	defer w.mu.Unlock()
	if n <= 0 || n > len(w.tail) {
		n = len(w.tail)
	}
	out := make([]Record, n)
	copy(out, w.tail[len(w.tail)-n:])
	return out
}

// Seal forces a checkpoint over the pending batch, if any. It is the
// operator-facing counterpart of the size and interval seals, used to bound
// the unsealed window before shutdown or verification.
func (w *Writer) Seal() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.sealLocked()
}

// Close drains the queue, seals the remaining batch, fsyncs, and closes.
func (w *Writer) Close() error {
	close(w.done)
	w.wg.Wait()
	return w.file.Close()
}

func (w *Writer) run() {
	var tick <-chan time.Time
	if w.opts.CheckpointInterval > 0 {
		ticker := time.NewTicker(w.opts.CheckpointInterval)
		defer ticker.Stop()
		tick = ticker.C
	}
	for {
		select {
		case event := <-w.queue:
			w.write(event)
		case <-tick:
			w.Seal()
		case <-w.done:
			for {
				select {
				case event := <-w.queue:
					w.write(event)
				default:
					w.Seal()
					return
				}
			}
		}
	}
}

func (w *Writer) write(event proxy.AuditEvent) {
	w.mu.Lock()
	defer w.mu.Unlock()
	// If events were dropped since the last write, first commit a gap leaf so
	// the loss is part of the verifiable record set rather than invisible.
	if dropped := w.dropped.Swap(0); dropped > 0 {
		w.commitLocked(proxy.AuditEvent{Type: eventGap}, dropped)
	}
	if event.Type == "" {
		return
	}
	w.commitLocked(event, 0)
	if len(w.pending) >= w.opts.BatchSize {
		w.sealLocked()
	}
}

func (w *Writer) commitLocked(event proxy.AuditEvent, dropped uint64) {
	entry := Record{
		Version:   Version,
		Seq:       w.seq + 1,
		Time:      time.Now().UTC().Format("2006-01-02T15:04:05.000000000Z"),
		Type:      event.Type,
		Target:    event.Target,
		Method:    event.Method,
		ClientID:  event.ClientID,
		Principal: event.Principal,
		Code:      event.Code,
		Dropped:   dropped,
	}
	line, err := json.Marshal(entry)
	if err != nil {
		w.failed.Add(1)
		return
	}
	if !w.appendLine(line) {
		return
	}
	if len(w.pending) == 0 {
		w.pendingStart = entry.Seq
	}
	w.pending = append(w.pending, leafHash(line))
	w.tailAppend(entry)
	w.seq = entry.Seq
	w.written.Add(1)
}

// sealLocked signs a checkpoint over the pending leaf batch, chains it to the
// previous checkpoint, and appends it to the file.
func (w *Writer) sealLocked() {
	if len(w.pending) == 0 {
		return
	}
	root := merkleRoot(w.pending)
	cp := checkpoint{
		Version: Version,
		Type:    typeCheckpoint,
		Start:   w.pendingStart,
		End:     w.seq,
		Root:    hex.EncodeToString(root[:]),
		Prev:    hex.EncodeToString(w.prev[:]),
		KeyID:   w.keyID,
	}
	canonical, err := cp.canonical()
	if err != nil {
		w.failed.Add(1)
		return
	}
	digest := sha256.Sum256(canonical)
	cp.Sig = hex.EncodeToString(ed25519.Sign(w.key, digest[:]))
	line, err := json.Marshal(cp)
	if err != nil {
		w.failed.Add(1)
		return
	}
	if !w.appendLine(line) {
		return
	}
	w.prev = digest
	w.sealed.Add(uint64(len(w.pending)))
	w.checkpoints.Add(1)
	w.pending = nil
}

// appendLine writes one line and fsyncs: audit durability outranks
// throughput, so every committed line reaches stable storage before the next
// is considered.
func (w *Writer) appendLine(line []byte) bool {
	if _, err := w.file.Write(append(line, '\n')); err != nil {
		w.failed.Add(1)
		return false
	}
	if err := w.file.Sync(); err != nil {
		w.failed.Add(1)
		return false
	}
	return true
}

const tailCap = 512

func (w *Writer) tailAppend(entry Record) {
	w.tail = append(w.tail, entry)
	if len(w.tail) > tailCap {
		w.tail = slices.Clone(w.tail[len(w.tail)-tailCap:])
	}
}

// KeyID returns the truncated public-key digest used as the record key ID.
func KeyID(public ed25519.PublicKey) string {
	digest := sha256.Sum256(public)
	return hex.EncodeToString(digest[:8])
}

// loadOrCreateKey reads a 32-byte hex Ed25519 seed from path, or generates and
// persists one with mode 0600.
func loadOrCreateKey(path string) (ed25519.PrivateKey, error) {
	content, err := os.ReadFile(path) //nolint:gosec // G304: path is the operator-configured audit log.
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("auditlog: read key %s: %w", path, err)
		}
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("auditlog: generate key: %w", err)
		}
		if err := os.WriteFile(path, []byte(hex.EncodeToString(key.Seed())), 0o600); err != nil {
			return nil, fmt.Errorf("auditlog: write key %s: %w", path, err)
		}
		return key, nil
	}
	seed, err := hex.DecodeString(string(bytes.TrimSpace(content)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("auditlog: %s does not contain a 32-byte hex Ed25519 seed", path)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func writePublicKey(path string, public ed25519.PublicKey) error {
	//nolint:gosec // The public key is shareable by design; verification needs it.
	return os.WriteFile(path, []byte(hex.EncodeToString(public)), 0o644)
}

// LoadPublicKey reads the hex public key written next to a private key file.
func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	content, err := os.ReadFile(path) //nolint:gosec // G304: path is the operator-configured audit log.
	if err != nil {
		return nil, err
	}
	key, err := hex.DecodeString(string(bytes.TrimSpace(content)))
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("auditlog: %s does not contain a hex Ed25519 public key", path)
	}
	return ed25519.PublicKey(key), nil
}

// Report summarizes a Verify pass over an audit log.
type Report struct {
	// Records is the number of leaf event records read.
	Records int `json:"records"`
	// Checkpoints is the number of signed checkpoints verified.
	Checkpoints int `json:"checkpoints"`
	// SealedThrough is the highest seq covered by a checkpoint.
	SealedThrough uint64 `json:"sealed_through"`
	// Unsealed is the number of leaf records after the last checkpoint —
	// pending seal or lost to truncation/crash. They are reported, not
	// rejected: only a checkpoint can attest them.
	Unsealed int `json:"unsealed"`
	// PartialTail reports a torn final line (an interrupted write) that was
	// skipped rather than treated as corruption.
	PartialTail bool `json:"partial_tail,omitempty"`
	// LastRoot is the hex Merkle root of the newest verified checkpoint.
	LastRoot string `json:"last_root,omitempty"`
	// KeyID is the verified signing key identifier.
	KeyID string `json:"key_id"`
}

// readLines splits the file into lines and reports whether the final line is
// unterminated — a torn write a verifier must tolerate rather than fail on.
func readLines(file *os.File) (lines [][]byte, partial bool, err error) {
	reader := bufio.NewReader(file)
	for {
		line, readErr := reader.ReadBytes('\n')
		if len(line) > 0 {
			trimmed := bytes.TrimRight(line, "\n")
			if len(trimmed) > 0 {
				if readErr == io.EOF {
					partial = true
				} else {
					lines = append(lines, trimmed)
				}
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				return lines, partial, nil
			}
			return lines, partial, readErr
		}
	}
}

// Verify checks record order, Merkle roots, checkpoint signatures, and the checkpoint chain. It
// stops at the first invalid record. Records after the last checkpoint are reported as unsealed.
func Verify(path string, public ed25519.PublicKey) (Report, error) {
	report := Report{KeyID: KeyID(public)}
	file, err := os.Open(path) //nolint:gosec // G304: path is the operator-configured audit log.
	if err != nil {
		return report, err
	}
	defer func() { _ = file.Close() }()
	lines, partial, err := readLines(file)
	if err != nil {
		return report, err
	}
	report.PartialTail = partial

	prev := genesis
	expectedSeq := uint64(0)
	var batch [][32]byte
	batchStart := uint64(0)
	for index, line := range lines {
		lineNumber := index + 1
		var probe struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(line, &probe); err != nil {
			return report, fmt.Errorf("auditlog: line %d: malformed record: %w", lineNumber, err)
		}
		if probe.Type == typeCheckpoint {
			var cp checkpoint
			if err := json.Unmarshal(line, &cp); err != nil {
				return report, fmt.Errorf("auditlog: line %d: malformed checkpoint: %w", lineNumber, err)
			}
			if err := checkCheckpoint(&cp, batch, batchStart, expectedSeq, prev, public); err != nil {
				return report, fmt.Errorf("auditlog: line %d: %w", lineNumber, err)
			}
			canonical, _ := cp.canonical()
			prev = sha256.Sum256(canonical)
			batch = nil
			report.Checkpoints++
			report.SealedThrough = cp.End
			report.LastRoot = cp.Root
			continue
		}
		var entry Record
		if err := json.Unmarshal(line, &entry); err != nil {
			return report, fmt.Errorf("auditlog: line %d: malformed record: %w", lineNumber, err)
		}
		expectedSeq++
		if entry.Seq != expectedSeq {
			return report, fmt.Errorf("auditlog: line %d: seq %d, want %d (records lost or reordered)", lineNumber, entry.Seq, expectedSeq)
		}
		if len(batch) == 0 {
			batchStart = entry.Seq
		}
		batch = append(batch, leafHash(line))
		report.Records++
	}
	report.Unsealed = len(batch)
	return report, nil
}

// checkCheckpoint validates one checkpoint against the leaves accumulated
// since the previous checkpoint: range, recomputed Merkle root, chain link,
// key identity, and signature.
func checkCheckpoint(cp *checkpoint, batch [][32]byte, batchStart, expectedSeq uint64, prev [32]byte, public ed25519.PublicKey) error {
	if len(batch) == 0 {
		return errors.New("checkpoint seals no records")
	}
	if cp.Start != batchStart || cp.End != expectedSeq {
		return fmt.Errorf("checkpoint range %d..%d does not match records %d..%d", cp.Start, cp.End, batchStart, expectedSeq)
	}
	if uint64(len(batch)) != cp.End-cp.Start+1 {
		return fmt.Errorf("checkpoint range %d..%d spans %d records but %d are present", cp.Start, cp.End, cp.End-cp.Start+1, len(batch))
	}
	root := merkleRoot(batch)
	if cp.Root != hex.EncodeToString(root[:]) {
		return errors.New("checkpoint Merkle root mismatch (records tampered)")
	}
	if cp.Prev != hex.EncodeToString(prev[:]) {
		return errors.New("checkpoint chain mismatch (checkpoints lost or reordered)")
	}
	if cp.KeyID != KeyID(public) {
		return fmt.Errorf("checkpoint signed by an unexpected key %q", cp.KeyID)
	}
	canonical, err := cp.canonical()
	if err != nil {
		return err
	}
	digest := sha256.Sum256(canonical)
	signature, err := hex.DecodeString(cp.Sig)
	if err != nil || !ed25519.Verify(public, digest[:], signature) {
		return errors.New("checkpoint signature verification failed")
	}
	return nil
}

// Inspect returns the newest tail leaf records of the log at path —
// checkpoint lines skipped — for operator inspection. Zero or negative tail
// returns everything, which callers should avoid on large logs.
func Inspect(path string, tail int) ([]Record, error) {
	file, err := os.Open(path) //nolint:gosec // G304: path is the operator-configured audit log.
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	lines, _, err := readLines(file)
	if err != nil {
		return nil, err
	}
	var records []Record
	for index, line := range lines {
		var probe struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(line, &probe); err != nil {
			return nil, fmt.Errorf("auditlog: line %d: malformed record: %w", index+1, err)
		}
		if probe.Type == typeCheckpoint {
			continue
		}
		var entry Record
		if err := json.Unmarshal(line, &entry); err != nil {
			return nil, fmt.Errorf("auditlog: line %d: malformed record: %w", index+1, err)
		}
		records = append(records, entry)
	}
	if tail > 0 && len(records) > tail {
		records = records[len(records)-tail:]
	}
	return records, nil
}

// Proof binds one leaf record to the signed checkpoint that sealed it: the
// raw leaf line plus the Merkle inclusion path and the checkpoint itself.
// VerifyProof re-derives the root from the leaf and checks the checkpoint
// signature; chain continuity across checkpoints still requires Verify.
type Proof struct {
	Seq        uint64          `json:"seq"`
	Leaf       json.RawMessage `json:"leaf"`
	Path       []ProofNode     `json:"path"`
	Checkpoint checkpoint      `json:"checkpoint"`
}

// Prove extracts an inclusion proof for the record with the given seq. The
// record must be sealed — pending records have no checkpoint to bind to.
func Prove(path string, seq uint64) (*Proof, error) {
	file, err := os.Open(path) //nolint:gosec // G304: path is the operator-configured audit log.
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	lines, _, err := readLines(file)
	if err != nil {
		return nil, err
	}
	var leaf []byte
	var batch [][32]byte
	for index, line := range lines {
		lineNumber := index + 1
		var probe struct {
			Type string `json:"type"`
			Seq  uint64 `json:"seq"`
		}
		if err := json.Unmarshal(line, &probe); err != nil {
			return nil, fmt.Errorf("auditlog: line %d: malformed record: %w", lineNumber, err)
		}
		if probe.Type == typeCheckpoint {
			var cp checkpoint
			if err := json.Unmarshal(line, &cp); err != nil {
				return nil, fmt.Errorf("auditlog: line %d: malformed checkpoint: %w", lineNumber, err)
			}
			if leaf != nil && seq >= cp.Start && seq <= cp.End {
				return &Proof{
					Seq:        seq,
					Leaf:       json.RawMessage(slices.Clone(leaf)),
					Path:       merklePath(batch, int(seq-cp.Start)), //nolint:gosec // G115: seq-cp.Start is bounded by the checkpoint batch length.
					Checkpoint: cp,
				}, nil
			}
			batch = nil
			continue
		}
		var entry Record
		if err := json.Unmarshal(line, &entry); err != nil {
			return nil, fmt.Errorf("auditlog: line %d: malformed record: %w", lineNumber, err)
		}
		batch = append(batch, leafHash(line))
		if entry.Seq == seq {
			leaf = line
		}
	}
	if leaf == nil {
		return nil, fmt.Errorf("auditlog: no record with seq %d", seq)
	}
	return nil, fmt.Errorf("auditlog: record %d is not yet sealed by a checkpoint", seq)
}

// VerifyProof checks that a proof's leaf hashes into the checkpoint's Merkle
// root and that the checkpoint signature verifies against public.
func VerifyProof(proof *Proof, public ed25519.PublicKey) error {
	var entry Record
	if err := json.Unmarshal(proof.Leaf, &entry); err != nil {
		return fmt.Errorf("auditlog: proof leaf is malformed: %w", err)
	}
	if entry.Seq != proof.Seq {
		return fmt.Errorf("auditlog: proof leaf seq %d, want %d", entry.Seq, proof.Seq)
	}
	cp := &proof.Checkpoint
	if proof.Seq < cp.Start || proof.Seq > cp.End {
		return fmt.Errorf("auditlog: proof checkpoint range %d..%d does not cover seq %d", cp.Start, cp.End, proof.Seq)
	}
	root, err := verifyPath(leafHash(proof.Leaf), proof.Path)
	if err != nil {
		return err
	}
	if cp.Root != hex.EncodeToString(root[:]) {
		return errors.New("auditlog: proof does not reach the checkpoint root")
	}
	if cp.KeyID != KeyID(public) {
		return fmt.Errorf("auditlog: checkpoint signed by an unexpected key %q", cp.KeyID)
	}
	canonical, err := cp.canonical()
	if err != nil {
		return err
	}
	digest := sha256.Sum256(canonical)
	signature, err := hex.DecodeString(cp.Sig)
	if err != nil || !ed25519.Verify(public, digest[:], signature) {
		return errors.New("auditlog: checkpoint signature verification failed")
	}
	return nil
}
