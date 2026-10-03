package auditlog

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/otpki/pkcs11/proxy"
)

func testWriter(t *testing.T, opts Options) (*Writer, string, string) {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	keyPath := filepath.Join(dir, "audit.key")
	writer, err := Open(logPath, keyPath, opts)
	if err != nil {
		t.Fatal(err)
	}
	return writer, logPath, keyPath
}

func event(kind string) proxy.AuditEvent {
	return proxy.AuditEvent{
		Type: kind, Target: "hsm", Method: "Login",
		ClientID: "010203040506070809000a0b0c0d0e0f", Principal: "workload-sha256:abc",
	}
}

func logLines(t *testing.T, path string) []string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimRight(string(content), "\n"), "\n")
}

func isCheckpoint(line string) bool {
	return strings.Contains(line, `"type":"checkpoint"`)
}

func TestSignedAuditRoundTrip(t *testing.T) {
	writer, logPath, keyPath := testWriter(t, Options{})
	writer.AuditProxy(context.Background(), event("client_established"))
	writer.AuditProxy(context.Background(), event("login_grant"))
	writer.AuditProxy(context.Background(), event("client_destroyed"))
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if writer.Written() != 3 {
		t.Fatalf("written = %d, want 3", writer.Written())
	}
	if writer.Sealed() != 3 || writer.Checkpoints() != 1 {
		t.Fatalf("sealed=%d checkpoints=%d, want 3 sealed under 1 checkpoint", writer.Sealed(), writer.Checkpoints())
	}
	// 4 lines: 3 leaves + 1 checkpoint.
	if lines := logLines(t, logPath); len(lines) != 4 || !isCheckpoint(lines[3]) {
		t.Fatalf("log has %d lines, want 3 leaves + checkpoint trailer; last line checkpoint=%v", len(lines), isCheckpoint(lines[3]))
	}
	public, err := LoadPublicKey(keyPath + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	report, err := Verify(logPath, public)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if report.Records != 3 || report.Checkpoints != 1 || report.Unsealed != 0 || report.SealedThrough != 3 {
		t.Fatalf("report %+v, want 3 records, 1 checkpoint, 0 unsealed", report)
	}
}

func TestAuditBatchSizeSeals(t *testing.T) {
	// BatchSize 2: every second record commits a checkpoint without waiting
	// for Close or the interval timer.
	writer, logPath, keyPath := testWriter(t, Options{BatchSize: 2, CheckpointInterval: time.Hour})
	for range 5 {
		writer.AuditProxy(context.Background(), event("login_grant"))
	}
	for deadline := time.Now().Add(5 * time.Second); writer.Checkpoints() < 2; {
		if time.Now().After(deadline) {
			t.Fatal("batch threshold never sealed a checkpoint")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	lines := logLines(t, logPath)
	checkpoints := 0
	for _, line := range lines {
		if isCheckpoint(line) {
			checkpoints++
		}
	}
	if checkpoints != 3 {
		t.Fatalf("%d checkpoints, want 3 (2 batch seals + close seal)", checkpoints)
	}
	public, _ := LoadPublicKey(keyPath + ".pub")
	report, err := Verify(logPath, public)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if report.Records != 5 || report.Checkpoints != 3 || report.Unsealed != 0 {
		t.Fatalf("report %+v, want 5 records, 3 checkpoints, 0 unsealed", report)
	}
}

func TestAuditIntervalSealsLowVolume(t *testing.T) {
	writer, logPath, keyPath := testWriter(t, Options{BatchSize: 1000, CheckpointInterval: 20 * time.Millisecond})
	writer.AuditProxy(context.Background(), event("drain"))
	for deadline := time.Now().Add(5 * time.Second); writer.Checkpoints() == 0; {
		if time.Now().After(deadline) {
			t.Fatal("interval seal never fired")
		}
		time.Sleep(5 * time.Millisecond)
	}
	_ = writer.Close()
	public, _ := LoadPublicKey(keyPath + ".pub")
	report, err := Verify(logPath, public)
	if err != nil || report.SealedThrough != 1 {
		t.Fatalf("interval seal verify = %+v, %v", report, err)
	}
}

func TestAuditTamperDetection(t *testing.T) {
	writer, logPath, keyPath := testWriter(t, Options{})
	for range 4 {
		writer.AuditProxy(context.Background(), event("login_grant"))
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	public, _ := LoadPublicKey(keyPath + ".pub")

	// Corrupt one byte inside a middle leaf's content.
	lines := logLines(t, logPath)
	if len(lines) != 5 {
		t.Fatalf("log has %d lines, want 4 leaves + checkpoint", len(lines))
	}
	record := []byte(lines[2])
	record[len(record)/2] ^= 0x01
	if record[len(record)/2] == 0 {
		record[len(record)/2] = 'x'
	}
	lines[2] = string(record)
	tampered := filepath.Join(t.TempDir(), "tampered.log")
	if err := os.WriteFile(tampered, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(tampered, public); err == nil {
		t.Fatal("tampered leaf verified cleanly")
	} else if !strings.Contains(err.Error(), "root") && !strings.Contains(err.Error(), "malformed") {
		t.Fatalf("tamper error should name the Merkle root or the line, got %v", err)
	}
}

func TestAuditTruncationDetection(t *testing.T) {
	writer, logPath, keyPath := testWriter(t, Options{BatchSize: 3, CheckpointInterval: time.Hour})
	for range 5 {
		writer.AuditProxy(context.Background(), event("activation"))
	}
	_ = writer.Close()
	public, _ := LoadPublicKey(keyPath + ".pub")

	// Layout: 3 leaves, checkpoint, 2 leaves, checkpoint.
	lines := logLines(t, logPath)
	if len(lines) != 7 || !isCheckpoint(lines[3]) || !isCheckpoint(lines[6]) {
		t.Fatalf("unexpected layout: %d lines", len(lines))
	}
	dir := t.TempDir()
	// Dropping the last checkpoint and its batch verifies with 2 unsealed
	// records dropped silently — same fundamental limit as before: nothing
	// attests history that no checkpoint sealed.
	truncated := filepath.Join(dir, "truncated.log")
	if err := os.WriteFile(truncated, []byte(strings.Join(lines[:4], "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := Verify(truncated, public)
	if err != nil || report.Records != 3 || report.Unsealed != 0 {
		t.Fatalf("tail-truncated verify = %+v, %v; want 3 records, 0 unsealed", report, err)
	}
	// Removing a sealed middle leaf breaks the first checkpoint's root.
	middle := filepath.Join(dir, "middle.log")
	if err := os.WriteFile(middle, []byte(strings.Join(append(lines[:2], lines[3:]...), "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(middle, public); err == nil {
		t.Fatal("removing a sealed middle record verified cleanly")
	}
}

func TestAuditResumeContinuesChain(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	keyPath := filepath.Join(dir, "audit.key")
	opts := Options{CheckpointInterval: time.Hour}

	first, err := Open(logPath, keyPath, opts)
	if err != nil {
		t.Fatal(err)
	}
	first.AuditProxy(context.Background(), event("client_established"))
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := Open(logPath, keyPath, opts)
	if err != nil {
		t.Fatal(err)
	}
	second.AuditProxy(context.Background(), event("login_grant"))
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	public, _ := LoadPublicKey(keyPath + ".pub")
	report, err := Verify(logPath, public)
	if err != nil {
		t.Fatalf("resumed chain did not verify: %v", err)
	}
	if report.Records != 2 || report.Checkpoints != 2 {
		t.Fatalf("verified %+v across restart, want 2 records + 2 checkpoints", report)
	}
	if second.seq != 2 {
		t.Fatalf("resumed seq = %d, want 2", second.seq)
	}
	// An unsealed tail resumes into the next batch: kill without closing by
	// writing directly through commitLocked.
	third, err := Open(logPath, keyPath, opts)
	if err != nil {
		t.Fatal(err)
	}
	third.mu.Lock()
	third.commitLocked(event("unsealed_tail"), 0)
	third.mu.Unlock()
	if third.Pending() != 1 {
		t.Fatalf("pending = %d, want 1", third.Pending())
	}
	// Simulate a crash: abandon the writer without Close's final seal.
	_ = third.file.Close()
	fourth, err := Open(logPath, keyPath, opts)
	if err != nil {
		t.Fatal(err)
	}
	if fourth.Pending() != 1 {
		t.Fatalf("resumed pending = %d, want the unsealed leaf carried over", fourth.Pending())
	}
	if err := fourth.Close(); err != nil {
		t.Fatal(err)
	}
	report, err = Verify(logPath, public)
	if err != nil || report.Records != 3 || report.Checkpoints != 3 {
		t.Fatalf("post-crash verify = %+v, %v", report, err)
	}
}

func TestAuditDropWritesSignedGapMarker(t *testing.T) {
	writer, logPath, keyPath := testWriter(t, Options{QueueSize: 1})
	// Let the writer commit one record first so the log holds real events
	// before the flood forces drops.
	writer.AuditProxy(context.Background(), event("client_established"))
	for deadline := time.Now().Add(5 * time.Second); writer.Written() == 0; {
		if time.Now().After(deadline) {
			t.Fatal("first audit record never written")
		}
		time.Sleep(5 * time.Millisecond)
	}
	for range 40 {
		writer.AuditProxy(context.Background(), event("login_grant"))
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	public, _ := LoadPublicKey(keyPath + ".pub")
	report, err := Verify(logPath, public)
	if err != nil {
		t.Fatalf("gap-marked log did not verify: %v", err)
	}
	if report.Records < 3 {
		t.Fatalf("verified %d records, want events plus the gap marker", report.Records)
	}
	content, _ := os.ReadFile(logPath)
	if !strings.Contains(string(content), eventGap) {
		t.Fatal("no audit_gap leaf in the log after drops")
	}
}

func TestAuditVerifyRejectsWrongKey(t *testing.T) {
	writer, logPath, _ := testWriter(t, Options{})
	writer.AuditProxy(context.Background(), event("drain"))
	_ = writer.Close()

	wrongDir := t.TempDir()
	wrong, err := Open(filepath.Join(wrongDir, "other.log"), filepath.Join(wrongDir, "other.key"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	_ = wrong.Close()
	wrongPub, _ := LoadPublicKey(wrong.PublicKeyPath())
	if _, err := Verify(logPath, wrongPub); err == nil {
		t.Fatal("log verified against a foreign key")
	}
}

func TestAuditProveAndVerifyProof(t *testing.T) {
	writer, logPath, keyPath := testWriter(t, Options{BatchSize: 4, CheckpointInterval: time.Hour})
	for i := range 5 {
		writer.AuditProxy(context.Background(), event("login_grant"))
		_ = i
	}
	for deadline := time.Now().Add(5 * time.Second); writer.Checkpoints() == 0; {
		if time.Now().After(deadline) {
			t.Fatal("batch never sealed")
		}
		time.Sleep(5 * time.Millisecond)
	}
	public, _ := LoadPublicKey(keyPath + ".pub")

	proof, err := Prove(logPath, 3)
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}
	if err := VerifyProof(proof, public); err != nil {
		t.Fatalf("VerifyProof: %v", err)
	}
	// A proof must not verify under a foreign key or a swapped leaf.
	if err := VerifyProof(proof, wrongKey(t)); err == nil {
		t.Fatal("proof verified against a foreign key")
	}
	other, err := Prove(logPath, 4)
	if err != nil {
		t.Fatal(err)
	}
	other.Leaf = proof.Leaf
	if err := VerifyProof(other, public); err == nil {
		t.Fatal("proof with a swapped leaf verified")
	}
	// Seq 5 is past the batch of 4 and not yet sealed.
	if _, err := Prove(logPath, 5); err == nil {
		t.Fatal("proved an unsealed record")
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	proof, err = Prove(logPath, 5)
	if err != nil {
		t.Fatalf("Prove after close: %v", err)
	}
	if err := VerifyProof(proof, public); err != nil {
		t.Fatalf("VerifyProof after close: %v", err)
	}
}

func wrongKey(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	w, err := Open(filepath.Join(dir, "w.log"), filepath.Join(dir, "w.key"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Close() }()
	pub, err := LoadPublicKey(w.PublicKeyPath())
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func TestAuditInspectTail(t *testing.T) {
	writer, logPath, _ := testWriter(t, Options{BatchSize: 2, CheckpointInterval: time.Hour})
	for range 3 {
		writer.AuditProxy(context.Background(), event("login_grant"))
	}
	_ = writer.Close()
	records, err := Inspect(logPath, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || records[0].Seq != 2 || records[1].Seq != 3 {
		t.Fatalf("inspect tail = %+v, want seqs 2,3", records)
	}
}
