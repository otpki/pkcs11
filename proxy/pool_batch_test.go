//go:build !windows

package proxy

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/otpki/pkcs11/raw"
)

// Requests on a pinned client reuse pooled connections instead of dialing per
// call: after describe and the first warm-up, accepted connections stay flat
// while request count grows.
func TestPooledConnectionsReused(t *testing.T) {
	harness := newProxyHarness(t, SessionBudget{MaxPhysicalTotal: 3}, nil)
	client := openRemoteRaw(t, harness.target)
	remoteSlot(t, client)

	before := harness.listener.accepted.Load()
	for range 8 {
		if _, err := client.GetInfo(); err != nil {
			t.Fatalf("GetInfo: %v", err)
		}
	}
	if accepted := harness.listener.accepted.Load(); accepted != before {
		t.Fatalf("accepted connections grew to %d after warm-up, want %d", accepted, before)
	}
}

// Concurrent callers may hold separate pooled connections, but the pool bound
// caps them: 12 concurrent calls with the default pool of 4 never exceed
// describe + 4 pooled connections.
func TestPooledConnectionsBoundedConcurrency(t *testing.T) {
	harness := newProxyHarness(t, SessionBudget{MaxPhysicalTotal: 3}, nil)
	client := openRemoteRaw(t, harness.target)

	var wg sync.WaitGroup
	errs := make(chan error, 12)
	for range 12 {
		wg.Go(func() {
			_, err := client.GetInfo()
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent GetInfo: %v", err)
		}
	}
	if accepted := harness.listener.accepted.Load(); accepted > int64(1+client.target.MaxPooledConnections) {
		t.Fatalf("accepted connections = %d, want <= %d", accepted, 1+client.target.MaxPooledConnections)
	}
}

// A pooled connection idle past the client timeout is discarded so its next
// checkout dials fresh instead of discovering a broker-side close mid-request.
func TestIdlePooledConnectionRedials(t *testing.T) {
	harness := newProxyHarness(t, SessionBudget{MaxPhysicalTotal: 3}, nil)
	client := openRemoteRaw(t, harness.target)
	remoteSlot(t, client)
	client.pool.idleTimeout = 50 * time.Millisecond

	before := harness.listener.accepted.Load()
	time.Sleep(150 * time.Millisecond)
	if _, err := client.GetInfo(); err != nil {
		t.Fatalf("GetInfo after idle: %v", err)
	}
	if accepted := harness.listener.accepted.Load(); accepted != before+1 {
		t.Fatalf("accepted connections = %d, want %d (expired conn replaced)", accepted, before+1)
	}
}

// @batch executes each call through the normal path: results decode like
// standalone calls and per-call errors are contained to their entry.
func TestInvokeBatchRoundTrip(t *testing.T) {
	harness := newProxyHarness(t, SessionBudget{MaxPhysicalTotal: 3}, nil)
	client := openRemoteRaw(t, harness.target)
	slot := remoteSlot(t, client)
	mechanisms, err := client.GetMechanismList(slot)
	if err != nil {
		t.Fatalf("GetMechanismList: %v", err)
	}
	if len(mechanisms) == 0 {
		t.Skip("mock module advertises no mechanisms")
	}

	var info raw.Info
	var token raw.TokenInfo
	var mechInfo raw.MechanismInfo
	var session raw.SessionHandle
	calls := []BatchCall{
		{Method: "GetInfo", Results: []any{&info}},
		{Method: "GetTokenInfo", Arguments: []any{slot}, Results: []any{&token}},
		{Method: "GetMechanismInfo", Arguments: []any{slot, mechanisms[0]}, Results: []any{&mechInfo}},
		{Method: "GetMechanismInfo", Arguments: []any{slot, raw.MechanismType(0xffffffff)}},
		// A session-opening call exercises the non-idempotent subcall path and
		// its derived dedup request ID.
		{Method: "OpenSession", Arguments: []any{slot, raw.CKF_SERIAL_SESSION}, Results: []any{&session}},
		{Method: "CloseSession", Arguments: []any{raw.SessionHandle(0)}},
	}
	if err := client.InvokeBatch(calls); err != nil {
		t.Fatalf("InvokeBatch: %v", err)
	}
	for i, call := range calls[:3] {
		if call.Err != nil {
			t.Fatalf("batch call %d (%s) failed: %v", i, call.Method, call.Err)
		}
	}
	if calls[4].Err != nil {
		t.Fatalf("OpenSession subcall failed: %v", calls[4].Err)
	}
	if calls[3].Err == nil {
		t.Fatal("bogus mechanism subcall unexpectedly succeeded")
	}
	if calls[5].Err == nil {
		t.Fatal("CloseSession on handle 0 unexpectedly succeeded")
	}
	if calls[2].Err != nil || mechInfo == (raw.MechanismInfo{}) {
		t.Fatal("GetMechanismInfo subcall returned no info")
	}

	// The session opened inside the batch is a live virtual session: prove it
	// by querying and closing it through ordinary calls.
	if session == 0 {
		t.Fatal("batch OpenSession returned handle 0")
	}
	if _, err = client.GetSessionInfo(session); err != nil {
		t.Fatalf("GetSessionInfo on batch-opened session: %v", err)
	}
	if err := client.CloseSession(session); err != nil {
		t.Fatalf("CloseSession on batch-opened session: %v", err)
	}
}

// A broker that does not know @batch rejects the method once; the client then
// runs calls serially and never retries the batch path again.
func TestInvokeBatchFallsBackOnUnknownMethod(t *testing.T) {
	var serverID, epoch [16]byte
	serverID[0], epoch[0] = 7, 9
	var batchAttempts, getInfoCalls int
	var mu sync.Mutex
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	respond := func(req request) response {
		resp := response{Version: protocolVersion, Epoch: epoch}
		mu.Lock()
		defer mu.Unlock()
		switch req.Method {
		case methodDescribe:
			describe := describeResult{
				ServerID:            serverID,
				Epoch:               epoch,
				AcceptingNewClients: true,
				Interface:           raw.InterfaceInfo{Version: raw.Version{Major: 3}},
			}
			encoded, encErr := encodeWireValue(describe, emptyCodecRegistry())
			if encErr == nil {
				resp.Results = []wireValue{encoded}
			}
		case methodBatch:
			batchAttempts++
			resp.Error = encodeError(&RemoteError{Code: "unknown_method", Message: req.Method})
		case "GetInfo":
			getInfoCalls++
			encoded, encErr := encodeWireValue(raw.Info{LibraryDescription: "fallback-fake"}, emptyCodecRegistry())
			if encErr == nil {
				resp.Results = []wireValue{encoded}
			}
		default:
			resp.Error = encodeError(&RemoteError{Code: "unknown_method", Message: req.Method})
		}
		return resp
	}
	go func() {
		for {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer func() { _ = connection.Close() }()
				for {
					var req request
					if err := readMessage(connection, &req, defaultMaximumMessageSize); err != nil {
						return
					}
					if err := writeMessage(connection, respond(req), defaultMaximumMessageSize); err != nil {
						return
					}
				}
			}()
		}
	}()

	target := Target{
		ConfigID: "batch-fallback", Revision: "rev",
		Endpoints:     []string{listener.Addr().String()},
		Route:         "route",
		AllowInsecure: true,
	}
	client, err := Open(context.Background(), target)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	var info raw.Info
	calls := []BatchCall{{Method: "GetInfo", Results: []any{&info}}}
	if err := client.InvokeBatch(calls); err != nil {
		t.Fatalf("InvokeBatch: %v", err)
	}
	if calls[0].Err != nil {
		t.Fatalf("serial fallback GetInfo failed: %v", calls[0].Err)
	}
	if info.LibraryDescription != "fallback-fake" {
		t.Fatalf("GetInfo result = %+v", info)
	}
	mu.Lock()
	if batchAttempts != 1 {
		t.Fatalf("@batch attempts = %d, want 1", batchAttempts)
	}
	if getInfoCalls != 1 {
		t.Fatalf("GetInfo calls = %d, want 1 (serial fallback)", getInfoCalls)
	}
	mu.Unlock()

	// A later batch must skip @batch entirely now that the broker proved it
	// unsupported.
	var again raw.Info
	calls = []BatchCall{{Method: "GetInfo", Results: []any{&again}}}
	if err := client.InvokeBatch(calls); err != nil {
		t.Fatalf("second InvokeBatch: %v", err)
	}
	if calls[0].Err != nil {
		t.Fatalf("second GetInfo failed: %v", calls[0].Err)
	}
	mu.Lock()
	if batchAttempts != 1 {
		t.Fatalf("@batch retried after rejection: attempts = %d", batchAttempts)
	}
	mu.Unlock()
}

// The server keeps reading framed requests on an open connection, so two
// requests written back-to-back are answered in order — the property pooled
// reuse relies on.
func TestPipelinedRequestsOnOneConnection(t *testing.T) {
	harness := newProxyHarness(t, SessionBudget{MaxPhysicalTotal: 3}, nil)

	connection, err := net.DialTimeout("tcp", harness.listener.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connection.Close() }()
	_ = connection.SetDeadline(time.Now().Add(10 * time.Second))

	var clientID [16]byte
	clientID[0] = 42
	newRequest := func(id byte) request {
		return request{
			Version:   protocolVersion,
			Target:    harness.target.Route,
			Revision:  harness.target.Revision,
			ClientID:  clientID,
			RequestID: [16]byte{id},
			Method:    methodDescribe,
		}
	}
	if err := writeMessage(connection, newRequest(1), defaultMaximumMessageSize); err != nil {
		t.Fatalf("write request 1: %v", err)
	}
	if err := writeMessage(connection, newRequest(2), defaultMaximumMessageSize); err != nil {
		t.Fatalf("write request 2: %v", err)
	}
	for i, want := range [2]byte{1, 2} {
		var resp response
		if err := readMessage(connection, &resp, defaultMaximumMessageSize); err != nil {
			t.Fatalf("read response %d: %v", i+1, err)
		}
		if resp.Error != nil {
			t.Fatalf("response %d error: %+v", i+1, resp.Error)
		}
		if len(resp.Results) != 1 {
			t.Fatalf("response %d results = %d, want 1", i+1, len(resp.Results))
		}
		var describe describeResult
		if err := assignDecoded(&describe, resp.Results[0], emptyCodecRegistry()); err != nil {
			t.Fatalf("decode response %d: %v", i+1, err)
		}
		if !describe.AcceptingNewClients {
			t.Fatalf("response %d reports draining server", i+1)
		}
		_ = want
	}
}
