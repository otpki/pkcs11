//go:build !windows

package proxy

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otpki/pkcs11/internal/testmock"
)

// BeforeListRoutes runs on every ListRoutes request and a hook failure leaves
// the catalog answering the last published set.
func TestBeforeListRoutesRunsPerListingAndToleratesFailure(t *testing.T) {
	var calls atomic.Int64
	var fail atomic.Bool
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	source := testmock.Source{Name: "hook-test", Tokens: 1}
	server, err := NewServer(context.Background(), ServerConfig{
		Listener:      listener,
		AllowInsecure: true,
		BeforeListRoutes: func(context.Context) error {
			calls.Add(1)
			if fail.Load() {
				return errors.New("enumeration failed")
			}
			return nil
		},
	}, testmockBrokerConfig(source))
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	serveContext, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(serveContext) }()
	t.Cleanup(func() {
		cancel()
		_ = server.Close(context.Background())
		<-serveDone
	})

	target := Target{Endpoints: []string{listener.Addr().String()}, AllowInsecure: true, RequestTimeout: 5 * time.Second}
	for range 3 {
		routes, err := ListRoutes(context.Background(), target)
		if err != nil {
			t.Fatal(err)
		}
		if len(routes) != 1 || routes[0].ID != "shared-hsm" {
			t.Fatalf("routes = %+v", routes)
		}
	}
	if calls.Load() != 3 {
		t.Fatalf("hook calls = %d, want 3", calls.Load())
	}

	fail.Store(true)
	routes, err := ListRoutes(context.Background(), target)
	if err != nil {
		t.Fatalf("listing after hook failure: %v", err)
	}
	if len(routes) != 1 {
		t.Fatalf("catalog after hook failure = %+v, want last published set", routes)
	}
}

// RetireTarget removes the route from publication at once — listings and new
// logical clients see it gone — while the returned channel closes only after
// in-flight native calls drain.
func TestRetireTargetUnpublishesThenDrains(t *testing.T) {
	module := testmock.New("retire", 1)
	source := testmock.SharedSource{Name: "retire", Module: module}
	server, addr := newTestmockBroker(t, testmockBrokerConfig(source))

	client, err := Open(context.Background(), Target{
		ConfigID: "retire-test", Revision: "v1", Route: "shared-hsm",
		Endpoints: []string{addr}, AllowInsecure: true, RequestTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Destroy()
	if err := client.Initialize(); err != nil {
		t.Fatal(err)
	}
	slot := remoteSlot(t, client)
	session := openVirtualSession(t, client, slot, false)

	// Hold one native call in flight so the drain has something to wait for.
	gate := testmock.NewGate()
	module.SetGate("GenerateRandom", gate)
	callDone := make(chan error, 1)
	go func() {
		_, callErr := client.GenerateRandom(session, 16)
		callDone <- callErr
	}()
	select {
	case <-gate.Entered:
	case <-time.After(5 * time.Second):
		t.Fatal("gated call never reached the module")
	}

	retired := server.RetireTarget("shared-hsm")
	// Unpublished immediately even though the drain is still parked.
	if ids := server.TargetIDs(); len(ids) != 0 {
		t.Fatalf("targets after retire = %v, want none", ids)
	}
	if routes := server.RouteCatalog(); len(routes) != 0 {
		t.Fatalf("catalog after retire = %+v, want empty", routes)
	}
	select {
	case <-retired:
		t.Fatal("retire channel closed while the gated call was still in flight")
	case <-time.After(50 * time.Millisecond):
	}
	select {
	case err := <-callDone:
		t.Fatalf("gated call finished early: %v", err)
	default:
	}

	gate.Open()
	select {
	case err := <-callDone:
		if err != nil {
			t.Fatalf("in-flight call on retired route failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("in-flight call did not finish after gate release")
	}
	select {
	case err := <-retired:
		if err != nil {
			t.Fatalf("retire drain failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("retire drain did not finish")
	}
	if count := module.SessionCount(); count != 0 {
		t.Fatalf("module still holds %d sessions after drain", count)
	}
}

// A RetireTarget on an unknown route yields a channel that is already
// complete — callers can always wait on it.
func TestRetireTargetUnknownRoute(t *testing.T) {
	server := &Server{}
	done := server.RetireTarget("never-published")
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("retiring an unknown route did not return a completed channel")
	}
}
