package proxy_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/proxy"
	"github.com/otpki/pkcs11/raw"
	"github.com/otpki/pkcs11/vendors/all"
)

// TestLatencyProbe measures each stage of a remote session against a live
// broker so proxy slowness can be attributed to network RTT, round-trip
// count, or broker-side work. Set P11_PROBE_ADDR (host:port, required),
// P11_PROBE_ROUTE (default first discovered route), P11_PROBE_PIN (enables
// login-dependent stages), and P11_PROBE_INSECURE=1 for plaintext brokers.
func TestLatencyProbe(t *testing.T) {
	addr := os.Getenv("P11_PROBE_ADDR")
	if addr == "" {
		t.Skip("P11_PROBE_ADDR not set")
	}
	pin := os.Getenv("P11_PROBE_PIN")
	ctx := context.Background()

	step := func(name string, fn func() error) {
		start := time.Now()
		err := fn()
		t.Logf("%-28s %9s  err=%v", name, time.Since(start).Round(time.Millisecond), err)
	}

	// Raw TCP RTT baseline — three fresh dials, min/avg is the per-round-trip floor.
	for i := range 3 {
		step(fmt.Sprintf("tcp dial %d", i+1), func() error {
			conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
			if err != nil {
				return err
			}
			return conn.Close()
		})
	}

	target := proxy.Target{
		ConfigID:          "latency-probe",
		SecurityContextID: "latency-probe",
		Endpoints:         []string{addr},
		AllowInsecure:     os.Getenv("P11_PROBE_INSECURE") == "1",
		Vendors:           all.Modules(),
	}

	var routes []proxy.RouteInfo
	step("ListRoutes #1", func() (err error) { routes, err = proxy.ListRoutes(ctx, target); return err })
	step("ListRoutes #2 (warm)", func() (err error) { _, err = proxy.ListRoutes(ctx, target); return err })
	if len(routes) == 0 {
		t.Fatalf("no routes published by %s", addr)
	}
	route := routes[0]
	if selected := os.Getenv("P11_PROBE_ROUTE"); selected != "" {
		route = proxy.RouteInfo{ID: selected, Revision: routes[0].Revision}
		for _, candidate := range routes {
			if candidate.ID == selected {
				route = candidate
			}
		}
	}
	routeNames := make([]string, 0, len(routes))
	for _, r := range routes {
		routeNames = append(routeNames, r.ID)
	}
	t.Logf("route=%s revision=%s routes=%v", route.ID, route.Revision, routeNames)

	// Raw protocol client: one remote invocation per C_* call. Timing each
	// call separates fixed broker overhead from per-call HSM/simulator cost.
	rawTarget := target
	rawTarget.Route, rawTarget.Revision = route.ID, route.Revision
	var rawClient *proxy.Client
	step("proxy.Open (raw handshake)", func() (err error) {
		rawClient, err = proxy.Open(ctx, rawTarget)
		return err
	})
	if rawClient == nil {
		t.Fatalf("raw open failed")
	}
	step("C_Initialize", func() error { return rawClient.Initialize() })
	step("C_GetInfo", func() (err error) { _, err = rawClient.GetInfo(); return err })
	step("C_GetInfo again", func() (err error) { _, err = rawClient.GetInfo(); return err })
	var slots []raw.SlotID
	step("C_GetSlotList", func() (err error) { slots, err = rawClient.GetSlotList(true); return err })
	if len(slots) > 0 {
		slot := slots[0]
		step("C_GetSlotInfo", func() (err error) { _, err = rawClient.GetSlotInfo(slot); return err })
		step("C_GetTokenInfo", func() (err error) { _, err = rawClient.GetTokenInfo(slot); return err })
		var mechs []raw.MechanismType
		step("C_GetMechanismList", func() (err error) { mechs, err = rawClient.GetMechanismList(slot); return err })
		t.Logf("mechanism count=%d", len(mechs))
		for i, mech := range mechs {
			if i >= 3 {
				break
			}
			step(fmt.Sprintf("C_GetMechanismInfo 0x%x", uint(mech)), func() (err error) {
				_, err = rawClient.GetMechanismInfo(slot, mech)
				return err
			})
		}
		var session raw.SessionHandle
		step("C_OpenSession RO", func() (err error) {
			session, err = rawClient.OpenSession(slot, raw.CKF_SERIAL_SESSION)
			return err
		})
		if session != 0 {
			step("C_FindObjectsInit", func() error { return rawClient.FindObjectsInit(session, nil) })
			step("C_FindObjects", func() (err error) { _, _, err = rawClient.FindObjects(session, 64); return err })
			step("C_FindObjectsFinal", func() error { return rawClient.FindObjectsFinal(session) })
			step("C_GetSessionInfo", func() (err error) { _, err = rawClient.GetSessionInfo(session); return err })
			step("C_CloseSession", func() error { return rawClient.CloseSession(session) })
		}
	}
	step("raw Close", func() error { return rawClient.Close() })

	// Open performs describe + module setup; LoginLazy defers C_Login to the
	// first authenticated operation.
	var client *pkcs11.Client
	openCfg := pkcs11.Config{
		Module: proxy.RemoteModule(proxy.Target{
			ConfigID: target.ConfigID, SecurityContextID: target.SecurityContextID,
			Endpoints: target.Endpoints, Route: route.ID, Revision: route.Revision,
			AllowInsecure: target.AllowInsecure, TLS: target.TLS, Vendors: target.Vendors,
		}),
		Vendors:  all.Modules(),
		Sessions: pkcs11.SessionConfig{MaxTotal: 4},
		Login:    pkcs11.LoginConfig{Mode: pkcs11.LoginLazy},
	}
	if pin != "" {
		openCfg.PIN = pkcs11.StaticPIN(pin)
	}
	step("Open (handshake)", func() (err error) {
		client, err = pkcs11.Open(ctx, openCfg)
		return err
	})
	if client == nil {
		t.Fatalf("client open failed")
	}
	defer func() { _ = client.Close(ctx) }()

	if pin != "" {
		step("Activate (C_Login)", func() error { return client.Activate(ctx) })
	}

	privateClass := raw.CKO_PRIVATE_KEY
	onToken := true
	var refs []pkcs11.ObjectRef
	step("Find private keys", func() (err error) {
		refs, err = client.Find(ctx, pkcs11.ObjectQuery{Class: &privateClass, Token: &onToken})
		return err
	})
	t.Logf("found %d private key objects", len(refs))
	step("Find again (cache/gen check)", func() (err error) {
		_, err = client.Find(ctx, pkcs11.ObjectQuery{Class: &privateClass, Token: &onToken})
		return err
	})

	if len(refs) > 0 {
		step("Attributes on first key", func() (err error) {
			_, err = client.Attributes(ctx, refs[0], raw.NewAttribute(raw.CKA_MODULUS_BITS, nil))
			return err
		})
	}

	// Cold/warm sign-path probe: SignerFor stacks FindKeyPair + resolve +
	// attribute reads; Sign stacks a session lease + login + resolve + sign.
	// Second runs exercise the object/refs/session caches.
	if label := os.Getenv("P11_PROBE_KEY_LABEL"); label != "" {
		var signer *pkcs11.Signer
		step("SignerFor #1 (cold)", func() (err error) {
			signer, err = client.SignerFor(ctx, pkcs11.KeyLocator{Label: label}, pkcs11.SignerConfig{})
			return err
		})
		step("SignerFor #2 (warm)", func() error {
			_, err := client.SignerFor(ctx, pkcs11.KeyLocator{Label: label}, pkcs11.SignerConfig{})
			return err
		})
		if signer != nil {
			step("Sign #1", func() error {
				_, err := signer.SignContext(ctx, []byte("latency-probe"), nil)
				return err
			})
			step("Sign #2", func() error {
				_, err := signer.SignContext(ctx, []byte("latency-probe"), nil)
				return err
			})
		}
	}

	step("Close", func() error { return client.Close(ctx) })
}
