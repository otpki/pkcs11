package conformance

import "testing"

func TestIdentityIsShortAndUnique(t *testing.T) {
	runner := &Runner{profile: Profile{Suite: SuiteProfile{Prefix: "otpki-utimaco-conformance-suite"}}}
	seen := make(map[string]struct{}, 1000)
	for range 1000 {
		identity := runner.identity("very-long-case-name-with-spaces-and-symbols")
		if len(identity) > 21 {
			t.Fatalf("base identity is %d bytes: %q", len(identity), identity)
		}
		if len(identity+"-unwrapped") > 31 {
			t.Fatalf("suffixed identity is %d bytes: %q", len(identity+"-unwrapped"), identity+"-unwrapped")
		}
		if _, duplicate := seen[identity]; duplicate {
			t.Fatalf("duplicate identity %q", identity)
		}
		seen[identity] = struct{}{}
	}
}
