package pkcs11

import "testing"

func TestModulePlanPromotionIsProcessWideAndMonotonic(t *testing.T) {
	module := &moduleRef{}

	module.applyPlan(behaviorPlan{
		module: moduleBehavior{
			serializeCalls: true,
			legacyInit:     true,
			skipFinalize:   true,
		},
		buffers: bufferBehavior{rejectNullProbe: true},
	})

	if !module.forceSerialize {
		t.Fatal("serialize-calls or legacy initialization was not promoted to the shared module")
	}
	if !module.legacyInitialize {
		t.Fatal("legacy-initialization policy was not retained for reinitialization")
	}
	if !module.skipFinalize {
		t.Fatal("skip-finalize policy was not promoted to the shared module")
	}
	if !module.rejectNullOutputProbe {
		t.Fatal("null-output-probe workaround was not promoted to the shared module")
	}

	// A later client selecting a standards-only token may add no restrictions,
	// but it must not weaken policy already required by another client that uses
	// the same loaded native library.
	module.applyPlan(behaviorPlan{})
	if !module.forceSerialize || !module.legacyInitialize || !module.skipFinalize || !module.rejectNullOutputProbe {
		t.Fatal("shared module policy was relaxed by a less restrictive plan")
	}
}
