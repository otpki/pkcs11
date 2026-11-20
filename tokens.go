package pkcs11

import (
	"cmp"
	"context"
	"fmt"
	"slices"

	"github.com/otpki/pkcs11/raw"
)

// TokenSummary is the light identity snapshot of one token-present slot,
// obtained without opening a session or reading the mechanism table.
type TokenSummary struct {
	// SlotID is the module-assigned slot identifier.
	SlotID raw.SlotID
	// Slot is the C_GetSlotInfo result for SlotID.
	Slot raw.SlotInfo
	// Token is the C_GetTokenInfo result for SlotID.
	Token raw.TokenInfo
	// Err reports why this slot's metadata could not be read. Other slots are
	// unaffected; callers decide whether to surface or skip the entry.
	Err error
}

// ListTokens returns lightweight metadata for every token-present slot without
// opening a managed Client or session. It shares the normal process-wide module
// registry. A per-slot metadata failure is returned in TokenSummary.Err, while
// a failure to list slots fails the whole call.
//
//nolint:contextcheck // Nil callers intentionally fall back to a detached context.
func ListTokens(ctx context.Context, source ModuleSource) ([]TokenSummary, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	module, err := acquireModule(ctx, source)
	if err != nil {
		return nil, err
	}
	defer func() { _ = releaseModule(module) }()
	var summaries []TokenSummary
	err = module.execute(ctx, behaviorPlan{}, func(m raw.Module) error {
		var enumerateErr error
		summaries, enumerateErr = readTokenSummaries(m)
		return enumerateErr
	})
	if err != nil {
		return nil, fmt.Errorf("pkcs11: enumerate tokens on %s: %w", module.path, err)
	}
	return summaries, nil
}

// readTokenSummaries reads slot and token metadata. A bad slot is recorded in
// its summary while enumeration continues.
func readTokenSummaries(module raw.Module) ([]TokenSummary, error) {
	slots, err := module.GetSlotList(true)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: list token slots: %w", err)
	}
	summaries := make([]TokenSummary, 0, len(slots))
	for _, slot := range slots {
		summary := TokenSummary{SlotID: slot}
		summary.Slot, summary.Err = module.GetSlotInfo(slot)
		if summary.Err == nil {
			summary.Token, summary.Err = module.GetTokenInfo(slot)
		}
		if summary.Err != nil {
			summary.Err = fmt.Errorf("pkcs11: slot %d: %w", slot, summary.Err)
		}
		summaries = append(summaries, summary)
	}
	slices.SortFunc(summaries, func(a, b TokenSummary) int { return cmp.Compare(a.SlotID, b.SlotID) })
	return summaries, nil
}

// DiscoveredToken is one slot's light summary plus its fingerprinted device
// when the probe succeeded, ready to hand back to Open through Config.Devices.
type DiscoveredToken struct {
	TokenSummary
	// Device is the fingerprinted device for the slot, zero when Err or
	// FingerprintErr is set.
	Device Device
	// FingerprintErr reports a fingerprint failure on a slot whose summary
	// reads worked. Activation falls back to discovery inside Open and sees
	// the same failure there.
	FingerprintErr error
}

// DiscoverTokens enumerates and fingerprints every token-present slot on
// source in one pass, with the same adapter selection Open would do. A bad
// slot lands in Err or FingerprintErr while enumeration continues; a listing
// failure fails the call. Handing each Device to Open fingerprints every
// slot once instead of once per open.
//
//nolint:contextcheck // Nil callers intentionally fall back to a detached context.
func DiscoverTokens(ctx context.Context, source ModuleSource, vendors ...VendorModule) ([]DiscoveredToken, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	validated, _, err := validateVendorModules(mergeSourceVendors(source, vendors))
	if err != nil {
		return nil, fmt.Errorf("pkcs11: %w", err)
	}
	module, err := acquireModule(ctx, source)
	if err != nil {
		return nil, err
	}
	defer func() { _ = releaseModule(module) }()
	var tokens []DiscoveredToken
	err = module.execute(ctx, behaviorPlan{}, func(m raw.Module) error {
		var enumerateErr error
		tokens, enumerateErr = discoverTokens(m, CompatibilityConfig{}, validated)
		return enumerateErr
	})
	if err != nil {
		return nil, fmt.Errorf("pkcs11: enumerate tokens on %s: %w", module.path, err)
	}
	return tokens, nil
}

// discoverTokens is readTokenSummaries with the fingerprint folded in. A bad
// slot is recorded in its entry while enumeration continues.
func discoverTokens(module raw.Module, compatibility CompatibilityConfig, vendors []VendorModule) ([]DiscoveredToken, error) {
	moduleInfo, err := module.GetInfo()
	if err != nil {
		return nil, fmt.Errorf("pkcs11: get module info: %w", err)
	}
	slots, err := module.GetSlotList(true)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: list token slots: %w", err)
	}
	tokens := make([]DiscoveredToken, 0, len(slots))
	for _, slotID := range slots {
		token := DiscoveredToken{SlotID: slotID}
		token.Slot, token.Err = module.GetSlotInfo(slotID)
		if token.Err == nil {
			token.Token, token.Err = module.GetTokenInfo(slotID)
		}
		if token.Err != nil {
			token.Err = fmt.Errorf("pkcs11: slot %d: %w", slotID, token.Err)
		} else {
			token.Device, token.FingerprintErr = fingerprintSlot(module, moduleInfo, slotID, token.Slot, token.Token, compatibility, vendors)
		}
		tokens = append(tokens, token)
	}
	slices.SortFunc(tokens, func(a, b DiscoveredToken) int { return cmp.Compare(a.SlotID, b.SlotID) })
	return tokens, nil
}
