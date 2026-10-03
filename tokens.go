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
