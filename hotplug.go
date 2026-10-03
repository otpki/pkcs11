package pkcs11

import (
	"cmp"
	"context"
	"errors"
	"slices"
	"time"

	"github.com/otpki/pkcs11/raw"
)

// SlotEventKind classifies a detected token or slot change.
type SlotEventKind string

const (
	// SlotEventChanged reports that a known slot now exposes different token
	// identity metadata or that the native API reported an unspecified change.
	SlotEventChanged SlotEventKind = "changed"
	// SlotEventAdded reports a token-present slot absent from the prior snapshot.
	SlotEventAdded SlotEventKind = "added"
	// SlotEventRemoved reports a previously token-present slot that disappeared.
	SlotEventRemoved SlotEventKind = "removed"
	// SlotEventError reports a watcher, polling, or optional refresh failure.
	SlotEventError SlotEventKind = "error"
)

// SlotEvent describes one hotplug, rediscovery, or watcher error event.
type SlotEvent struct {
	// Time is assigned when the driver emits or enriches the event.
	Time time.Time `json:"time"`
	// Kind classifies the observed change.
	Kind SlotEventKind `json:"kind"`
	// SlotID is the numeric slot associated with the event. It is zero for
	// watcher errors that are not attributable to one slot.
	SlotID raw.SlotID `json:"slot_id"`
	// Device is present when the event concerns the client's currently selected
	// slot and enrichment or refresh succeeded. It is an independent snapshot.
	Device *Device `json:"device,omitempty"`
	// Err retains the concrete watcher or refresh error for in-process callers.
	Err error `json:"-"`
	// Error is Err.Error() for JSON and diagnostic transports.
	Error string `json:"error,omitempty"`
}

// WatchConfig controls native C_WaitForSlotEvent use and polling fallback.
type WatchConfig struct {
	// PollInterval controls both nonblocking native event checks and snapshot
	// polling. Values less than or equal to zero select 500 milliseconds.
	PollInterval time.Duration
	// Refresh updates the client's selected token/adapter and invalidates pools
	// after an event for the selected slot. Events for other slots do not refresh
	// the client.
	Refresh bool
}

// Refresh rediscovers the selected token and rebuilds its vendor adapter, sessions, and caches. It
// waits for active operations before changing the device. Even a failed refresh invalidates old
// handles because the token may have changed.
func (c *Client) Refresh(ctx context.Context) error {
	if c == nil || c.closed.Load() || c.module == nil {
		return errors.New("pkcs11: client is closed")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// Refresh changes the slot/adapter attached to both pools. Wait for all
	// checked-out session leases so no active operation observes a half-updated
	// device, then invalidate every idle handle by advancing the generation.
	c.module.lifecycle.Lock()
	defer c.module.lifecycle.Unlock()
	c.module.leases.Lock()
	defer c.module.leases.Unlock()
	if c.closed.Load() || c.module.closed {
		return errors.New("pkcs11: module is closed")
	}
	current := c.currentDevice()
	devices, err := discoverManagedWithPlan(ctx, c.module, current.plan, c.compatibility, c.vendors)
	if err != nil {
		return err
	}
	device, err := selectDevice(devices, c.selector)
	// Advance the epoch even when reselection fails. Any token replacement can
	// invalidate handles that were opened under the previous slot contents.
	c.module.bumpGeneration()
	if err != nil {
		c.invalidateState(ctx)
		return err
	}
	// Publish the new diagnostic device before updating pools. The lease write
	// lock above prevents an operation from observing this transition partially.
	c.deviceMu.Lock()
	c.device = device
	c.deviceMu.Unlock()
	c.module.applyPlanLocked(device.plan)
	c.roPool.SetDevice(ctx, device)
	c.rwPool.SetDevice(ctx, device)
	c.cache.invalidate()
	c.login.reset()
	return nil
}

// slotSnapshot stores a compact token identity per token-present slot. The
// NUL separators prevent ambiguous concatenation of serial, label, and model.
type slotSnapshot map[raw.SlotID]string

func (c *Client) slotSnapshot(ctx context.Context) (slotSnapshot, error) {
	summaries, err := clientValue(ctx, c, "C_GetSlotList", readTokenSummaries)
	if err != nil {
		return nil, err
	}
	result := make(slotSnapshot, len(summaries))
	for _, summary := range summaries {
		if summary.Err != nil {
			return nil, summary.Err
		}
		// Handles are intentionally excluded: they are session-local and may change
		// without a physical token replacement.
		result[summary.SlotID] = summary.Token.SerialNumber + "\x00" + summary.Token.Label + "\x00" + summary.Token.Model
	}
	return result, nil
}

func diffSnapshots(before, after slotSnapshot) []SlotEvent {
	var events []SlotEvent
	for slot, oldValue := range before {
		newValue, ok := after[slot]
		switch {
		case !ok:
			events = append(events, SlotEvent{Kind: SlotEventRemoved, SlotID: slot})
		case newValue != oldValue:
			events = append(events, SlotEvent{Kind: SlotEventChanged, SlotID: slot})
		}
	}
	for slot := range after {
		if _, ok := before[slot]; !ok {
			events = append(events, SlotEvent{Kind: SlotEventAdded, SlotID: slot})
		}
	}
	// Map iteration is nondeterministic; stable slot order makes tests, logs, and
	// downstream reconciliation repeatable.
	slices.SortFunc(events, func(a, b SlotEvent) int { return cmp.Compare(a.SlotID, b.SlotID) })
	return events
}

func (c *Client) enrichSlotEvent(ctx context.Context, event SlotEvent, refresh bool) SlotEvent {
	event.Time = time.Now()
	selected := c.currentDevice().Fingerprint.SlotID
	if refresh && event.SlotID == selected {
		if err := c.Refresh(ctx); err != nil {
			event.Err = err
			event.Error = err.Error()
			return event
		}
	}
	device := c.currentDevice()
	if device.Fingerprint.SlotID == event.SlotID {
		event.Device = &device
	}
	return event
}

// WatchSlotEvents reports token and slot changes. It uses C_WaitForSlotEvent when available and
// falls back to polling when it is not. The channel closes with ctx. Errors are reported as
// SlotEventError and watching continues.
func (c *Client) WatchSlotEvents(ctx context.Context, config WatchConfig) <-chan SlotEvent {
	out := make(chan SlotEvent, 4)
	interval := config.PollInterval
	if interval <= 0 {
		interval = 500 * time.Millisecond
	}
	go func() {
		defer close(out)
		// The baseline is best effort. If it fails, native events can still work;
		// polling will report the next snapshot failure explicitly.
		previous, _ := c.slotSnapshot(ctx)
		useSnapshot := false
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			if err := ctx.Err(); err != nil {
				return
			}
			if !useSnapshot {
				slot, err := c.waitForSlotEvent(ctx, raw.CKF_DONT_BLOCK)
				switch {
				case err == nil:
					event := c.enrichSlotEvent(ctx, SlotEvent{Kind: SlotEventChanged, SlotID: slot}, config.Refresh)
					select {
					case out <- event:
					case <-ctx.Done():
						return
					}
					previous, _ = c.slotSnapshot(ctx)
					continue
				case raw.IsError(err, raw.CKR_NO_EVENT):
					// Wait for the poll interval below.
				case raw.IsError(err, raw.CKR_FUNCTION_NOT_SUPPORTED):
					// Do not probe the unsupported native function again on every tick.
					useSnapshot = true
				default:
					event := SlotEvent{Time: time.Now(), Kind: SlotEventError, Err: err, Error: err.Error()}
					select {
					case out <- event:
					case <-ctx.Done():
						return
					}
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			if useSnapshot {
				current, err := c.slotSnapshot(ctx)
				if err != nil {
					event := SlotEvent{Time: time.Now(), Kind: SlotEventError, Err: err, Error: err.Error()}
					select {
					case out <- event:
					case <-ctx.Done():
						return
					}
					continue
				}
				for _, event := range diffSnapshots(previous, current) {
					event = c.enrichSlotEvent(ctx, event, config.Refresh)
					select {
					case out <- event:
					case <-ctx.Done():
						return
					}
				}
				previous = current
			}
		}
	}()
	return out
}
