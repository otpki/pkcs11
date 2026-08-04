package pkcs11

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/otpki/pkcs11/raw"
)

// HealthStatus summarizes the result of a managed health check.
type HealthStatus string

const (
	// HealthHealthy means every requested check succeeded and the selected
	// device reported no discovery warnings.
	HealthHealthy HealthStatus = "healthy"
	// HealthDegraded means all requested checks succeeded, but discovery or
	// adapter diagnostics reported one or more non-fatal warnings.
	HealthDegraded HealthStatus = "degraded"
	// HealthUnhealthy means at least one requested check failed or the client
	// could not be inspected.
	HealthUnhealthy HealthStatus = "unhealthy"
)

// HealthOptions selects non-destructive checks to run against the token.
type HealthOptions struct {
	// CheckRandom asks the token RNG for RandomBytes bytes. It does not create,
	// mutate, or use a test key.
	CheckRandom bool
	// RandomBytes is the exact number of bytes requested when CheckRandom is
	// true. Values less than or equal to zero select the 32-byte default.
	RandomBytes int
	// ReadWrite makes the session check acquire the read/write pool instead of
	// the read-only pool. The RNG check remains read-only.
	ReadWrite bool
}

// HealthCheck records one named check and its duration or error.
type HealthCheck struct {
	// Name is the stable machine-readable check name.
	Name string `json:"name"`
	// Duration is wall-clock time spent in this individual check.
	Duration time.Duration `json:"duration"`
	// Err retains the original error for in-process callers and is omitted from
	// JSON because concrete error values are not generally serializable.
	Err error `json:"-"`
	// Error is Err.Error() for JSON, logs, and diagnostic transports.
	Error string `json:"error,omitempty"`
}

// PoolStats is a point-in-time view of one internal session pool.
type PoolStats struct {
	// Minimum is the configured warm-session target after normalization.
	Minimum int `json:"minimum"`
	// Maximum is the effective concurrency limit after token and adapter clamps.
	Maximum int `json:"maximum"`
	// Opened is the number of native session handles currently owned by the pool.
	Opened int `json:"opened"`
	// Active is the number of handles currently checked out to callers.
	Active int `json:"active"`
	// Idle is the number of reusable handles currently queued in the pool.
	Idle int `json:"idle"`
}

// HealthReport contains token, adapter, pool, and individual check results.
type HealthReport struct {
	// Status is derived after all requested checks complete.
	Status HealthStatus `json:"status"`
	// CheckedAt is the start time of the report, not the completion time.
	CheckedAt time.Time `json:"checked_at"`
	// Duration covers report setup and all individual checks.
	Duration time.Duration `json:"duration"`
	// ModulePath is the canonical native-library path owned by Client.
	ModulePath string `json:"module_path"`
	// Interface is the Cryptoki interface selected when the module was opened.
	Interface raw.InterfaceInfo `json:"interface"`
	// Device is an independent snapshot of the selected token and adapter.
	Device Device `json:"device"`
	// Generation identifies the module/session epoch observed by this check.
	Generation uint64 `json:"generation"`
	// ReadOnly and ReadWrite snapshot the two internal pools before checks run.
	ReadOnly  PoolStats `json:"read_only_pool"`
	ReadWrite PoolStats `json:"read_write_pool"`
	// Checks preserves execution order and includes both successes and failures.
	Checks []HealthCheck `json:"checks"`
	// Warnings contains non-fatal discovery and adapter diagnostics.
	Warnings []string `json:"warnings,omitempty"`
}

func (p *sessionPool) stats() PoolStats {
	if p == nil {
		return PoolStats{}
	}
	// opened and active are protected together because native-handle accounting
	// is updated under p.mu. len(idle) is safe for concurrent channel readers and
	// is intentionally only an approximate point-in-time value.
	p.mu.Lock()
	opened, active := p.opened, p.active
	p.mu.Unlock()
	return PoolStats{Minimum: p.min, Maximum: p.max, Opened: opened, Active: active, Idle: len(p.idle)}
}

func healthCheck(report *HealthReport, name string, fn func() error) error {
	start := time.Now()
	err := fn()
	// Preserve the concrete error for programmatic callers and a string form for
	// JSON. Keeping both avoids throwing away errors.Is/errors.As information.
	check := HealthCheck{Name: name, Duration: time.Since(start), Err: err}
	if err != nil {
		check.Error = err.Error()
	}
	report.Checks = append(report.Checks, check)
	return err
}

// Health performs non-destructive module, slot, token, mechanism, and session
// checks. It never requires a configured test key and does not create or mutate
// token objects. Optional RNG validation only requests bytes from C_GenerateRandom.
//
// Health runs all applicable checks and returns both a complete report and an
// errors.Join aggregation of failures. A non-nil error therefore does not imply
// that the report is incomplete. Adapter warnings produce HealthDegraded without
// producing an error; failed checks produce HealthUnhealthy.
func (c *Client) Health(ctx context.Context, options HealthOptions) (HealthReport, error) {
	start := time.Now()
	report := HealthReport{Status: HealthHealthy, CheckedAt: start}
	if c == nil || c.closed.Load() || c.module == nil {
		err := errors.New("pkcs11: client is closed")
		report.Status = HealthUnhealthy
		report.Checks = append(report.Checks, HealthCheck{Name: "client", Err: err, Error: err.Error()})
		return report, err
	}
	// Capture diagnostics before entering the module so the report still records
	// the selected device and pool state if a later native call fails.
	report.ModulePath = c.ModulePath()
	report.Interface = c.Interface()
	report.Device = c.Device()
	report.Generation = c.module.currentGeneration()
	report.ReadOnly = c.roPool.stats()
	report.ReadWrite = c.rwPool.stats()

	var errs []error
	if err := healthCheck(&report, "module-info", func() error {
		_, err := c.getInfo(ctx)
		return err
	}); err != nil {
		errs = append(errs, err)
	}
	device := report.Device
	if err := healthCheck(&report, "slot-info", func() error {
		_, err := c.getSlotInfo(ctx, device.Fingerprint.SlotID)
		return err
	}); err != nil {
		errs = append(errs, err)
	}
	if err := healthCheck(&report, "token-info", func() error {
		info, err := c.getTokenInfo(ctx, device.Fingerprint.SlotID)
		// A changed serial number means the slot now contains a different token,
		// even if the numeric slot ID remained stable.
		if err == nil && device.Fingerprint.Token.SerialNumber != "" && info.SerialNumber != device.Fingerprint.Token.SerialNumber {
			return fmt.Errorf("pkcs11: token serial changed from %q to %q", device.Fingerprint.Token.SerialNumber, info.SerialNumber)
		}
		return err
	}); err != nil {
		errs = append(errs, err)
	}
	if err := healthCheck(&report, "mechanism-list", func() error {
		mechanisms, err := c.getMechanismList(ctx, device.Fingerprint.SlotID)
		if err == nil && len(mechanisms) == 0 {
			return errors.New("pkcs11: token reports no mechanisms")
		}
		return err
	}); err != nil {
		errs = append(errs, err)
	}
	pool := c.roPool
	if options.ReadWrite {
		pool = c.rwPool
	}
	if err := healthCheck(&report, "session", func() error {
		session, err := pool.Acquire(ctx)
		if err != nil {
			return err
		}
		_, infoErr := session.GetSessionInfo()
		closeErr := session.Close()
		return errors.Join(infoErr, closeErr)
	}); err != nil {
		errs = append(errs, err)
	}
	if options.CheckRandom {
		length := options.RandomBytes
		if length <= 0 {
			length = 32
		}
		if err := healthCheck(&report, "random", func() error {
			return c.withSession(ctx, sessionOptions{ReadWrite: false, Idempotent: true, Operation: "health-random"}, func(session *sessionLease) error {
				value, err := session.GenerateRandom(length)
				if err == nil && len(value) != length {
					return fmt.Errorf("pkcs11: token returned %d random bytes, expected %d", len(value), length)
				}
				return err
			})
		}); err != nil {
			errs = append(errs, err)
		}
	}
	// Discovery warnings are intentionally weaker than failed live checks. They
	// describe incomplete metadata or compatibility concerns, not loss of service.
	report.Warnings = append(report.Warnings, report.Device.Warnings...)
	if len(errs) > 0 {
		report.Status = HealthUnhealthy
	} else if len(report.Warnings) > 0 {
		report.Status = HealthDegraded
	}
	report.Duration = time.Since(start)
	return report, errors.Join(errs...)
}
