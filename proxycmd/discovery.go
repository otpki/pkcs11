package proxycmd

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/proxy"
	"github.com/otpki/pkcs11/raw"
	"github.com/otpki/pkcs11/vendors/all"
)

// discoverySpec enables one route per initialized token reported by a module. The route set is
// refreshed at startup, before ListRoutes and on each /readyz probe. Overrides can change settings
// for selected discovered tokens.
type discoverySpec struct {
	// Module is the vendor library path or "test[:<name>[:<tokens>]]" scheme,
	// exactly as a target's module field.
	Module string `mapstructure:"module"`
	// NamePrefix namespaces this module's derived route IDs
	// ("<prefix><serial>"), separating its tokens from identically named
	// tokens on another discovery module. Override names are verbatim — the
	// prefix does not touch them.
	NamePrefix string `mapstructure:"name_prefix"`
	// Vendors allowlists bundled vendor modules by adapter ID or name;
	// empty enables all. Identical semantics to a target's vendors field.
	Vendors []string `mapstructure:"vendors"`
	// Overrides give individual tokens a fixed route name and patched
	// template fields; each must select exactly one token at startup.
	Overrides []discoveryOverride `mapstructure:"overrides"`
	// RefreshInterval bounds how often a refresh re-enumerates the module: a
	// refresh within the interval reuses the last result without touching the
	// HSM. Zero selects defaultRefreshInterval; a negative value enumerates on
	// every refresh.
	RefreshInterval time.Duration `mapstructure:"refresh_interval"`
}

const defaultRefreshInterval = 5 * time.Second

// discoveryOverride names one discovered token and patches its template.
// Exactly one of TokenSerial, TokenLabel, or SlotID selects the token.
type discoveryOverride struct {
	// Name is the public route ID the selected token publishes under.
	Name string `mapstructure:"name"`
	// TokenSerial selects by the token's trimmed serial number.
	TokenSerial string `mapstructure:"token_serial"`
	// TokenLabel selects by the token's trimmed label.
	TokenLabel string `mapstructure:"token_label"`
	// SlotID selects by physical slot ID — the only selector that separates
	// two tokens sharing a serial and label.
	SlotID *uint `mapstructure:"slot_id"`
	// Sessions patches the resolved sessions template for this route only.
	Sessions sessionPatch `mapstructure:"sessions"`
	// Activation patches the resolved activation template for this route only.
	Activation activationPatch `mapstructure:"activation"`
}

// sessionPatch is the sparse counterpart of sessionSpec: nil fields inherit
// the template. It exists because a struct of plain scalars cannot express
// "the operator did not set this field".
type sessionPatch struct {
	MaxPhysicalTotal            *int           `mapstructure:"max_physical_total"`
	MaxPhysicalReadWrite        *int           `mapstructure:"max_physical_read_write"`
	MaxPinned                   *int           `mapstructure:"max_pinned"`
	MaxQueued                   *int           `mapstructure:"max_queued"`
	MaxClients                  *int           `mapstructure:"max_clients"`
	MaxVirtualSessionsPerClient *int           `mapstructure:"max_virtual_sessions_per_client"`
	MaxObjectsPerClient         *int           `mapstructure:"max_objects_per_client"`
	QueueTimeout                *time.Duration `mapstructure:"queue_timeout"`
	ClientDrainIdleTimeout      *time.Duration `mapstructure:"client_drain_idle_timeout"`
}

func (p sessionPatch) apply(s sessionSpec) sessionSpec {
	if p.MaxPhysicalTotal != nil {
		s.MaxPhysicalTotal = *p.MaxPhysicalTotal
	}
	if p.MaxPhysicalReadWrite != nil {
		s.MaxPhysicalReadWrite = *p.MaxPhysicalReadWrite
	}
	if p.MaxPinned != nil {
		s.MaxPinned = *p.MaxPinned
	}
	if p.MaxQueued != nil {
		s.MaxQueued = *p.MaxQueued
	}
	if p.MaxClients != nil {
		s.MaxClients = *p.MaxClients
	}
	if p.MaxVirtualSessionsPerClient != nil {
		s.MaxVirtualSessionsPerClient = *p.MaxVirtualSessionsPerClient
	}
	if p.MaxObjectsPerClient != nil {
		s.MaxObjectsPerClient = *p.MaxObjectsPerClient
	}
	if p.QueueTimeout != nil {
		s.QueueTimeout = *p.QueueTimeout
	}
	if p.ClientDrainIdleTimeout != nil {
		s.ClientDrainIdleTimeout = *p.ClientDrainIdleTimeout
	}
	return s
}

// activationPatch is the sparse counterpart of activationSpec.
type activationPatch struct {
	FailureCooldown     *time.Duration `mapstructure:"failure_cooldown"`
	PINRotationInterval *time.Duration `mapstructure:"pin_rotation_interval"`
}

func (p activationPatch) apply(a activationSpec) activationSpec {
	if p.FailureCooldown != nil {
		a.FailureCooldown = *p.FailureCooldown
	}
	if p.PINRotationInterval != nil {
		a.PINRotationInterval = *p.PINRotationInterval
	}
	return a
}

// selectorFields reports which selectors the override sets, for validation.
func (o discoveryOverride) selectorFields() []string {
	var fields []string
	if strings.TrimSpace(o.TokenSerial) != "" {
		fields = append(fields, "token_serial")
	}
	if strings.TrimSpace(o.TokenLabel) != "" {
		fields = append(fields, "token_label")
	}
	if o.SlotID != nil {
		fields = append(fields, "slot_id")
	}
	return fields
}

// validate checks the override is well formed: a route name plus exactly one
// token selector.
func (o discoveryOverride) validate(index int) error {
	what := fmt.Sprintf("discovery.overrides[%d]", index)
	if o.Name != "" {
		what = fmt.Sprintf("discovery override %q", o.Name)
	}
	if strings.TrimSpace(o.Name) == "" {
		return fmt.Errorf("%s: name is required", what)
	}
	switch fields := o.selectorFields(); len(fields) {
	case 0:
		return fmt.Errorf("%s: one of token_serial, token_label, or slot_id is required", what)
	case 1:
	default:
		return fmt.Errorf("%s: selectors are exclusive, got %s", what, strings.Join(fields, ", "))
	}
	return nil
}

// matches reports whether the override's selector names this token.
func (o discoveryOverride) matches(summary pkcs11.TokenSummary) bool {
	switch {
	case o.SlotID != nil:
		return summary.SlotID == raw.SlotID(*o.SlotID)
	case strings.TrimSpace(o.TokenSerial) != "":
		return strings.TrimSpace(summary.Token.SerialNumber) == strings.TrimSpace(o.TokenSerial)
	default:
		return strings.TrimSpace(summary.Token.Label) == strings.TrimSpace(o.TokenLabel)
	}
}

// selector builds the token binding the route's target will hold.
func (o discoveryOverride) selector() pkcs11.TokenSelector {
	switch {
	case o.SlotID != nil:
		slot := raw.SlotID(*o.SlotID)
		return pkcs11.TokenSelector{SlotID: &slot}
	case strings.TrimSpace(o.TokenSerial) != "":
		return pkcs11.TokenSelector{SerialNumber: strings.TrimSpace(o.TokenSerial)}
	default:
		return pkcs11.TokenSelector{Label: strings.TrimSpace(o.TokenLabel)}
	}
}

// desiredRoute is one route the module should currently publish.
type desiredRoute struct {
	id         string
	slot       raw.SlotID // diagnostics only; identity lives in selector/binding
	selector   pkcs11.TokenSelector
	sessions   sessionSpec
	activation activationSpec
	revision   string
	binding    string // slotBinding of the route's token
}

func (r desiredRoute) record() publishedRoute {
	return publishedRoute{binding: r.binding, revision: r.revision}
}

// publishedRoute is the reconciler's record of a live route. A desired route
// with a different record is rebuilt, so clients observe a new epoch.
type publishedRoute struct {
	binding  string
	revision string
}

// reconcileCall is the singleflight record: one in-flight enumeration whose
// result every concurrent caller shares.
type reconcileCall struct {
	done chan struct{}
	err  error
}

func (c *reconcileCall) wait(ctx context.Context) error {
	select {
	case <-c.done:
		return c.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// discoverer reconciles the published route set with the tokens the module
// reports. One reconciliation runs at a time; concurrent callers wait for
// it and share its result.
type discoverer struct {
	moduleSpec string
	source     pkcs11.ModuleSource
	namePrefix string
	vendorIDs  []string // sorted canonical IDs baked into route revisions
	vendors    []pkcs11.VendorModule
	sessions   sessionSpec
	activation activationSpec
	findTTL    time.Duration
	overrides  []discoveryOverride

	// server is set by attach before the server starts serving; reconcile is
	// only reachable through the server's BeforeListRoutes hook or explicit
	// startup reconciliation after attach.
	server *proxy.Server

	mu       sync.Mutex
	inflight *reconcileCall
	// lastRun/lastErr cache the completed reconciliation for refreshInterval,
	// so steady refreshes serve the catalog without re-enumerating the module.
	lastRun time.Time
	lastErr error
	// refreshInterval is the max-age window for lastRun; negative disables
	// caching so every refresh reconciles.
	refreshInterval time.Duration
	// published is only touched by the goroutine running reconcileOnce: the
	// singleflight above guarantees there is at most one.
	published map[string]publishedRoute
}

// newDiscoverer builds the reconciler. cfg supplies the template sessions
// and activation policy; spec supplies module, vendors, and overrides.
func newDiscoverer(spec *discoverySpec, source pkcs11.ModuleSource, vendors []pkcs11.VendorModule, sessions sessionSpec, activation activationSpec, findTTL time.Duration) (*discoverer, error) {
	names := make(map[string]bool, len(spec.Overrides))
	for i, override := range spec.Overrides {
		if err := override.validate(i); err != nil {
			return nil, err
		}
		name := strings.TrimSpace(override.Name)
		if names[name] {
			return nil, fmt.Errorf("discovery override %q: name is already claimed by another override", name)
		}
		names[name] = true
	}
	refreshInterval := spec.RefreshInterval
	if refreshInterval == 0 {
		refreshInterval = defaultRefreshInterval
	}
	d := &discoverer{
		moduleSpec:      spec.Module,
		source:          source,
		namePrefix:      strings.TrimSpace(spec.NamePrefix),
		vendors:         vendors,
		sessions:        sessions,
		activation:      activation,
		findTTL:         findTTL,
		overrides:       spec.Overrides,
		refreshInterval: refreshInterval,
		published:       make(map[string]publishedRoute),
	}
	for _, vendor := range vendors {
		d.vendorIDs = append(d.vendorIDs, string(vendor.Definition().ID))
	}
	slices.Sort(d.vendorIDs)
	return d, nil
}

func (d *discoverer) attach(server *proxy.Server) { d.server = server }

// reconcile is the BeforeListRoutes hook, and concurrent callers share one
// enumeration. Each caller stops waiting when its ctx ends.
func (d *discoverer) reconcile(ctx context.Context) error {
	d.mu.Lock()
	if call := d.inflight; call != nil {
		d.mu.Unlock()
		return call.wait(ctx)
	}
	if d.lastResultFreshLocked() {
		err := d.lastErr
		d.mu.Unlock()
		return err
	}
	call := &reconcileCall{done: make(chan struct{})}
	d.inflight = call
	d.mu.Unlock()
	// The enumeration runs detached from every caller. A module hung in a
	// native call then holds one goroutine, and each caller answers by its own deadline.
	go d.settle(context.WithoutCancel(ctx), call)
	return call.wait(ctx)
}

// lastResultFreshLocked lets a refresh reuse lastErr, since token churn is rare
// and enumeration can cost hundreds of milliseconds per slot probe.
func (d *discoverer) lastResultFreshLocked() bool {
	cachingEnabled := d.refreshInterval >= 0
	ranOnce := !d.lastRun.IsZero()
	return cachingEnabled && ranOnce && time.Since(d.lastRun) < d.refreshInterval
}

// settle runs reconcileOnce, caches its result for refreshInterval and
// releases the call's waiters.
func (d *discoverer) settle(ctx context.Context, call *reconcileCall) {
	call.err = d.reconcileOnce(ctx, false)
	d.mu.Lock()
	d.inflight = nil
	d.lastRun = time.Now()
	d.lastErr = call.err
	d.mu.Unlock()
	close(call.done)
}

// reconcileStartup performs the first reconciliation with the additional
// strictness startup warrants: every override must resolve to exactly one of
// the enumerated tokens, and a whole-enumeration failure aborts startup.
func (d *discoverer) reconcileStartup(ctx context.Context) error {
	return d.reconcileOnce(ctx, true)
}

// reconcileOnce enumerates tokens, publishes new routes before retiring
// vanished ones, and leaves the catalog answering the latest known set.
func (d *discoverer) reconcileOnce(ctx context.Context, startup bool) error {
	server := d.server
	if server == nil {
		return errors.New("discovery reconciler is not attached to a server")
	}
	summaries, err := pkcs11.ListTokens(ctx, d.source)
	if err != nil {
		// The caller keeps serving the last published catalog; make the
		// failure visible on the binary's log pipeline even when no OTel
		// collector receives the proxy's warning record.
		slog.Warn("token enumeration failed; serving last published routes",
			"module", d.moduleSpec, "error", err)
		return fmt.Errorf("enumerate tokens on %s: %w", d.moduleSpec, err)
	}
	summaries = d.withoutUninitialized(summaries)
	if startup {
		if err := d.validateOverrideMatches(summaries); err != nil {
			return err
		}
	}
	desired := d.plan(summaries)

	published := maps.Clone(d.published)
	// Publish first: a listing during reconciliation sees new IDs before
	// vanished ones disappear. A rebuilt ID is absent between its retire and
	// its AddTarget.
	for id, want := range desired {
		current, ok := published[id]
		if ok && current == want.record() {
			continue
		}
		if ok {
			d.retire(server, id) //nolint:contextcheck // The drain runs on the server's work context.
		}
		config := d.targetConfig(want)
		if err := server.AddTarget(ctx, config); err != nil {
			// e.g. ErrClientActivationUnsupported on a per-session-login
			// module: skip the token but keep reconciling the rest.
			slog.Warn("discovered token skipped: route activation failed",
				"route", id, "module", d.moduleSpec, "slot", want.slot, "error", err)
			continue
		}
		d.published[id] = want.record()
	}
	for id := range published {
		if _, ok := desired[id]; !ok {
			d.retire(server, id) //nolint:contextcheck // The drain runs on the server's work context.
		}
	}
	return nil
}

// retire unpublishes id and logs the outcome of its background drain.
func (d *discoverer) retire(server *proxy.Server, id string) {
	done := server.RetireTarget(id)
	delete(d.published, id)
	slog.Info("route retired", "route", id, "module", d.moduleSpec)
	go func() {
		if err := <-done; err != nil {
			slog.Warn("retired route drain failed", "route", id, "module", d.moduleSpec, "error", err)
		}
	}()
}

// withoutUninitialized drops, in place, the tokens awaiting C_InitToken, such as
// SoftHSM's free slot, since login needs an initialized token.
func (d *discoverer) withoutUninitialized(summaries []pkcs11.TokenSummary) []pkcs11.TokenSummary {
	return slices.DeleteFunc(summaries, func(summary pkcs11.TokenSummary) bool {
		if !uninitialized(summary) {
			return false
		}
		slog.Debug("uninitialized token skipped", "module", d.moduleSpec, "slot", summary.SlotID)
		return true
	})
}

// uninitialized reports a readable token that awaits C_InitToken.
func uninitialized(summary pkcs11.TokenSummary) bool {
	return summary.Err == nil && summary.Token.Flags&raw.CKF_TOKEN_INITIALIZED == 0
}

// initialized reports a readable token that C_InitToken has set up.
func initialized(summary pkcs11.TokenSummary) bool {
	return summary.Err == nil && summary.Token.Flags&raw.CKF_TOKEN_INITIALIZED != 0
}

// validateOverrideMatches enforces the startup contract: every override must
// select exactly one readable, initialized token.
func (d *discoverer) validateOverrideMatches(summaries []pkcs11.TokenSummary) error {
	for i := range d.overrides {
		override := &d.overrides[i]
		matched := 0
		for _, summary := range summaries {
			if initialized(summary) && override.matches(summary) {
				matched++
			}
		}
		if matched != 1 {
			return fmt.Errorf("discovery override %q matches %d tokens: it must select exactly one of the initialized tokens reported by %s",
				override.Name, matched, d.moduleSpec)
		}
	}
	return nil
}

// plan computes the desired route set from the enumeration. Tokens whose
// metadata could not be read are skipped with a warning; tokens resolving to
// a route ID already claimed by another token in the same listing are all
// skipped until an override separates them.
func (d *discoverer) plan(summaries []pkcs11.TokenSummary) map[string]desiredRoute {
	// Serial or label values shared by several tokens make a selector based
	// on that field alone ambiguous; those selectors get the observed slot
	// pinned so a token an override separated out of an ID collision stays
	// individually addressable.
	serials := make(map[string]int)
	labels := make(map[string]int)
	for _, summary := range summaries {
		if summary.Err != nil {
			continue
		}
		serials[strings.TrimSpace(summary.Token.SerialNumber)]++
		labels[strings.TrimSpace(summary.Token.Label)]++
	}
	shared := func(_ pkcs11.TokenSummary, selector pkcs11.TokenSelector) bool {
		switch {
		case selector.SlotID != nil:
			return false
		case selector.SerialNumber != "":
			return serials[selector.SerialNumber] > 1
		default:
			return labels[selector.Label] > 1
		}
	}

	byID := make(map[string][]desiredRoute)
	for _, summary := range summaries {
		if summary.Err != nil {
			slog.Warn("token slot unreadable; skipped",
				"module", d.moduleSpec, "slot", summary.SlotID, "error", summary.Err)
			continue
		}
		route := d.routeFor(summary)
		if route.id == "" {
			slog.Warn("token has no usable route identity; skipped",
				"module", d.moduleSpec, "slot", summary.SlotID)
			continue
		}
		if shared(summary, route.selector) {
			slot := summary.SlotID
			route.selector.SlotID = &slot
			route.revision = d.revision(route)
		}
		byID[route.id] = append(byID[route.id], route)
	}
	desired := make(map[string]desiredRoute, len(byID))
	for id, group := range byID {
		if len(group) > 1 {
			slots := make([]raw.SlotID, 0, len(group))
			for _, route := range group {
				slots = append(slots, route.slot)
			}
			slog.Warn("tokens resolve to the same route; all skipped until an override separates them",
				"route", id, "module", d.moduleSpec, "slots", slots)
			continue
		}
		desired[id] = group[0]
	}
	return desired
}

// routeFor resolves one token summary into a desired route: override name or
// derived ID, selector, patched template, and derived revision.
func (d *discoverer) routeFor(summary pkcs11.TokenSummary) desiredRoute {
	serial := strings.TrimSpace(summary.Token.SerialNumber)
	label := strings.TrimSpace(summary.Token.Label)
	route := desiredRoute{
		slot:       summary.SlotID,
		sessions:   d.sessions,
		activation: d.activation,
	}
	for i := range d.overrides {
		override := &d.overrides[i]
		if !override.matches(summary) {
			continue
		}
		route.id = strings.TrimSpace(override.Name)
		route.selector = override.selector()
		route.sessions = override.Sessions.apply(route.sessions)
		route.activation = override.Activation.apply(route.activation)
		break
	}
	if route.id == "" {
		switch {
		case serial != "":
			route.id = d.namePrefix + serial
			route.selector = pkcs11.TokenSelector{SerialNumber: serial}
		case label != "":
			route.id = d.namePrefix + label
			route.selector = pkcs11.TokenSelector{Label: label}
		default:
			return route
		}
	}
	route.binding = slotBinding(summary)
	route.revision = d.revision(route)
	return route
}

// slotBinding identifies a token by its slot as well as serial and label.
func slotBinding(summary pkcs11.TokenSummary) string {
	return fmt.Sprintf("slot=%d\x00sn=%s\x00lb=%s", summary.SlotID,
		strings.TrimSpace(summary.Token.SerialNumber), strings.TrimSpace(summary.Token.Label))
}

// revision derives a short stable digest from everything that defines the
// route: its ID and selector, the canonical module identity, the vendor
// allowlist, and the resolved template. Identical configuration produces the
// same revision across restarts; any change shifts it.
func (d *discoverer) revision(route desiredRoute) string {
	hash := sha256.New()
	_, _ = fmt.Fprintf(hash, "route=%s\n", route.id)
	_, _ = fmt.Fprintf(hash, "selector=%s\n", selectorKey(route.selector))
	_, _ = fmt.Fprintf(hash, "module=%s\n", d.source.RegistryKey())
	for _, id := range d.vendorIDs {
		_, _ = fmt.Fprintf(hash, "vendor=%s\n", id)
	}
	_, _ = fmt.Fprintf(hash, "sessions=%+v\n", route.sessions)
	_, _ = fmt.Fprintf(hash, "activation=%+v\n", route.activation)
	sum := hash.Sum(nil)
	return "d" + hex.EncodeToString(sum[:8])
}

// selectorKey renders a token selector canonically for revision hashing.
func selectorKey(selector pkcs11.TokenSelector) string {
	key := fmt.Sprintf("label=%q serial=%q", selector.Label, selector.SerialNumber)
	if selector.SlotID != nil {
		key += fmt.Sprintf(" slot=%d", *selector.SlotID)
	}
	return key
}

// targetConfig builds the proxy target for one discovered route: identical
// policy to a targets[] route — client-activated login, per-route PIN
// verification — with the discovery-derived ID and revision.
func (d *discoverer) targetConfig(route desiredRoute) proxy.TargetConfig {
	return proxy.TargetConfig{
		ID:       route.id,
		Revision: route.revision,
		Client: pkcs11.Config{
			Module:  d.source,
			Token:   route.selector,
			Vendors: d.vendors,
		},
		Sessions:     route.sessions.budget(),
		FindCacheTTL: d.findTTL,
		Login:        route.activation.loginPolicy(),
	}
}

// reconcilerSet fans the BeforeListRoutes hook out to each configured
// module's discoverer. A failing module keeps its last
// published routes, and the hook returns the joined errors.
type reconcilerSet []*discoverer

func (set reconcilerSet) reconcile(ctx context.Context) error {
	errs := make([]error, len(set))
	var wg sync.WaitGroup
	for i, d := range set {
		wg.Go(func() { errs[i] = d.reconcile(ctx) })
	}
	wg.Wait()
	return errors.Join(errs...)
}

// newDiscoveryServer builds the discovery-mode broker: one reconciler per
// discovery[] entry wired into the server's BeforeListRoutes hook, then a
// strict startup reconciliation per module that validates overrides and
// seeds routes.
func (cfg options) newDiscoveryServer(ctx context.Context, listener net.Listener, tlsConfig *tls.Config, audit proxy.AuditSink) (*proxy.Server, error) {
	if len(cfg.Targets) > 0 {
		return nil, errors.New("discovery and targets[] are mutually exclusive: configure one or the other")
	}
	modules := cfg.bundledVendors
	if modules == nil {
		modules = all.Modules()
	}
	reconcilers := make(reconcilerSet, 0, len(cfg.Discovery))
	claimed := make(map[string]int, len(cfg.Discovery))
	for i := range cfg.Discovery {
		spec := &cfg.Discovery[i]
		where := fmt.Sprintf("discovery[%d]", i)
		if strings.TrimSpace(spec.Module) == "" {
			return nil, fmt.Errorf("%s: module is required", where)
		}
		source, err := targetModuleSource(spec.Module)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", where, err)
		}
		vendors, err := selectVendorModules(modules, spec.Vendors)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", where, err)
		}
		// Two entries over one module would publish the same tokens under
		// colliding route IDs; name a prefix and one module per entry instead.
		key := source.RegistryKey()
		if first, ok := claimed[key]; ok {
			return nil, fmt.Errorf("%s: module %q is already enumerated by discovery[%d]", where, spec.Module, first)
		}
		claimed[key] = i
		d, err := newDiscoverer(spec, source, vendors, cfg.Sessions, cfg.Activation, cfg.FindCache.TTL)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", where, err)
		}
		reconcilers = append(reconcilers, d)
	}
	serverConfig := cfg.serverConfig(listener, tlsConfig, audit)
	serverConfig.BeforeListRoutes = reconcilers.reconcile
	server, err := proxy.NewServer(ctx, serverConfig)
	if err != nil {
		return nil, err
	}
	for i, d := range reconcilers {
		d.attach(server)
		if err := d.reconcileStartup(ctx); err != nil {
			_ = server.Close(ctx)
			return nil, fmt.Errorf("discovery[%d]: %w", i, err)
		}
	}
	slog.Info("token discovery active", "modules", len(reconcilers), "routes", server.TargetIDs())
	return server, nil
}
