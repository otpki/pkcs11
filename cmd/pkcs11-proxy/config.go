package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/internal/auditlog"
	"github.com/otpki/pkcs11/internal/obslog"
	"github.com/otpki/pkcs11/proxy"
	"github.com/otpki/pkcs11/raw"
	"github.com/otpki/pkcs11/vendors/all"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const (
	environmentPrefix = "PKCS11_PROXY"
	configBaseName    = "pkcs11-proxy"

	// targetRouteID is the route name used when a target entry leaves its name
	// empty — a single-route broker is reachable as Route "hsm" exactly as
	// before. targetRevision is fixed for every route: revisions exist for
	// brokers that hot-swap targets via Server.ReplaceTarget, which this
	// binary never does, and the random per-process epoch already invalidates
	// clients across restarts. Clients use Revision "v1" on every route.
	targetRouteID  = "hsm"
	targetRevision = "v1"
)

// targetSpec is one published route: a public name plus the module and token
// the route binds to. Repeating one module with different token selectors
// publishes several tokens on the same HSM; listing different modules fronts
// multiple HSMs behind one broker.
type targetSpec struct {
	// Name is the public route name clients pass as proxy.Target.Route. An
	// empty name defaults to "hsm"; names must be unique across the list.
	Name string `mapstructure:"name"`
	// Module is the path to the vendor's local PKCS #11 shared library. The
	// "test[:<name>[:<tokens>]]" scheme instead binds the route to the
	// in-memory test module for development; --test builds a whole test
	// topology without a config file.
	Module string `mapstructure:"module"`
	// TokenLabel selects which token inside the module this route binds to;
	// empty picks the first reported. TokenSerial and SlotID are optional
	// additional selectors when a module reports several tokens.
	TokenLabel  string `mapstructure:"token_label"`
	TokenSerial string `mapstructure:"token_serial"`
	SlotID      *uint  `mapstructure:"slot_id"`
	// Vendors allowlists bundled vendor modules by adapter ID or name;
	// empty enables all. Clients must configure the same set — the
	// describe handshake requires exact parameter-codec parity.
	Vendors []string `mapstructure:"vendors"`
}

// configKey registers one scalar option across every configuration surface
// with a single identifier: the YAML key, the flag spelled identically
// (--audit.path), and the PKCS11_PROXY_* environment variable
// (PKCS11_PROXY_AUDIT_PATH). The table below is the single source of truth —
// flag registration, viper defaults, and --help text all derive from it, so
// the three surfaces can never drift apart. targets[] is the only exception:
// a list of route structs is expressible in YAML only.
type configKey struct {
	key   string
	def   any
	usage string
}

var configKeys = []configKey{
	{"listen", "127.0.0.1:9443", "broker listen address clients dial (proxy.Target.Endpoints)"},
	{"drain_timeout", 5 * time.Minute, "graceful scale-down: how long existing clients have after SIGTERM"},
	{"insecure", false, "permit plaintext TCP when no TLS certificate is configured (development)"},
	{"test", false, "serve synthetic in-memory test routes (PIN \"1234\"); replaces targets[]"},

	{"tls.cert_file", "", "PEM server certificate; with key_file enables TLS"},
	{"tls.key_file", "", "PEM server private key; with cert_file enables TLS"},
	{"tls.client_ca_file", "", "PEM CA that additionally requires client certificates (mTLS)"},

	{"sessions.max_physical_total", 8, "cap on native HSM sessions per route (control + pool + in-flight + pinned)"},
	{"sessions.max_physical_read_write", 4, "cap on physical sessions opened read/write"},
	{"sessions.max_pinned", 2, "cap on physical leases held across network calls"},
	{"sessions.max_queued", 64, "cap on requests waiting for physical capacity; full queue fails fast"},
	{"sessions.max_clients", 256, "cap on concurrently retained logical clients"},
	{"sessions.max_virtual_sessions_per_client", 16, "cap on virtual sessions per client (no physical session until used)"},
	{"sessions.max_objects_per_client", 1024, "cap on virtual object handles per client"},
	{"sessions.queue_timeout", 5 * time.Second, "max wait for physical capacity before a request fails busy"},

	{"activation.failure_cooldown", time.Second, "PIN-guessing cooldown after a failed activation"},

	{"dev_ui.enabled", false, "serve the read-only dev dashboard"},
	{"dev_ui.listen", "127.0.0.1:9463", "dev dashboard bind address"},
	{"dev_ui.allow_remote", false, "permit non-loopback dashboard clients (the dashboard is secret-free but loopback is the default)"},

	{"verifier.wait_poll_interval", 25 * time.Millisecond, "re-check interval for clients gated on an in-flight activation"},
	{"verifier.wait_timeout", 30 * time.Second, "bound on follower wait and stalled-leader contention"},

	{"logging.level", "info", "minimum slog level: debug, info, warn, or error"},
	{"logging.format", "text", "log format: text or json"},
	{"logging.queue_size", obslog.DefaultQueueSize, "buffered log records; overflow is dropped and counted"},

	{"audit.path", "", "JSONL audit log, appended across restarts (empty disables audit)"},
	{"audit.key_file", "", "Ed25519 audit signing key (default <path>.key; <key>.pub is written for verifiers)"},
	{"audit.queue_size", auditlog.DefaultQueueSize, "buffered audit events; overflow drops with an audit_gap record"},
	{"audit.batch_size", auditlog.DefaultBatchSize, "records sealed by one signed Merkle checkpoint"},
	{"audit.checkpoint_interval", auditlog.DefaultCheckpointInterval, "max time records sit unsealed at low volume"},

	{"otel.endpoint", "", "OTLP/HTTP collector host:port or URL (empty disables export)"},
	{"otel.insecure", false, "plaintext OTLP transport"},
	{"otel.service_name", "pkcs11-proxy", "OTel resource service.name attribute"},
	{"otel.metric_interval", 15 * time.Second, "periodic metric export cadence"},
}

// registerServeFlags registers one flag per config key — the flag name IS the
// config key — plus --config. Binding the whole flagset into viper then makes
// every key resolve flag > env > YAML > default with no per-key plumbing.
func registerServeFlags(flags *pflag.FlagSet) {
	flags.String("config", "", "YAML config file (default ./pkcs11-proxy.yaml; env PKCS11_PROXY_CONFIG)")
	for _, k := range configKeys {
		switch def := k.def.(type) {
		case string:
			flags.String(k.key, def, k.usage)
		case bool:
			flags.Bool(k.key, def, k.usage)
		case int:
			flags.Int(k.key, def, k.usage)
		case time.Duration:
			flags.Duration(k.key, def, k.usage)
		default:
			panic(fmt.Sprintf("configKeys[%q]: unsupported default type %T", k.key, k.def))
		}
	}
}

// options is the complete operator-facing configuration surface. Every scalar
// key is settable identically through the YAML file, a flag spelled like the
// key, or a PKCS11_PROXY_* environment variable; the targets list is YAML-only.
// No option carries the HSM PIN — activating clients supply it with their
// login and only its digest is retained in memory.
type options struct {
	// Listen is the client-facing address of the broker (clients set it as
	// entries of proxy.Target.Endpoints).
	Listen string `mapstructure:"listen"`
	// DrainTimeout bounds graceful scale-down: after the shutdown signal the
	// broker stops accepting new logical clients and waits this long for
	// existing ones to close before forcing them off with ErrTargetLost.
	DrainTimeout time.Duration `mapstructure:"drain_timeout"`
	// Insecure permits plaintext TCP. It only removes transport encryption —
	// workload tokens and PIN verification still apply — and is rejected
	// unless TLS is also unconfigured.
	Insecure bool `mapstructure:"insecure"`
	// Test swaps the configured targets for the synthetic in-memory module
	// routes; equivalent to the --test flag and resolvable through the same
	// viper chain.
	Test bool `mapstructure:"test"`
	TLS  struct {
		// CertFile and KeyFile are the PEM server certificate pair; both must
		// be set together or neither.
		CertFile string `mapstructure:"cert_file"`
		KeyFile  string `mapstructure:"key_file"`
		// ClientCAFile additionally requires clients to present a certificate
		// signed by this CA (mutual TLS); the certificate then doubles as the
		// workload identity.
		ClientCAFile string `mapstructure:"client_ca_file"`
	} `mapstructure:"tls"`
	// Targets lists the published routes: each entry is one route bound to
	// one token, so multiple entries over the same or different modules
	// publish multiple tokens.
	Targets []targetSpec `mapstructure:"targets"`
	// Sessions bounds the physical-resource pool; see proxy.SessionBudget for
	// the authoritative semantics of each field.
	Sessions struct {
		// MaxPhysicalTotal caps native HSM sessions for the target, including
		// the reserved control session, idle pool, in-flight calls, and pins.
		MaxPhysicalTotal int `mapstructure:"max_physical_total"`
		// MaxPhysicalReadWrite caps the subset of the pool opened read/write.
		MaxPhysicalReadWrite int `mapstructure:"max_physical_read_write"`
		// MaxPinned caps physical leases held across network calls by
		// multipart operations and session-object affinity.
		MaxPinned int `mapstructure:"max_pinned"`
		// MaxQueued caps requests waiting for physical capacity; a full queue
		// fails fast instead of accumulating goroutines.
		MaxQueued int `mapstructure:"max_queued"`
		// MaxClients caps concurrently retained logical clients.
		MaxClients int `mapstructure:"max_clients"`
		// MaxVirtualSessionsPerClient caps cheap virtual sessions per client;
		// they consume no physical session until real work is admitted.
		MaxVirtualSessionsPerClient int `mapstructure:"max_virtual_sessions_per_client"`
		// MaxObjectsPerClient caps virtual object-handle mappings per client.
		MaxObjectsPerClient int `mapstructure:"max_objects_per_client"`
		// QueueTimeout bounds how long an admitted request waits for physical
		// capacity before failing busy.
		QueueTimeout time.Duration `mapstructure:"queue_timeout"`
	} `mapstructure:"sessions"`
	Activation struct {
		// FailureCooldown rejects further activation attempts for this long
		// after a wrong-PIN failure, so racing clients cannot become a PIN
		// guessing loop that locks the token.
		FailureCooldown time.Duration `mapstructure:"failure_cooldown"`
	} `mapstructure:"activation"`
	// DevUI is the read-only development dashboard; it serves secret-free
	// broker counters only and must stay on loopback unless AllowRemote.
	DevUI struct {
		Enabled     bool   `mapstructure:"enabled"`
		Listen      string `mapstructure:"listen"`
		AllowRemote bool   `mapstructure:"allow_remote"`
	} `mapstructure:"dev_ui"`
	// Verifier tunes how clients arriving during another client's in-flight
	// activation wait for it to resolve.
	Verifier struct {
		// WaitPollInterval is the re-check interval for gated followers.
		WaitPollInterval time.Duration `mapstructure:"wait_poll_interval"`
		// WaitTimeout bounds the follower wait and how long a stalled
		// candidate may hold leadership before others may contend.
		WaitTimeout time.Duration `mapstructure:"wait_timeout"`
	} `mapstructure:"verifier"`
	// Logging controls application logging to stderr through a bounded,
	// non-blocking queue: a saturated downstream can never stall requests.
	Logging struct {
		// Level is the minimum slog level: debug, info, warn, or error.
		Level string `mapstructure:"level"`
		// Format is text or json.
		Format string `mapstructure:"format"`
		// QueueSize bounds buffered records; overflow is dropped and counted.
		QueueSize int `mapstructure:"queue_size"`
	} `mapstructure:"logging"`
	// Audit configures the signed append-only audit log. Disabled while Path
	// is empty; when enabled, security events are JSON leaf lines sealed in
	// batches by signed Merkle checkpoints — one signature attests a batch.
	Audit struct {
		// Path is the JSONL audit file, appended across restarts.
		Path string `mapstructure:"path"`
		// KeyFile is the Ed25519 seed file (created 0600 if missing);
		// defaults to <path>.key, with <key>.pub written for verifiers.
		KeyFile string `mapstructure:"key_file"`
		// QueueSize bounds events buffered for the writer; overflow is
		// dropped, counted, and marked by an audit_gap record.
		QueueSize int `mapstructure:"queue_size"`
		// BatchSize is the number of records sealed by one checkpoint.
		BatchSize int `mapstructure:"batch_size"`
		// CheckpointInterval seals pending records on a timer so low-volume
		// periods never leave events unsealed for long.
		CheckpointInterval time.Duration `mapstructure:"checkpoint_interval"`
	} `mapstructure:"audit"`
	// OTel exports traces, metrics, and log records to an OTLP/HTTP
	// collector. Empty Endpoint leaves the proxy's global no-op providers
	// installed and disables export.
	OTel struct {
		// Endpoint is host:port of an OTLP/HTTP collector; an http:// or
		// https:// scheme overrides Insecure.
		Endpoint string `mapstructure:"endpoint"`
		// Insecure switches the exporter to plaintext HTTP.
		Insecure bool `mapstructure:"insecure"`
		// ServiceName is the OTel resource service.name attribute.
		ServiceName string `mapstructure:"service_name"`
		// MetricInterval is the periodic metric export cadence.
		MetricInterval time.Duration `mapstructure:"metric_interval"`
	} `mapstructure:"otel"`
}

// newConfigViper builds the shared viper environment every command resolves
// through: the PKCS11_PROXY_ prefix, the key replacer, and AutomaticEnv.
func newConfigViper() *viper.Viper {
	v := viper.New()
	v.SetEnvPrefix(environmentPrefix)
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	v.AutomaticEnv()
	return v
}

// loadOptions resolves the full serve configuration through viper: flags on
// the command's flagset bind over PKCS11_PROXY_* env vars over the YAML file
// over the configKeys defaults. A nil flagset (tests) skips flag binding.
func loadOptions(flags *pflag.FlagSet) (options, error) {
	v := newConfigViper()
	if flags != nil {
		if err := v.BindPFlags(flags); err != nil {
			return options{}, err
		}
	}

	// Defaults also register every key so AutomaticEnv can resolve the
	// corresponding PKCS11_PROXY_* variable during Unmarshal.
	for _, k := range configKeys {
		v.SetDefault(k.key, k.def)
	}
	v.SetDefault("config", "")
	v.SetDefault("targets", []targetSpec{})

	configFile := v.GetString("config")
	if configFile != "" {
		v.SetConfigFile(configFile)
	} else {
		// Look for ./pkcs11-proxy.yaml by exact path: viper's name search would
		// otherwise also try the pkcs11-proxy binary itself as a config file.
		v.SetConfigFile("./" + configBaseName + ".yaml")
	}
	// The default file is optional; environment and flags still apply.
	if err := v.ReadInConfig(); err != nil && (configFile != "" || !os.IsNotExist(err)) {
		return options{}, err
	}

	var cfg options
	if err := v.Unmarshal(&cfg); err != nil {
		return options{}, fmt.Errorf("decode %s config: %w", environmentPrefix, err)
	}
	return cfg, nil
}

// serverTLS builds the transport configuration. TLS requires an explicit
// certificate pair; client_ca_file additionally requires verified client
// certificates. With no certificate pair the operator must opt into plaintext
// explicitly with insecure: true.
func (cfg options) serverTLS() (*tls.Config, error) {
	if cfg.TLS.CertFile == "" && cfg.TLS.KeyFile == "" {
		if !cfg.Insecure {
			return nil, errors.New("no TLS certificate configured; set tls.cert_file/tls.key_file or insecure: true for development")
		}
		return nil, nil
	}
	if cfg.TLS.CertFile == "" || cfg.TLS.KeyFile == "" {
		return nil, errors.New("tls.cert_file and tls.key_file must be configured together")
	}
	certificate, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load server TLS key pair: %w", err)
	}
	config := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}
	if cfg.TLS.ClientCAFile != "" {
		pem, err := os.ReadFile(cfg.TLS.ClientCAFile)
		if err != nil {
			return nil, fmt.Errorf("read client CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("client CA file %q contains no PEM certificates", cfg.TLS.ClientCAFile)
		}
		config.ClientCAs = pool
		config.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return config, nil
}

// workloadAuthenticator derives a stable principal from the client's workload
// credential. Clients must send a non-empty token so two workloads can never
// collide on the shared anonymous principal or claim each other's pending
// activation. This credential is an identifier, not authorization; with
// verified mTLS the certificate digest would be a stronger principal.
func workloadAuthenticator(_ context.Context, identity proxy.RequestIdentity) (string, error) {
	if len(identity.Auth) == 0 {
		return "", errors.New("workload credential is required")
	}
	digest := sha256.Sum256(identity.Auth)
	return "workload-sha256:" + hex.EncodeToString(digest[:]), nil
}

// vendorModules selects bundled vendor modules by name. An empty list loads
// every module shipped with this repository.
func vendorModules(names []string) ([]pkcs11.VendorModule, error) {
	modules := all.Modules()
	if len(names) == 0 {
		return modules, nil
	}
	wanted := make(map[string]struct{}, len(names))
	for _, name := range names {
		wanted[strings.ToLower(strings.TrimSpace(name))] = struct{}{}
	}
	var selected []pkcs11.VendorModule
	for _, module := range modules {
		definition := module.Definition()
		key := strings.ToLower(string(definition.ID))
		if _, ok := wanted[key]; ok {
			selected = append(selected, module)
			delete(wanted, key)
			continue
		}
		if _, ok := wanted[strings.ToLower(definition.Name)]; ok {
			selected = append(selected, module)
			delete(wanted, strings.ToLower(definition.Name))
		}
	}
	if len(wanted) != 0 {
		missing := make([]string, 0, len(wanted))
		for name := range wanted {
			missing = append(missing, name)
		}
		return nil, fmt.Errorf("unknown vendor modules: %s", strings.Join(missing, ", "))
	}
	return selected, nil
}

// targetSpecs validates the configured route list.
func (cfg options) targetSpecs() ([]targetSpec, error) {
	specs := append([]targetSpec(nil), cfg.Targets...)
	if len(specs) == 0 {
		return nil, errors.New("at least one target is required: configure targets[]")
	}
	seen := make(map[string]struct{}, len(specs))
	for index := range specs {
		specs[index].Name = strings.TrimSpace(specs[index].Name)
		if specs[index].Name == "" {
			specs[index].Name = targetRouteID
		}
		if specs[index].Module == "" {
			return nil, fmt.Errorf("target %q: module is required", specs[index].Name)
		}
		if _, exists := seen[specs[index].Name]; exists {
			return nil, fmt.Errorf("duplicate target name %q", specs[index].Name)
		}
		seen[specs[index].Name] = struct{}{}
	}
	return specs, nil
}

func (cfg options) targetConfig(spec targetSpec, verifier *PINVerifier) (proxy.TargetConfig, error) {
	vendors, err := vendorModules(spec.Vendors)
	if err != nil {
		return proxy.TargetConfig{}, err
	}
	selector := pkcs11.TokenSelector{Label: spec.TokenLabel, SerialNumber: spec.TokenSerial}
	if spec.SlotID != nil {
		slot := raw.SlotID(*spec.SlotID)
		selector.SlotID = &slot
	}
	module, err := targetModuleSource(spec.Module)
	if err != nil {
		return proxy.TargetConfig{}, err
	}
	return proxy.TargetConfig{
		ID:       spec.Name,
		Revision: targetRevision,
		Client: pkcs11.Config{
			Module:  module,
			Token:   selector,
			Vendors: vendors,
		},
		Sessions: proxy.SessionBudget{
			MaxPhysicalTotal:            cfg.Sessions.MaxPhysicalTotal,
			MaxPhysicalReadWrite:        cfg.Sessions.MaxPhysicalReadWrite,
			MaxPinned:                   cfg.Sessions.MaxPinned,
			MaxQueued:                   cfg.Sessions.MaxQueued,
			MaxClients:                  cfg.Sessions.MaxClients,
			MaxVirtualSessionsPerClient: cfg.Sessions.MaxVirtualSessionsPerClient,
			MaxObjectsPerClient:         cfg.Sessions.MaxObjectsPerClient,
			QueueTimeout:                cfg.Sessions.QueueTimeout,
		},
		Login: proxy.LoginPolicy{
			Mode:                      proxy.PhysicalLoginClientActivated,
			PhysicalUserType:          raw.CKU_USER,
			AllowedUserTypes:          []uint{raw.CKU_USER},
			ActivationFailureCooldown: cfg.Activation.FailureCooldown,
			Authenticate:              verifier.Authenticate,
		},
		// No target authorization: any authenticated client may use every
		// operation. Client PIN verification is enforced by Login.Authenticate.
	}, nil
}

// newServerOn builds one route per configured target, optionally on a
// pre-bound listener, with an optional audit sink. Each route gets its own
// PINVerifier: the verifier is keyed to a single route's activation
// generation, and distinct tokens legitimately have distinct PINs.
func newServerOn(ctx context.Context, cfg options, listener net.Listener, audit proxy.AuditSink) (*proxy.Server, error) {
	tlsConfig, err := cfg.serverTLS()
	if err != nil {
		return nil, err
	}
	specs, err := cfg.targetSpecs()
	if err != nil {
		return nil, err
	}
	verifiers := make(map[string]*PINVerifier, len(specs))
	targets := make([]proxy.TargetConfig, 0, len(specs))
	for _, spec := range specs {
		verifier := NewPINVerifier()
		verifier.WaitPollInterval = cfg.Verifier.WaitPollInterval
		verifier.WaitTimeout = cfg.Verifier.WaitTimeout
		target, err := cfg.targetConfig(spec, verifier)
		if err != nil {
			return nil, fmt.Errorf("target %q: %w", spec.Name, err)
		}
		verifiers[spec.Name] = verifier
		targets = append(targets, target)
	}
	server, err := proxy.NewServer(ctx, proxy.ServerConfig{
		Address:       cfg.Listen,
		Listener:      listener,
		TLS:           tlsConfig,
		AllowInsecure: cfg.Insecure,
		Authenticator: workloadAuthenticator,
		DrainTimeout:  cfg.DrainTimeout,
		Audit:         audit,
	}, targets...)
	if err != nil {
		return nil, err
	}
	for name, verifier := range verifiers {
		route := name
		verifier.Observe(func() proxy.ActivationStatus {
			stats, _ := server.TargetStats(route)
			return stats.Activation
		})
	}
	return server, nil
}
