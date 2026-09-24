package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	pkcs11 "github.com/otpki/pkcs11"
	"github.com/otpki/pkcs11/proxy"
	"github.com/otpki/pkcs11/raw"
	"github.com/otpki/pkcs11/vendors/all"
	"github.com/spf13/viper"
)

const (
	environmentPrefix = "PKCS11_PROXY"
	configBaseName    = "pkcs11-proxy"
)

// options is the complete operator-facing configuration surface. Every value
// is settable through the YAML file, PKCS11_PROXY_* environment variables, or
// the bound command flags. No option carries the HSM PIN — activating clients
// supply it with their login and only its digest is retained in memory.
type options struct {
	// Listen is the client-facing address of the broker (clients set it as
	// proxy.Target.Endpoint).
	Listen string `mapstructure:"listen"`
	// Insecure permits plaintext TCP. It only removes transport encryption —
	// workload tokens and PIN verification still apply — and is rejected
	// unless TLS is also unconfigured.
	Insecure bool `mapstructure:"insecure"`
	TLS      struct {
		// CertFile and KeyFile are the PEM server certificate pair; both must
		// be set together or neither.
		CertFile string `mapstructure:"cert_file"`
		KeyFile  string `mapstructure:"key_file"`
		// ClientCAFile additionally requires clients to present a certificate
		// signed by this CA (mutual TLS); the certificate then doubles as the
		// workload identity.
		ClientCAFile string `mapstructure:"client_ca_file"`
	} `mapstructure:"tls"`
	Target struct {
		// ID is the public route name clients pass as proxy.Target.Route.
		ID string `mapstructure:"id"`
		// Revision is a free-form version clients must match; bump it when the
		// target configuration changes so mismatched clients fail fast.
		Revision string `mapstructure:"revision"`
		// Module is the path to the vendor's local PKCS #11 shared library.
		Module string `mapstructure:"module"`
		// TokenLabel selects the token inside the module; empty picks the
		// first reported. TokenSerial is an optional second selector when two
		// tokens share a label.
		TokenLabel  string `mapstructure:"token_label"`
		TokenSerial string `mapstructure:"token_serial"`
		// Vendors allowlists bundled vendor modules by adapter ID or name;
		// empty enables all. Clients must configure the same set — the
		// describe handshake requires exact parameter-codec parity.
		Vendors []string `mapstructure:"vendors"`
		// UserType is the physical identity activated on the token; only
		// "user" is supported — SO/maintenance access is not exposed.
		UserType string `mapstructure:"user_type"`
	} `mapstructure:"target"`
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
}

func loadOptions(configFile string) (options, error) {
	v := viper.New()
	v.SetEnvPrefix(environmentPrefix)
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	v.AutomaticEnv()

	// Defaults also register every key so AutomaticEnv can resolve the
	// corresponding PKCS11_PROXY_* variable during Unmarshal.
	for key, value := range map[string]any{
		"listen":   "127.0.0.1:9443",
		"insecure": false,

		"tls.cert_file":      "",
		"tls.key_file":       "",
		"tls.client_ca_file": "",

		"target.id":           "hsm",
		"target.revision":     "v1",
		"target.module":       "",
		"target.token_label":  "",
		"target.token_serial": "",
		"target.vendors":      []string{},
		"target.user_type":    "user",

		"sessions.max_physical_total":              8,
		"sessions.max_physical_read_write":         4,
		"sessions.max_pinned":                      2,
		"sessions.max_queued":                      64,
		"sessions.max_clients":                     256,
		"sessions.max_virtual_sessions_per_client": 16,
		"sessions.max_objects_per_client":          1024,
		"sessions.queue_timeout":                   5 * time.Second,

		"activation.failure_cooldown": time.Second,

		"dev_ui.enabled":      false,
		"dev_ui.listen":       "127.0.0.1:9463",
		"dev_ui.allow_remote": false,

		"verifier.wait_poll_interval": 25 * time.Millisecond,
		"verifier.wait_timeout":       30 * time.Second,
	} {
		v.SetDefault(key, value)
	}

	if configFile != "" {
		v.SetConfigFile(configFile)
	} else {
		// Look for ./pkcs11-proxy.yaml by exact path: viper's name search would
		// otherwise also try the pkcs11-proxy binary itself as a config file.
		v.SetConfigFile("./" + configBaseName + ".yaml")
	}
	if err := v.ReadInConfig(); err != nil {
		if configFile == "" && os.IsNotExist(err) {
			// The default file is optional; environment and flags still apply.
		} else {
			return options{}, err
		}
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
			return nil, fmt.Errorf("no TLS certificate configured; set tls.cert_file/tls.key_file or insecure: true for development")
		}
		return nil, nil
	}
	if cfg.TLS.CertFile == "" || cfg.TLS.KeyFile == "" {
		return nil, fmt.Errorf("tls.cert_file and tls.key_file must be configured together")
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
		return "", fmt.Errorf("workload credential is required")
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

func (cfg options) targetConfig(verifier *PINVerifier) (proxy.TargetConfig, error) {
	if cfg.Target.Module == "" {
		return proxy.TargetConfig{}, fmt.Errorf("target.module is required")
	}
	if strings.ToLower(cfg.Target.UserType) != "user" {
		return proxy.TargetConfig{}, fmt.Errorf("target.user_type %q is unsupported; only %q is configurable", cfg.Target.UserType, "user")
	}
	vendors, err := vendorModules(cfg.Target.Vendors)
	if err != nil {
		return proxy.TargetConfig{}, err
	}
	return proxy.TargetConfig{
		ID:       cfg.Target.ID,
		Revision: cfg.Target.Revision,
		Client: pkcs11.Config{
			Module:  pkcs11.LocalModule(cfg.Target.Module),
			Token:   pkcs11.TokenSelector{Label: cfg.Target.TokenLabel, SerialNumber: cfg.Target.TokenSerial},
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

func newServer(ctx context.Context, cfg options) (*proxy.Server, *PINVerifier, error) {
	tlsConfig, err := cfg.serverTLS()
	if err != nil {
		return nil, nil, err
	}
	verifier := NewPINVerifier()
	verifier.WaitPollInterval = cfg.Verifier.WaitPollInterval
	verifier.WaitTimeout = cfg.Verifier.WaitTimeout
	target, err := cfg.targetConfig(verifier)
	if err != nil {
		return nil, nil, err
	}
	server, err := proxy.NewServer(ctx, proxy.ServerConfig{
		Address:       cfg.Listen,
		TLS:           tlsConfig,
		AllowInsecure: cfg.Insecure,
		Authenticator: workloadAuthenticator,
	}, target)
	if err != nil {
		return nil, nil, err
	}
	route := cfg.Target.ID
	verifier.Observe(func() proxy.ActivationStatus {
		stats, _ := server.TargetStats(route)
		return stats.Activation
	})
	return server, verifier, nil
}
