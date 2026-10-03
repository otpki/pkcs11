package pkcs11

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/otpki/pkcs11/raw"
)

// ModuleCandidate is a native PKCS #11 shared library that can be probed.
// Family is a discovery hint supplied by the VendorModule that contributed the
// path; actual adapter selection still uses the loaded module fingerprint.
type ModuleCandidate struct {
	Path   string        `json:"path"`
	Family AdapterFamily `json:"family,omitempty"`
	Source string        `json:"source,omitempty"`
}

// DetectionConfig controls bounded module discovery. Discovery checks only configured paths, a
// small set of environment variables, and known library locations. It does not scan every shared
// library on the machine.
type DetectionConfig struct {
	// ExplicitPaths are considered first and require no vendor module.
	ExplicitPaths []string
	// SearchDirectories are searched for basenames declared by the supplied
	// vendor modules. They are considered before conventional system locations.
	SearchDirectories []string
	// IncludeEnvironment reads the generic variables and each supplied module's
	// VendorDiscovery.EnvironmentVariables.
	IncludeEnvironment bool
	// IncludeSystem adds conservative platform library directories plus each
	// supplied module's conventional installation directories.
	IncludeSystem bool
	// PreferredFamilies filters successfully opened clients by selected module ID.
	PreferredFamilies []AdapterFamily
}

// DefaultDetectionConfig returns conservative in-process discovery settings.
func DefaultDetectionConfig() DetectionConfig {
	return DetectionConfig{IncludeEnvironment: true, IncludeSystem: true}
}

// ModuleProbe is the result of loading, initializing, and enumerating one
// candidate through the same process-wide registry used by Client.
type ModuleProbe struct {
	Candidate ModuleCandidate   `json:"candidate"`
	Interface raw.InterfaceInfo `json:"interface"`
	Devices   []Device          `json:"devices,omitempty"`
	Duration  time.Duration     `json:"duration"`
	Error     string            `json:"error,omitempty"`
}

var genericModuleEnvironmentVariables = []string{
	"PKCS11_MODULE",
	"PKCS11_MODULE_PATH",
	"CRYPTOKI_LIBRARY",
}

func defaultSearchDirectories() []string {
	var directories []string
	switch runtime.GOOS {
	case "windows":
		for _, env := range []string{"ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"} {
			if root := os.Getenv(env); root != "" {
				directories = append(directories, root)
			}
		}
	case "darwin":
		directories = append(directories, "/usr/local/lib", "/opt/homebrew/lib", "/Library")
	default:
		directories = append(directories,
			"/usr/lib", "/usr/lib64", "/usr/local/lib", "/usr/local/lib64",
			"/usr/lib/pkcs11", "/usr/lib64/pkcs11", "/usr/local/lib/pkcs11",
			"/usr/lib/x86_64-linux-gnu", "/usr/lib/aarch64-linux-gnu",
			"/usr/lib/x86_64-linux-gnu/pkcs11", "/usr/lib/aarch64-linux-gnu/pkcs11",
		)
	}
	return directories
}

func canonicalExistingPath(path string) (string, bool) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", false
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", false
	}
	info, err := os.Stat(absolute)
	if err != nil || info.IsDir() {
		return "", false
	}
	if evaluated, err := filepath.EvalSymlinks(absolute); err == nil {
		absolute = evaluated
	}
	return filepath.Clean(absolute), true
}

// ModuleCandidates returns existing, deduplicated candidates in deterministic
// preference order: explicit paths, environment variables, caller directories,
// then system/vendor installation directories.
//
// Vendor-specific names and paths come exclusively from vendors; the root
// driver contains no product filename catalog.
func ModuleCandidates(config DetectionConfig, vendors ...VendorModule) ([]ModuleCandidate, error) {
	validated, definitions, err := validateVendorModules(vendors)
	if err != nil {
		return nil, err
	}
	validated = sortedVendorModules(validated)

	var candidates []ModuleCandidate
	for _, path := range config.ExplicitPaths {
		candidates = append(candidates, ModuleCandidate{Path: path, Source: "explicit"})
	}

	if config.IncludeEnvironment {
		for _, key := range genericModuleEnvironmentVariables {
			for _, path := range filepath.SplitList(os.Getenv(key)) {
				if strings.TrimSpace(path) != "" {
					candidates = append(candidates, ModuleCandidate{Path: path, Source: "env:" + key})
				}
			}
		}
		for _, module := range validated {
			definition := definitions[normalizeAdapterFamily(module.Definition().ID)]
			keys := slices.Sorted(slices.Values(definition.Discovery.EnvironmentVariables))
			for _, key := range keys {
				for _, path := range filepath.SplitList(os.Getenv(key)) {
					if strings.TrimSpace(path) != "" {
						candidates = append(candidates, ModuleCandidate{
							Path: path, Family: definition.ID, Source: "env:" + key,
						})
					}
				}
			}
		}
	}

	baseDirectories := slices.Clone(config.SearchDirectories)
	if config.IncludeSystem {
		baseDirectories = append(baseDirectories, defaultSearchDirectories()...)
	}
	for _, module := range validated {
		definition := definitions[normalizeAdapterFamily(module.Definition().ID)]
		discovery := vendorDiscoveryForOS(definition.Discovery)
		directories := slices.Clone(baseDirectories)
		if config.IncludeSystem {
			directories = append(directories, discovery.Directories(runtime.GOOS)...)
		}
		for _, directory := range directories {
			for _, name := range discovery.Names(runtime.GOOS) {
				candidates = append(candidates, ModuleCandidate{
					Path: filepath.Join(directory, name), Family: definition.ID,
					Source: "vendor-discovery:" + string(definition.ID),
				})
			}
		}
	}

	seen := make(map[string]struct{})
	result := make([]ModuleCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		path, ok := canonicalExistingPath(candidate.Path)
		if !ok {
			continue
		}
		key := path
		if runtime.GOOS == "windows" {
			key = strings.ToLower(path)
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		candidate.Path = path
		result = append(result, candidate)
	}
	return result, nil
}

func probeModule(ctx context.Context, candidate ModuleCandidate, vendors []VendorModule) ModuleProbe {
	start := time.Now()
	probe := ModuleProbe{Candidate: candidate}
	if err := ctx.Err(); err != nil {
		probe.Error = err.Error()
		return probe
	}
	module, err := acquireModule(ctx, LocalModule(candidate.Path))
	if err != nil {
		probe.Error = err.Error()
		probe.Duration = time.Since(start)
		return probe
	}
	probe.Interface = module.raw.Interface()
	devices, discoverErr := discoverManaged(ctx, module, CompatibilityConfig{}, vendors)
	releaseErr := releaseModule(module)
	probe.Devices = devices
	if discoverErr != nil || releaseErr != nil {
		probe.Error = errors.Join(discoverErr, releaseErr).Error()
	}
	probe.Duration = time.Since(start)
	return probe
}

// DetectModules probes all discovered native modules in process. Because a
// faulty vendor library can crash or block its host process, callers should
// normally provide explicit paths in production and reserve broad probing for
// controlled setup or diagnostics.
func DetectModules(ctx context.Context, config DetectionConfig, vendors ...VendorModule) ([]ModuleProbe, error) {
	candidates, err := ModuleCandidates(config, vendors...)
	if err != nil {
		return nil, err
	}
	probes := make([]ModuleProbe, 0, len(candidates))
	for _, candidate := range candidates {
		if ctx.Err() != nil {
			break
		}
		probes = append(probes, probeModule(ctx, candidate, vendors))
	}
	//nolint:nilerr // Partial probe results are useful when the context was canceled.
	return probes, nil
}

func familyPreferred(family AdapterFamily, preferred []AdapterFamily) bool {
	if len(preferred) == 0 {
		return true
	}
	family = normalizeAdapterFamily(family)
	return slices.ContainsFunc(preferred, func(value AdapterFamily) bool {
		return normalizeAdapterFamily(value) == family
	})
}

// OpenDetected opens the first usable module in candidate order. Config.Vendors
// is used both to contribute discovery hints and to select/adapt the loaded HSM.
// A token selector is still required when a module exposes multiple matches.
func OpenDetected(ctx context.Context, config Config, detection DetectionConfig) (*Client, error) {
	candidates, err := ModuleCandidates(detection, config.Vendors...)
	if err != nil {
		return nil, err
	}
	if len(candidates) == 0 {
		return nil, errors.New("pkcs11: no native PKCS #11 module candidates found")
	}
	var errs []error
	for _, candidate := range candidates {
		if err := ctx.Err(); err != nil {
			return nil, errors.Join(append(errs, err)...)
		}
		candidateConfig := config
		candidateConfig.Module = LocalModule(candidate.Path)
		client, err := Open(ctx, candidateConfig)
		if err == nil {
			family := client.Adapter().Family
			if familyPreferred(family, detection.PreferredFamilies) {
				return client, nil
			}
			closeErr := client.Close(ctx)
			err = fmt.Errorf("detected family %q is not preferred", family)
			if closeErr != nil {
				err = errors.Join(err, closeErr)
			}
		}
		errs = append(errs, fmt.Errorf("%s: %w", candidate.Path, err))
	}
	if len(errs) == 0 {
		return nil, errors.New("pkcs11: no candidate matched preferred families")
	}
	return nil, fmt.Errorf("pkcs11: no detected module could be opened: %w", errors.Join(errs...))
}

// OpenAuto uses DefaultDetectionConfig. Without Config.Vendors it can discover
// only explicit/generic environment paths; pass vendor modules (for example
// vendors/all.Modules()) to enable their filename and installation-directory hints.
func OpenAuto(ctx context.Context, config Config) (*Client, error) {
	return OpenDetected(ctx, config, DefaultDetectionConfig())
}
