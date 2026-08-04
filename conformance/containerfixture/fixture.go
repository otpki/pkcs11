// Package containerfixture defines the provider-owned boundary used by the
// optional Testcontainers conformance launcher.
//
// The package deliberately has no Docker or Testcontainers dependency. A
// vendor integration can therefore describe and prepare its own test runtime
// without adding container libraries to applications that import the driver.
package containerfixture

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Asset declares one external file required to prepare a conformance runtime.
// Licensed SDKs, simulator archives, client bundles, and configuration files
// should be supplied as assets rather than committed to the repository.
type Asset struct {
	// Name is the stable command-line key used with p11containers -asset.
	Name string
	// Environment is the optional environment-variable fallback for the asset.
	Environment string
	// Description is shown in validation errors and provider documentation.
	Description string
	// Required rejects a run when neither -asset nor Environment supplies a path.
	Required bool
	// Sensitive marks material whose path should not be echoed more than needed.
	// It does not encrypt or otherwise protect the file itself.
	Sensitive bool
}

// Definition is immutable metadata for one containerized conformance provider.
type Definition struct {
	// ID is the stable name accepted by p11containers -provider.
	ID string
	// Dockerfile is relative to the repository root unless Prepare overrides it.
	Dockerfile string
	// Platform is an optional OCI platform such as "linux/amd64". Set it when a
	// licensed simulator or native client is available for only one architecture.
	// The launcher applies the value to both image construction and container
	// creation so architecture-specific vendor middleware and simulators run under the requested ABI.
	Platform string
	// Timeout is the provider's default image-build and conformance deadline.
	Timeout time.Duration
	// IncludeInAll includes public fixtures in the -provider all selection.
	IncludeInAll bool
	// Licensed documents that the prepared image may contain restricted material.
	Licensed bool
	// Assets lists files needed before the image can be built.
	Assets []Asset
	// Environment contains non-secret defaults passed to the container.
	Environment map[string]string
}

// Request contains caller-controlled inputs for Fixture.Prepare.
type Request struct {
	// RepositoryRoot is the absolute root of the otpki-pkcs11 checkout.
	RepositoryRoot string
	// Assets maps Definition.Assets names to caller-supplied paths.
	Assets map[string]string
	// Environment contains generic command-line environment overrides.
	Environment map[string]string
}

// Prepared is the build context returned by Fixture.Prepare.
type Prepared struct {
	// BuildContext is passed to Testcontainers as the Docker build context.
	BuildContext string
	// Dockerfile is interpreted relative to BuildContext.
	Dockerfile string
	// Platform is the OCI image/container platform selected by the fixture.
	// Custom Prepare implementations should normally copy Definition.Platform.
	Platform string
	// Environment is passed to the started conformance container.
	Environment map[string]string
	// Cleanup removes temporary build material. It must be safe to call once even
	// when preparation or the subsequent container run partially fails.
	Cleanup func() error
}

// Fixture owns all provider-specific container preparation.
//
// A simple public simulator usually embeds Base and needs no custom methods. A
// licensed provider can implement Prepare to copy only the required runtime
// files into an ephemeral context, leaving the central launcher vendor-neutral.
type Fixture interface {
	Definition() Definition
	Prepare(context.Context, Request) (Prepared, error)
}

// Base implements a fixture that builds directly from the repository checkout.
type Base struct {
	DefinitionValue Definition
}

// New returns a simple fixture whose Dockerfile can use the repository root as
// its build context.
func New(definition Definition) Fixture {
	return &Base{DefinitionValue: cloneDefinition(definition)}
}

// Definition returns an independent metadata snapshot.
func (b *Base) Definition() Definition {
	if b == nil {
		return Definition{}
	}
	return cloneDefinition(b.DefinitionValue)
}

// Prepare validates the request and returns the repository itself as the build
// context. Provider-specific extraction is intentionally left to custom
// fixtures instead of adding conditionals here.
func (b *Base) Prepare(ctx context.Context, request Request) (Prepared, error) {
	if b == nil {
		return Prepared{}, errors.New("container fixture is nil")
	}
	if err := ctx.Err(); err != nil {
		return Prepared{}, err
	}
	definition, err := Validate(b.DefinitionValue)
	if err != nil {
		return Prepared{}, err
	}
	root, err := canonicalDirectory(request.RepositoryRoot)
	if err != nil {
		return Prepared{}, err
	}
	if _, err := ResolveAssets(definition, request.Assets); err != nil {
		return Prepared{}, err
	}
	return Prepared{
		BuildContext: root,
		Dockerfile:   definition.Dockerfile,
		Platform:     definition.Platform,
		Environment:  mergeEnvironment(definition.Environment, request.Environment),
		Cleanup:      func() error { return nil },
	}, nil
}

// Validate normalizes and validates a fixture definition.
func Validate(definition Definition) (Definition, error) {
	definition = cloneDefinition(definition)
	definition.ID = strings.TrimSpace(definition.ID)
	definition.Dockerfile = filepath.ToSlash(strings.TrimSpace(definition.Dockerfile))
	definition.Platform = strings.ToLower(strings.TrimSpace(definition.Platform))
	if definition.ID == "" {
		return Definition{}, errors.New("container fixture ID is required")
	}
	if definition.Dockerfile == "" {
		return Definition{}, fmt.Errorf("container fixture %q Dockerfile is required", definition.ID)
	}
	if definition.Timeout <= 0 {
		return Definition{}, fmt.Errorf("container fixture %q timeout must be positive", definition.ID)
	}
	if definition.Platform != "" {
		parts := strings.Split(definition.Platform, "/")
		if (len(parts) != 2 && len(parts) != 3) || parts[0] == "" || parts[1] == "" || (len(parts) == 3 && parts[2] == "") {
			return Definition{}, fmt.Errorf("container fixture %q platform %q must use os/arch[/variant]", definition.ID, definition.Platform)
		}
	}
	seen := make(map[string]struct{}, len(definition.Assets))
	for index := range definition.Assets {
		asset := &definition.Assets[index]
		asset.Name = normalizeAssetName(asset.Name)
		asset.Environment = strings.TrimSpace(asset.Environment)
		asset.Description = strings.TrimSpace(asset.Description)
		if asset.Name == "" {
			return Definition{}, fmt.Errorf("container fixture %q asset %d has no name", definition.ID, index)
		}
		if _, exists := seen[asset.Name]; exists {
			return Definition{}, fmt.Errorf("container fixture %q has duplicate asset %q", definition.ID, asset.Name)
		}
		seen[asset.Name] = struct{}{}
	}
	return definition, nil
}

// ResolveAssets applies environment-variable fallbacks and verifies that every
// required asset points to a regular file. Returned paths are absolute.
func ResolveAssets(definition Definition, supplied map[string]string) (map[string]string, error) {
	definition, err := Validate(definition)
	if err != nil {
		return nil, err
	}
	result := make(map[string]string, len(definition.Assets))
	for _, asset := range definition.Assets {
		value := strings.TrimSpace(supplied[asset.Name])
		if value == "" && asset.Environment != "" {
			value = strings.TrimSpace(os.Getenv(asset.Environment))
		}
		if value == "" {
			if asset.Required {
				message := asset.Description
				if message == "" {
					message = "required file"
				}
				return nil, fmt.Errorf("container fixture %q asset %q is required (%s); use -asset %s=PATH or %s", definition.ID, asset.Name, message, asset.Name, asset.Environment)
			}
			continue
		}
		absolute, err := filepath.Abs(value)
		if err != nil {
			return nil, fmt.Errorf("container fixture %q asset %q: %w", definition.ID, asset.Name, err)
		}
		info, err := os.Stat(absolute)
		if err != nil {
			return nil, fmt.Errorf("container fixture %q asset %q: %w", definition.ID, asset.Name, err)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("container fixture %q asset %q is not a regular file", definition.ID, asset.Name)
		}
		result[asset.Name] = absolute
	}
	return result, nil
}

// Definitions validates a fixture set, rejects duplicate IDs, and returns it in
// stable ID order. The launcher uses this to make provider selection deterministic.
func Definitions(fixtures []Fixture) ([]Fixture, map[string]Definition, error) {
	result := make([]Fixture, 0, len(fixtures))
	definitions := make(map[string]Definition, len(fixtures))
	for index, fixture := range fixtures {
		if fixture == nil {
			return nil, nil, fmt.Errorf("container fixture %d is nil", index)
		}
		definition, err := Validate(fixture.Definition())
		if err != nil {
			return nil, nil, fmt.Errorf("container fixture %d: %w", index, err)
		}
		if _, exists := definitions[definition.ID]; exists {
			return nil, nil, fmt.Errorf("duplicate container fixture ID %q", definition.ID)
		}
		definitions[definition.ID] = definition
		result = append(result, fixture)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Definition().ID < result[j].Definition().ID
	})
	return result, definitions, nil
}

func canonicalDirectory(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("repository root is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(absolute)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%s is not a directory", absolute)
	}
	return filepath.Clean(absolute), nil
}

func normalizeAssetName(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func cloneDefinition(value Definition) Definition {
	value.Assets = append([]Asset(nil), value.Assets...)
	value.Environment = cloneEnvironment(value.Environment)
	return value
}

func cloneEnvironment(source map[string]string) map[string]string {
	if len(source) == 0 {
		return nil
	}
	result := make(map[string]string, len(source))
	maps.Copy(result, source)
	return result
}

func mergeEnvironment(base, overlay map[string]string) map[string]string {
	result := cloneEnvironment(base)
	if result == nil && len(overlay) != 0 {
		result = make(map[string]string, len(overlay))
	}
	maps.Copy(result, overlay)
	return result
}
