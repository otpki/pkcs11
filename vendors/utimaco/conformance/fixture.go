// Package conformance owns the container fixtures for the licensed Utimaco
// CryptoServer (GP) and QuantumProtect simulators. The fixtures stage the
// required licensed runtime files from caller-supplied release archives into an
// ephemeral build directory, so nothing restricted is committed to git.
package conformance

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/otpki/pkcs11/conformance/containerfixture"
)

// Provider IDs accepted by p11containers -provider.
const (
	// ProviderGP runs the u.trust GP HSM simulator for classical PKCS #11 coverage.
	ProviderGP = "utimaco-gp"
	// ProviderQP runs the QuantumProtect evaluation simulator, which ships the
	// HBS, ML, and PQMI firmware modules for PQC coverage.
	ProviderQP = "utimaco-qp"
)

// stagingDirectory is the build-context-relative directory the Dockerfile
// copies into /opt/utimaco. It is removed again by the fixture's cleanup.
const stagingDirectory = "licensed/utimaco"

var (
	gpArchiveAsset = containerfixture.Asset{
		Name:        "gp-archive",
		Environment: "PKCS11_UTIMACO_GP_ARCHIVE",
		Description: "u.trust GP HSM Simulator release archive (u.trust-GP-HSM-Simulator_v*.zip)",
		Required:    true,
		Sensitive:   true,
	}
	qpArchiveAsset = containerfixture.Asset{
		Name:        "qp-archive",
		Environment: "PKCS11_UTIMACO_QP_ARCHIVE",
		Description: "QuantumProtect evaluation archive (QuantumProtect-*-Evaluation.zip)",
		Required:    true,
		Sensitive:   true,
	}
)

// zipRule maps archive members under prefix (below the bundle's top-level
// directory) into stagingDirectory/dest.
type zipRule struct {
	prefix string
	dest   string
}

// gpRules stage the administration tools, the PKCS #11 client library, and the
// client configuration sample shared by both simulators.
var gpRules = []zipRule{
	{prefix: "Software/Linux/Administration/csadm", dest: "admin/csadm"},
	{prefix: "Software/Linux/Administration/cxitool", dest: "admin/cxitool"},
	{prefix: "Software/Linux/Administration/gladm", dest: "admin/gladm"},
	{prefix: "Software/Linux/Administration/p11tool2", dest: "admin/p11tool2"},
	{prefix: "Software/Linux/Administration/key/", dest: "admin/key"},
	{prefix: "Software/Linux/Crypto_APIs/PKCS11_R3/lib/libcs_pkcs11_R3.so", dest: "lib/libcs_pkcs11_R3.so"},
	{prefix: "Software/Linux/Crypto_APIs/PKCS11_R3/sample/cs_pkcs11_R3.cfg", dest: "etc/cs_pkcs11_R3.cfg"},
}

// gpSimulatorRule stages the plain SecurityServer simulator.
var gpSimulatorRule = zipRule{prefix: "Software/Linux/Simulator/sim5_linux/", dest: "simulator"}

// qpRules stage the QuantumProtect extras: the simulator (with its own bl_sim5
// plus pre-loaded PQC firmware modules under devices/SDRAM) and the qptool2
// demo binary used for container-side debugging.
var qpRules = []zipRule{
	{prefix: "linux/sim5_linux/", dest: "simulator"},
	{prefix: "Crypto_APIs/PKCS11_R3/samples/qptool2/bin/qptool2", dest: "admin/qptool2"},
}

type archiveFixture struct {
	definition     containerfixture.Definition
	quantumProtect bool
}

// Fixtures returns the licensed Utimaco conformance runtimes. Neither is
// included in the -provider all selection because both need licensed archives.
func Fixtures() []containerfixture.Fixture {
	return []containerfixture.Fixture{
		archiveFixture{
			definition: containerfixture.Definition{
				ID:         ProviderGP,
				Dockerfile: "vendors/utimaco/conformance/docker/Dockerfile",
				Platform:   "linux/amd64",
				Timeout:    45 * time.Minute,
				Licensed:   true,
				Assets:     []containerfixture.Asset{gpArchiveAsset},
				Environment: map[string]string{
					"UTIMACO_PROFILE": "gp",
					"UTIMACO_SLOT":    "1",
				},
			},
		},
		archiveFixture{
			definition: containerfixture.Definition{
				ID:         ProviderQP,
				Dockerfile: "vendors/utimaco/conformance/docker/Dockerfile",
				Platform:   "linux/amd64",
				Timeout:    60 * time.Minute,
				Licensed:   true,
				Assets:     []containerfixture.Asset{gpArchiveAsset, qpArchiveAsset},
				Environment: map[string]string{
					"UTIMACO_PROFILE":       "qp",
					"UTIMACO_SLOT":          "0",
					"UTIMACO_FALLBACK_PIN":  "12345688",
					"UTIMACO_FALLBACK_SLOT": "0",
				},
			},
			quantumProtect: true,
		},
	}
}

// Definition returns an independent metadata snapshot.
func (f archiveFixture) Definition() containerfixture.Definition {
	return f.definition
}

// Prepare extracts the licensed runtime files into licensed/utimaco inside the
// repository checkout so the Dockerfile can COPY them, then removes them again
// during cleanup.
func (f archiveFixture) Prepare(ctx context.Context, request containerfixture.Request) (prepared containerfixture.Prepared, returnedErr error) {
	definition, err := containerfixture.Validate(f.definition)
	if err != nil {
		return prepared, err
	}
	root := strings.TrimSpace(request.RepositoryRoot)
	if root == "" {
		return prepared, errors.New("utimaco: repository root is required")
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return prepared, err
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return prepared, fmt.Errorf("utimaco: repository root %q is not a directory", root)
	}
	assets, err := containerfixture.ResolveAssets(definition, request.Assets)
	if err != nil {
		return prepared, err
	}

	destination := filepath.Join(root, filepath.FromSlash(stagingDirectory))
	cleanup := func() error { return os.RemoveAll(destination) }
	if err := os.RemoveAll(destination); err != nil {
		return prepared, fmt.Errorf("utimaco: clear stale staging directory: %w", err)
	}
	defer func() {
		if returnedErr != nil {
			returnedErr = errors.Join(returnedErr, cleanup())
		}
	}()

	staged := 0
	count, err := extractRules(assets["gp-archive"], gpRules, root, destination)
	staged += count
	if err != nil {
		return prepared, fmt.Errorf("utimaco: stage GP archive: %w", err)
	}
	simulatorRules := []zipRule{gpSimulatorRule}
	archive := assets["gp-archive"]
	if f.quantumProtect {
		simulatorRules = qpRules
		archive = assets["qp-archive"]
	}
	count, err = extractRules(archive, simulatorRules, root, destination)
	staged += count
	if err != nil {
		return prepared, fmt.Errorf("utimaco: stage simulator: %w", err)
	}
	if staged == 0 {
		return prepared, errors.New("utimaco: archives produced no simulator files; check that the supplied archives are unmodified Utimaco releases")
	}

	prepared = containerfixture.Prepared{
		BuildContext: root,
		Dockerfile:   definition.Dockerfile,
		Platform:     definition.Platform,
		Environment:  mergeEnvironment(definition.Environment, request.Environment),
		Cleanup:      cleanup,
	}
	return prepared, nil
}

// extractRules copies archive members matching each rule's prefix into
// destination. The archive's top-level bundle directory is stripped before
// prefix matching so either zipped or pre-extracted release layouts work.
func extractRules(archivePath string, rules []zipRule, root, destination string) (int, error) {
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		return 0, err
	}
	defer reader.Close()

	written := 0
	for _, file := range reader.File {
		if file.FileInfo().IsDir() {
			continue
		}
		relative := stripBundleRoot(file.Name)
		for _, rule := range rules {
			if !strings.HasPrefix(relative, rule.prefix) {
				continue
			}
			target := filepath.Join(destination, filepath.FromSlash(rule.dest))
			// Directory rules keep the remainder of the member path; file rules
			// land exactly on rule.dest.
			if strings.HasSuffix(rule.prefix, "/") {
				target = filepath.Join(target, filepath.FromSlash(strings.TrimPrefix(relative, rule.prefix)))
			}
			if err := extractMember(file, target); err != nil {
				return written, err
			}
			written++
			break
		}
	}
	return written, nil
}

// stripBundleRoot removes the single top-level directory every Utimaco release
// archive wraps its contents in, tolerating archives repacked without it.
func stripBundleRoot(name string) string {
	name = filepath.ToSlash(name)
	parts := strings.SplitN(name, "/", 2)
	if len(parts) == 2 && !strings.HasPrefix(name, "Software/") && !strings.HasPrefix(name, "linux/") {
		return parts[1]
	}
	return name
}

func extractMember(file *zip.File, target string) error {
	source, err := file.Open()
	if err != nil {
		return err
	}
	defer source.Close()
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	destination, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, executableMode(file))
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(destination, source)
	closeErr := destination.Close()
	return errors.Join(copyErr, closeErr)
}

// executableMode restores execute permission for shell scripts and ELF
// binaries. The archives do not reliably carry Unix mode bits.
func executableMode(file *zip.File) os.FileMode {
	name := filepath.Base(file.Name)
	if file.FileInfo().Mode()&0o111 != 0 {
		return 0o755
	}
	switch {
	case strings.HasSuffix(name, ".sh"),
		name == "bl_sim5",
		name == "csadm",
		name == "cxitool",
		name == "gladm",
		name == "p11tool2",
		name == "qptool2":
		return 0o755
	default:
		return 0o644
	}
}

func mergeEnvironment(base, overlay map[string]string) map[string]string {
	result := make(map[string]string, len(base)+len(overlay))
	for key, value := range base {
		result[key] = value
	}
	for key, value := range overlay {
		result[key] = value
	}
	return result
}
