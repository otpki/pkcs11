package runner

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/moby/moby/client"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/otpki/pkcs11/conformance/containerfixture"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

type keyValueFlag map[string]string

func (values *keyValueFlag) String() string {
	if values == nil || len(*values) == 0 {
		return ""
	}
	keys := slices.Sorted(maps.Keys(*values))
	var parts []string
	for _, key := range keys {
		parts = append(parts, key+"="+(*values)[key])
	}
	return strings.Join(parts, ",")
}

func (values *keyValueFlag) Set(value string) error {
	key, item, ok := strings.Cut(value, "=")
	key = strings.ToLower(strings.TrimSpace(key))
	if !ok || key == "" {
		return fmt.Errorf("expected NAME=VALUE, got %q", value)
	}
	if *values == nil {
		*values = make(map[string]string)
	}
	(*values)[key] = item
	return nil
}

// Main runs the container launcher with explicitly supplied provider fixtures.
func Main(providerFixtures []containerfixture.Fixture) {
	var (
		selected      string
		root          string
		output        string
		nativeBackend string
		legacyBackend string
		timeout       time.Duration
		image         string
		buildLogs     bool
		liveLogs      bool
		assets        keyValueFlag
		env           keyValueFlag
	)
	flag.StringVar(&selected, "provider", "softhsm2", "provider ID, comma-separated IDs, or 'all'")
	flag.StringVar(&root, "root", "", "repository root; auto-detected when empty")
	flag.StringVar(&output, "output", "", "report directory; defaults to <root>/reports/conformance")
	flag.StringVar(&nativeBackend, "backend", "", "native ABI backend to build inside provider images: cgo or purego; defaults to cgo")
	flag.StringVar(&legacyBackend, "native-backend", "", "deprecated alias for -backend")
	flag.DurationVar(&timeout, "timeout", 0, "override the selected fixture timeout")
	flag.StringVar(&image, "image", "", "run a prebuilt provider image instead of building the fixture Dockerfile; requires exactly one provider")
	flag.BoolVar(&buildLogs, "build-logs", true, "print Docker image build logs")
	flag.BoolVar(&liveLogs, "live-logs", true, "stream container startup and conformance logs")
	flag.Var(&assets, "asset", "provider asset as NAME=PATH; repeatable (provider.NAME=PATH also works)")
	flag.Var(&env, "env", "container environment override as NAME=VALUE; repeatable")
	flag.Parse()

	normalizedBackend, err := resolveNativeBackend(nativeBackend, legacyBackend)
	if err != nil {
		fatal(err)
	}
	nativeBackend = normalizedBackend
	if root == "" {
		root, err = findRepositoryRoot()
		if err != nil {
			fatal(err)
		}
	}
	root, err = filepath.Abs(root)
	if err != nil {
		fatal(err)
	}
	if output == "" {
		output = filepath.Join(root, "reports", "conformance")
	}

	fixtures, definitions, err := containerfixture.Definitions(providerFixtures)
	if err != nil {
		fatal(err)
	}
	selectedFixtures, err := selectFixtures(selected, fixtures, definitions)
	if err != nil {
		fatal(err)
	}
	// One image can only ever describe one provider runtime, so a caller-
	// supplied image requires a single provider selection.
	image = strings.TrimSpace(image)
	if image != "" && len(selectedFixtures) != 1 {
		fatal(fmt.Errorf("-image %q requires exactly one provider, got %d", image, len(selectedFixtures)))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var failures []error
	for _, fixture := range selectedFixtures {
		definition := definitions[fixture.Definition().ID]
		fixtureTimeout := definition.Timeout
		if timeout > 0 {
			fixtureTimeout = timeout
		}
		fixtureAssets := assetsForFixture(definition.ID, assets)
		fmt.Fprintf(os.Stderr, "p11containers: provider=%s backend=%s dockerfile=%s timeout=%s licensed=%t\n", definition.ID, nativeBackend, definition.Dockerfile, fixtureTimeout, definition.Licensed)
		request := containerfixture.Request{
			RepositoryRoot: root,
			Assets:         fixtureAssets,
			Environment:    normalizedEnvironment(env),
		}
		if err := runFixture(ctx, output, fixture, definition, request, nativeBackend, image, fixtureTimeout, buildLogs, liveLogs); err != nil {
			failures = append(failures, err)
		}
	}
	if len(failures) != 0 {
		fatal(errors.Join(failures...))
	}
}

func selectFixtures(value string, fixtures []containerfixture.Fixture, definitions map[string]containerfixture.Definition) ([]containerfixture.Fixture, error) {
	byID := make(map[string]containerfixture.Fixture, len(fixtures))
	for _, fixture := range fixtures {
		byID[fixture.Definition().ID] = fixture
	}
	var names []string
	if strings.TrimSpace(value) == "all" {
		for id, definition := range definitions {
			if definition.IncludeInAll {
				names = append(names, id)
			}
		}
		slices.Sort(names)
	} else {
		for name := range strings.SplitSeq(value, ",") {
			if name = strings.TrimSpace(name); name != "" {
				names = append(names, name)
			}
		}
	}
	if len(names) == 0 {
		return nil, errors.New("no providers selected")
	}
	result := make([]containerfixture.Fixture, 0, len(names))
	for _, name := range names {
		fixture, ok := byID[name]
		if !ok {
			return nil, fmt.Errorf("unknown provider %q; available: %s", name, strings.Join(fixtureNames(definitions), ", "))
		}
		result = append(result, fixture)
	}
	return result, nil
}

func fixtureNames(definitions map[string]containerfixture.Definition) []string {
	return slices.Sorted(maps.Keys(definitions))
}

func assetsForFixture(id string, supplied map[string]string) map[string]string {
	result := make(map[string]string)
	prefix := strings.ToLower(strings.TrimSpace(id)) + "."
	for key, value := range supplied {
		key = strings.ToLower(strings.TrimSpace(key))
		if !strings.Contains(key, ".") {
			result[key] = value
		}
	}
	for key, value := range supplied {
		key = strings.ToLower(strings.TrimSpace(key))
		if trimmed, ok := strings.CutPrefix(key, prefix); ok {
			result[trimmed] = value
		}
	}
	return result
}

func normalizedEnvironment(source map[string]string) map[string]string {
	if len(source) == 0 {
		return nil
	}
	result := make(map[string]string, len(source))
	for key, value := range source {
		result[strings.TrimSpace(key)] = value
	}
	return result
}

func runFixture(
	ctx context.Context,
	output string,
	fixture containerfixture.Fixture,
	definition containerfixture.Definition,
	request containerfixture.Request,
	nativeBackend string,
	image string,
	timeout time.Duration,
	buildLogs bool,
	liveLogs bool,
) (returnedErr error) {
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	stage(definition.ID, "prepare fixture")
	prepared, err := fixture.Prepare(runCtx, request)
	if err != nil {
		return fmt.Errorf("%s: prepare fixture: %w", definition.ID, err)
	}
	cleanup := prepared.Cleanup
	if cleanup == nil {
		cleanup = func() error { return nil }
	}
	defer func() { returnedErr = errors.Join(returnedErr, cleanup()) }()
	if prepared.BuildContext == "" || prepared.Dockerfile == "" {
		return fmt.Errorf("%s: fixture returned an incomplete build context", definition.ID)
	}
	if prepared.Platform != "" {
		stage(definition.ID, "target platform "+prepared.Platform)
	}

	// Keep reports from cgo and PureGo runs side-by-side. Without the backend
	// component, a parity run would silently overwrite the first result with the
	// second and make report comparison impossible.
	providerOutput := backendOutputDirectory(output, definition.ID, nativeBackend)
	if err := os.MkdirAll(providerOutput, 0o755); err != nil {
		return err
	}

	environment := map[string]string{"CONFORMANCE_HOLD": "1"}
	for key, value := range prepared.Environment {
		environment[key] = value
	}
	// This is an orchestration invariant rather than a provider or user
	// override. The Go test binary exits before opening the module if the image was
	// accidentally built with the wrong backend.
	environment["CONFORMANCE_EXPECT_BACKEND"] = nativeBackend
	backendBuildArg := nativeBackend
	fromDockerfile := testcontainers.FromDockerfile{
		Context:    prepared.BuildContext,
		Dockerfile: prepared.Dockerfile,
		Repo:       "otpki/conformance-" + sanitizeImageComponent(definition.ID) + "-" + sanitizeImageComponent(nativeBackend),
		Tag:        "local",
		KeepImage:  true,
		BuildArgs: map[string]*string{
			"PKCS11_BACKEND": &backendBuildArg,
		},
	}
	if buildLogs {
		fromDockerfile.BuildLogWriter = os.Stderr
	}
	requestContainer := testcontainers.ContainerRequest{
		FromDockerfile: fromDockerfile,
		Env:            environment,
		ImagePlatform:  prepared.Platform,
		WaitingFor:     wait.ForLog("CONFORMANCE_DONE").WithStartupTimeout(timeout),
	}
	if liveLogs {
		requestContainer.LogConsumerCfg = &testcontainers.LogConsumerConfig{
			Opts:      []testcontainers.LogProductionOption{testcontainers.WithLogProductionTimeout(60 * time.Second)},
			Consumers: []testcontainers.LogConsumer{&prefixedLogConsumer{provider: definition.ID}},
		}
	}
	switch {
	case image != "":
		// A caller-supplied image (for example a CI build exported through the
		// BuildKit cache) skips the Dockerfile build entirely.
		requestContainer.FromDockerfile = testcontainers.FromDockerfile{}
		requestContainer.Image = image
		stage(definition.ID, "start container from image "+image)
	case prepared.Platform != "":
		builtImage := fromDockerfile.Repo + ":" + fromDockerfile.Tag
		stage(definition.ID, "build "+nativeBackend+" image with buildx")
		err := buildPlatformImage(runCtx, prepared.BuildContext, prepared.Dockerfile, builtImage, nativeBackend, prepared.Platform, false, buildLogs)
		if err != nil && isDockerCacheFailure(err) {
			stage(definition.ID, "inconsistent Docker cache detected; retry buildx without cache")
			err = buildPlatformImage(runCtx, prepared.BuildContext, prepared.Dockerfile, builtImage, nativeBackend, prepared.Platform, true, buildLogs)
		}
		if err != nil {
			return fmt.Errorf("%s: build platform image: %w%s", definition.ID, err, dockerBuildHint(err))
		}
		requestContainer.FromDockerfile = testcontainers.FromDockerfile{}
		requestContainer.Image = builtImage
		stage(definition.ID, "start conformance container")
	default:
		stage(definition.ID, "build "+nativeBackend+" image and start container")
	}
	container, err := testcontainers.GenericContainer(runCtx, testcontainers.GenericContainerRequest{
		ContainerRequest: requestContainer,
		Started:          true,
	})
	if err != nil && isDockerCacheFailure(err) {
		if container != nil {
			terminateCtx, terminateCancel := context.WithTimeout(context.Background(), 30*time.Second)
			terminateErr := container.Terminate(terminateCtx)
			terminateCancel()
			if terminateErr != nil {
				return fmt.Errorf("%s: clean failed build before retry: %w", definition.ID, terminateErr)
			}
		}
		stage(definition.ID, "inconsistent Docker cache detected; retry build without cache")
		requestContainer.FromDockerfile.BuildOptionsModifier = freshBuildOptions
		container, err = testcontainers.GenericContainer(runCtx, testcontainers.GenericContainerRequest{
			ContainerRequest: requestContainer,
			Started:          true,
		})
	}
	if err != nil {
		startupErr := captureStartupFailure(definition.ID, providerOutput, container)
		if container != nil {
			terminateCtx, terminateCancel := context.WithTimeout(context.Background(), 30*time.Second)
			startupErr = errors.Join(startupErr, container.Terminate(terminateCtx))
			terminateCancel()
		}
		return fmt.Errorf("%s: start conformance container: %w%s", definition.ID, errors.Join(err, startupErr), dockerBuildHint(err))
	}
	defer func() {
		terminateCtx, terminateCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer terminateCancel()
		if err := container.Terminate(terminateCtx); err != nil {
			returnedErr = errors.Join(returnedErr, fmt.Errorf("%s: terminate container: %w", definition.ID, err))
		}
	}()

	stage(definition.ID, "copy test artifacts")
	artifactCtx, artifactCancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer artifactCancel()

	// The wrapper writes exit-code after the test binary returns, even when the
	// process was terminated by SIGILL/SIGSEGV. Read that durable status first so
	// a missing log never hides the native crash.
	exitPath := filepath.Join(providerOutput, "exit-code")
	if err := copyArtifact(artifactCtx, container, "/reports/exit-code", exitPath); err != nil {
		return fmt.Errorf("%s: copy exit-code: %w", definition.ID, err)
	}
	exitData, err := os.ReadFile(exitPath)
	if err != nil {
		return err
	}
	exitCode, err := strconv.Atoi(strings.TrimSpace(string(exitData)))
	if err != nil {
		return fmt.Errorf("%s: invalid exit-code report %q: %w", definition.ID, exitData, err)
	}

	logPath := filepath.Join(providerOutput, "container.log")
	if err := writeContainerLogs(artifactCtx, container, logPath); err != nil {
		fmt.Fprintf(os.Stderr, "p11containers: warning: %s: save logs: %v\n", definition.ID, err)
	}

	if err := copyArtifact(artifactCtx, container, "/reports/test.log", filepath.Join(providerOutput, "test.log")); err != nil && exitCode == 0 {
		return fmt.Errorf("%s: copy successful test log: %w", definition.ID, err)
	}

	fmt.Fprintf(os.Stderr, "p11containers: provider=%s reports=%s exit=%d\n", definition.ID, providerOutput, exitCode)
	if exitCode != 0 {
		return fmt.Errorf("%s: conformance process exited with code %d (logs: %s; reports: %s)", definition.ID, exitCode, logPath, providerOutput)
	}
	return nil
}

type prefixedLogConsumer struct {
	provider string
	mu       sync.Mutex
}

func (consumer *prefixedLogConsumer) Accept(log testcontainers.Log) {
	consumer.mu.Lock()
	defer consumer.mu.Unlock()
	content := strings.TrimRight(string(log.Content), "\r\n")
	for line := range strings.SplitSeq(content, "\n") {
		if line != "" {
			fmt.Fprintf(os.Stderr, "p11containers: %s: %s\n", consumer.provider, line)
		}
	}
}

func stage(provider, message string) {
	fmt.Fprintf(os.Stderr, "p11containers: %s: %s\n", provider, message)
}

func parseOCIPlatform(value string) (ocispec.Platform, error) {
	parts := strings.Split(strings.ToLower(strings.TrimSpace(value)), "/")
	if len(parts) != 2 && len(parts) != 3 {
		return ocispec.Platform{}, fmt.Errorf("platform %q must use os/arch[/variant]", value)
	}
	platform := ocispec.Platform{OS: parts[0], Architecture: parts[1]}
	if len(parts) == 3 {
		platform.Variant = parts[2]
	}
	if platform.OS == "" || platform.Architecture == "" || (len(parts) == 3 && platform.Variant == "") {
		return ocispec.Platform{}, fmt.Errorf("platform %q contains an empty component", value)
	}
	return platform, nil
}

func freshBuildOptions(options *client.ImageBuildOptions) {
	options.NoCache = true
	options.PullParent = true
}

func platformBuildArguments(contextRoot, dockerfile, image, backend, platformValue string, refresh bool) ([]string, error) {
	platform, err := parseOCIPlatform(platformValue)
	if err != nil {
		return nil, err
	}
	canonicalPlatform := platform.OS + "/" + platform.Architecture
	if platform.Variant != "" {
		canonicalPlatform += "/" + platform.Variant
	}
	arguments := []string{
		"buildx", "build", "--load",
		"--platform", canonicalPlatform,
		"--build-arg", "PKCS11_BACKEND=" + backend,
		"--tag", image,
		"--file", filepath.Join(contextRoot, filepath.FromSlash(dockerfile)),
	}
	if refresh {
		arguments = append(arguments, "--no-cache", "--pull")
	}
	return append(arguments, contextRoot), nil
}

func buildPlatformImage(ctx context.Context, contextRoot, dockerfile, image, backend, platformValue string, refresh, buildLogs bool) error {
	arguments, err := platformBuildArguments(contextRoot, dockerfile, image, backend, platformValue, refresh)
	if err != nil {
		return err
	}
	command := exec.CommandContext(ctx, "docker", arguments...)
	if buildLogs {
		command.Stdout = os.Stderr
		command.Stderr = os.Stderr
		return command.Run()
	}
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Run(); err != nil {
		return fmt.Errorf("docker %s: %w\n%s", strings.Join(arguments, " "), err, strings.TrimSpace(output.String()))
	}
	return nil
}

func sanitizeImageComponent(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var builder strings.Builder
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			builder.WriteRune(r)
		} else {
			builder.WriteByte('-')
		}
	}
	if builder.Len() == 0 {
		return "provider"
	}
	return builder.String()
}

func normalizeNativeBackend(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "cgo", "purego":
		return value, nil
	default:
		return "", fmt.Errorf("native backend %q must be cgo or purego", value)
	}
}

func resolveNativeBackend(value, legacy string) (string, error) {
	value = strings.TrimSpace(value)
	legacy = strings.TrimSpace(legacy)
	if value == "" && legacy == "" {
		return "cgo", nil
	}
	if value == "" {
		return normalizeNativeBackend(legacy)
	}
	selected, err := normalizeNativeBackend(value)
	if err != nil {
		return "", err
	}
	if legacy == "" {
		return selected, nil
	}
	deprecated, err := normalizeNativeBackend(legacy)
	if err != nil {
		return "", err
	}
	if deprecated != selected {
		return "", fmt.Errorf("-backend %q conflicts with -native-backend %q", selected, deprecated)
	}
	return selected, nil
}

func backendOutputDirectory(root, provider, backend string) string {
	return filepath.Join(root, provider, backend)
}

func captureStartupFailure(provider, output string, container testcontainers.Container) error {
	if container == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var errs []error
	logPath := filepath.Join(output, "startup-container.log")
	if err := writeContainerLogs(ctx, container, logPath); err != nil {
		errs = append(errs, fmt.Errorf("save startup logs: %w", err))
	} else {
		fmt.Fprintf(os.Stderr, "p11containers: %s: startup logs saved to %s\n", provider, logPath)
	}
	if state, err := container.State(ctx); err == nil && state != nil {
		fmt.Fprintf(os.Stderr, "p11containers: %s: container state running=%t exit=%d error=%q\n", provider, state.Running, state.ExitCode, state.Error)
	} else if err != nil {
		errs = append(errs, fmt.Errorf("inspect startup state: %w", err))
	}
	return errors.Join(errs...)
}

func dockerBuildHint(err error) string {
	if isDockerCacheFailure(err) {
		return "\nDocker still reports an inconsistent build cache after an automatic cache-free retry. Run `docker buildx prune -af` (or `docker builder prune -af`), restart Docker Desktop if needed, then retry."
	}
	return ""
}

func isDockerCacheFailure(err error) bool {
	return isMissingDockerContent(err) || isPlatformCacheMismatch(err)
}

func isMissingDockerContent(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "content digest") && strings.Contains(message, "not found")
}

func isPlatformCacheMismatch(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "does not provide") && strings.Contains(message, "specified platform")
}

func copyArtifact(ctx context.Context, container testcontainers.Container, source, destination string) error {
	reader, err := container.CopyFileFromContainer(ctx, source)
	if err != nil {
		return err
	}
	defer func() { _ = reader.Close() }()
	file, err := os.Create(destination)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(file, reader)
	closeErr := file.Close()
	return errors.Join(copyErr, closeErr)
}

func writeContainerLogs(ctx context.Context, container testcontainers.Container, destination string) error {
	reader, err := container.Logs(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = reader.Close() }()
	file, err := os.Create(destination)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(file, reader)
	closeErr := file.Close()
	return errors.Join(copyErr, closeErr)
}

func findRepositoryRoot() (string, error) {
	current, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		data, readErr := os.ReadFile(filepath.Join(current, "go.mod"))
		if readErr == nil && isRootModule(data) {
			return current, nil
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", errors.New("could not locate github.com/otpki/pkcs11 repository root")
		}
		current = parent
	}
}

func isRootModule(data []byte) bool {
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		return line == "module github.com/otpki/pkcs11"
	}
	return false
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "p11containers:", err)
	os.Exit(1)
}
