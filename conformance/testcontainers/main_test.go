package main

import (
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/moby/moby/client"
	"github.com/otpki/pkcs11/conformance/containerfixture"
)

func testFixtures(t *testing.T) ([]containerfixture.Fixture, map[string]containerfixture.Definition) {
	t.Helper()
	fixtures, definitions, err := containerfixture.Definitions([]containerfixture.Fixture{
		containerfixture.New(containerfixture.Definition{ID: "public-a", Dockerfile: "a/Dockerfile", Timeout: time.Minute, IncludeInAll: true}),
		containerfixture.New(containerfixture.Definition{ID: "public-b", Dockerfile: "b/Dockerfile", Timeout: time.Minute, IncludeInAll: true}),
		containerfixture.New(containerfixture.Definition{ID: "licensed", Dockerfile: "licensed/Dockerfile", Timeout: time.Minute, Licensed: true}),
	})
	if err != nil {
		t.Fatal(err)
	}
	return fixtures, definitions
}

func TestSelectFixtures(t *testing.T) {
	fixtures, definitions := testFixtures(t)
	selected, err := selectFixtures("public-b,public-a", fixtures, definitions)
	if err != nil {
		t.Fatal(err)
	}
	if got := []string{selected[0].Definition().ID, selected[1].Definition().ID}; !reflect.DeepEqual(got, []string{"public-b", "public-a"}) {
		t.Fatalf("selected = %#v", got)
	}
	if _, err := selectFixtures("missing", fixtures, definitions); err == nil {
		t.Fatal("expected unknown provider error")
	}

	all, err := selectFixtures("all", fixtures, definitions)
	if err != nil {
		t.Fatal(err)
	}
	got := []string{all[0].Definition().ID, all[1].Definition().ID}
	if !reflect.DeepEqual(got, []string{"public-a", "public-b"}) {
		t.Fatalf("all = %#v", got)
	}
}

func TestAssetsForFixture(t *testing.T) {
	got := assetsForFixture("vendor-a", map[string]string{
		"runtime":          "/shared/runtime.zip",
		"vendor-a.runtime": "/specific/runtime.zip",
		"vendor-b.runtime": "/other/runtime.zip",
	})
	want := map[string]string{"runtime": "/specific/runtime.zip"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("assets = %#v, want %#v", got, want)
	}
}

func TestKeyValueFlag(t *testing.T) {
	var values keyValueFlag
	if err := values.Set("runtime=/tmp/runtime.zip"); err != nil {
		t.Fatal(err)
	}
	if values["runtime"] != "/tmp/runtime.zip" {
		t.Fatalf("values = %#v", values)
	}
	if err := values.Set("missing-separator"); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestIsRootModule(t *testing.T) {
	tests := []struct {
		data string
		want bool
	}{
		{data: "module github.com/otpki/pkcs11\n\ngo 1.26\n", want: true},
		{data: "module github.com/otpki/pkcs11/conformance/testcontainers\n", want: false},
		{data: "// generated\nmodule github.com/otpki/pkcs11\n", want: true},
	}
	for _, test := range tests {
		if got := isRootModule([]byte(test.data)); got != test.want {
			t.Fatalf("isRootModule(%q) = %t, want %t", test.data, got, test.want)
		}
	}
}

func TestDockerBuildHint(t *testing.T) {
	missing := assertError("build image: NotFound: content digest sha256:abc: not found")
	if !isMissingDockerContent(missing) {
		t.Fatal("expected missing Docker content error")
	}
	platform := assertError(`image with reference sha256:abc was found but does not provide the specified platform (linux/amd64)`)
	if !isPlatformCacheMismatch(platform) || !isDockerCacheFailure(platform) {
		t.Fatal("expected Docker platform cache mismatch")
	}
	hint := dockerBuildHint(missing)
	if hint == "" {
		t.Fatal("expected missing BuildKit blob hint")
	}
	if isMissingDockerContent(nil) {
		t.Fatal("nil error reported as missing Docker content")
	}
	if isPlatformCacheMismatch(nil) {
		t.Fatal("nil error reported as a platform cache mismatch")
	}
	if got := dockerBuildHint(assertError("permission denied")); got != "" {
		t.Fatalf("unexpected hint %q", got)
	}
}

func TestFreshBuildOptions(t *testing.T) {
	options := new(client.ImageBuildOptions)
	freshBuildOptions(options)
	if !options.NoCache || !options.PullParent {
		t.Fatalf("fresh build options = %#v", options)
	}
}

func TestPlatformBuildArguments(t *testing.T) {
	arguments, err := platformBuildArguments("/tmp/context", "vendors/acme/Dockerfile", "acme:test", "purego", " LINUX/AMD64 ", false)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"buildx", "build", "--load",
		"--platform", "linux/amd64",
		"--build-arg", "PKCS11_BACKEND=purego",
		"--tag", "acme:test",
		"--file", filepath.Join("/tmp/context", "vendors/acme/Dockerfile"),
		"/tmp/context",
	}
	if !reflect.DeepEqual(arguments, want) {
		t.Fatalf("arguments = %#v, want %#v", arguments, want)
	}
	refreshed, err := platformBuildArguments("/tmp/context", "Dockerfile", "acme:test", "cgo", "linux/amd64", true)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(refreshed, "--no-cache") || !slices.Contains(refreshed, "--pull") {
		t.Fatalf("refreshed arguments = %#v", refreshed)
	}
}

func TestParseOCIPlatform(t *testing.T) {
	tests := []struct {
		value            string
		wantOS           string
		wantArchitecture string
		wantVariant      string
	}{
		{value: "linux/amd64", wantOS: "linux", wantArchitecture: "amd64"},
		{value: "linux/arm64/v8", wantOS: "linux", wantArchitecture: "arm64", wantVariant: "v8"},
		{value: " LINUX/AMD64 ", wantOS: "linux", wantArchitecture: "amd64"},
	}
	for _, test := range tests {
		got, err := parseOCIPlatform(test.value)
		if err != nil {
			t.Fatalf("parseOCIPlatform(%q): %v", test.value, err)
		}
		if got.OS != test.wantOS || got.Architecture != test.wantArchitecture || got.Variant != test.wantVariant {
			t.Fatalf("parseOCIPlatform(%q) = %#v", test.value, got)
		}
	}
	for _, value := range []string{"", "linux", "linux//v8", "/amd64", "linux/amd64/"} {
		if _, err := parseOCIPlatform(value); err == nil {
			t.Fatalf("parseOCIPlatform(%q) unexpectedly succeeded", value)
		}
	}
}

func TestSanitizeImageComponent(t *testing.T) {
	if got, want := sanitizeImageComponent(" Acme HSM/Simulator "), "acme-hsm-simulator"; got != want {
		t.Fatalf("sanitizeImageComponent = %q, want %q", got, want)
	}
}

func TestNormalizeNativeBackend(t *testing.T) {
	for input, want := range map[string]string{
		"cgo":      "cgo",
		"CGO":      "cgo",
		" purego ": "purego",
	} {
		got, err := normalizeNativeBackend(input)
		if err != nil {
			t.Fatalf("normalizeNativeBackend(%q): %v", input, err)
		}
		if got != want {
			t.Fatalf("normalizeNativeBackend(%q) = %q, want %q", input, got, want)
		}
	}

	for _, input := range []string{"", "auto", "ffi"} {
		if _, err := normalizeNativeBackend(input); err == nil {
			t.Fatalf("normalizeNativeBackend(%q) unexpectedly succeeded", input)
		}
	}
}

func TestResolveNativeBackend(t *testing.T) {
	tests := []struct {
		name   string
		value  string
		legacy string
		want   string
	}{
		{name: "default", want: "cgo"},
		{name: "primary", value: "purego", want: "purego"},
		{name: "deprecated alias", legacy: "purego", want: "purego"},
		{name: "matching flags", value: "CGO", legacy: "cgo", want: "cgo"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := resolveNativeBackend(test.value, test.legacy)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("resolveNativeBackend(%q, %q) = %q, want %q", test.value, test.legacy, got, test.want)
			}
		})
	}

	if _, err := resolveNativeBackend("cgo", "purego"); err == nil {
		t.Fatal("expected conflicting backend flags to fail")
	}
}

func TestBackendOutputDirectory(t *testing.T) {
	got := backendOutputDirectory("reports", "softhsm2", "purego")
	want := filepath.Join("reports", "softhsm2", "purego")
	if got != want {
		t.Fatalf("backendOutputDirectory = %q, want %q", got, want)
	}
}

type assertError string

func (err assertError) Error() string { return string(err) }
