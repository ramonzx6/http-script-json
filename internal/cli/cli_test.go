package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ramonzx6/http-script-json/internal/scanner"
)

func TestVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Main([]string{"--version"}, &stdout, &stderr, strings.NewReader("")); code != 0 {
		t.Fatalf("Main() code = %d, stderr = %q", code, stderr.String())
	}
	if got := stdout.String(); got != "rapid-reset-check dev\n" {
		t.Fatalf("version output = %q", got)
	}
}

func TestHelpWritesToStdout(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Main([]string{"--help"}, &stdout, &stderr, strings.NewReader("")); code != 0 {
		t.Fatalf("Main() code = %d", code)
	}
	if !strings.Contains(stdout.String(), "Usage:") || stderr.Len() != 0 {
		t.Fatalf("stdout = %q, stderr = %q", stdout.String(), stderr.String())
	}
}

func TestInputAndPositionalsAreMutuallyExclusive(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Main([]string{"--input", "-", "example.com"}, &stdout, &stderr, strings.NewReader(`["example.org"]`))
	if code != 2 || !strings.Contains(stderr.String(), "mutually exclusive") {
		t.Fatalf("Main() code = %d, stdout = %q, stderr = %q", code, stdout.String(), stderr.String())
	}
}

func TestJSONReportHasSchemaAndDoesNotLeakInvalidCredentials(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Main([]string{"--format", "json", "https://secret@example.com"}, &stdout, &stderr, strings.NewReader(""))
	if code != 1 {
		t.Fatalf("Main() code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"schema_version": 1`) {
		t.Fatalf("JSON output has no schema: %s", stdout.String())
	}
	if strings.Contains(stdout.String(), "secret") {
		t.Fatalf("JSON output leaked credentials: %s", stdout.String())
	}
}

func TestPolicySkipReturnsIncompleteExitCode(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Main([]string{"127.0.0.1"}, &stdout, &stderr, strings.NewReader(""))
	if code != 1 || !strings.Contains(stdout.String(), "not_scanned_policy") {
		t.Fatalf("Main() code = %d, stdout = %q, stderr = %q", code, stdout.String(), stderr.String())
	}
}

func TestInvalidFormatIsUsageError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Main([]string{"--format", "yaml", "example.com"}, &stdout, &stderr, strings.NewReader(""))
	if code != 2 || !strings.Contains(stderr.String(), "invalid --format") {
		t.Fatalf("Main() code = %d, stdout = %q, stderr = %q", code, stdout.String(), stderr.String())
	}
}

func TestUnknownFlagWritesToStderr(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Main([]string{"--unknown"}, &stdout, &stderr, strings.NewReader(""))
	if code != 2 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "flag provided but not defined") {
		t.Fatalf("Main() code = %d, stdout = %q, stderr = %q", code, stdout.String(), stderr.String())
	}
}

func TestExcessivePositionalTargetCountIsUsageError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	args := make([]string, scanner.MaxTargets+1)
	for index := range args {
		args[index] = "example.com"
	}
	code := Main(args, &stdout, &stderr, strings.NewReader(""))
	if code != 2 || !strings.Contains(stderr.String(), "exceeds the limit") {
		t.Fatalf("Main() code = %d, stdout = %q, stderr = %q", code, stdout.String(), stderr.String())
	}
}
