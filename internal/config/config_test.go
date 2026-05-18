package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadEndpointTokenPrefersFile(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("from-file\n"), 0o600); err != nil {
		t.Fatalf("failed to write token file: %v", err)
	}
	t.Setenv("TEST_ENDPOINT_TOKEN", "from-env")
	t.Setenv("TEST_ENDPOINT_TOKEN_FILE", tokenFile)

	got := loadEndpointToken("TEST_ENDPOINT_TOKEN", "TEST_ENDPOINT_TOKEN_FILE", "fallback")
	if got != "from-file" {
		t.Fatalf("expected file token, got %q", got)
	}
}

func TestLoadEndpointTokenRejectsConfiguredMissingFile(t *testing.T) {
	t.Setenv("TEST_ENDPOINT_TOKEN", "from-env")
	t.Setenv("TEST_ENDPOINT_TOKEN_FILE", filepath.Join(t.TempDir(), "missing"))

	got := loadEndpointToken("TEST_ENDPOINT_TOKEN", "TEST_ENDPOINT_TOKEN_FILE", "fallback")
	if got == "" || got == "from-env" || got == "fallback" {
		t.Fatalf("expected invalid non-fallback token, got %q", got)
	}
}

func TestLoadEndpointTokenFallsBackWhenNoFileConfigured(t *testing.T) {
	t.Setenv("TEST_ENDPOINT_TOKEN", "")
	t.Setenv("TEST_ENDPOINT_TOKEN_FILE", "")

	got := loadEndpointToken("TEST_ENDPOINT_TOKEN", "TEST_ENDPOINT_TOKEN_FILE", "fallback")
	if got != "fallback" {
		t.Fatalf("expected fallback token, got %q", got)
	}
}
