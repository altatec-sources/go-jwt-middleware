package jwt

import (
	"testing"
)

const testPublicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYZSJGgd4Pe/36LFdvsFnPI6MonpM
04h1ILMYBT0XWZlqbl16XO3ZZtUM1hDPExHqYDVPGgWyFb5i+1Il6fqjwA==
-----END PUBLIC KEY-----`

func TestNewJwtValidatorFromConfigs_EmptyArray(t *testing.T) {
	_, err := NewJwtValidatorFromConfigs(nil)
	if err == nil {
		t.Fatal("expected error for empty configs")
	}
}

func TestNewJwtValidatorFromConfigs_SkipsInvalidEntries(t *testing.T) {
	_, err := NewJwtValidatorFromConfigs([]IssuerConfig{
		{Issuer: "", PublicKey: testPublicKey, Audience: "aud"},
		{Issuer: "issuer", PublicKey: "", Audience: "aud"},
	})
	if err == nil {
		t.Fatal("expected error when all entries are invalid")
	}
}

func TestNewJwtValidatorFromConfigs_DuplicateIssuerOverwrite(t *testing.T) {
	validator, err := NewJwtValidatorFromConfigs([]IssuerConfig{
		{Issuer: "issuer-a", PublicKey: testPublicKey, Audience: "aud-1"},
		{Issuer: "issuer-a", PublicKey: testPublicKey, Audience: "aud-2"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cfg := validator.configs["issuer-a"]
	if cfg.audience != "aud-2" {
		t.Fatalf("expected last audience to win, got %q", cfg.audience)
	}
}

func TestNewJwtValidator_LegacyConstructor(t *testing.T) {
	validator := NewJwtValidator(testPublicKey, "issuer-a", "aud-1")
	if len(validator.configs) != 1 {
		t.Fatalf("expected one issuer config, got %d", len(validator.configs))
	}
}

func TestValidate_UnknownIssuer(t *testing.T) {
	validator, err := NewJwtValidatorFromConfigs([]IssuerConfig{
		{Issuer: "issuer-a", PublicKey: testPublicKey, Audience: "aud-1"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = validator.Validate("invalid.token.value")
	if err == nil {
		t.Fatal("expected validation error")
	}
}
