package jwt

import (
	"errors"
	"fmt"

	"github.com/deepmap/oapi-codegen/pkg/ecdsafile"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type JwtValidatorInterface interface {
	Validate(jws string) (jwt.Token, error)
}

type issuerKeyConfig struct {
	issuer   string
	audience string
	pubkey   jwk.Key
}

type JwtValidator struct {
	configs map[string]issuerKeyConfig
}

var _ JwtValidatorInterface = (*JwtValidator)(nil)

func NewJwtValidator(publicKeyStr string, issuer string, audience string) *JwtValidator {
	validator, err := NewJwtValidatorFromConfigs([]IssuerConfig{{
		PublicKey: publicKeyStr,
		Issuer:    issuer,
		Audience:  audience,
	}})
	if err != nil {
		return &JwtValidator{configs: make(map[string]issuerKeyConfig)}
	}
	return validator
}

func NewJwtValidatorFromConfigs(configs []IssuerConfig) (*JwtValidator, error) {
	issuerConfigs := make(map[string]issuerKeyConfig)

	for _, cfg := range configs {
		if cfg.Issuer == "" || cfg.PublicKey == "" {
			continue
		}

		pubkey, err := loadPublicKey(cfg.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load pub key for issuer %q: %w", cfg.Issuer, err)
		}

		issuerConfigs[cfg.Issuer] = issuerKeyConfig{
			issuer:   cfg.Issuer,
			audience: cfg.Audience,
			pubkey:   pubkey,
		}
	}

	if len(issuerConfigs) == 0 {
		return nil, errors.New("no valid JWT issuer configs")
	}

	return &JwtValidator{configs: issuerConfigs}, nil
}

func (m *JwtValidator) Validate(jws string) (jwt.Token, error) {
	unverifiedToken, err := jwt.Parse(
		[]byte(jws),
		jwt.WithVerify(false),
		jwt.WithValidate(false),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	issuer := unverifiedToken.Issuer()
	if issuer == "" {
		return nil, errors.New("token has no issuer")
	}

	cfg, ok := m.configs[issuer]
	if !ok {
		return nil, fmt.Errorf("unknown issuer: %s", issuer)
	}

	token, err := jwt.Parse(
		[]byte(jws),
		jwt.WithKey(jwa.ES256, cfg.pubkey),
		jwt.WithAudience(cfg.audience),
		jwt.WithIssuer(cfg.issuer),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to validate token: %w", err)
	}

	return token, nil
}

func loadPublicKey(publicKeyStr string) (jwk.Key, error) {
	publicKey, err := ecdsafile.LoadEcdsaPublicKey([]byte(publicKeyStr))
	if err != nil {
		return nil, fmt.Errorf("failed to load pub key: %w", err)
	}

	pubkey, err := jwk.FromRaw(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse pub key: %w", err)
	}

	return pubkey, nil
}
