package jwt

import (
	"fmt"

	"github.com/deepmap/oapi-codegen/pkg/ecdsafile"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type JwtValidatorInterface interface {
	Validate(jws string) (jwt.Token, error)
}

type JwtValidator struct {
	publicKeyStr string
	issuer       string
	audience     string
}

var _ JwtValidatorInterface = (*JwtValidator)(nil)

func NewJwtValidator(publicKeyStr string, issuer string, audience string) *JwtValidator {
	return &JwtValidator{publicKeyStr, issuer, audience}
}

func (m *JwtValidator) Validate(jws string) (token jwt.Token, err error) {
	publicKey, err := ecdsafile.LoadEcdsaPublicKey([]byte(m.publicKeyStr))
	if err != nil {
		return nil, fmt.Errorf("failed to load pub key: %s\n", err)
	}
	pubkey, err := jwk.FromRaw(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse pub key: %s\n", err)
	}
	token, err = jwt.Parse([]byte(jws), jwt.WithKey(jwa.ES256, pubkey), jwt.WithAudience(m.audience), jwt.WithIssuer(m.issuer))
	return
}
