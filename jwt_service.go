package jwt

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type JwtContext struct {
	echo.Context
	Token      jwt.Token
	UniqueName string
	EmailHash  string
	Roles      []string
}

func (m *JwtValidatorMiddleware) JwtParseMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		jws, err := GetJWSFromRequest(c.Request())
		if err != nil {
			return m.getHttpError(fmt.Errorf("getting jws: %w", err))
		}

		token, err := m.jwtValidator.Validate(jws)
		if err != nil {
			return m.getHttpError(fmt.Errorf("failed to validate JWT token: %s\n", err))
		}
		uniqueName := ""
		if val, ok := token.PrivateClaims()["unique_name"]; ok {
			uniqueName = val.(string)
		}
		emailHash := ""
		if val, ok := token.PrivateClaims()["email_hash"]; ok {
			emailHash = val.(string)
		}
		roles := make([]string, 0)
		if val, ok := token.PrivateClaims()["role"]; ok {
			roleClaims := val.([]interface{})
			for _, v := range roleClaims {
				roles = append(roles, v.(string))
			}
		}
		cc := &JwtContext{c, token, uniqueName, emailHash, roles}
		return next(cc)
	}

}

func (m *JwtValidatorMiddleware) getHttpError(err error) *echo.HTTPError {
	message := fmt.Sprintf("validating JWS: %s", err)
	httpErr := echo.HTTPError{
		Code:     401,
		Message:  message,
		Internal: err,
	}
	return &httpErr
}

type JwtValidatorMiddleware struct {
	jwtValidator JwtValidatorInterface
}

func NewJwtValidatorMiddleware(jwtValidator JwtValidatorInterface) *JwtValidatorMiddleware {
	return &JwtValidatorMiddleware{jwtValidator}
}

// GetJWSFromRequest extracts a JWS string from an Authorization: Bearer <jws> header
func GetJWSFromRequest(req *http.Request) (string, error) {
	authHdr := req.Header.Get("Authorization")
	// Check for the Authorization header.
	if authHdr == "" {
		return "", errors.New("no auth")
	}
	// We expect a header value of the form "Bearer <token>", with 1 space after
	// Bearer, per spec.
	prefix := "Bearer "
	if !strings.HasPrefix(authHdr, prefix) {
		return "", errors.New("invalide auth header")
	}
	return strings.TrimPrefix(authHdr, prefix), nil
}
