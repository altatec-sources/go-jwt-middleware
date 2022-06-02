package jwt

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
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

const UniqueName string = "unique_name"
const EmailHash string = "email_hash"
const Role string = "role"
const Unauthorized int = 401

func contains(s []string, searchterm string) bool {
	for _, regex := range s {
		matched, _ := regexp.MatchString(regex, searchterm)
		if matched {
			return true
		}
	}
	return false
}
func (m *JwtValidatorMiddleware) JwtParseMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		req := c.Request()
		path := req.URL.Path
		method := req.Method
		secureMethods, ok := m.routeMap[method]
		if !ok {
			return next(c)
		}
		if !contains(secureMethods, path) {
			return next(c)
		}

		jws, err := GetJWSFromRequest(c.Request())
		if err != nil {
			return m.getHttpError(fmt.Errorf("getting jws: %w", err), Unauthorized)
		}

		token, err := m.jwtValidator.Validate(jws)
		if err != nil {
			return m.getHttpError(fmt.Errorf("failed to validate JWT token: %s\n", err), Unauthorized)
		}
		uniqueName := ""
		if val, ok := token.PrivateClaims()[UniqueName]; ok {
			uniqueName = val.(string)
		}
		emailHash := ""
		if val, ok := token.PrivateClaims()[EmailHash]; ok {
			emailHash = val.(string)
		}
		roles := make([]string, 0)
		if val, ok := token.PrivateClaims()[Role]; ok {
			roleClaims := val.([]interface{})
			for _, v := range roleClaims {
				roles = append(roles, v.(string))
			}
		}
		cc := &JwtContext{c, token, uniqueName, emailHash, roles}
		return next(cc)
	}
}

func (m *JwtValidatorMiddleware) getHttpError(err error, code int) *echo.HTTPError {
	message := fmt.Sprintf("validating JWS: %s", err)
	httpErr := echo.HTTPError{
		Code:     code,
		Message:  message,
		Internal: err,
	}
	return &httpErr
}

type JwtValidatorMiddleware struct {
	jwtValidator JwtValidatorInterface
	routeMap     map[string][]string
}

func NewJwtValidatorMiddleware(jwtValidator JwtValidatorInterface, routeMap map[string][]string) *JwtValidatorMiddleware {
	return &JwtValidatorMiddleware{jwtValidator, routeMap}
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
