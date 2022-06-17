package jwt

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
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
const Anonymous string = "default"
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
		secured := m.isTheMethodSecured(method, path)
		jws, err := m.getJws(c)
		if err != nil {
			if !secured {
				return next(c)
			} else {
				return m.getHttpError(fmt.Errorf("failed to get JWS: %s\n", err), Unauthorized)
			}
		}
		token, err := m.getJwtToken(jws)
		if err != nil {
			return m.getHttpError(fmt.Errorf("failed to get validate token: %s\n", err), Unauthorized)
		}
		cc, err := m.makeContext(c, token)
		if err != nil {
			return m.getHttpError(fmt.Errorf("failed to parse JWT token: %s\n", err), Unauthorized)
		}
		return next(cc)
	}
}

func (m *JwtValidatorMiddleware) isTheMethodSecured(method string, path string) bool {
	secureMethods, ok := m.routeMap[method]
	if !ok {
		return false
	}
	if !contains(secureMethods, path) {
		return false
	}
	return true
}
func (m *JwtValidatorMiddleware) getJwtToken(jws string) (jwt.Token, error) {
	token, err := m.jwtValidator.Validate(jws)
	if err != nil {
		return nil, err
	}
	return token, nil
}

func (m *JwtValidatorMiddleware) getJws(c echo.Context) (string, error) {
	jws, err := GetJWSFromRequest(c.Request())
	if err != nil {
		return "", err
	}
	return jws, nil
}
func (m *JwtValidatorMiddleware) makeContext(c echo.Context, token jwt.Token) (*JwtContext, error) {
	uniqueName := ""
	if val, ok := token.PrivateClaims()[UniqueName]; ok {
		uniqueName = val.(string)
	}
	emailHash := ""
	if val, ok := token.PrivateClaims()[EmailHash]; ok {
		emailHash = val.(string)
	}
	anonymous := 1
	if val, ok := token.PrivateClaims()[Anonymous]; ok {
		if s, ok := val.(string); ok {
			anonymous, _ = strconv.Atoi(s)
		}
	}
	if anonymous == 1 {
		err := errors.New("user has no permissions")
		return nil, err
	}
	roles := make([]string, 0)
	if val, ok := token.PrivateClaims()[Role]; ok {
		if roleClaims, ok := val.([]interface{}); ok {
			for _, v := range roleClaims {
				roles = append(roles, v.(string))
			}
		}
		if oneRole, ok := val.(string); ok {
			roles = append(roles, oneRole)
		}
	}
	cc := &JwtContext{c, token, uniqueName, emailHash, roles}
	return cc, nil
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
