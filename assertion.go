package zorealoauth2

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// The provider rejects an assertion whose exp is more than 60 seconds out
// (and an iat more than 60 seconds back). An assertion is proof for one
// request, not a bearer credential, so the window is the cap, not a choice.
const clientAssertionLifetime = 60 * time.Second

// clientAssertion builds and signs the private_key_jwt assertion (RFC 7523):
// iss and sub are the client_id, aud is the token endpoint, exp is now+60s,
// and jti is fresh random per assertion because the provider enforces single
// use. ES256 for a P-256 key, RS256 for an RSA key; the kid header is set
// when the configuration names one.
func (c *Client) clientAssertion() (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": c.clientID,
		"sub": c.clientID,
		"aud": c.issuer + "/token",
		"exp": now.Add(clientAssertionLifetime).Unix(),
		"iat": now.Unix(),
		"jti": newJTI(),
	}

	var method jwt.SigningMethod
	switch c.privateKey.(type) {
	case *ecdsa.PrivateKey:
		method = jwt.SigningMethodES256
	case *rsa.PrivateKey:
		method = jwt.SigningMethodRS256
	default:
		// NewClient refuses anything else; this is a guard, not a path.
		return "", fmt.Errorf("unsupported private key type %T", c.privateKey)
	}

	token := jwt.NewWithClaims(method, claims)
	if c.keyID != "" {
		token.Header["kid"] = c.keyID
	}
	return token.SignedString(c.privateKey)
}

func newJTI() string {
	b := make([]byte, 16)
	// crypto/rand.Read does not fail on any supported platform; a jti that
	// could silently repeat would defeat the provider's replay check, so a
	// failure here is a panic, not a fallback.
	if _, err := rand.Read(b); err != nil {
		panic("zorealoauth2: crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
