package zorealoauth2

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// exchangeAndCaptureAssertion runs one exchange with the given client and
// returns the client_assertion the form carried.
func exchangeAndCaptureAssertion(t *testing.T, p *provider, c *Client) string {
	t.Helper()
	var form url.Values
	var auth string
	captureForm(p, &form, &auth)
	if _, err := c.Exchange(context.Background(), "code-1", "verifier-1"); err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if got := form.Get("client_assertion_type"); got != clientAssertionType {
		t.Fatalf("client_assertion_type = %q", got)
	}
	assertion := form.Get("client_assertion")
	if assertion == "" {
		t.Fatal("no client_assertion in the form")
	}
	if auth != "" {
		t.Fatalf("private_key_jwt sent an Authorization header: %q", auth)
	}
	return assertion
}

// decodeAssertion verifies the assertion against the given public key and
// returns its claims and header.
func decodeAssertion(t *testing.T, assertion string, alg string, pub any) (jwt.MapClaims, map[string]any) {
	t.Helper()
	claims := jwt.MapClaims{}
	token, err := jwt.NewParser(jwt.WithValidMethods([]string{alg})).
		ParseWithClaims(assertion, claims, func(*jwt.Token) (any, error) { return pub, nil })
	if err != nil {
		t.Fatalf("the assertion did not verify as %s: %v", alg, err)
	}
	return claims, token.Header
}

func assertAssertionClaims(t *testing.T, p *provider, claims jwt.MapClaims) {
	t.Helper()
	now := time.Now().Unix()
	if got := claims["iss"]; got != testClientID {
		t.Fatalf("iss = %v", got)
	}
	if got := claims["sub"]; got != testClientID {
		t.Fatalf("sub = %v", got)
	}
	if got := claims["aud"]; got != p.issuer()+"/token" {
		t.Fatalf("aud = %v, want %s/token", got, p.issuer())
	}
	exp := int64(claims["exp"].(float64))
	if exp > now+61 || exp <= now {
		t.Fatalf("exp = %d, now = %d: outside the 60-second window", exp, now)
	}
	iat := int64(claims["iat"].(float64))
	if iat > now || iat < now-10 {
		t.Fatalf("iat = %d, now = %d", iat, now)
	}
	if jti, _ := claims["jti"].(string); jti == "" {
		t.Fatal("jti is empty")
	}
}

func TestPrivateKeyJWTAssertionES256(t *testing.T) {
	p := newProvider(t)
	key := newECKey(t)
	c, err := NewClient(Config{
		ClientID: testClientID, Issuer: p.issuer(),
		PrivateKey: key, KeyID: "rp-key-1",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	assertion := exchangeAndCaptureAssertion(t, p, c)
	claims, header := decodeAssertion(t, assertion, "ES256", &key.PublicKey)
	assertAssertionClaims(t, p, claims)
	if got := header["alg"]; got != "ES256" {
		t.Fatalf("alg = %v", got)
	}
	if got := header["kid"]; got != "rp-key-1" {
		t.Fatalf("kid = %v", got)
	}
}

func TestPrivateKeyJWTAssertionRS256FromPEM(t *testing.T) {
	p := newProvider(t)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
	})
	c, err := NewClient(Config{ClientID: testClientID, Issuer: p.issuer(), PrivateKeyPEM: pemBytes})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	assertion := exchangeAndCaptureAssertion(t, p, c)
	claims, header := decodeAssertion(t, assertion, "RS256", &rsaKey.PublicKey)
	assertAssertionClaims(t, p, claims)
	if got := header["alg"]; got != "RS256" {
		t.Fatalf("alg = %v", got)
	}
	if _, present := header["kid"]; present {
		t.Fatal("kid set without a configured KeyID")
	}
}

func TestECKeyAcceptedAsSEC1AndPKCS8PEM(t *testing.T) {
	p := newProvider(t)
	key := newECKey(t)

	sec1, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal SEC1: %v", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal PKCS8: %v", err)
	}

	for name, block := range map[string]*pem.Block{
		"SEC1":  {Type: "EC PRIVATE KEY", Bytes: sec1},
		"PKCS8": {Type: "PRIVATE KEY", Bytes: pkcs8},
	} {
		c, err := NewClient(Config{
			ClientID: testClientID, Issuer: p.issuer(),
			PrivateKeyPEM: pem.EncodeToMemory(block),
		})
		if err != nil {
			t.Fatalf("%s PEM refused: %v", name, err)
		}
		assertion := exchangeAndCaptureAssertion(t, p, c)
		claims, _ := decodeAssertion(t, assertion, "ES256", &key.PublicKey)
		assertAssertionClaims(t, p, claims)
	}
}

func TestAssertionJTIIsFreshPerExchange(t *testing.T) {
	p := newProvider(t)
	key := newECKey(t)
	c, err := NewClient(Config{ClientID: testClientID, Issuer: p.issuer(), PrivateKey: key})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	first, _ := decodeAssertion(t, exchangeAndCaptureAssertion(t, p, c), "ES256", &key.PublicKey)
	second, _ := decodeAssertion(t, exchangeAndCaptureAssertion(t, p, c), "ES256", &key.PublicKey)
	if first["jti"] == second["jti"] {
		t.Fatalf("jti repeated across assertions: %v", first["jti"])
	}
}
