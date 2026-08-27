package zorealoauth2

// The offline test provider: an httptest.Server standing in for the ZOREAL
// OpenID Provider. It serves a JWKS for a P-256 key generated per test, and
// whatever /token and /userinfo handlers the test assigns. Nothing in the
// test suite touches the network.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const testClientID = "ast_test_client"

type provider struct {
	t   *testing.T
	srv *httptest.Server

	mu          sync.Mutex
	key         *ecdsa.PrivateKey
	kid         string
	jwksFetches int
	token       http.HandlerFunc
	userinfo    http.HandlerFunc
}

func newProvider(t *testing.T) *provider {
	t.Helper()
	p := &provider{t: t, kid: "test-key-1", key: newECKey(t)}

	mux := http.NewServeMux()
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		p.mu.Lock()
		p.jwksFetches++
		body := jwksBody(&p.key.PublicKey, p.kid)
		p.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		handler := p.token
		p.mu.Unlock()
		if handler == nil {
			http.NotFound(w, r)
			return
		}
		handler(w, r)
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		handler := p.userinfo
		p.mu.Unlock()
		if handler == nil {
			http.NotFound(w, r)
			return
		}
		handler(w, r)
	})

	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	return p
}

func (p *provider) issuer() string { return p.srv.URL }

func (p *provider) setToken(h http.HandlerFunc)    { p.mu.Lock(); p.token = h; p.mu.Unlock() }
func (p *provider) setUserinfo(h http.HandlerFunc) { p.mu.Lock(); p.userinfo = h; p.mu.Unlock() }

func (p *provider) fetchCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.jwksFetches
}

// rotate replaces the provider's signing key and kid, as a key rotation
// would, returning the new private key.
func (p *provider) rotate(kid string) *ecdsa.PrivateKey {
	key := newECKey(p.t)
	p.mu.Lock()
	p.key = key
	p.kid = kid
	p.mu.Unlock()
	return key
}

// client builds a public client against this provider.
func (p *provider) client(t *testing.T) *Client {
	t.Helper()
	c, err := NewClient(Config{ClientID: testClientID, Issuer: p.issuer()})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

// sign issues an ID token with the provider's current key and kid.
func (p *provider) sign(claims jwt.MapClaims) string {
	p.mu.Lock()
	key, kid := p.key, p.kid
	p.mu.Unlock()
	return signES256(p.t, key, kid, claims)
}

// baseClaims is a valid ID token claim set for this provider; overrides
// replace individual claims.
func (p *provider) baseClaims(overrides map[string]any) jwt.MapClaims {
	claims := jwt.MapClaims{
		"iss":   p.issuer(),
		"sub":   "7QK3-9F2M-XR84-B5NP",
		"aud":   testClientID,
		"exp":   time.Now().Add(2 * time.Minute).Unix(),
		"iat":   time.Now().Unix(),
		"nonce": "n-1",
		"acr":   "zoreal.device",
	}
	for k, v := range overrides {
		claims[k] = v
	}
	return claims
}

// serveTokenSuccess answers every /token call with a fixed token response.
func (p *provider) serveTokenSuccess(idToken, accessToken, scope string) {
	p.setToken(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id_token":     idToken,
			"access_token": accessToken,
			"token_type":   "Bearer",
			"expires_in":   600,
			"scope":        scope,
		})
	})
}

func newECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-256 key: %v", err)
	}
	return key
}

func signES256(t *testing.T, key *ecdsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	if kid != "" {
		token.Header["kid"] = kid
	}
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}

func jwksBody(pub *ecdsa.PublicKey, kid string) []byte {
	x := base64.RawURLEncoding.EncodeToString(pub.X.FillBytes(make([]byte, 32)))
	y := base64.RawURLEncoding.EncodeToString(pub.Y.FillBytes(make([]byte, 32)))
	return []byte(fmt.Sprintf(
		`{"keys":[{"kty":"EC","crv":"P-256","kid":%q,"use":"sig","alg":"ES256","x":%q,"y":%q}]}`,
		kid, x, y))
}
