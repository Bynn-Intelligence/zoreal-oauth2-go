package zorealoauth2

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// The JWKS is parsed here with the standard library rather than a JWKS
// dependency: the provider signs ID tokens with EC P-256 keys and nothing
// else, so the whole grammar this package has to understand is kty EC,
// crv P-256, x, y, kid. Keys of any other shape are skipped, not rejected —
// a provider is free to advertise keys this package will never need.
type jwksSet struct {
	byKid map[string]*ecdsa.PublicKey
	all   []*ecdsa.PublicKey
}

func parseJWKS(data []byte) (*jwksSet, error) {
	var doc struct {
		Keys []struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			Kid string `json:"kid"`
			X   string `json:"x"`
			Y   string `json:"y"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("the JWKS is not valid JSON: %w", err)
	}

	set := &jwksSet{byKid: make(map[string]*ecdsa.PublicKey)}
	for _, k := range doc.Keys {
		if k.Kty != "EC" || k.Crv != "P-256" {
			continue
		}
		x, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			continue
		}
		y, err := base64.RawURLEncoding.DecodeString(k.Y)
		if err != nil {
			continue
		}
		pub := &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(x),
			Y:     new(big.Int).SetBytes(y),
		}
		// ECDH() validates the point is actually on the curve; a coordinate
		// pair that is not gets skipped rather than verified against.
		if _, err := pub.ECDH(); err != nil {
			continue
		}
		set.all = append(set.all, pub)
		if k.Kid != "" {
			set.byKid[k.Kid] = pub
		}
	}
	return set, nil
}

// lookup returns the key for a kid, or every key as a set when the token
// carries no kid (the parser then tries each).
func (s *jwksSet) lookup(kid string) (any, bool) {
	if kid != "" {
		key, ok := s.byKid[kid]
		return key, ok
	}
	if len(s.all) == 0 {
		return nil, false
	}
	keys := make([]jwt.VerificationKey, len(s.all))
	for i, k := range s.all {
		keys[i] = k
	}
	return jwt.VerificationKeySet{Keys: keys}, true
}

// signingKey resolves the verification key for a token header. An unknown kid
// invalidates the cache and refetches ONCE — a provider key rotation must not
// strand logins for the cache TTL, and one refetch is all a rotation can
// need; refetching per failure would let a forged kid hammer the endpoint.
func (c *Client) signingKey(ctx context.Context, kid string) (any, error) {
	set, err := c.jwks(ctx, false)
	if err != nil {
		return nil, err
	}
	if key, ok := set.lookup(kid); ok {
		return key, nil
	}
	set, err = c.jwks(ctx, true)
	if err != nil {
		return nil, err
	}
	if key, ok := set.lookup(kid); ok {
		return key, nil
	}
	return nil, &VerificationError{Reason: "no key in the provider JWKS matches the ID token"}
}

// jwks returns the cached key set, fetching {issuer}/jwks when the cache is
// empty, expired, or force-invalidated by an unknown kid.
func (c *Client) jwks(ctx context.Context, force bool) (*jwksSet, error) {
	c.jwksMu.Lock()
	defer c.jwksMu.Unlock()

	if !force && c.jwksSet != nil && time.Now().Before(c.jwksExpiry) {
		return c.jwksSet, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.issuer+"/jwks", nil)
	if err != nil {
		return nil, &VerificationError{Reason: "could not build the JWKS request", cause: err}
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, &VerificationError{Reason: "could not fetch the provider JWKS", cause: err}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, &VerificationError{Reason: "could not read the provider JWKS", cause: err}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &VerificationError{Reason: fmt.Sprintf("could not fetch the provider JWKS (%d)", resp.StatusCode)}
	}

	set, err := parseJWKS(body)
	if err != nil {
		return nil, &VerificationError{Reason: "could not parse the provider JWKS", cause: err}
	}
	c.jwksSet = set
	c.jwksExpiry = time.Now().Add(c.jwksTTL)
	return set, nil
}
