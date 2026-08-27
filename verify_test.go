package zorealoauth2

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestValidTokenVerifiesAndReturnsClaims(t *testing.T) {
	p := newProvider(t)
	c := p.client(t)

	claims, err := c.VerifyIDToken(context.Background(), p.sign(p.baseClaims(nil)), "n-1")
	if err != nil {
		t.Fatalf("VerifyIDToken: %v", err)
	}
	if got := claims["sub"]; got != "7QK3-9F2M-XR84-B5NP" {
		t.Fatalf("sub = %v", got)
	}
	if got := claims["acr"]; got != "zoreal.device" {
		t.Fatalf("acr = %v", got)
	}
}

func TestNonceMismatchIsRefused(t *testing.T) {
	p := newProvider(t)
	c := p.client(t)

	_, err := c.VerifyIDToken(context.Background(), p.sign(p.baseClaims(nil)), "other")
	assertVerificationError(t, err)
}

func TestNonceIsNotCheckedWhenCallerHasNone(t *testing.T) {
	p := newProvider(t)
	c := p.client(t)

	if _, err := c.VerifyIDToken(context.Background(), p.sign(p.baseClaims(nil)), ""); err != nil {
		t.Fatalf("VerifyIDToken without nonce: %v", err)
	}
}

func TestWrongAudienceIsRefused(t *testing.T) {
	p := newProvider(t)
	c := p.client(t)

	token := p.sign(p.baseClaims(map[string]any{"aud": "ast_other"}))
	_, err := c.VerifyIDToken(context.Background(), token, "")
	assertVerificationError(t, err)
}

func TestWrongIssuerIsRefused(t *testing.T) {
	p := newProvider(t)
	c := p.client(t)

	token := p.sign(p.baseClaims(map[string]any{"iss": "https://evil.example"}))
	_, err := c.VerifyIDToken(context.Background(), token, "")
	assertVerificationError(t, err)
}

func TestExpiredTokenIsRefused(t *testing.T) {
	p := newProvider(t)
	c := p.client(t)

	token := p.sign(p.baseClaims(map[string]any{"exp": time.Now().Add(-5 * time.Second).Unix()}))
	_, err := c.VerifyIDToken(context.Background(), token, "")
	assertVerificationError(t, err)
}

func TestMissingExpIsRefused(t *testing.T) {
	p := newProvider(t)
	c := p.client(t)

	claims := p.baseClaims(nil)
	delete(claims, "exp")
	_, err := c.VerifyIDToken(context.Background(), p.sign(claims), "")
	assertVerificationError(t, err)
}

func TestForeignKeyIsRefused(t *testing.T) {
	p := newProvider(t)
	c := p.client(t)

	// Signed by a key the provider JWKS does not hold, under the kid of the
	// key it does: the signature check itself has to catch this.
	foreign := newECKey(t)
	token := signES256(t, foreign, "test-key-1", p.baseClaims(nil))
	_, err := c.VerifyIDToken(context.Background(), token, "")
	assertVerificationError(t, err)
}

func TestNonES256AlgorithmsAreRefused(t *testing.T) {
	p := newProvider(t)
	c := p.client(t)

	// HS256: symmetric, and the classic algorithm-confusion vector.
	hs, err := jwt.NewWithClaims(jwt.SigningMethodHS256, p.baseClaims(nil)).SignedString([]byte("secret"))
	if err != nil {
		t.Fatalf("sign HS256: %v", err)
	}
	_, err = c.VerifyIDToken(context.Background(), hs, "")
	assertVerificationError(t, err)

	// alg none: an unsigned token, crafted by hand because the library
	// rightly makes it hard to build one.
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"` + p.issuer() + `","aud":"` + testClientID + `"}`))
	_, err = c.VerifyIDToken(context.Background(), header+"."+payload+".", "")
	assertVerificationError(t, err)
}

func TestUnknownKidInvalidatesAndRefetchesOnce(t *testing.T) {
	p := newProvider(t)
	c := p.client(t)

	// Warm the cache with the first key.
	if _, err := c.VerifyIDToken(context.Background(), p.sign(p.baseClaims(nil)), ""); err != nil {
		t.Fatalf("warm-up verify: %v", err)
	}
	if got := p.fetchCount(); got != 1 {
		t.Fatalf("jwks fetches after warm-up = %d, want 1", got)
	}

	// Rotate the provider key. The cached set does not know the new kid, so
	// verification must refetch once and then succeed.
	p.rotate("test-key-2")
	if _, err := c.VerifyIDToken(context.Background(), p.sign(p.baseClaims(nil)), ""); err != nil {
		t.Fatalf("verify after rotation: %v", err)
	}
	if got := p.fetchCount(); got != 2 {
		t.Fatalf("jwks fetches after rotation = %d, want 2", got)
	}

	// A kid the provider never advertised: exactly one more refetch, then a
	// refusal — not a retry loop.
	ghost := signES256(t, newECKey(t), "no-such-kid", p.baseClaims(nil))
	_, err := c.VerifyIDToken(context.Background(), ghost, "")
	assertVerificationError(t, err)
	if got := p.fetchCount(); got != 3 {
		t.Fatalf("jwks fetches after unknown kid = %d, want 3", got)
	}
}

func TestJWKSIsCachedBetweenVerifications(t *testing.T) {
	p := newProvider(t)
	c := p.client(t)

	for i := 0; i < 3; i++ {
		if _, err := c.VerifyIDToken(context.Background(), p.sign(p.baseClaims(nil)), ""); err != nil {
			t.Fatalf("verify %d: %v", i, err)
		}
	}
	if got := p.fetchCount(); got != 1 {
		t.Fatalf("jwks fetches = %d, want 1", got)
	}
}

func TestEqualACRSatisfies(t *testing.T) {
	p := newProvider(t)
	c := p.client(t)

	token := p.sign(p.baseClaims(map[string]any{"acr": "zoreal.live"}))
	if _, err := c.VerifyIDToken(context.Background(), token, "", WithRequiredACR("zoreal.live")); err != nil {
		t.Fatalf("VerifyIDToken: %v", err)
	}
}

func TestStrongerACRSatisfies(t *testing.T) {
	p := newProvider(t)
	c := p.client(t)

	token := p.sign(p.baseClaims(map[string]any{"acr": "zoreal.live"}))
	if _, err := c.VerifyIDToken(context.Background(), token, "", WithRequiredACR("zoreal.device")); err != nil {
		t.Fatalf("VerifyIDToken: %v", err)
	}
}

func TestWeakerACRIsRefused(t *testing.T) {
	p := newProvider(t)
	c := p.client(t)

	token := p.sign(p.baseClaims(map[string]any{"acr": "zoreal.device"}))
	_, err := c.VerifyIDToken(context.Background(), token, "", WithRequiredACR("zoreal.live"))
	assertVerificationError(t, err)
	// The refusal names both values — and never the token itself.
	if !strings.Contains(err.Error(), "zoreal.device") || !strings.Contains(err.Error(), "zoreal.live") {
		t.Fatalf("the refusal does not name both acr values: %v", err)
	}
	if strings.Contains(err.Error(), token) {
		t.Fatalf("the refusal leaks the token: %v", err)
	}
}

func TestMissingACRIsRefusedWhenRequired(t *testing.T) {
	p := newProvider(t)
	c := p.client(t)

	claims := p.baseClaims(nil)
	delete(claims, "acr")
	_, err := c.VerifyIDToken(context.Background(), p.sign(claims), "", WithRequiredACR("zoreal.session"))
	assertVerificationError(t, err)
}

func TestUnknownRequiredACRIsACallerBug(t *testing.T) {
	p := newProvider(t)
	c := p.client(t)

	token := p.sign(p.baseClaims(map[string]any{"acr": "zoreal.live"}))
	_, err := c.VerifyIDToken(context.Background(), token, "", WithRequiredACR("zoreal.liveness"))
	if !errors.Is(err, ErrConfiguration) {
		t.Fatalf("expected ErrConfiguration, got %T: %v", err, err)
	}
	var verr *VerificationError
	if errors.As(err, &verr) {
		t.Fatalf("a typo in the requirement must not read as a bad token: %v", err)
	}
}

func TestNoRequiredACRChecksNothing(t *testing.T) {
	p := newProvider(t)
	c := p.client(t)

	claims := p.baseClaims(nil)
	delete(claims, "acr")
	if _, err := c.VerifyIDToken(context.Background(), p.sign(claims), ""); err != nil {
		t.Fatalf("VerifyIDToken without a requirement: %v", err)
	}
}

func assertVerificationError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected a *VerificationError, got nil")
	}
	var verr *VerificationError
	if !errors.As(err, &verr) {
		t.Fatalf("expected a *VerificationError, got %T: %v", err, err)
	}
}
