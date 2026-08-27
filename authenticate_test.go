package zorealoauth2

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

func TestAuthenticateRunsTheWholeLogin(t *testing.T) {
	p := newProvider(t)
	c := p.client(t)
	idToken := p.sign(p.baseClaims(map[string]any{
		"nonce":       "n-42",
		"acr":         "zoreal.live",
		"age_over_18": true,
	}))
	p.serveTokenSuccess(idToken, "at-1", "openid email zoreal.age")
	p.setUserinfo(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"sub":"7QK3-9F2M-XR84-B5NP","email":"holder@example.com","email_verified":true}`))
	})

	login, err := c.Authenticate(context.Background(), "code-1", "verifier-1", "n-42")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if login.Sub() != "7QK3-9F2M-XR84-B5NP" || login.ACR() != "zoreal.live" {
		t.Fatalf("login = sub %q acr %q", login.Sub(), login.ACR())
	}
	if login.AccessToken != "at-1" || login.Scope != "openid email zoreal.age" || login.IDToken != idToken {
		t.Fatalf("token response fields: %q %q", login.AccessToken, login.Scope)
	}
	if over, ok := login.AgeOver(18); !ok || !over {
		t.Fatalf("AgeOver(18) = %v, %v", over, ok)
	}
	email, err := login.Email(context.Background())
	if err != nil || email != "holder@example.com" {
		t.Fatalf("Email = %q, %v", email, err)
	}
}

func TestAuthenticateRefusesANonceMismatch(t *testing.T) {
	p := newProvider(t)
	c := p.client(t)
	p.serveTokenSuccess(p.sign(p.baseClaims(map[string]any{"nonce": "n-1"})), "at-1", "openid")

	_, err := c.Authenticate(context.Background(), "code-1", "verifier-1", "n-other")
	assertVerificationError(t, err)
}

func TestAuthenticateSurfacesTheExchangeRefusal(t *testing.T) {
	p := newProvider(t)
	c := p.client(t)
	p.setToken(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"the code is not valid"}`))
	})

	_, err := c.Authenticate(context.Background(), "code-used", "verifier-1", "")
	if err == nil {
		t.Fatal("expected an error")
	}
	var exchErr *ExchangeError
	if !errors.As(err, &exchErr) {
		t.Fatalf("expected *ExchangeError, got %T: %v", err, err)
	}
}
