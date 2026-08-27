package zorealoauth2

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"testing"
)

// captureForm parses and stores what /token received, then answers with a
// minimal valid token response.
func captureForm(p *provider, into *url.Values, authHeader *string) {
	idToken := p.sign(p.baseClaims(nil))
	p.setToken(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		*into = r.PostForm
		*authHeader = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id_token": idToken, "access_token": "at-1",
			"token_type": "Bearer", "expires_in": 600, "scope": "openid",
		})
	})
}

func TestExchangePublicClientAuthenticatesWithPKCEAlone(t *testing.T) {
	p := newProvider(t)
	c := p.client(t)
	var form url.Values
	var auth string
	captureForm(p, &form, &auth)

	tokens, err := c.Exchange(context.Background(), "code-1", "verifier-1")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if tokens.IDToken == "" || tokens.AccessToken != "at-1" {
		t.Fatalf("token response = %+v", tokens)
	}
	if auth != "" {
		t.Fatalf("public client sent an Authorization header: %q", auth)
	}
	for key, want := range map[string]string{
		"grant_type":    "authorization_code",
		"code":          "code-1",
		"code_verifier": "verifier-1",
		"client_id":     testClientID,
	} {
		if got := form.Get(key); got != want {
			t.Fatalf("form[%s] = %q, want %q", key, got, want)
		}
	}
	for _, absent := range []string{"client_secret", "client_assertion", "client_assertion_type"} {
		if form.Has(absent) {
			t.Fatalf("public client sent %s", absent)
		}
	}
}

func TestExchangeClientSecretBasicSendsTheSecretAsBasicAuth(t *testing.T) {
	p := newProvider(t)
	c, err := NewClient(Config{ClientID: testClientID, Issuer: p.issuer(), ClientSecret: "zcs_secret"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	var form url.Values
	var auth string
	captureForm(p, &form, &auth)

	if _, err := c.Exchange(context.Background(), "code-1", "verifier-1"); err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	req, _ := http.NewRequest(http.MethodPost, "http://x", nil)
	req.SetBasicAuth(testClientID, "zcs_secret")
	if auth != req.Header.Get("Authorization") {
		t.Fatalf("Authorization = %q", auth)
	}
	// The form still carries client_id — the provider matches the code
	// against it — and never the secret.
	if got := form.Get("client_id"); got != testClientID {
		t.Fatalf("form[client_id] = %q", got)
	}
	if form.Has("client_secret") {
		t.Fatal("the secret travelled as a form field")
	}
}

func TestExchangeErrorCarriesTheProviderRefusalVerbatim(t *testing.T) {
	p := newProvider(t)
	c := p.client(t)
	p.setToken(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"the code is not valid"}`))
	})

	_, err := c.Exchange(context.Background(), "code-1", "verifier-1")
	var exchErr *ExchangeError
	if !errors.As(err, &exchErr) {
		t.Fatalf("expected *ExchangeError, got %T: %v", err, err)
	}
	if exchErr.OAuthError != "invalid_grant" ||
		exchErr.Description != "the code is not valid" ||
		exchErr.Status != http.StatusBadRequest {
		t.Fatalf("ExchangeError = %+v", exchErr)
	}
}

func TestExchangeSurfacesTheTLSClientAuth501(t *testing.T) {
	p := newProvider(t)
	c := p.client(t)
	p.setToken(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotImplemented)
		_, _ = w.Write([]byte(`{"error":"invalid_request","error_description":"tls_client_auth is not implemented at this endpoint yet; use private_key_jwt or client_secret_basic"}`))
	})

	_, err := c.Exchange(context.Background(), "code-1", "verifier-1")
	var exchErr *ExchangeError
	if !errors.As(err, &exchErr) {
		t.Fatalf("expected *ExchangeError, got %T: %v", err, err)
	}
	if exchErr.Status != http.StatusNotImplemented {
		t.Fatalf("Status = %d, want 501", exchErr.Status)
	}
}

func TestExchangeRefusesAResponseWithoutAnIDToken(t *testing.T) {
	p := newProvider(t)
	c := p.client(t)
	p.setToken(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at-1","token_type":"Bearer"}`))
	})

	_, err := c.Exchange(context.Background(), "code-1", "verifier-1")
	var exchErr *ExchangeError
	if !errors.As(err, &exchErr) {
		t.Fatalf("expected *ExchangeError, got %T: %v", err, err)
	}
	if exchErr.OAuthError != "server_error" || exchErr.Description != "no id_token in the token response" {
		t.Fatalf("ExchangeError = %+v", exchErr)
	}
}

func TestExchangeMapsANonJSONFailure(t *testing.T) {
	p := newProvider(t)
	c := p.client(t)
	p.setToken(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("<html>bad gateway</html>"))
	})

	_, err := c.Exchange(context.Background(), "code-1", "verifier-1")
	var exchErr *ExchangeError
	if !errors.As(err, &exchErr) {
		t.Fatalf("expected *ExchangeError, got %T: %v", err, err)
	}
	if exchErr.OAuthError != "server_error" || exchErr.Status != http.StatusBadGateway {
		t.Fatalf("ExchangeError = %+v", exchErr)
	}
}

func TestExchangeRequiresCodeAndVerifier(t *testing.T) {
	p := newProvider(t)
	c := p.client(t)

	var exchErr *ExchangeError
	if _, err := c.Exchange(context.Background(), "", "verifier-1"); !errors.As(err, &exchErr) {
		t.Fatalf("missing code: got %T: %v", err, err)
	}
	if _, err := c.Exchange(context.Background(), "code-1", ""); !errors.As(err, &exchErr) {
		t.Fatalf("missing verifier: got %T: %v", err, err)
	}
}
