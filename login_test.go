package zorealoauth2

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
)

func TestUserinfoReturnsTheClaims(t *testing.T) {
	p := newProvider(t)
	c := p.client(t)
	p.setUserinfo(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer at-1" {
			t.Errorf("Authorization = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"sub":"7QK3-9F2M-XR84-B5NP","email":"holder@example.com","email_verified":true}`))
	})

	claims, err := c.Userinfo(context.Background(), "at-1")
	if err != nil {
		t.Fatalf("Userinfo: %v", err)
	}
	if claims["email"] != "holder@example.com" {
		t.Fatalf("claims = %v", claims)
	}
}

func TestUserinfoRefusalMapsToUserinfoError(t *testing.T) {
	p := newProvider(t)
	c := p.client(t)
	p.setUserinfo(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="the access token is not valid"`)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_token","error_description":"the access token is not valid"}`))
	})

	_, err := c.Userinfo(context.Background(), "at-expired")
	var uerr *UserinfoError
	if !errors.As(err, &uerr) {
		t.Fatalf("expected *UserinfoError, got %T: %v", err, err)
	}
	if uerr.Status != http.StatusUnauthorized || uerr.Description != "the access token is not valid" {
		t.Fatalf("UserinfoError = %+v", uerr)
	}
}

func TestLoginFetchesUserinfoOnceAndMemoizes(t *testing.T) {
	p := newProvider(t)
	c := p.client(t)
	var mu sync.Mutex
	calls := 0
	p.setUserinfo(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"sub":"s","email":"holder@example.com","email_verified":true,` +
			`"name":"ANNA MARIA LINDQVIST","given_name":"ANNA MARIA","family_name":"LINDQVIST",` +
			`"birthdate":"1993-04-12","document_type":"passport","document_number":"X1234567",` +
			`"issuing_country":"SWE","document_expires_on":"2031-04-11"}`))
	})

	login := &Login{client: c, Claims: map[string]any{"sub": "s"}, AccessToken: "at-1"}
	ctx := context.Background()

	email, err := login.Email(ctx)
	if err != nil || email != "holder@example.com" {
		t.Fatalf("Email = %q, %v", email, err)
	}
	verified, err := login.EmailVerified(ctx)
	if err != nil || !verified {
		t.Fatalf("EmailVerified = %v, %v", verified, err)
	}
	name, _ := login.Name(ctx)
	given, _ := login.GivenName(ctx)
	family, _ := login.FamilyName(ctx)
	birthdate, _ := login.Birthdate(ctx)
	docType, _ := login.DocumentType(ctx)
	docNumber, _ := login.DocumentNumber(ctx)
	country, _ := login.IssuingCountry(ctx)
	expires, _ := login.DocumentExpiresOn(ctx)
	portrait, _ := login.Portrait(ctx)
	if name != "ANNA MARIA LINDQVIST" || given != "ANNA MARIA" || family != "LINDQVIST" ||
		birthdate != "1993-04-12" || docType != "passport" || docNumber != "X1234567" ||
		country != "SWE" || expires != "2031-04-11" {
		t.Fatalf("userinfo accessors: %q %q %q %q %q %q %q %q",
			name, given, family, birthdate, docType, docNumber, country, expires)
	}
	// The provider does not serve the portrait claim yet.
	if portrait != "" {
		t.Fatalf("portrait = %q", portrait)
	}

	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Fatalf("userinfo was fetched %d times, want 1", calls)
	}
}

func TestLoginWithoutAnAccessTokenNeverFetches(t *testing.T) {
	p := newProvider(t)
	c := p.client(t)
	p.setUserinfo(func(http.ResponseWriter, *http.Request) {
		t.Error("userinfo was fetched without an access token")
	})

	login := &Login{client: c, Claims: map[string]any{"sub": "s"}}
	info, err := login.Userinfo(context.Background())
	if err != nil {
		t.Fatalf("Userinfo: %v", err)
	}
	if len(info) != 0 {
		t.Fatalf("Userinfo = %v, want empty", info)
	}
	email, err := login.Email(context.Background())
	if err != nil || email != "" {
		t.Fatalf("Email = %q, %v", email, err)
	}
}

func TestLoginUserinfoFailureIsNotMemoized(t *testing.T) {
	p := newProvider(t)
	c := p.client(t)
	p.setUserinfo(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	login := &Login{client: c, Claims: map[string]any{"sub": "s"}, AccessToken: "at-1"}
	if _, err := login.Userinfo(context.Background()); err == nil {
		t.Fatal("expected the first fetch to fail")
	}

	p.setUserinfo(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"sub":"s","email":"holder@example.com"}`))
	})
	info, err := login.Userinfo(context.Background())
	if err != nil {
		t.Fatalf("the retry after a failure did not fetch: %v", err)
	}
	if info["email"] != "holder@example.com" {
		t.Fatalf("Userinfo = %v", info)
	}
}

func TestLoginReadsTheIDTokenClaims(t *testing.T) {
	login := &Login{Claims: map[string]any{
		"sub":         "7QK3-9F2M-XR84-B5NP",
		"acr":         "zoreal.live",
		"amr":         []any{"hwk", "face", "user"},
		"zoreal":      map[string]any{"trust_tier": "high", "verified_on": "2026-07"},
		"age_over_18": true,
		"nationality": "SWE",
	}}

	if login.Sub() != "7QK3-9F2M-XR84-B5NP" {
		t.Fatalf("Sub = %q", login.Sub())
	}
	if login.ACR() != "zoreal.live" {
		t.Fatalf("ACR = %q", login.ACR())
	}
	if amr := login.AMR(); len(amr) != 3 || amr[0] != "hwk" {
		t.Fatalf("AMR = %v", amr)
	}
	if login.Assurance()["trust_tier"] != "high" {
		t.Fatalf("Assurance = %v", login.Assurance())
	}
	if over, ok := login.AgeOver(18); !ok || !over {
		t.Fatalf("AgeOver(18) = %v, %v", over, ok)
	}
	// 21 was never registered for this client: absent, which is a different
	// fact from false.
	if _, ok := login.AgeOver(21); ok {
		t.Fatal("AgeOver(21) reported a claim that is not there")
	}
	if login.Nationality() != "SWE" {
		t.Fatalf("Nationality = %q", login.Nationality())
	}
}

func TestLoginACRConveniences(t *testing.T) {
	live := &Login{Claims: map[string]any{"acr": "zoreal.live"}}
	if !live.Live() {
		t.Fatal("Live() = false for acr zoreal.live")
	}
	if !live.SatisfiesACR(ACRDevice) || !live.SatisfiesACR(ACRLive) {
		t.Fatal("a live login must satisfy device and live")
	}
	if live.SatisfiesACR("made.up") {
		t.Fatal("an unknown required value must satisfy nothing")
	}

	device := &Login{Claims: map[string]any{"acr": "zoreal.device"}}
	if device.Live() {
		t.Fatal("Live() = true for acr zoreal.device")
	}
	if device.SatisfiesACR(ACRLive) {
		t.Fatal("a device login must not satisfy live")
	}
	if !device.SatisfiesACR(ACRSession) {
		t.Fatal("a device login must satisfy session")
	}

	unknown := &Login{Claims: map[string]any{"acr": "made.up"}}
	if unknown.SatisfiesACR(ACRSession) {
		t.Fatal("an acr outside the vocabulary must satisfy nothing")
	}
}
