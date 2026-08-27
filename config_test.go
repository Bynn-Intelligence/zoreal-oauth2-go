package zorealoauth2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"net/http"
	"testing"
)

func TestClientIDIsRequired(t *testing.T) {
	_, err := NewClient(Config{})
	if !errors.Is(err, ErrConfiguration) {
		t.Fatalf("expected ErrConfiguration, got %v", err)
	}
}

func TestIssuerDefaultsAndTrimsTheTrailingSlash(t *testing.T) {
	c, err := NewClient(Config{ClientID: testClientID})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if c.Issuer() != DefaultIssuer {
		t.Fatalf("Issuer = %q", c.Issuer())
	}

	c, err = NewClient(Config{ClientID: testClientID, Issuer: "https://id.zoreal.example/"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if c.Issuer() != "https://id.zoreal.example" {
		t.Fatalf("Issuer = %q", c.Issuer())
	}
}

func TestTwoAuthenticationMethodsAreRefused(t *testing.T) {
	key := newECKey(t)
	_, err := NewClient(Config{
		ClientID: testClientID, ClientSecret: "zcs_secret", PrivateKey: key,
	})
	if !errors.Is(err, ErrConfiguration) {
		t.Fatalf("expected ErrConfiguration, got %v", err)
	}
	_, err = NewClient(Config{
		ClientID: testClientID, ClientSecret: "zcs_secret", TLSCertificate: &tls.Certificate{},
	})
	if !errors.Is(err, ErrConfiguration) {
		t.Fatalf("expected ErrConfiguration, got %v", err)
	}
}

func TestNonP256ECKeyIsRefused(t *testing.T) {
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-384 key: %v", err)
	}
	_, err = NewClient(Config{ClientID: testClientID, PrivateKey: p384})
	if !errors.Is(err, ErrConfiguration) {
		t.Fatalf("expected ErrConfiguration, got %v", err)
	}
}

func TestGarbagePEMIsRefused(t *testing.T) {
	_, err := NewClient(Config{ClientID: testClientID, PrivateKeyPEM: []byte("not a key")})
	if !errors.Is(err, ErrConfiguration) {
		t.Fatalf("expected ErrConfiguration, got %v", err)
	}
}

func TestPrivateKeyAndPEMTogetherAreRefused(t *testing.T) {
	key := newECKey(t)
	_, err := NewClient(Config{
		ClientID: testClientID, PrivateKey: key, PrivateKeyPEM: []byte("x"),
	})
	if !errors.Is(err, ErrConfiguration) {
		t.Fatalf("expected ErrConfiguration, got %v", err)
	}
}

func TestTLSCertificateWithCustomHTTPClientIsRefused(t *testing.T) {
	_, err := NewClient(Config{
		ClientID:       testClientID,
		TLSCertificate: &tls.Certificate{},
		HTTPClient:     &http.Client{},
	})
	if !errors.Is(err, ErrConfiguration) {
		t.Fatalf("expected ErrConfiguration, got %v", err)
	}
}
