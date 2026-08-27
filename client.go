package zorealoauth2

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// DefaultIssuer is the production ZOREAL OpenID Provider. Every endpoint this
// package calls is relative to the issuer, and the configured value must match
// the iss inside the tokens exactly — it is compared, not normalized.
const DefaultIssuer = "https://id.zoreal.com"

const (
	defaultTimeout = 10 * time.Second
	// The provider serves its JWKS with a 10-minute public cache; mirroring
	// it here keeps a busy relying party off the endpoint without holding a
	// rotated-out key longer than the provider itself would.
	defaultJWKSTTL = 600 * time.Second
	// Responses are small JSON documents; a cap keeps a misbehaving endpoint
	// from ballooning memory.
	maxResponseBytes = 1 << 20
)

type authMethod int

const (
	authNone authMethod = iota
	authClientSecretBasic
	authPrivateKeyJWT
	authTLSClientAuth
)

// The assurance vocabulary the acr claim speaks, weakest to strongest.
// Verification accepts equal or stronger: a relying party requiring
// ACRDevice is satisfied by a zoreal.live token, never the reverse.
const (
	ACRSession = "zoreal.session"
	ACRDevice  = "zoreal.device"
	ACRLive    = "zoreal.live"
)

// acrOrder ranks the vocabulary. A value outside it has no rank and
// satisfies nothing.
var acrOrder = map[string]int{ACRSession: 0, ACRDevice: 1, ACRLive: 2}

// Config configures a Client. ClientID is required; everything else has a
// default or is one of the four client authentication postures:
//
//   - none: leave ClientSecret, PrivateKey/PrivateKeyPEM and TLSCertificate
//     unset. A public client authenticates with PKCE alone and can only ever
//     have been granted Tier A scopes.
//   - client_secret_basic: set ClientSecret. The secret travels as HTTP
//     Basic, never as a form field.
//   - private_key_jwt: set PrivateKey (an *ecdsa.PrivateKey on P-256, signed
//     ES256, or an *rsa.PrivateKey, signed RS256) or PrivateKeyPEM. KeyID
//     sets the kid header on the assertion when your registered JWKS names
//     one.
//   - tls_client_auth: set TLSCertificate. The certificate and its key ride
//     the TLS handshake on every request this client makes. The provider
//     accepts the method at registration but does not implement it at the
//     token endpoint yet and answers 501; that surfaces as the
//     *ExchangeError it is rather than being papered over.
//
// Set exactly one of the three. Setting more than one is a configuration
// error, because a client that authenticates two ways is a client whose
// registration this package cannot guess.
type Config struct {
	// ClientID is the asset token from the ZOREAL dashboard (ast_...). It is
	// also the OAuth client_id — one value, not two.
	ClientID string

	// Issuer defaults to DefaultIssuer. A trailing slash is trimmed.
	Issuer string

	// ClientSecret selects client_secret_basic.
	ClientSecret string

	// PrivateKey selects private_key_jwt: an *ecdsa.PrivateKey on P-256 or
	// an *rsa.PrivateKey.
	PrivateKey crypto.PrivateKey
	// PrivateKeyPEM is the same key as PEM ("EC PRIVATE KEY", "RSA PRIVATE
	// KEY" or PKCS #8 "PRIVATE KEY" blocks are understood). Set it or
	// PrivateKey, not both.
	PrivateKeyPEM []byte
	// KeyID is the kid the client assertion advertises, when your registered
	// JWKS names one. Optional.
	KeyID string

	// TLSCertificate selects tls_client_auth (mutual TLS).
	TLSCertificate *tls.Certificate

	// HTTPClient replaces the built one. When set, Timeout and
	// TLSCertificate are yours to configure on it; setting TLSCertificate
	// alongside a custom HTTPClient is a configuration error rather than a
	// certificate that silently never rides a handshake.
	HTTPClient *http.Client

	// Timeout bounds every request the built HTTP client makes. Defaults to
	// 10 seconds. Ignored when HTTPClient is set.
	Timeout time.Duration

	// JWKSTTL is how long the fetched provider JWKS is held before it is
	// re-fetched. Defaults to 10 minutes, matching the provider's own cache
	// header. An unknown kid invalidates the cache early, once per
	// verification, so a key rotation never strands a login for the TTL.
	JWKSTTL time.Duration
}

// Client is the relying-party client: one instance per registered ZOREAL
// client, safe for concurrent use, so build it once at boot and share it.
type Client struct {
	clientID     string
	issuer       string
	authMethod   authMethod
	clientSecret string
	privateKey   crypto.PrivateKey
	keyID        string
	httpClient   *http.Client
	jwksTTL      time.Duration

	jwksMu     sync.Mutex
	jwksSet    *jwksSet
	jwksExpiry time.Time
}

// NewClient validates the configuration and builds a Client. Every error it
// returns wraps ErrConfiguration.
func NewClient(cfg Config) (*Client, error) {
	if strings.TrimSpace(cfg.ClientID) == "" {
		return nil, fmt.Errorf("%w: ClientID is required", ErrConfiguration)
	}
	issuer := cfg.Issuer
	if strings.TrimSpace(issuer) == "" {
		issuer = DefaultIssuer
	}
	issuer = strings.TrimRight(issuer, "/")

	c := &Client{
		clientID: cfg.ClientID,
		issuer:   issuer,
		keyID:    cfg.KeyID,
		jwksTTL:  cfg.JWKSTTL,
	}
	if c.jwksTTL <= 0 {
		c.jwksTTL = defaultJWKSTTL
	}

	key, err := resolvePrivateKey(cfg)
	if err != nil {
		return nil, err
	}

	methods := 0
	if cfg.ClientSecret != "" {
		methods++
		c.authMethod = authClientSecretBasic
		c.clientSecret = cfg.ClientSecret
	}
	if key != nil {
		methods++
		c.authMethod = authPrivateKeyJWT
		c.privateKey = key
	}
	if cfg.TLSCertificate != nil {
		methods++
		c.authMethod = authTLSClientAuth
	}
	if methods > 1 {
		return nil, fmt.Errorf("%w: set one client authentication method, not several "+
			"(ClientSecret, PrivateKey/PrivateKeyPEM and TLSCertificate are mutually exclusive)", ErrConfiguration)
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	switch {
	case cfg.HTTPClient != nil && cfg.TLSCertificate != nil:
		return nil, fmt.Errorf("%w: TLSCertificate configures the built HTTP client; "+
			"with your own HTTPClient, put the certificate in its transport's tls.Config instead", ErrConfiguration)
	case cfg.HTTPClient != nil:
		c.httpClient = cfg.HTTPClient
	case cfg.TLSCertificate != nil:
		c.httpClient = &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{Certificates: []tls.Certificate{*cfg.TLSCertificate}},
			},
		}
	default:
		c.httpClient = &http.Client{Timeout: timeout}
	}

	return c, nil
}

// ClientID returns the configured client_id.
func (c *Client) ClientID() string { return c.clientID }

// Issuer returns the configured issuer, without a trailing slash.
func (c *Client) Issuer() string { return c.issuer }

func resolvePrivateKey(cfg Config) (crypto.PrivateKey, error) {
	if cfg.PrivateKey != nil && len(cfg.PrivateKeyPEM) > 0 {
		return nil, fmt.Errorf("%w: set PrivateKey or PrivateKeyPEM, not both", ErrConfiguration)
	}
	key := cfg.PrivateKey
	if len(cfg.PrivateKeyPEM) > 0 {
		parsed, err := parsePrivateKeyPEM(cfg.PrivateKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("%w: PrivateKeyPEM: %v", ErrConfiguration, err)
		}
		key = parsed
	}
	switch k := key.(type) {
	case nil:
		return nil, nil
	case *ecdsa.PrivateKey:
		if k.Curve != elliptic.P256() {
			return nil, fmt.Errorf("%w: the EC private key must be on P-256 (ES256); the provider verifies nothing else for EC keys", ErrConfiguration)
		}
		return k, nil
	case *rsa.PrivateKey:
		return k, nil
	default:
		return nil, fmt.Errorf("%w: the private key must be an *ecdsa.PrivateKey on P-256 or an *rsa.PrivateKey, got %T", ErrConfiguration, key)
	}
}

func parsePrivateKeyPEM(data []byte) (crypto.PrivateKey, error) {
	for block, rest := pem.Decode(data); block != nil; block, rest = pem.Decode(rest) {
		switch block.Type {
		case "EC PRIVATE KEY":
			return x509.ParseECPrivateKey(block.Bytes)
		case "RSA PRIVATE KEY":
			return x509.ParsePKCS1PrivateKey(block.Bytes)
		case "PRIVATE KEY":
			return x509.ParsePKCS8PrivateKey(block.Bytes)
		}
	}
	return nil, fmt.Errorf("no private key block found in the PEM data")
}

// TokenResponse is the provider's answer to a successful code exchange. The
// access token lives ten minutes: read /userinfo while handling the login,
// do not store it for later.
type TokenResponse struct {
	IDToken     string `json:"id_token"`
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
}

// Authenticate is the whole login, in order: exchange the code (with the PKCE
// verifier the browser SDK handed over), verify the ID token against the
// JWKS, check the nonce when the caller has one (pass "" when it does not,
// and know that without the nonce the backend cannot tell a substituted ID
// token from the real one), and — when the caller passes WithRequiredACR —
// refuse a token whose assurance is below it. Returns a Login; personal data
// is NOT fetched here, because the ID token never carries it and not every
// caller wants it — Login.Userinfo fetches on first use.
func (c *Client) Authenticate(ctx context.Context, code, codeVerifier, nonce string, opts ...VerifyOption) (*Login, error) {
	tokens, err := c.Exchange(ctx, code, codeVerifier)
	if err != nil {
		return nil, err
	}
	claims, err := c.VerifyIDToken(ctx, tokens.IDToken, nonce, opts...)
	if err != nil {
		return nil, err
	}
	return &Login{
		client:      c,
		Claims:      claims,
		IDToken:     tokens.IDToken,
		AccessToken: tokens.AccessToken,
		Scope:       tokens.Scope,
	}, nil
}

// Exchange posts the authorization code to {issuer}/token. The verifier is
// mandatory: PKCE is required for every ZOREAL client, and the browser SDK
// that generated it hands it to your frontend precisely so your backend can
// present it here. Client authentication rides along per the configured
// method. Every failure is an *ExchangeError.
func (c *Client) Exchange(ctx context.Context, code, codeVerifier string) (*TokenResponse, error) {
	if strings.TrimSpace(code) == "" {
		return nil, &ExchangeError{OAuthError: "invalid_request", Description: "code is required"}
	}
	if strings.TrimSpace(codeVerifier) == "" {
		return nil, &ExchangeError{OAuthError: "invalid_request", Description: "code_verifier is required"}
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {codeVerifier},
		// The form always carries client_id, whatever the authentication
		// method, because the provider matches the code against it.
		"client_id": {c.clientID},
	}
	if c.authMethod == authPrivateKeyJWT {
		assertion, err := c.clientAssertion()
		if err != nil {
			return nil, &ExchangeError{Description: "could not sign the client assertion", cause: err}
		}
		form.Set("client_assertion_type", clientAssertionType)
		form.Set("client_assertion", assertion)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.issuer+"/token",
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, &ExchangeError{Description: "could not build the token request", cause: err}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if c.authMethod == authClientSecretBasic {
		// client_secret_basic: the secret travels as the Basic password,
		// never as a form field.
		req.SetBasicAuth(c.clientID, c.clientSecret)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, &ExchangeError{Description: "the token request did not complete", cause: err}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, &ExchangeError{Description: "the token response could not be read", Status: resp.StatusCode, cause: err}
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var refusal struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		_ = json.Unmarshal(body, &refusal)
		if refusal.Error == "" {
			refusal.Error = "server_error"
		}
		if refusal.ErrorDescription == "" {
			refusal.ErrorDescription = fmt.Sprintf("the provider answered %d", resp.StatusCode)
		}
		return nil, &ExchangeError{
			OAuthError:  refusal.Error,
			Description: refusal.ErrorDescription,
			Status:      resp.StatusCode,
		}
	}

	var tokens TokenResponse
	if err := json.Unmarshal(body, &tokens); err != nil {
		return nil, &ExchangeError{OAuthError: "server_error",
			Description: "the token response was not valid JSON", Status: resp.StatusCode, cause: err}
	}
	if tokens.IDToken == "" {
		return nil, &ExchangeError{OAuthError: "server_error",
			Description: "no id_token in the token response", Status: resp.StatusCode}
	}
	return &tokens, nil
}

// VerifyOption tightens what Authenticate and VerifyIDToken require of the
// ID token beyond the always-on checks.
type VerifyOption func(*verifyConfig)

type verifyConfig struct {
	requiredACR string
}

// WithRequiredACR sets the assurance floor: the token's acr claim must be
// the required value or a stronger one (ACRSession < ACRDevice < ACRLive),
// or verification refuses the token with a *VerificationError. A required
// value outside the vocabulary is a typo in YOUR code, not a bad token, and
// wraps ErrConfiguration instead of failing every login.
//
// REQUESTING an assurance on the wire (the browser SDK's acr_values) is
// advisory; the signed acr claim is the proof, and this option is where a
// relying party that asked for a liveness check verifies it actually
// happened. An RP that requires zoreal.live and never passes this option has
// checked nothing.
func WithRequiredACR(required string) VerifyOption {
	return func(v *verifyConfig) { v.requiredACR = required }
}

// verifyACR: equal or stronger satisfies; anything else — weaker, missing,
// or a value outside the vocabulary — is refused. An unknown REQUIREMENT is
// a caller bug and says so plainly rather than failing every login.
func verifyACR(claims map[string]any, required string) error {
	requiredRank, known := acrOrder[required]
	if !known {
		return fmt.Errorf("%w: unknown required acr %q; supported: %s, %s, %s",
			ErrConfiguration, required, ACRSession, ACRDevice, ACRLive)
	}
	actual, _ := claims["acr"].(string)
	if actualRank, ok := acrOrder[actual]; ok && actualRank >= requiredRank {
		return nil
	}
	return &VerificationError{
		Reason: fmt.Sprintf("the ID token says acr %q, below the required %s", actual, required),
	}
}

// VerifyIDToken checks the compact JWT against the provider JWKS: ES256
// signature, exact iss, aud == client_id, exp — and, when the caller passes
// the nonce the SDK generated, the nonce binding, and, with WithRequiredACR,
// the assurance floor. Returns the claims. There is no RS256 fallback on
// purpose: ZOREAL signs ID tokens with nothing else, and accepting a second
// algorithm is how algorithm confusion starts.
func (c *Client) VerifyIDToken(ctx context.Context, idToken, nonce string, opts ...VerifyOption) (map[string]any, error) {
	if strings.TrimSpace(idToken) == "" {
		return nil, &VerificationError{Reason: "no ID token was given"}
	}
	var vc verifyConfig
	for _, opt := range opts {
		opt(&vc)
	}

	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"ES256"}),
		jwt.WithIssuer(c.issuer),
		jwt.WithAudience(c.clientID),
		jwt.WithExpirationRequired(),
	)
	claims := jwt.MapClaims{}
	_, err := parser.ParseWithClaims(idToken, claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		return c.signingKey(ctx, kid)
	})
	if err != nil {
		var already *VerificationError
		if errors.As(err, &already) {
			return nil, already
		}
		return nil, &VerificationError{Reason: err.Error(), cause: err}
	}

	if nonce != "" {
		got, _ := claims["nonce"].(string)
		if got != nonce {
			return nil, &VerificationError{Reason: "the ID token nonce is not the one this login started with"}
		}
	}
	if vc.requiredACR != "" {
		if err := verifyACR(claims, vc.requiredACR); err != nil {
			return nil, err
		}
	}
	return map[string]any(claims), nil
}

// Userinfo reads {issuer}/userinfo with the Bearer access token from the
// exchange. This is the only place personal claims (email, profile.*) are
// served, and the access token lives ten minutes, so call it as part of
// handling the login rather than storing the token for later. Every failure
// is an *UserinfoError.
func (c *Client) Userinfo(ctx context.Context, accessToken string) (map[string]any, error) {
	if strings.TrimSpace(accessToken) == "" {
		return nil, &UserinfoError{Description: "an access token is required"}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.issuer+"/userinfo", nil)
	if err != nil {
		return nil, &UserinfoError{Description: "could not build the userinfo request", cause: err}
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, &UserinfoError{Description: "the userinfo request did not complete", cause: err}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, &UserinfoError{Description: "the userinfo response could not be read", Status: resp.StatusCode, cause: err}
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var refusal struct {
			ErrorDescription string `json:"error_description"`
		}
		_ = json.Unmarshal(body, &refusal)
		description := refusal.ErrorDescription
		if description == "" {
			description = fmt.Sprintf("userinfo answered %d", resp.StatusCode)
		}
		return nil, &UserinfoError{Description: description, Status: resp.StatusCode}
	}

	var userinfoClaims map[string]any
	if err := json.Unmarshal(body, &userinfoClaims); err != nil {
		return nil, &UserinfoError{Description: "the userinfo response was not valid JSON", Status: resp.StatusCode, cause: err}
	}
	return userinfoClaims, nil
}
