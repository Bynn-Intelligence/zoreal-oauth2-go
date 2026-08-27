package zorealoauth2

import (
	"errors"
	"strings"
)

// ErrConfiguration is wrapped by every error NewClient returns for a client
// built without something it cannot work without. Test for it with
// errors.Is(err, zorealoauth2.ErrConfiguration).
var ErrConfiguration = errors.New("zorealoauth2: configuration error")

// ExchangeError is returned when the code exchange at the token endpoint
// fails. OAuthError is the RFC 6749 error code and Description the provider's
// own reason, verbatim: the provider's words are the only signal that says
// WHY (a consumed code, a PKCE mismatch, a lapsed sector), and rewriting them
// would hide it. Status is the HTTP status, or 0 when the request never
// completed; in that case Unwrap carries the transport error, so
// errors.Is(err, context.DeadlineExceeded) and friends keep working.
//
// Token values never appear in the message.
type ExchangeError struct {
	OAuthError  string
	Description string
	Status      int
	cause       error
}

func (e *ExchangeError) Error() string {
	parts := make([]string, 0, 2)
	if e.OAuthError != "" {
		parts = append(parts, e.OAuthError)
	}
	if e.Description != "" {
		parts = append(parts, e.Description)
	}
	if len(parts) == 0 {
		parts = append(parts, "the token exchange failed")
	}
	return "zorealoauth2: " + strings.Join(parts, ": ")
}

func (e *ExchangeError) Unwrap() error { return e.cause }

// VerificationError is returned when the ID token did not verify: bad
// signature, wrong issuer or audience, expired, an algorithm that is not
// ES256, a key the provider JWKS does not hold, or a nonce that was not the
// one this login started with. A JWKS that could not be fetched surfaces here
// too, because a token that cannot be checked is a token that did not verify.
type VerificationError struct {
	Reason string
	cause  error
}

func (e *VerificationError) Error() string {
	return "zorealoauth2: the ID token did not verify: " + e.Reason
}

func (e *VerificationError) Unwrap() error { return e.cause }

// UserinfoError is returned when /userinfo answered with anything but the
// claims. Callers that can live without personal data (a returning user
// matched by sub) may treat it as non-fatal and continue; callers that need
// the email should not. Status is the HTTP status, or 0 when the request
// never completed.
type UserinfoError struct {
	Description string
	Status      int
	cause       error
}

func (e *UserinfoError) Error() string {
	return "zorealoauth2: userinfo: " + e.Description
}

func (e *UserinfoError) Unwrap() error { return e.cause }
