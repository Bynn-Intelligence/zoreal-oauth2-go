package zorealoauth2

import (
	"context"
	"fmt"
	"sync"
)

// Login is one verified login. The ID token claims are already checked when
// this exists; userinfo is fetched on first use, because the ID token never
// carries personal data and not every login needs any.
type Login struct {
	// Claims are the verified ID token claims.
	Claims map[string]any
	// IDToken is the raw compact JWT the claims came from.
	IDToken string
	// AccessToken is from the token response and lives ten minutes.
	AccessToken string
	// Scope is the granted scope from the token response.
	Scope string

	client *Client
	mu     sync.Mutex
	info   map[string]any
}

// Sub is the pairwise subject: stable for your verified domain, meaningless
// to anyone else. This is the value to key accounts on — and it is derived
// from YOUR registered sector, so changing your asset's domain rotates every
// sub you have stored.
func (l *Login) Sub() string { return l.claimString("sub") }

// ACR is how the login was authenticated: zoreal.live, zoreal.device or
// zoreal.session. It describes what happened, never what was requested.
func (l *Login) ACR() string { return l.claimString("acr") }

// AMR is the authentication methods reference, as the provider sent it.
func (l *Login) AMR() []string {
	raw, _ := l.Claims["amr"].([]any)
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// Assurance is the zoreal claim block: uniqueness basis, verification month,
// chip liveness, trust tier, key protection.
func (l *Login) Assurance() map[string]any {
	m, _ := l.Claims["zoreal"].(map[string]any)
	return m
}

// AgeOver reads the age_over_<threshold> boolean the zoreal.age scope
// delivers. Only the thresholds registered for your client appear, never an
// age; ok reports whether the claim is present at all, which is a different
// fact from a false.
func (l *Login) AgeOver(threshold int) (over, ok bool) {
	v, present := l.Claims[fmt.Sprintf("age_over_%d", threshold)]
	b, _ := v.(bool)
	return b, present
}

// Nationality is the zoreal.nationality scope's claim: ISO 3166-1 alpha-3,
// read from the document chip. Empty without the scope.
func (l *Login) Nationality() string { return l.claimString("nationality") }

// Userinfo returns the personal claims from /userinfo, fetched once and
// memoized. It returns an *UserinfoError when the endpoint refuses — treat it
// as non-fatal if your flow can continue without personal data, as a
// returning user matched on Sub can. A failed fetch is not memoized, so a
// later call may retry. Returns an empty map, and never fetches, when the
// exchange carried no access token.
func (l *Login) Userinfo(ctx context.Context) (map[string]any, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.info != nil {
		return l.info, nil
	}
	if l.AccessToken == "" {
		l.info = map[string]any{}
		return l.info, nil
	}
	info, err := l.client.Userinfo(ctx, l.AccessToken)
	if err != nil {
		return nil, err
	}
	l.info = info
	return l.info, nil
}

// Email is the address the holder verified with ZOREAL. From /userinfo, with
// the email scope.
func (l *Login) Email(ctx context.Context) (string, error) {
	return l.userinfoString(ctx, "email")
}

// EmailVerified reports whether the provider has verified the email.
func (l *Login) EmailVerified(ctx context.Context) (bool, error) {
	info, err := l.Userinfo(ctx)
	if err != nil {
		return false, err
	}
	verified, _ := info["email_verified"].(bool)
	return verified, nil
}

// Name is the document display name. From /userinfo, profile.name scope.
func (l *Login) Name(ctx context.Context) (string, error) {
	return l.userinfoString(ctx, "name")
}

// GivenName is from /userinfo, profile.name scope.
func (l *Login) GivenName(ctx context.Context) (string, error) {
	return l.userinfoString(ctx, "given_name")
}

// FamilyName is from /userinfo, profile.name scope.
func (l *Login) FamilyName(ctx context.Context) (string, error) {
	return l.userinfoString(ctx, "family_name")
}

// Birthdate is ISO 8601, from the profile.birthdate scope.
func (l *Login) Birthdate(ctx context.Context) (string, error) {
	return l.userinfoString(ctx, "birthdate")
}

// DocumentType is from the profile.document scope.
func (l *Login) DocumentType(ctx context.Context) (string, error) {
	return l.userinfoString(ctx, "document_type")
}

// DocumentNumber is from the profile.document scope.
func (l *Login) DocumentNumber(ctx context.Context) (string, error) {
	return l.userinfoString(ctx, "document_number")
}

// IssuingCountry is from the profile.document scope.
func (l *Login) IssuingCountry(ctx context.Context) (string, error) {
	return l.userinfoString(ctx, "issuing_country")
}

// DocumentExpiresOn is ISO 8601, from the profile.document scope.
func (l *Login) DocumentExpiresOn(ctx context.Context) (string, error) {
	return l.userinfoString(ctx, "document_expires_on")
}

// Portrait is the profile.portrait scope's claim. The scope is registrable,
// but the provider does not serve the claim yet, so this returns "" today;
// the accessor exists so the shape is stable when it ships.
func (l *Login) Portrait(ctx context.Context) (string, error) {
	return l.userinfoString(ctx, "portrait")
}

func (l *Login) claimString(name string) string {
	s, _ := l.Claims[name].(string)
	return s
}

func (l *Login) userinfoString(ctx context.Context, name string) (string, error) {
	info, err := l.Userinfo(ctx)
	if err != nil {
		return "", err
	}
	s, _ := info[name].(string)
	return s, nil
}
