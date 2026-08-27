# zoreal-oauth2-go

Login with ZOREAL for Go backends: the relying-party half of the flow that
[`@zoreal/oauth2-react`](https://github.com/Bynn-Intelligence/zoreal-oauth2-react)
starts in the browser.

The browser SDK runs the pairing (QR or app link), and hands your frontend an
authorization `code` plus the `code_verifier` and `nonce` it generated. Your
frontend posts all three to your backend, and this module does the rest: the
code exchange with your client authentication, ES256 verification of the ID
token against the provider's JWKS, and the `/userinfo` read for personal
claims.

```
zoreal-oauth2-go (this module)   your backend: exchange, verify, userinfo
@zoreal/oauth2-react             your frontend: the button, the QR, the polling
```

## Install

```sh
go get github.com/Bynn-Intelligence/zoreal-oauth2-go
```

Go >= 1.22. One dependency: `github.com/golang-jwt/jwt/v5`. The JWKS is
parsed with the standard library — the provider signs with EC P-256 keys and
nothing else, so that is the whole grammar.

## Getting your credentials

Everything `Config` needs comes from a ZOREAL **asset**.

1. Create an account at **https://zoreal.com** and open **Assets**.
2. **Create an asset** — a *website* (a domain you own) or an *app bundle* (a
   reverse-DNS bundle id). An asset is the thing users log in to; its token is
   your `ClientID` and it looks like `ast_...`.
3. On the asset, open the **OAuth2** tab and set:
   - the **redirect URIs** and **JavaScript origins** your app uses (requests
     from anything not registered are rejected — this is the core control),
   - the **scopes** the client is allowed to request (see the catalogue below),
   - your **client authentication**: generate a **client secret**
     (`client_secret_basic`, the `ClientSecret` field), or register a **JWKS**
     for `private_key_jwt` (the `PrivateKey` / `PrivateKeyPEM` fields). A public
     client authenticates with PKCE alone and no secret.
4. A website asset must **verify its domain** (a DNS or meta-tag proof, shown in
   the dashboard) before it can request personal-data scopes or sign users in;
   the verified domain is what your users' `sub` is pairwise against.

The `ClientID` is public (it ships in your frontend). The client secret is not —
keep it in your server's secret store (an env var, a secrets manager), never in
the browser.

### There is no test-identity sandbox — and that is deliberate

ZOREAL **never issues fake or sandbox humans**: a pool of test identities would
be a fraud vector against the exact thing the product proves. So you always
authenticate **real** ZOREAL IDs.

To develop and test, **create a free ZOREAL ID for yourself** (enrol in the
ZOREAL ID app) and sign in with it. Mark your asset's environment **sandbox**
in the dashboard while building — a sandbox asset may register `http://localhost`
origins and redirect URIs that a production asset may not — and flip it to
production when you ship. The identities are real either way; only the allowed
origins differ.

## Quick start

Build one client at boot and share it; it is safe for concurrent use.

```go
import zorealoauth2 "github.com/Bynn-Intelligence/zoreal-oauth2-go"

zoreal, err := zorealoauth2.NewClient(zorealoauth2.Config{
	ClientID:     os.Getenv("ZOREAL_CLIENT_ID"), // ast_...
	ClientSecret: os.Getenv("ZOREAL_CLIENT_SECRET"),
	// Issuer defaults to https://id.zoreal.com
})
```

The endpoint your frontend posts to:

```go
func handleZorealLogin(w http.ResponseWriter, r *http.Request) {
	login, err := zoreal.Authenticate(r.Context(),
		r.PostFormValue("code"),
		r.PostFormValue("code_verifier"), // PKCE is mandatory; the SDK hands it over
		r.PostFormValue("nonce"),         // binds the ID token to this login
	)
	if err != nil {
		http.Error(w, "login failed", http.StatusUnauthorized)
		return
	}

	login.Sub()       // "TC5X-JN7G-YTSE-6E63" — pairwise, stable for YOUR domain
	login.ACR()       // "zoreal.live" | "zoreal.device" | "zoreal.session"
	login.Assurance() // uniqueness basis, verification month, chip liveness, trust tier

	email, err := login.Email(r.Context()) // from /userinfo, when your client has the email scope
	verified, _ := login.EmailVerified(r.Context())
	over18, registered := login.AgeOver(18) // zoreal.age scope; registered says the claim exists at all
	_ = over18
	_, _, _ = email, verified, registered
}
```

Account matching, the shape that works: look the user up by
(`"zoreal"`, `login.Sub()`) first; only when that misses, and only when
`login.EmailVerified(ctx)` is true, claim an existing account by its email —
then store the provider and `Sub` on it. Claim, don't collide.

## Assurance levels — `acr`, and requiring a liveness check

### What `acr` is

`acr` is an OpenID Connect standard claim — *Authentication Context Class
Reference*. It is a single string in the ID token that says **how strongly this
particular login was authenticated**. Every ZOREAL login carries one, and it is
the difference between "someone who once enrolled this identity is behind this
request" and "a live human, verified to be the right one, is behind this request
right now". Read it with `login.ACR()`.

It answers a question `Sub` cannot. `login.Sub()` tells you *who* (a stable,
pairwise identifier for this person at your site). `login.ACR()` tells you *how
sure ZOREAL is that the person is really there for this login*. A stolen,
unlocked phone can still produce a `sub`; it cannot produce a fresh
`zoreal.live`.

### The three levels

Ordered weakest to strongest. Each is what actually happened, never what was
requested — a login that could only reach a weaker level says so honestly rather
than claiming the level you asked for.

| `acr` | What the holder did | `amr` | What it proves | What it does **not** prove |
|---|---|---|---|---|
| `zoreal.session` | Nothing — a returning holder at a site they have used before, resumed silently from an existing ZOREAL session, no phone interaction | `[]` | Continuity: the same browser/session ZOREAL already knew | That the holder is present, or even awake |
| `zoreal.device` | Approved the login on their enrolled phone: a signature from a key in the phone's secure element, released by a local biometric or passcode unlock | `["hwk","user"]` | Possession of the enrolled device **and** a local unlock on it | That a live face was captured for *this* login — an unlocked phone in the wrong hands still signs |
| `zoreal.live` | All of the above **plus** a fresh face capture this login: a flash-plus-zoom video scored for presentation attacks and screen replay (moire), matched 1:1 against the government document read at enrolment | `["hwk","face","user"]` | A live, real, unique human, verified to be the enrolled person, **at the moment of this login** | — (this is the strongest level) |

`amr` (*Authentication Methods References*, read with `login.AMR()`) is the
companion claim listing the factors used: `hwk` a hardware key, `user` a
user-presence/unlock gesture, `face` a face biometric. `zoreal.live` is exactly
`zoreal.device` with `face` added, because a live login is a device approval
with a capture on top.

The **default is `zoreal.device`**, never `zoreal.session`: a login that asks
for nothing still requires the enrolled phone and a local unlock. Silence has to
be explicitly asked for (the SDK's `prompt=none`), and it succeeds only for a
returning holder at a site whose consent they have already given.

The vocabulary is exported as `ACRSession`, `ACRDevice` and `ACRLive` if you
prefer a compile-time spelling to a string literal.

### When to require which

- **`ACRSession`** — you never *require* this; it is what a returning holder
  gets for a low-stakes convenience re-auth when they ask for the silent path.
- **`ACRDevice`** (the default) — a forum, a community, a normal account login.
  Possession of the enrolled phone plus a local unlock is a high bar already;
  most sites want exactly this and should pass no `acr` option at all.
- **`ACRLive`** — a bank onboarding, a high-value transaction, an age-gated
  purchase, a first login, a "confirm it is really you" step before a sensitive
  action. Anywhere a *fresh, unforgeable proof of the live, right human* is
  worth the few seconds a face capture costs.

### Requesting versus verifying — the one rule that matters

Requesting a level and verifying it are **two separate steps, and only the
second is security**:

1. **Request** it on the wire, in the frontend, with the SDK's
   `acr_values: 'zoreal.live'`. This is what makes the holder's ZOREAL ID app
   run the face capture before it will approve. It is **advisory** — it shapes
   what the holder is asked to do, nothing more. A browser is
   attacker-controlled; a value that only travels through it proves nothing.
2. **Verify** it here, at token exchange, by passing `WithRequiredACR`. The
   signed `acr` claim in the ID token — minted by ZOREAL, not by the browser —
   is the proof.

```go
login, err := zoreal.Authenticate(r.Context(), code, codeVerifier, nonce,
	zorealoauth2.WithRequiredACR(zorealoauth2.ACRLive), // *VerificationError unless the signed token says so
)

login.ACR()                                 // "zoreal.live" — what actually happened
login.Live()                                // convenience: ACR() == ACRLive
login.SatisfiesACR(zorealoauth2.ACRDevice)  // true — live is stronger than device
```

**An RP that requests `zoreal.live` on the wire but never passes
`WithRequiredACR` here has checked nothing** — it has only asked the holder
nicely and then trusted a value it never validated.

### How the check behaves

Verification satisfies **upward**: `ACRSession < ACRDevice < ACRLive`, so a
requirement of `ACRDevice` accepts a `zoreal.live` token (the holder gave you
*more* assurance than you demanded). A token whose `acr` is below the
requirement, missing entirely, or outside the vocabulary is refused with a
`*VerificationError` (test with `errors.As`). An unknown *required* value — a
typo like `"zoreal.liveness"` — wraps `ErrConfiguration` (test with
`errors.Is`) instead, because that is a bug in your code, not a bad token, and
failing every login silently is worse than saying so.

```go
login, err := zoreal.Authenticate(r.Context(), code, codeVerifier, nonce,
	zorealoauth2.WithRequiredACR(zorealoauth2.ACRLive),
)
if err != nil {
	var verr *zorealoauth2.VerificationError
	switch {
	case errors.As(err, &verr):
		// the token fell short of the floor — refuse this login
	case errors.Is(err, zorealoauth2.ErrConfiguration):
		// the required value is a typo — your bug, not the holder's
	}
}
```

If you prefer to branch rather than have verification refuse the token, omit the
option and inspect the result with the predicate:

```go
login, err := zoreal.Authenticate(r.Context(), code, codeVerifier, nonce)
if err != nil {
	// handle the exchange/verification failure
}
if !login.SatisfiesACR(zorealoauth2.ACRLive) {
	// step the user up, or refuse the sensitive action
}
```

### `acr` versus the assurance block

Do not confuse `login.ACR()` with `login.Assurance()`. `acr` grades *this login
event*. The **assurance block** (`login.Assurance()`) describes the *identity
behind it* — how the person was verified at enrolment (uniqueness basis,
verification month, whether chip liveness was proven, the trust tier, the
device's key protection). One is about now; the other is about who they are. A
high-value flow usually wants both: `WithRequiredACR(zorealoauth2.ACRLive)` for
presence, and the assurance block for the strength of the underlying identity
proofing. The block's full schema is [below](#the-assurance-block).

## What each call does

| Call | What happens |
|---|---|
| `Authenticate(ctx, code, codeVerifier, nonce, opts...)` | `Exchange` + `VerifyIDToken`, returns a `*Login` |
| `Exchange(ctx, code, codeVerifier)` | `POST {issuer}/token` with your client authentication |
| `VerifyIDToken(ctx, jwt, nonce, opts...)` | ES256 against `{issuer}/jwks`, checks `iss`, `aud`, `exp`, `nonce` when given (`""` skips it), and the `WithRequiredACR` floor |
| `Userinfo(ctx, accessToken)` | `GET {issuer}/userinfo` with the Bearer token |
| `Login.Userinfo(ctx)` | the above, once, memoized; an empty map when there is no access token |

Tier A claims read straight off the `*Login` — `Sub()`, `ACR()`, `AMR()`,
`Assurance()`, `AgeOver(n)`, `Nationality()`. The Tier B/C accessors take a
`context.Context` and read `/userinfo` on first use: `Email(ctx)`,
`EmailVerified(ctx)`, `Name(ctx)`, `GivenName(ctx)`, `FamilyName(ctx)`,
`Birthdate(ctx)`, `DocumentType(ctx)`, `DocumentNumber(ctx)`,
`IssuingCountry(ctx)`, `DocumentExpiresOn(ctx)` and `Portrait(ctx)`. See the
scope catalogue for which scope grants each, and the error reference for the
error types every call returns.

## Client authentication

Set exactly one of these on `Config`; leaving all unset is the fourth method.

| Method | Config | Notes |
|---|---|---|
| `none` | nothing | Public client: PKCE is the only proof, Tier A scopes only |
| `client_secret_basic` | `ClientSecret` | The secret travels as HTTP Basic, never as a form field |
| `private_key_jwt` | `PrivateKey` or `PrivateKeyPEM`, optional `KeyID` | The module builds and signs the RFC 7523 assertion: ES256 for a P-256 key, RS256 for an RSA key, 60-second lifetime, fresh single-use `jti` per request |
| `tls_client_auth` | `TLSCertificate` | The certificate rides the TLS handshake on every request. The provider accepts the method at registration but does not implement it at the token endpoint yet and answers 501, which surfaces as the `*ExchangeError` it is |

`PrivateKeyPEM` understands `EC PRIVATE KEY`, `RSA PRIVATE KEY` and PKCS #8
`PRIVATE KEY` blocks. An EC key must be on P-256.

## Scopes and claims

Scopes are requested in the **frontend** (the SDK's `scope` string, always
starting with `openid`), consented to by the holder, and pre-authorized on your
asset. What each grants and where it is delivered:

| Scope | Claims | Delivered in | Tier | Requires |
|---|---|---|---|---|
| `openid` | `sub`, `iss`, `aud`, `exp`, `iat`, `nonce`, `auth_time`, `acr`, `amr`, and the assurance block | ID token | A | any client |
| `zoreal.age` | `age_over_13/16/18/21/65` booleans — only the thresholds you registered, never an age or birthdate | ID token | A | any client |
| `zoreal.nationality` | `nationality` (ISO 3166-1 alpha-3) | ID token | A | any client |
| `email` | `email`, `email_verified` | `/userinfo` | B | confidential client + verified domain |
| `profile.name` | `name`, `given_name`, `family_name` | `/userinfo` | B | confidential client + verified domain |
| `profile.birthdate` | `birthdate` (full ISO 8601 date) | `/userinfo` | B | confidential client + verified domain |
| `profile.document` | `document_type`, `document_number`, `issuing_country`, `document_expires_on` | `/userinfo` | B | confidential client + verified domain |
| `profile.portrait` | `portrait` (the chip's facial image; GDPR Article 9 data) | `/userinfo` | C | confidential client + verified domain — *registrable but not served yet* |

- **Tier A** rides in the ID token and is available to every client, so the
  no-backend browser button can use it. Read it straight off the `*Login`:
  `Sub()`, `ACR()`, `AMR()`, `Assurance()`, `AgeOver(n)`, `Nationality()`.
- **Tier B and C** are personal data, served only from `/userinfo` to a
  confidential client on a domain you have verified, and never placed in a
  browser token. Their accessors take a `context.Context` and may fetch —
  `Email(ctx)`, `Name(ctx)`, `Birthdate(ctx)`, `DocumentNumber(ctx)`, and so on.
- **Age thresholds are a fixed set** — 13, 16, 18, 21, 65 — that you register on
  the asset. `login.AgeOver(n)` returns `ok == false` for a threshold you did
  not register (no claim was minted), which is a different fact from
  `over == false`.

## Error reference

`Exchange` / `Authenticate` return an `*ExchangeError`, which carries the
provider's own OAuth error code and reason, verbatim, plus the HTTP status.
Test for it with `errors.As`. What you will actually see:

| `OAuthError` | Cause | Retryable? |
|---|---|---|
| `invalid_grant` | The code is spent — unknown, expired (60s), already used, PKCE mismatch, or the asset's domain verification lapsed mid-flow | No. Start a **new** login; the code cannot be reused |
| `invalid_request` | Client authentication failed — wrong secret, a bad `private_key_jwt` assertion, or `tls_client_auth` (not accepted at `/token` yet) | No. Fix your client configuration |
| `unsupported_grant_type` | Something other than `authorization_code` reached `/token` | No. A bug |

Errors that surface in the **frontend** instead, before your backend is
involved (from the SDK's `onError` / `onNonOAuthError` callbacks), so handle
them there:

| Where | Code | Meaning |
|---|---|---|
| `/pair` | `invalid_scope` | A scope not on the asset's allowed list, or a Tier B scope from a public client |
| `/pair` | `invalid_request` | Missing PKCE/nonce, an unverified sector, an unregistered `redirect_uri`, or an unknown `acr_values` |
| `/pair` | `login_required` | `prompt=none` with no silent session to resume — the expected quiet outcome, not a failure |
| pairing | `request_denied` | The holder declined in their ZOREAL ID app — **not an error to alarm on**; offer to try again |
| pairing | `request_expired` | The pairing window elapsed, or a required liveness the device could not meet — offer to try again |

This package's own error types, and what each means:

| Type | Test with | Means |
|---|---|---|
| `ErrConfiguration` | `errors.Is` | You built the client wrong, or passed `WithRequiredACR` a value outside the vocabulary — a bug in your code, not a bad token |
| `*ExchangeError` | `errors.As` | The code exchange at `/token` failed; `OAuthError`, `Description` and `Status` carry the provider's verdict (table above). `Status` is `0` when the request never completed, and `Unwrap` then carries the transport error, so `errors.Is(err, context.DeadlineExceeded)` keeps working |
| `*VerificationError` | `errors.As` | The ID token did not verify: signature, `iss`, `aud`, `exp`, the `nonce`, or the `WithRequiredACR` floor. A JWKS that could not be fetched surfaces here too, because a token that cannot be checked is a token that did not verify |
| `*UserinfoError` | `errors.As` | The `/userinfo` read failed. A returning user matched on `Sub` can survive a tolerated one; a signup that needs the email cannot |

Token values never appear in an error message.

## The assurance block

`login.Assurance()` is the ID token's `zoreal` claim — a `map[string]any`
describing the strength of the *identity* behind this login (distinct from
`acr`, which grades the *login event*). Its keys and their value sets:

| Key | Values | Meaning |
|---|---|---|
| `uniqueness` | `personal_number` \| `document` \| `none` | The anchor the holder is deduplicated on. `personal_number` (a national number from the chip) is strongest; `none` means no reliable anchor |
| `verified_on` | `"YYYY-MM"` | The month the underlying document was verified. Quantised to a month on purpose — a day-precision date is a cross-site correlator |
| `chip_liveness_proven` | `true` \| `false` | Whether the passport chip's active-authentication challenge was proven (a genuine chip, not a clone) |
| `trust_tier` | `high` \| `standard` | `high` when `chip_liveness_proven`, else `standard` |
| `key_protection` | `secure_enclave` \| `strongbox` \| `tee` \| `software` | How the holder's device key is protected. `software` means no hardware attestation |

A high-value flow usually pairs `WithRequiredACR(zorealoauth2.ACRLive)` (fresh
presence) with a check on the assurance block (identity strength) — e.g.
requiring `uniqueness == "personal_number"` and `trust_tier == "high"`:

```go
a := login.Assurance()
if a["uniqueness"] != "personal_number" || a["trust_tier"] != "high" {
	// not a strongly-anchored identity — step up or refuse the sensitive action
}
```

## A complete example

A full `net/http` handler, end to end — the shape a real integration takes.

```go
package main

import (
	"errors"
	"log"
	"net/http"
	"os"

	zorealoauth2 "github.com/Bynn-Intelligence/zoreal-oauth2-go"
)

var zoreal *zorealoauth2.Client

func init() {
	var err error
	zoreal, err = zorealoauth2.NewClient(zorealoauth2.Config{
		ClientID:     os.Getenv("ZOREAL_CLIENT_ID"),     // ast_...
		ClientSecret: os.Getenv("ZOREAL_CLIENT_SECRET"), // server-side secret, never in the browser
	})
	if err != nil {
		log.Fatal(err)
	}
}

// handleZorealLogin is where your frontend's ZorealLogin onSuccess POSTs
// { code, code_verifier, nonce } over your own TLS. Protect this route with
// your normal CSRF / same-origin controls, exactly as you would any login
// endpoint — the ZOREAL nonce protects the token, not your route.
func handleZorealLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	login, err := zoreal.Authenticate(ctx,
		r.PostFormValue("code"),
		r.PostFormValue("code_verifier"),
		r.PostFormValue("nonce"),
		// zorealoauth2.WithRequiredACR(zorealoauth2.ACRLive), // for a step-up / high-value login
	)
	if err != nil {
		var exchErr *zorealoauth2.ExchangeError
		var verifyErr *zorealoauth2.VerificationError
		switch {
		case errors.As(err, &exchErr), errors.As(err, &verifyErr):
			// A spent code or a token that did not verify: the login must be restarted.
			log.Printf("ZOREAL login failed: %v", err)
		case errors.Is(err, zorealoauth2.ErrConfiguration):
			// A bug in this server's own configuration, not the holder's problem.
			log.Printf("ZOREAL client misconfigured: %v", err)
		}
		http.Error(w, "sign in failed", http.StatusUnauthorized)
		return
	}

	// Personal data lives at /userinfo, not in the ID token. EmailVerified
	// fetches it. A *UserinfoError is fine for a returning user matched on
	// Sub, and fatal only for a signup that needs the email.
	emailVerified, err := login.EmailVerified(ctx)
	if err != nil {
		var uErr *zorealoauth2.UserinfoError
		if !errors.As(err, &uErr) {
			http.Error(w, "sign in failed", http.StatusUnauthorized)
			return
		}
	}

	// find/create/claim against your own store. Match on (provider, Sub)
	// first; only then, and only for a verified email, claim an existing
	// account. Claim, don't collide.
	user, err := findUserByProvider("zoreal", login.Sub())
	if err != nil {
		http.Error(w, "sign in failed", http.StatusInternalServerError)
		return
	}
	if user == nil {
		email, _ := login.Email(ctx)
		if emailVerified {
			user, _ = findUserByEmail(email)
		}
		if user == nil {
			name, _ := login.Name(ctx)
			user = createUser(email, name)
		}
		linkProvider(user, "zoreal", login.Sub())
	}

	establishSession(w, r, user) // your framework's session, rotated to defend against fixation
	w.WriteHeader(http.StatusNoContent)
}
```

The `findUserByProvider`, `findUserByEmail`, `createUser`, `linkProvider` and
`establishSession` helpers are your application's own; the package's job ends at
a verified `*Login`.

## Things worth knowing before you integrate

- **The ID token never carries personal data.** `sub`, timing, `acr`/`amr`,
  the assurance block, and — if registered — `age_over_*` booleans and
  `nationality`. Email, names, birthdate and document fields come only from
  `/userinfo`, which is why `Authenticate` alone is not enough for a signup.
- **The access token lives 10 minutes.** Read `/userinfo` while handling the
  login; do not store the token for later.
- **`Sub` is pairwise per verified domain.** It is the right account key and
  it is derived from your registered sector: changing your asset's domain
  rotates every `sub` you have stored. Plan domain changes as a migration.
- **ES256 only.** The provider signs ID tokens with nothing else, and this
  module refuses other algorithms rather than negotiating.
- **Always pass the nonce through, and protect your own endpoint too.** The SDK
  generates the nonce and gives it to your frontend in `onSuccess`; passing it
  here lets the package confirm the ID token was minted for *this* login rather
  than substituted. Two things it does **not** do: it is not your endpoint's
  CSRF token (protect your login route with your framework's normal CSRF /
  same-origin defence), and PKCE — not the nonce — is what proves whoever
  exchanges the code is whoever started the flow.
- **Email is a deliberate choice.** It is a Tier B scope precisely because a
  shared email defeats the unlinkability the pairwise `sub` provides. Request
  it because you need it, not because the checkbox is familiar.
- **Pick the client authentication your registration names.** A public client
  configures nothing; a confidential client sets its secret or its private
  key. `private_key_jwt` is the strongest of the shipped methods: the key
  never travels, only a 60-second single-use assertion does.
- **`profile.portrait` is registrable but not served yet.** `Login.Portrait`
  exists so the shape is stable, and returns `""` until the provider ships
  the claim.
- **The `Issuer` must match the token's `iss` exactly** — it is compared, not
  normalized. Production is `https://id.zoreal.com` (the default); set `Issuer`
  only when you were given a non-production provider to point at.

## The ZOREAL OAuth2 library family

| Repository | Package | Role |
|---|---|---|
| zoreal-oauth2-react | @zoreal/oauth2-react (npm) | React frontend: the button, the QR, the polling |
| zoreal-oauth2-js | @zoreal/oauth2-js (npm) | Framework-free browser core |
| zoreal-oauth2-react-native | @zoreal/oauth2-react-native (npm) | React Native frontend |
| zoreal-oauth2-node | @zoreal/oauth2-node (npm) | Node.js backend |
| zoreal-oauth2-ruby | zoreal-oauth2 (RubyGems) | Ruby backend |
| zoreal-oauth2-python | zoreal-oauth2 (PyPI) | Python backend |
| zoreal-oauth2-php | zoreal/oauth2 (Packagist) | PHP backend |
| zoreal-oauth2-go | github.com/Bynn-Intelligence/zoreal-oauth2-go | Go backend |
| zoreal-oauth2-java | com.zoreal:oauth2 (Maven Central) | JVM backend |
| zoreal-oauth2-dotnet | Zoreal.OAuth2 (NuGet) | .NET backend |

## License

MIT.
