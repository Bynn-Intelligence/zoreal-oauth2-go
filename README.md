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
proofing.

## What each call does

| Call | What happens |
|---|---|
| `Authenticate(ctx, code, codeVerifier, nonce, opts...)` | `Exchange` + `VerifyIDToken`, returns a `*Login` |
| `Exchange(ctx, code, codeVerifier)` | `POST {issuer}/token` with your client authentication |
| `VerifyIDToken(ctx, jwt, nonce, opts...)` | ES256 against `{issuer}/jwks`, checks `iss`, `aud`, `exp`, `nonce` when given (`""` skips it), and the `WithRequiredACR` floor |
| `Userinfo(ctx, accessToken)` | `GET {issuer}/userinfo` with the Bearer token |
| `Login.Userinfo(ctx)` | the above, once, memoized; an empty map when there is no access token |

Errors: `ErrConfiguration` (test with `errors.Is`), `*ExchangeError`,
`*VerificationError` and `*UserinfoError` (test with `errors.As`).
`ExchangeError` carries the provider's OAuth error code and reason, verbatim,
plus the HTTP status. A returning user matched on `Sub` can survive a
tolerated `UserinfoError`; a signup that needs the email cannot. Token values
never appear in an error message.

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
- **Always pass the nonce through.** The SDK generates it and gives it to your
  frontend in `onSuccess`; without it your backend cannot tell a substituted
  ID token from the real one.
- **Email is a deliberate choice.** It is a Tier B scope precisely because a
  shared email defeats the unlinkability the pairwise `sub` provides. Request
  it because you need it, not because the checkbox is familiar.
- **Sandbox clients accept localhost origins; production clients do not.**
  Registration lives in the ZOREAL dashboard on the asset's OAuth2 tab; Tier B
  scopes (email, profile.\*) need a confidential client on a verified domain.
- **Pick the client authentication your registration names.** A public client
  configures nothing; a confidential client sets its secret or its private
  key. `private_key_jwt` is the strongest of the shipped methods: the key
  never travels, only a 60-second single-use assertion does.
- **`profile.portrait` is registrable but not served yet.** `Login.Portrait`
  exists so the shape is stable, and returns `""` until the provider ships
  the claim.

## Development against a local provider

Point `Issuer` at your provider instance. The issuer value must match the `iss` inside the
tokens exactly — it is compared, not normalized.

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
