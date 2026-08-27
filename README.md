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

## What each call does

| Call | What happens |
|---|---|
| `Authenticate(ctx, code, codeVerifier, nonce)` | `Exchange` + `VerifyIDToken`, returns a `*Login` |
| `Exchange(ctx, code, codeVerifier)` | `POST {issuer}/token` with your client authentication |
| `VerifyIDToken(ctx, jwt, nonce)` | ES256 against `{issuer}/jwks`, checks `iss`, `aud`, `exp`, and `nonce` when given (`""` skips it) |
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
