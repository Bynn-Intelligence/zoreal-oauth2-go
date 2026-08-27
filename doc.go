// Package zorealoauth2 is Login with ZOREAL for Go backends: the
// relying-party half of the flow that the ZOREAL browser SDKs start in the
// frontend.
//
// The browser SDK runs the pairing (QR or app link) and hands your frontend
// an authorization code plus the PKCE code_verifier and the nonce it
// generated. Your frontend posts all three to your backend, and this package
// does the rest: the code exchange with your client authentication, ES256
// verification of the ID token against the provider's JWKS, and the
// /userinfo read for personal claims.
//
// Build one *Client at boot and share it; it is safe for concurrent use.
//
//	zoreal, err := zorealoauth2.NewClient(zorealoauth2.Config{
//		ClientID:     os.Getenv("ZOREAL_CLIENT_ID"), // ast_...
//		ClientSecret: os.Getenv("ZOREAL_CLIENT_SECRET"),
//	})
//
//	login, err := zoreal.Authenticate(ctx, code, codeVerifier, nonce)
//	login.Sub()               // the pairwise subject: your stable user key
//	login.Email(ctx)          // from /userinfo, when your client has the email scope
package zorealoauth2

// Version is the package version. The module is tagged v<Version>.
const Version = "0.1.0"
