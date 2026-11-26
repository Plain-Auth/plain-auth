package passkey

import (
	"encoding/json"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/go-webauthn/webauthn/protocol"
	wa "github.com/go-webauthn/webauthn/webauthn"
)

// ExtensionsResolver returns the WebAuthn extension inputs for one options
// request. It runs for every request, after the user and the passkeys are
// resolved, so the inputs can depend on the request or its session. A fixed
// set is a function that returns it. A zero result adds nothing. An error
// refuses the request, and no challenge is issued. Inputs are checked
// against the ceremony, so an input that does not apply to it, such as
// credProps on sign-in, fails the request with a server error, where the
// other runtime passes it to the browser.
//
// As on the other runtime, the server does not check client extension
// outputs (clientExtensionResults): they are unsigned client data, and the
// published browser client never sends them. Signed authenticator extension
// outputs, such as an enforced credProtect policy, are checked against the
// challenge.
type ExtensionsResolver func(auth.EndpointContext) (protocol.AuthenticationExtensions, error)

// AuthenticationOptions configures passkey sign-in.
type AuthenticationOptions struct {
	// Extensions adds WebAuthn extension inputs to each GET
	// /passkey/generate-authenticate-options response. See
	// ExtensionsResolver.
	Extensions ExtensionsResolver
	// AfterVerification runs after an assertion passes verification and
	// before the passkey's counter is saved and the session is issued,
	// outside any store transaction. The challenge is already spent. An error
	// refuses the sign-in and nothing is saved: a *plainauth.APIError is the
	// response, and any other error is logged and answered with
	// ErrAuthentication.
	AfterVerification func(auth.EndpointContext, VerifiedAuthentication) error
}

// VerifiedAuthentication is a sign-in assertion that passed WebAuthn
// verification.
type VerifiedAuthentication struct {
	// Passkey is the stored passkey that signed, as it was before this
	// sign-in.
	Passkey Record
	// Credential is the verified credential, with the new signature counter.
	// Its Flags are the stored record's, not this assertion's.
	Credential wa.Credential
	// UserVerified reports whether this assertion's authenticator data
	// carries the user-verified flag.
	UserVerified bool
	// Response is the credential JSON the client sent. The published browser
	// client sends no clientExtensionResults.
	Response json.RawMessage
}
