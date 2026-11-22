package oauthprovider

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"strings"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
)

var (
	ErrAuthorizationCodeInvalid    = errors.New("oauthprovider: invalid authorization code")
	ErrAuthorizationUserMissing    = errors.New("oauthprovider: authorization user no longer exists")
	ErrAuthorizationSessionExpired = errors.New("oauthprovider: authorization session no longer active")
)

// DelegatedAccessRecord is an opaque access token bound to the browser grant.
type DelegatedAccessRecord struct {
	MachineTokenRecord
	UserID, SessionID string
	ReferenceID       *string
}

// AuthorizationCodeClient contains the current policy for delegated issuance.
type AuthorizationCodeClient struct {
	MachineClient
	Scopes      []string // nil means the client has no explicit scope restriction.
	RequirePKCE *bool
}

// PKCERequirement returns the reason the request requires a code challenge.
// An empty result permits a confidential client to use its registered credentials alone.
func (client AuthorizationCodeClient) PKCERequirement(scopes []string, nonce string) string {
	if client.AuthMethod == "none" {
		return "pkce is required for public clients"
	}
	if slices.Contains(scopes, "offline_access") && !(slices.Contains(scopes, "openid") && nonce != "") {
		return "pkce or OIDC nonce is required when requesting offline_access scope"
	}
	if client.RequirePKCE == nil || *client.RequirePKCE {
		return "pkce is required for this client"
	}
	return ""
}

// AuthorizationCodeStore redeems a code in a transaction. Check the current
// client before looking up the code. Prepare the new grant from the newest
// unexpired verification record, check the user and session, then consume the
// code and persist the token together. A replay removes this client's stored
// descendants of that code before returning ErrAuthorizationCodeInvalid.
// Both callbacks are local checks and perform no I/O.
type AuthorizationCodeStore interface {
	MachineClientReader
	RedeemAuthorizationCode(ctx context.Context, clientID, identifier string, checkClient func(MachineClient) error, prepare func(AuthorizationCodeClient, json.RawMessage) (DelegatedAccessRecord, error)) error
}

type storedAuthorizationCode struct {
	Type        string   `json:"type"`
	UserID      string   `json:"userId"`
	SessionID   string   `json:"sessionId"`
	ReferenceID *string  `json:"referenceId"`
	Resources   []string `json:"resource"`
	Query       struct {
		ClientID        string          `json:"client_id"`
		ResponseType    string          `json:"response_type"`
		RedirectURI     string          `json:"redirect_uri"`
		Scope           *string         `json:"scope"`
		Nonce           string          `json:"nonce"`
		Challenge       string          `json:"code_challenge"`
		ChallengeMethod string          `json:"code_challenge_method"`
		Thumbprint      string          `json:"dpop_jkt"`
		Resource        json.RawMessage `json:"resource"`
	} `json:"query"`
}

func (opts Options) redeemAuthorizationCode(c auth.EndpointContext, in tokenRequest, form url.Values) (MachineToken, error) {
	var result MachineToken
	for _, field := range []string{"code", "code_verifier", "redirect_uri"} {
		if len(form[field]) > 1 {
			return result, registrationProblem(400, "invalid_request", field+" must not be repeated")
		}
	}
	raw, verifier := form.Get("code"), form.Get("code_verifier")
	if raw == "" {
		return result, registrationProblem(400, "invalid_request", "code is required")
	}
	if in.method == "none" && verifier == "" {
		return result, registrationProblem(400, "invalid_request", "Either code_verifier or client_secret is required")
	}
	store, ok := c.Store().(AuthorizationCodeStore)
	if !ok {
		return result, &auth.APIError{Status: 501, Code: "OAUTH_CODE_STORE_UNAVAILABLE", Message: "The configured store does not support authorization-code redemption"}
	}
	first, err := opts.authenticateClient(c, store, in, "/oauth2/token")
	if err != nil {
		return result, err
	}
	checkClient := func(current MachineClient) error {
		if err := in.recheckClient(first, current); err != nil {
			return err
		}
		if len(current.GrantTypes) > 0 && !slices.Contains(current.GrantTypes, "authorization_code") {
			return registrationProblem(400, "unauthorized_client", "client is not authorized to use grant type authorization_code")
		}
		return nil
	}
	if err := checkClient(first); err != nil {
		return result, err
	}
	if len(c.Request.Header.Values("DPoP")) > 1 {
		return result, proofError("DPoP proof header must not be repeated")
	}
	ctx := c.Request.Context()
	identifier := tokenDigest(raw)
	if hash := opts.Tokens.HashAuthorizationCode; hash != nil {
		identifier, err = hash(ctx, raw)
		if err != nil {
			return result, err
		}
		if identifier == "" {
			return result, errors.New("oauthprovider: empty stored authorization code identifier")
		}
	}
	issued, stored, err := opts.Tokens.newOpaqueToken(ctx)
	if err != nil {
		return result, err
	}
	prepare := func(client AuthorizationCodeClient, value json.RawMessage) (DelegatedAccessRecord, error) {
		var code storedAuthorizationCode
		if err := json.Unmarshal(value, &code); err != nil || code.Type != "authorization_code" || code.Query.ClientID == "" ||
			(code.Query.ResponseType != "" && code.Query.ResponseType != "code") {
			return DelegatedAccessRecord{}, registrationProblem(400, "invalid_grant", "malformed verification value")
		}
		scopes, err := code.scopesForExchange(client, in, verifier, form.Get("redirect_uri"))
		if err != nil {
			return DelegatedAccessRecord{}, err
		}
		now := time.Now().UTC().Truncate(time.Second)
		lifetime := opts.Tokens.scopeLifetime(opts.Tokens.AccessLifetime, scopes)
		result = machineResponse(issued, "", scopes, now, lifetime)
		return DelegatedAccessRecord{
			MachineTokenRecord: MachineTokenRecord{StoredToken: stored, Scopes: scopes, IssuedAt: now, ExpiresAt: now.Add(lifetime)},
			UserID:             code.UserID, SessionID: code.SessionID, ReferenceID: code.ReferenceID,
		}, nil
	}
	err = store.RedeemAuthorizationCode(ctx, in.id, identifier, checkClient, prepare)
	switch {
	case errors.Is(err, ErrAuthorizationCodeInvalid):
		err = registrationProblem(400, "invalid_grant", "invalid code")
	case errors.Is(err, ErrAuthorizationUserMissing):
		err = registrationProblem(400, "invalid_user", "missing user, user may have been deleted")
	case errors.Is(err, ErrAuthorizationSessionExpired):
		err = registrationProblem(400, "invalid_request", "session no longer exists")
	}
	if err != nil {
		return MachineToken{}, err
	}
	return result, nil
}

func (code storedAuthorizationCode) scopesForExchange(client AuthorizationCodeClient, in tokenRequest, verifier, redirect string) ([]string, error) {
	q := code.Query
	if q.ClientID != client.ClientID {
		return nil, registrationProblem(400, "invalid_grant", "invalid client_id")
	}
	if q.RedirectURI != "" && redirect == "" {
		return nil, registrationProblem(400, "invalid_request", "redirect_uri is required")
	}
	if q.RedirectURI != redirect {
		return nil, registrationProblem(400, "invalid_grant", "redirect_uri mismatch")
	}
	if q.Scope == nil {
		return nil, registrationProblem(500, "invalid_scope", "verification scope unset")
	}
	scopes := strings.Split(*q.Scope, " ")
	for _, scope := range scopes {
		if client.Scopes != nil && !slices.Contains(client.Scopes, scope) {
			return nil, registrationProblem(400, "invalid_scope", "client does not allow scope "+scope)
		}
	}
	if verifier == "" && (client.PKCERequirement(scopes, q.Nonce) != "" || q.Challenge != "" || q.ChallengeMethod != "") {
		return nil, registrationProblem(400, "invalid_request", "code_verifier is required")
	}
	if verifier != "" {
		if q.Challenge == "" {
			return nil, registrationProblem(400, "invalid_request", "code_verifier provided but PKCE was not used in authorization")
		}
		if q.ChallengeMethod != "S256" || subtle.ConstantTimeCompare([]byte(tokenDigest(verifier)), []byte(q.Challenge)) != 1 {
			return nil, registrationProblem(400, "invalid_grant", "code verification failed")
		}
	}
	if client.RequireDPoP || q.Thumbprint != "" || in.proof != "" {
		if in.proof == "" {
			return nil, proofError("DPoP proof header is required")
		}
		return nil, registrationProblem(501, "server_error", "sender-bound authorization-code issuance is unavailable")
	}
	if len(code.Resources) > 0 || (len(q.Resource) > 0 && string(q.Resource) != "null") || len(in.resources) > 0 {
		return nil, registrationProblem(501, "server_error", "resource-targeted authorization-code issuance is unavailable")
	}
	if slices.Contains(scopes, "openid") || slices.Contains(scopes, "offline_access") {
		return nil, registrationProblem(501, "server_error", "ID and refresh token issuance is unavailable")
	}
	return scopes, nil
}
