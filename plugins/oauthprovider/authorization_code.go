package oauthprovider

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"strings"
	"time"

	auth "github.com/Plain-Org/plain-auth"
)

var (
	ErrAuthorizationCodeInvalid    = errors.New("oauthprovider: invalid authorization code")
	ErrAuthorizationUserMissing    = errors.New("oauthprovider: authorization user no longer exists")
	ErrAuthorizationSessionExpired = errors.New("oauthprovider: authorization session no longer active")
)

// DelegatedAccessRecord describes an opaque access token issued for a user's grant.
type DelegatedAccessRecord struct {
	MachineTokenRecord
	UserID, SessionID       string
	ReferenceID             *string
	Refresh                 *InitialRefreshGrant
	RequestedUserInfoClaims []string
	IDToken                 IDTokenGrant
	// Non-nil requests a trusted claims snapshot from the store, even for an
	// application with no additional user columns.
	IDTokenUserFields map[string]auth.UserField
	// Deferred asks the store to run its issue phase, outside the grant
	// transaction, even without a refresh or ID token.
	Deferred bool
	// Resources are the token's resource audiences, stored with it.
	Resources []string
}

// InitialRefreshGrant holds the expiry and original authentication time of a
// refresh token issued with delegated access. Code redemption defaults AuthTime
// to the browser session's creation time. Rotation carries it from the parent.
type InitialRefreshGrant struct {
	ExpiresAt time.Time
	AuthTime  *time.Time
	// Resources are the resources the grant authorized, which later
	// refresh exchanges may request.
	Resources []string
}

// DelegatedToken is the response to an authorization-code or refresh exchange.
type DelegatedToken struct {
	MachineToken
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
}

// AuthorizationCodeClient contains the current policy for delegated issuance.
type AuthorizationCodeClient struct {
	MachineClient
	Scopes        []string // nil means the client has no explicit scope restriction.
	RequirePKCE   *bool
	SubjectType   string
	RedirectURIs  []string
	EmitSessionID bool
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

// OfflineAuthorizationCodeStore atomically consumes a code and inserts the
// authorized tokens. For an offline grant it calls issueRefresh with the
// verified session ID outside database locks, then rechecks the client, code,
// user and session before persisting the returned digest and linking both rows.
// prepare can run again during this final check and must perform no I/O.
type OfflineAuthorizationCodeStore interface {
	AuthorizationCodeStore
	RedeemAuthorizationCodeWithRefresh(ctx context.Context, clientID, identifier string, checkClient func(MachineClient) error, prepare func(AuthorizationCodeClient, json.RawMessage) (DelegatedAccessRecord, error), issueRefresh func(sessionID string) (string, error)) error
}

// AuthorizationCodeGater is a store whose code methods ask the request's
// plainauth.VerificationGate about the codes they store and spend, so that the
// codes' verification database hooks run outside the store's transactions. New
// requires it for verification hooks with the authorization_code grant.
// Following the gate's rules:
//   - IssueBrowserCode, and FinishBrowserConsent with an acceptance, ask Create
//     with AuthorizationCodeRecord(AuthorizationCodeRecordID(identifier),
//     issue.UserID, start+Lifetime) once the client, session, prompt, consent
//     and identifier checks pass, just before storing the code, which they
//     date from start, the gate's Now truncated to the second. A declined code
//     is not stored, and the call commits the rest: a consumed prompt and an
//     accepted consent.
//   - RedeemAuthorizationCode, RedeemAuthorizationCodeWithRefresh and
//     RedeemOpenIDCode ask Delete with the stored row's ID, the code's user and
//     the row's expiry once the client, the code's value, the user, the session
//     and the expiry pass, in every pass, before deferring issuance or spending
//     the code. A declined spend returns ErrAuthorizationCodeInvalid and spends
//     and revokes nothing.
type AuthorizationCodeGater interface{ GatesAuthorizationCodes() }

// AuthorizationCodeRecordID is the ID of the row that stores a code under
// identifier: the hex of the first 16 bytes of the SHA-256 of "oauth-code/"
// and the identifier. The deterministic key serializes simultaneous issues of
// one identifier. It cannot redeem the code, but keep it private.
func AuthorizationCodeRecordID(identifier string) string {
	sum := sha256.Sum256([]byte("oauth-code/" + identifier))
	return hex.EncodeToString(sum[:16])
}

// AuthorizationCodeRecord is an authorization code as a verification record,
// owned by the user who approved it. id is the stored row's ID. It never
// carries the code's stored identifier, which a weak HashAuthorizationCode
// could make redeemable, nor the authorization request's state, nonce, PKCE
// challenge, login hint, claims or session.
func AuthorizationCodeRecord(id, userID string, expiresAt time.Time) auth.VerificationRecord {
	return auth.VerificationRecord{ID: id, Identifier: "authorization-code", UserID: userID, ExpiresAt: expiresAt.UTC().Truncate(time.Millisecond)}
}

// revokeCodeTokens removes the tokens an exchange of identifier stored but
// never returned, by redeeming the spent code again: an AuthorizationCodeStore
// answers a replay by removing the code's descendants.
func revokeCodeTokens(c auth.EndpointContext, store AuthorizationCodeStore, clientID, identifier string) {
	ctx := context.WithoutCancel(c.Request.Context())
	err := store.RedeemAuthorizationCode(ctx, clientID, identifier,
		func(MachineClient) error { return nil },
		func(AuthorizationCodeClient, json.RawMessage) (DelegatedAccessRecord, error) {
			return DelegatedAccessRecord{}, ErrAuthorizationCodeInvalid
		})
	if !errors.Is(err, ErrAuthorizationCodeInvalid) {
		c.Auth.Logger().ErrorContext(ctx, "oauthprovider: could not remove the tokens of an exchange whose verification hook failed", "error", err)
	}
}

type storedAuthorizationCode struct {
	Type        string   `json:"type"`
	UserID      string   `json:"userId"`
	SessionID   string   `json:"sessionId"`
	ReferenceID *string  `json:"referenceId"`
	AuthTime    *int64   `json:"authTime"`
	Resources   []string `json:"resource"`
	Query       struct {
		ClientID        string          `json:"client_id"`
		ResponseType    string          `json:"response_type"`
		RedirectURI     string          `json:"redirect_uri"`
		Scope           *string         `json:"scope"`
		Nonce           string          `json:"nonce"`
		Claims          json.RawMessage `json:"claims"`
		Challenge       string          `json:"code_challenge"`
		ChallengeMethod string          `json:"code_challenge_method"`
		Thumbprint      string          `json:"dpop_jkt"`
		Resource        json.RawMessage `json:"resource"`
	} `json:"query"`
}

func (opts Options) redeemAuthorizationCode(c auth.EndpointContext, in tokenRequest, form url.Values) (DelegatedToken, error) {
	var result DelegatedToken
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
	identifier, err := opts.Tokens.storedAuthorizationCode(ctx, raw)
	if err != nil {
		return result, err
	}
	issued, stored, err := opts.Tokens.newOpaqueToken(ctx)
	if err != nil {
		return result, err
	}
	offlineStore, canIssueRefresh := store.(OfflineAuthorizationCodeStore)
	// policy holds the resources' policy rows once read; needed names the
	// resources prepare asked for.
	var policy *codeResources
	var needed []string
	// signing is set when the grant's access token is an at+jwt, signed in
	// the issue phase instead of stored.
	var signing *delegatedSigning
	var signingUser, signedAccess string
	now := time.Now().UTC().Truncate(time.Second)
	openidStore, supportsOpenID := store.(OpenIDGrantStore)
	var codeValue json.RawMessage
	prepare := func(client AuthorizationCodeClient, value json.RawMessage) (DelegatedAccessRecord, error) {
		codeValue, signing = slices.Clone(value), nil
		var code storedAuthorizationCode
		if err := json.Unmarshal(value, &code); err != nil || code.Type != "authorization_code" || code.Query.ClientID == "" ||
			(code.Query.ResponseType != "" && code.Query.ResponseType != "code") {
			return DelegatedAccessRecord{}, registrationProblem(400, "invalid_grant", "malformed verification value")
		}
		scopes, err := code.scopesForExchange(client, in, verifier, form.Get("redirect_uri"))
		if err != nil {
			return DelegatedAccessRecord{}, err
		}
		claims, err := opts.grantUserInfoClaims(code.Query.Claims, slices.Contains(scopes, "openid"))
		if err != nil {
			return DelegatedAccessRecord{}, registrationProblem(400, "invalid_grant", "malformed authorization claims")
		}
		lifetime, err := opts.Tokens.scopeLifetime(opts.Tokens.AccessLifetime, scopes, now)
		if err != nil {
			return DelegatedAccessRecord{}, err
		}
		signingUser = code.UserID
		effective, authorized, err := code.resources(in.resources)
		if err != nil {
			return DelegatedAccessRecord{}, err
		}
		refreshLifetime := opts.Tokens.RefreshLifetime
		if len(effective) > 0 {
			// The UserInfo URL is an implicit audience, not a registered resource.
			userInfo := c.Auth.PublicURL() + "/oauth2/userinfo"
			ids := slices.DeleteFunc(slices.Clone(effective), func(id string) bool { return id == userInfo })
			if policy == nil || !slices.Equal(policy.ids, ids) {
				needed = ids
				return DelegatedAccessRecord{}, errResourcePolicyNeeded
			}
			granted, err := opts.Tokens.resourcePolicy(client.ClientID, false, scopes, ids, policy.rows, lifetime)
			if err != nil {
				return DelegatedAccessRecord{}, err
			}
			if granted.bound {
				if in.proof == "" {
					return DelegatedAccessRecord{}, proofError("DPoP proof header is required")
				}
				return DelegatedAccessRecord{}, registrationProblem(501, "server_error", "sender-bound authorization-code issuance is unavailable")
			}
			if supportsOpenID && opts.signsResourceTokens(c) {
				signing = newDelegatedSigning(c, granted, effective, scopes)
			}
			scopes, lifetime = granted.scopes, granted.lifetime
			refreshLifetime = granted.refreshLifetime(refreshLifetime)
			// Narrowed scopes keep the claims only openid allows.
			if claims, err = opts.grantUserInfoClaims(code.Query.Claims, slices.Contains(scopes, "openid")); err != nil {
				return DelegatedAccessRecord{}, registrationProblem(400, "invalid_grant", "malformed authorization claims")
			}
		}
		result.MachineToken = machineResponse(issued, "", scopes, now, lifetime)
		record := DelegatedAccessRecord{
			MachineTokenRecord: MachineTokenRecord{StoredToken: stored, Scopes: scopes, IssuedAt: now, ExpiresAt: now.Add(lifetime)},
			UserID:             code.UserID, SessionID: code.SessionID, ReferenceID: code.ReferenceID,
			RequestedUserInfoClaims: claims, Resources: effective,
		}
		var authTime time.Time
		if code.AuthTime != nil {
			authTime = time.UnixMilli(*code.AuthTime).UTC()
		}
		// A client without a secret gets no ID token when the secret signs it.
		if slices.Contains(scopes, "openid") && (!opts.DisableJWTPlugin || in.secret != "") {
			if !opts.canIssueIDToken(c) {
				return DelegatedAccessRecord{}, registrationProblem(501, "server_error", "ID token issuance is unavailable")
			}
			if opts.Tokens.CustomIDTokenClaims != nil || opts.extendsIDTokens() {
				record.IDTokenUserFields = c.TrustedUserFields()
			}
			record.IDToken, err = opts.idTokenGrant(client, code.UserID, code.SessionID, code.Query.Nonce, authTime)
			if err != nil {
				return DelegatedAccessRecord{}, err
			}
		}
		// A signed access token is issued in the issue phase and not stored;
		// its claim contributors read the account's snapshot.
		if signing != nil {
			record.StoredToken, record.Deferred = "", true
			if opts.contributesAccessClaims() && record.IDTokenUserFields == nil {
				record.IDTokenUserFields = c.TrustedUserFields()
			}
		}
		// Host response fields run in the issue phase, from a claims
		// snapshot of the account.
		if opts.Tokens.CustomTokenResponseFields != nil {
			record.Deferred = true
			if record.IDTokenUserFields == nil {
				record.IDTokenUserFields = c.TrustedUserFields()
			}
		}
		if slices.Contains(scopes, "offline_access") {
			if !canIssueRefresh {
				return DelegatedAccessRecord{}, &auth.APIError{Status: 501, Code: "OAUTH_REFRESH_STORE_UNAVAILABLE", Message: "The configured store does not support offline grants"}
			}
			record.Refresh = &InitialRefreshGrant{ExpiresAt: now.Add(refreshLifetime), Resources: authorized}
			if len(authorized) == 0 {
				record.Refresh.Resources = effective
			}
			if code.AuthTime != nil {
				record.Refresh.AuthTime = &authTime
			}
		}
		return record, nil
	}
	issueRefresh := func(sessionID string) (string, error) {
		wire, digest, err := opts.Tokens.issueRefreshToken(ctx, sessionID)
		result.RefreshToken = wire
		return digest, err
	}
	var fields map[string]any
	issueOpenID := func(grant DelegatedTokenIssue) (string, error) {
		if opts.Tokens.CustomTokenResponseFields != nil {
			input, err := claimsResponseInput("authorization_code", grant.IDToken.ClaimsInput, codeValue)
			if err != nil {
				return "", err
			}
			if fields, err = opts.Tokens.responseFields(ctx, input); err != nil {
				return "", err
			}
		}
		// The ID token's at_hash covers the access token sent, signed or not.
		access := issued
		if signing != nil {
			token, err := opts.signDelegated(c, signing, "authorization_code", in.id, signingUser, grant.SessionID, grant.IDToken.ClaimsInput, now)
			if err != nil {
				return "", err
			}
			signedAccess, access = token, token
		}
		if grant.IDToken.Subject != "" {
			token, err := opts.Tokens.signIDToken(c, in.id, access, grant.IDToken, now, opts.idTokenSecret(in), opts.idTokenContributors("authorization_code"))
			if err != nil {
				return "", err
			}
			result.IDToken = token
		}
		if grant.Refresh {
			return issueRefresh(grant.SessionID)
		}
		return "", nil
	}
	// The store asks the request's gate before spending the code, so its
	// verification hooks run outside the store's transaction.
	committed := false
	err = c.GateVerifications(func(ctx context.Context) error {
		now = time.Now().UTC().Truncate(time.Second) // a rerun follows slow hooks
		var err error
		for range 3 {
			switch {
			case supportsOpenID:
				err = openidStore.RedeemOpenIDCode(ctx, in.id, identifier, checkClient, prepare, issueOpenID)
			case canIssueRefresh:
				err = offlineStore.RedeemAuthorizationCodeWithRefresh(ctx, in.id, identifier, checkClient, prepare, issueRefresh)
			default:
				err = store.RedeemAuthorizationCode(ctx, in.id, identifier, checkClient, prepare)
			}
			if !errors.Is(err, errResourcePolicyNeeded) {
				break
			}
			// Read outside the redemption's transaction, as another runtime
			// reads them; the second pass uses this policy.
			read, err := opts.readCodeResources(c, in.id, needed)
			if err != nil {
				return err
			}
			policy = &read
		}
		if errors.Is(err, errResourcePolicyNeeded) {
			err = registrationProblem(400, "invalid_request", "resource policy changed during issuance, retry the request")
		}
		committed = err == nil
		return err
	})
	if err != nil && committed {
		// A delete after hook failed once the exchange committed. Remove the
		// tokens it stored, which were never returned, as an undelivered
		// session is removed when its hook fails.
		revokeCodeTokens(c, store, in.id, identifier)
	}
	switch {
	case errors.Is(err, ErrAuthorizationCodeInvalid):
		err = registrationProblem(400, "invalid_grant", "invalid code")
	case errors.Is(err, ErrAuthorizationUserMissing):
		err = registrationProblem(400, "invalid_user", "missing user, user may have been deleted")
	case errors.Is(err, ErrAuthorizationSessionExpired):
		err = registrationProblem(400, "invalid_request", "session no longer exists")
	}
	if err != nil {
		return DelegatedToken{}, err
	}
	// The second pass rebuilt the response; the token sent is the signed one.
	if signedAccess != "" {
		result.AccessToken = signedAccess
	}
	result.fields = fields
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
	scopes := distinct(strings.Split(*q.Scope, " "))
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
	return scopes, nil
}

// resources returns the token's resources, the requested ones or else those
// the code authorized, and those the code authorized, from its top-level
// resource or a legacy query.resource. A requested resource the code did
// not authorize is refused, as in another runtime.
func (code storedAuthorizationCode) resources(requested []string) (effective, authorized []string, err error) {
	authorized = code.Resources
	if len(authorized) == 0 && len(code.Query.Resource) > 0 {
		var one string
		if json.Unmarshal(code.Query.Resource, &one) == nil {
			authorized = []string{one}
		} else if json.Unmarshal(code.Query.Resource, &authorized) != nil {
			return nil, nil, registrationProblem(400, "invalid_grant", "malformed verification value")
		}
	}
	effective = authorized
	if len(requested) > 0 {
		effective = requested
		if len(authorized) > 0 {
			for _, id := range requested {
				if !slices.Contains(authorized, id) {
					return nil, nil, registrationProblem(400, "invalid_target", "requested resource not authorized")
				}
			}
		}
	}
	return distinct(effective), authorized, nil
}

// errResourcePolicyNeeded stops a redemption whose resources' policies are
// not read yet. prepare returns it before the code is spent or a hook is
// asked; they are read outside the transaction and the redemption runs again.
var errResourcePolicyNeeded = errors.New("oauthprovider: resource policy needed")

// codeResources holds the policy rows of a redemption's resources.
type codeResources struct {
	ids  []string
	rows map[string]MachineResource
}

// readCodeResources reads the policy rows of resources for a client.
func (opts Options) readCodeResources(c auth.EndpointContext, clientID string, ids []string) (codeResources, error) {
	store, ok := c.Store().(ResourceMachineTokenStore)
	if !ok {
		return codeResources{}, &auth.APIError{Status: 501, Code: "OAUTH_RESOURCE_TOKEN_STORE_UNAVAILABLE", Message: "The configured store cannot issue resource-targeted tokens"}
	}
	if err := opts.seedResources(c); err != nil {
		return codeResources{}, err
	}
	read := codeResources{ids: slices.Clone(ids)}
	err := store.WithMachineResources(c.Request.Context(), clientID, ids, func(_ MachineClient, rows map[string]MachineResource) (*ResourceMachineTokenRecord, error) {
		read.rows = rows
		return nil, nil
	})
	return read, err
}

func (opts TokenOptions) issueRefreshToken(ctx context.Context, sessionID string) (wire, digest string, err error) {
	var raw string
	if opts.GenerateRefreshToken != nil {
		raw, err = opts.GenerateRefreshToken(ctx)
	} else {
		raw, err = randomClientCredential()
	}
	if err != nil {
		return "", "", err
	}
	if raw == "" {
		return "", "", errors.New("oauthprovider: empty generated refresh token")
	}
	digest, err = opts.storedRefresh(ctx, raw)
	if err != nil {
		return "", "", err
	}
	wire = raw
	if opts.EncodeRefreshToken != nil {
		wire, err = opts.EncodeRefreshToken(ctx, raw, sessionID)
		if err != nil {
			return "", "", err
		}
		if wire == "" {
			return "", "", errors.New("oauthprovider: empty encoded refresh token")
		}
	}
	return opts.RefreshPrefix + wire, digest, nil
}

func (opts TokenOptions) storedAuthorizationCode(ctx context.Context, raw string) (string, error) {
	if opts.HashAuthorizationCode == nil {
		return tokenDigest(raw), nil
	}
	id, err := opts.HashAuthorizationCode(ctx, raw)
	if err == nil && id == "" {
		return "", errors.New("oauthprovider: empty stored authorization code identifier")
	}
	return id, err
}
