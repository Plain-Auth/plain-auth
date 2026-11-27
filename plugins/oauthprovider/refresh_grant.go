package oauthprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"reflect"
	"slices"
	"time"

	auth "github.com/Plain-Org/plain-auth"
)

// RefreshGrant describes the stored permissions and session at exchange time.
type RefreshGrant struct {
	Scopes, Resources              []string
	SessionID, AuthorizationCodeID string
	// Thumbprint is the DPoP key the family is bound to. SenderBound marks
	// another kind of binding, which this issuer cannot prove.
	Thumbprint               string
	SessionLive, SenderBound bool
	// Replayed marks a rotated token presented outside its reuse
	// interval: the store ends the family once prepare accepts the request.
	Replayed bool
	UserID   string
	AuthTime time.Time
}

// RefreshGrantDigests contains only the storage keys of the credentials issued
// for a refresh exchange. Refresh is empty for an access-only exchange.
// Replay, with a reuse interval, is the sealed response the store keeps on
// the rotated parent until the record's ReplayUntil.
type RefreshGrantDigests struct{ Access, Refresh, Replay string }

// RefreshReplay is what a store returns when a rotated refresh token is
// presented again inside its reuse interval: the response sealed at
// rotation, which the issuer opens and sends again for an identical request.
type RefreshReplay struct{ Response string }

func (*RefreshReplay) Error() string {
	return "oauthprovider: refresh token reused inside its interval"
}

// refreshReplay is the sealed request and response of a rotation.
type refreshReplay struct {
	Request  refreshReplayRequest `json:"request"`
	Response map[string]any       `json:"response"`
}

type refreshReplayRequest struct {
	Scopes       []string          `json:"effectiveScopes"`
	Resources    []string          `json:"requestedResources,omitempty"`
	Confirmation map[string]string `json:"confirmation,omitempty"`
}

func newReplayRequest(scopes, resources []string, thumb string) refreshReplayRequest {
	r := refreshReplayRequest{Scopes: slices.Sorted(slices.Values(distinct(scopes)))}
	if len(resources) > 0 {
		r.Resources = slices.Sorted(slices.Values(distinct(resources)))
	}
	if thumb != "" {
		r.Confirmation = map[string]string{"jkt": thumb}
	}
	return r
}

// refreshReplayPurpose binds a sealed response to the refresh token it
// rotated.
func refreshReplayPurpose(digest string) string { return "oauth-refresh-replay:" + digest }

// RefreshGrantStore authenticates the current registration before reading the
// grant, rejects expired or foreign credentials and serializes reuse handling.
// prepare is a local policy check. After validation the store calls issue
// outside database locks, revalidates and atomically records the
// parent revocation and both replacements. It copies user, session, reference,
// authorization code, authentication time and requested claims from the parent.
type RefreshGrantStore interface {
	MachineClientReader
	ExchangeRefreshGrant(ctx context.Context, clientID, digest string, checkClient func(MachineClient) error, prepare func(AuthorizationCodeClient, RefreshGrant) (DelegatedAccessRecord, error), issue func(sessionID string, rotate bool) (RefreshGrantDigests, error)) error
}

func (opts Options) exchangeRefreshGrant(c auth.EndpointContext, in tokenRequest, form url.Values) (DelegatedToken, error) {
	var result DelegatedToken
	if len(form["refresh_token"]) != 1 || form.Get("refresh_token") == "" {
		return result, registrationProblem(400, "invalid_request", "a single refresh_token is required")
	}
	if len(c.Request.Header.Values("DPoP")) > 1 {
		return result, proofError("DPoP proof header must not be repeated")
	}
	store, ok := c.Store().(RefreshGrantStore)
	if !ok {
		return result, &auth.APIError{Status: 501, Code: "OAUTH_REFRESH_STORE_UNAVAILABLE", Message: "The configured store does not support refresh-token exchange"}
	}
	first, err := opts.authenticateClient(c, store, in, "/oauth2/token")
	if err != nil {
		return result, err
	}
	checkClient := func(client MachineClient) error {
		if err := in.recheckClient(first, client); err != nil {
			return err
		}
		if len(client.GrantTypes) > 0 && !slices.Contains(client.GrantTypes, "authorization_code") && !slices.Contains(client.GrantTypes, "refresh_token") {
			return registrationProblem(400, "unauthorized_client", "client is not authorized to use grant type refresh_token")
		}
		return nil
	}
	if err := checkClient(first); err != nil {
		return result, err
	}
	ctx := c.Request.Context()
	// A DPoP proof is verified before the grant is read, so its jti is
	// spent outside the store's transaction, and its key binds the
	// replacements, which keep the family's key. A failed proof is the
	// answer only once reuse detection has run, as in another runtime,
	// which checks the proof when it issues.
	thumb, proofErr := opts.machineThumbprint(c, in, false)
	digest, err := opts.Tokens.storedTokenDigest(ctx, form.Get("refresh_token"), StoredRefreshToken)
	if err != nil {
		return result, err
	}
	if digest == "" {
		return result, registrationProblem(400, "invalid_grant", "invalid refresh token")
	}
	var access string
	now := time.Now().UTC().Truncate(time.Second)
	// policy holds the resources' policy rows once read; needed names the
	// resources prepare asked for.
	var policy *codeResources
	var needed []string
	// signing is set when the access token is an at+jwt, signed in the
	// issue phase instead of stored, for the grant's user and live session.
	var signing *delegatedSigning
	var signingUser, signingSID string
	// replayRequest is the exchange's request as a reuse retry compares it.
	var replayRequest refreshReplayRequest
	openidStore, supportsOpenID := store.(OpenIDGrantStore)
	prepare := func(client AuthorizationCodeClient, grant RefreshGrant) (DelegatedAccessRecord, error) {
		signing, signingUser, signingSID = nil, grant.UserID, ""
		if grant.SessionLive {
			signingSID = grant.SessionID
		}
		scopes, err := grant.scopesForRefresh(client, in)
		if err != nil {
			return DelegatedAccessRecord{}, err
		}
		effective, kept, err := grant.refreshResources(in.resources)
		if err != nil {
			return DelegatedAccessRecord{}, err
		}
		// Reuse outside the interval ends the family before the proof, the
		// binding and the resources' policy are checked, as in another
		// runtime; a grant whose session ended, judged by the family's own
		// scopes, is refused first and keeps the family.
		if grant.Replayed {
			return DelegatedAccessRecord{}, grant.sessionBound(grant.Scopes)
		}
		if proofErr != nil {
			return DelegatedAccessRecord{}, proofErr
		}
		if err := grant.checkBinding(client, in.proof, thumb); err != nil {
			return DelegatedAccessRecord{}, err
		}
		ttl, err := opts.Tokens.scopeLifetime(opts.Tokens.AccessLifetime, scopes, now)
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
			granted, err := opts.Tokens.resourcePolicy(client.ClientID, false, scopes, ids, policy.rows, ttl)
			if err != nil {
				return DelegatedAccessRecord{}, err
			}
			if granted.bound && thumb == "" {
				return DelegatedAccessRecord{}, proofError("DPoP proof header is required")
			}
			if opts.signsResourceTokens(c) {
				signing = newDelegatedSigning(c, granted, effective, scopes)
			}
			scopes, ttl, refreshLifetime = granted.scopes, granted.lifetime, granted.refreshLifetime(refreshLifetime)
		}
		if err := grant.sessionBound(scopes); err != nil {
			return DelegatedAccessRecord{}, err
		}
		result.MachineToken = machineResponse("", thumb, scopes, now, ttl)
		record := DelegatedAccessRecord{MachineTokenRecord: MachineTokenRecord{Scopes: scopes, IssuedAt: now, ExpiresAt: now.Add(ttl)}, Resources: effective, Thumbprint: thumb}
		if slices.Contains(scopes, "openid") && (!opts.DisableJWTPlugin || in.secret != "") {
			if !opts.canIssueIDToken(c) {
				return DelegatedAccessRecord{}, registrationProblem(501, "server_error", "ID token issuance is unavailable")
			}
			var sid string
			if grant.SessionLive {
				sid = grant.SessionID
			}
			if opts.Tokens.CustomIDTokenClaims != nil || opts.extendsIDTokens() {
				record.IDTokenUserFields = c.TrustedUserFields()
			}
			record.IDToken, err = opts.idTokenGrant(client, grant.UserID, sid, "", grant.AuthTime)
			if err != nil {
				return DelegatedAccessRecord{}, err
			}
		}
		if slices.Contains(grant.Scopes, "offline_access") {
			// The rotated token keeps the family's resources, and its
			// lifetime counts from rotation.
			record.Refresh = &InitialRefreshGrant{ExpiresAt: now.Add(refreshLifetime), Resources: kept}
			if opts.Tokens.RefreshReuseInterval > 0 {
				record.ReplayUntil = now.Add(opts.Tokens.RefreshReuseInterval)
			}
		}
		replayRequest = newReplayRequest(scopes, effective, thumb)
		if (opts.Tokens.CustomTokenResponseFields != nil || signing != nil && opts.contributesAccessClaims()) && record.IDTokenUserFields == nil {
			record.IDTokenUserFields = c.TrustedUserFields()
		}
		return record, nil
	}
	var fields map[string]any
	responseFields := func(grant DelegatedTokenIssue) error {
		if opts.Tokens.CustomTokenResponseFields == nil {
			return nil
		}
		input, err := claimsResponseInput("refresh_token", grant.IDToken.ClaimsInput, nil)
		if err == nil {
			fields, err = opts.Tokens.responseFields(ctx, input)
		}
		return err
	}
	// issueKeys issues the access token, signed and not stored, or opaque,
	// and the rotated refresh token.
	issueKeys := func(sid string, rotate bool, snapshot string) (RefreshGrantDigests, error) {
		var keys RefreshGrantDigests
		var err error
		if signing != nil {
			access, err = opts.signDelegated(c, signing, "refresh_token", in.id, signingUser, signingSID, thumb, snapshot, now)
		} else {
			access, keys.Access, err = opts.Tokens.newOpaqueToken(ctx)
		}
		if err == nil && rotate {
			result.RefreshToken, keys.Refresh, err = opts.Tokens.issueRefreshToken(ctx, sid)
		}
		return keys, err
	}
	issue := func(sid string, rotate bool) (RefreshGrantDigests, error) { return issueKeys(sid, rotate, "") }
	for range 3 {
		if supportsOpenID {
			err = openidStore.ExchangeOpenIDRefresh(ctx, in.id, digest, checkClient, prepare, func(grant DelegatedTokenIssue) (RefreshGrantDigests, error) {
				if err := responseFields(grant); err != nil {
					return RefreshGrantDigests{}, err
				}
				keys, err := issueKeys(grant.SessionID, grant.Refresh, grant.IDToken.ClaimsInput)
				if err == nil && grant.IDToken.Subject != "" {
					result.IDToken, err = opts.Tokens.signIDToken(c, in.id, access, grant.IDToken, now, opts.idTokenSecret(in), opts.idTokenContributors("refresh_token"))
				}
				// With a reuse interval, the whole response is sealed for the
				// rotated parent, with the request a retry must repeat.
				if err == nil && grant.Refresh && opts.Tokens.RefreshReuseInterval > 0 {
					keys.Replay, err = opts.sealRefreshReplay(c, digest, replayRequest, result, access, fields)
				}
				return keys, err
			})
		} else {
			err = store.ExchangeRefreshGrant(ctx, in.id, digest, checkClient, prepare, issue)
		}
		if !errors.Is(err, errResourcePolicyNeeded) {
			break
		}
		// Read outside the exchange's transaction, as another runtime reads
		// them; the next exchange uses this policy.
		read, readErr := opts.readCodeResources(c, in.id, needed)
		if readErr != nil {
			return DelegatedToken{}, readErr
		}
		policy = &read
	}
	if errors.Is(err, errResourcePolicyNeeded) {
		err = registrationProblem(400, "invalid_request", "resource policy changed during issuance, retry the request")
	}
	var reuse *RefreshReplay
	if errors.As(err, &reuse) {
		return opts.openRefreshReplay(c, digest, replayRequest, reuse.Response)
	}
	if errors.Is(err, ErrInvalidRefreshToken) {
		err = registrationProblem(400, "invalid_grant", "invalid refresh token")
	}
	if err != nil {
		return DelegatedToken{}, err
	}
	result.AccessToken = access
	result.fields = fields
	return result, nil
}

func (grant RefreshGrant) scopesForRefresh(client AuthorizationCodeClient, in tokenRequest) ([]string, error) {
	scopes := grant.Scopes
	if in.scopes != nil {
		scopes = in.scopes
		for _, scope := range scopes {
			if !slices.Contains(grant.Scopes, scope) {
				return nil, registrationProblem(400, "invalid_scope", "unable to issue scope "+scope)
			}
		}
	}
	for _, scope := range scopes {
		if client.Scopes != nil && !slices.Contains(client.Scopes, scope) {
			return nil, registrationProblem(400, "invalid_scope", "client does not allow scope "+scope)
		}
	}
	return scopes, nil
}

// checkBinding requires a proof by the family's DPoP key, or by any key for
// a client that requires DPoP.
func (grant RefreshGrant) checkBinding(client AuthorizationCodeClient, proof, thumb string) error {
	if grant.SenderBound {
		return registrationProblem(501, "server_error", "sender-bound refresh issuance is unavailable")
	}
	if (client.RequireDPoP || grant.Thumbprint != "") && proof == "" {
		return proofError("DPoP proof header is required")
	}
	if grant.Thumbprint != "" && thumb != grant.Thumbprint {
		return proofError("DPoP proof key does not match the bound token")
	}
	return nil
}

// sessionBound refuses a grant whose session ended unless the scopes it
// issues keep offline_access, checked after resources narrow them.
func (grant RefreshGrant) sessionBound(scopes []string) error {
	if !grant.SessionLive && (grant.SessionID != "" || grant.AuthorizationCodeID != "") && !slices.Contains(scopes, "offline_access") {
		return ErrInvalidRefreshToken
	}
	return nil
}

// refreshResources returns the token's resources, the requested ones or
// else the family's, and the resources a rotated refresh token keeps. A
// requested resource outside the family's is refused, as in another runtime.
func (grant RefreshGrant) refreshResources(requested []string) (effective, kept []string, err error) {
	effective, kept = grant.Resources, grant.Resources
	if len(requested) > 0 {
		if len(grant.Resources) > 0 {
			for _, id := range requested {
				if !slices.Contains(grant.Resources, id) {
					return nil, nil, registrationProblem(400, "invalid_target", "requested resource invalid")
				}
			}
		}
		effective = distinct(requested)
		if len(kept) == 0 {
			kept = effective
		}
	}
	return effective, kept, nil
}

// sealRefreshReplay encrypts the response a rotation sends, bound to the
// rotated refresh token.
func (opts Options) sealRefreshReplay(c auth.EndpointContext, digest string, request refreshReplayRequest, result DelegatedToken, access string, fields map[string]any) (string, error) {
	result.AccessToken = access
	body, err := tokenBody(result, fields)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	var response map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&response); err != nil {
		return "", err
	}
	sealed, err := json.Marshal(refreshReplay{Request: request, Response: response})
	if err != nil {
		return "", err
	}
	return c.Auth.EncryptRecord(refreshReplayPurpose(digest), sealed)
}

// openRefreshReplay sends the sealed response again when the retry repeats
// the rotation's scopes, resources and DPoP key, with expires_in counted
// again from now, as another runtime does. Any other reuse inside the
// interval, or a record that does not open, answers invalid_grant and keeps
// the family.
func (opts Options) openRefreshReplay(c auth.EndpointContext, digest string, request refreshReplayRequest, sealed string) (DelegatedToken, error) {
	invalid := registrationProblem(400, "invalid_grant", "invalid refresh token")
	raw, err := c.Auth.DecryptRecord(refreshReplayPurpose(digest), sealed)
	if err != nil {
		return DelegatedToken{}, invalid
	}
	var replay refreshReplay
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&replay) != nil || replay.Response == nil || !reflect.DeepEqual(replay.Request, request) {
		return DelegatedToken{}, invalid
	}
	if expires, ok := replay.Response["expires_at"].(json.Number); ok {
		if at, err := expires.Int64(); err == nil {
			replay.Response["expires_in"] = max(0, at-time.Now().Unix())
		}
	}
	return DelegatedToken{replay: replay.Response}, nil
}
