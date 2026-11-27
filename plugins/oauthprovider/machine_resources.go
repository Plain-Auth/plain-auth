package oauthprovider

import (
	"context"
	"encoding/json"
	"maps"
	"math"
	"reflect"
	"slices"
	"strings"
	"time"

	auth "github.com/Plain-Org/plain-auth"
)

// MachineResource is the current policy and issuing client's link to one audience.
type MachineResource struct {
	Resource Resource
	Linked   bool
}

// ResourceMachineTokenRecord persists an opaque grant with its original ordered
// resource parameters and any verified sender binding.
type ResourceMachineTokenRecord struct {
	MachineTokenRecord
	Resources  []string
	Thumbprint string
}

// ResourceMachineTokenStore locks the requested policies, authenticated registration
// and client links together. Missing resource identifiers are absent from the map.
// A nil record validates the snapshot without inserting a token. The callback
// performs no I/O. Implementations commit the returned record before reporting success.
type ResourceMachineTokenStore interface {
	WithMachineResources(ctx context.Context, clientID string, identifiers []string, prepare func(MachineClient, map[string]MachineResource) (*ResourceMachineTokenRecord, error)) error
}

type machineResourcePolicy struct {
	scopes           []string
	lifetime         time.Duration
	algorithm, keyID string
	claims           map[string]json.RawMessage
	bound            bool
	// refreshTTL is the shortest refresh lifetime the resources set, in
	// seconds, or nil.
	refreshTTL *int64
}

// refreshLifetime caps a refresh lifetime at the resources' shortest.
func (p machineResourcePolicy) refreshLifetime(lifetime time.Duration) time.Duration {
	if p.refreshTTL != nil && time.Duration(*p.refreshTTL)*time.Second < lifetime {
		return time.Duration(*p.refreshTTL) * time.Second
	}
	return lifetime
}

func (opts TokenOptions) machineResourcePolicy(client MachineClient, scopes, identifiers []string, rows map[string]MachineResource, now time.Time) (machineResourcePolicy, error) {
	lifetime, err := opts.machineLifetime(scopes, now)
	if err != nil {
		return machineResourcePolicy{}, err
	}
	return opts.resourcePolicy(client.ClientID, client.RequireDPoP, scopes, identifiers, rows, lifetime)
}

// resourcePolicy applies the requested resources' policies to a grant, as
// another runtime's resolveResourcePolicy does: each must be configured,
// enabled and linked to the client unless AllowUnlinkedResources is set,
// their allowed scopes narrow the request, the shortest access lifetime
// applies, and their signing pins must agree.
func (opts TokenOptions) resourcePolicy(clientID string, bound bool, scopes, identifiers []string, rows map[string]MachineResource, lifetime time.Duration) (machineResourcePolicy, error) {
	p := machineResourcePolicy{scopes: scopes, lifetime: lifetime, bound: bound}
	var unlinked []string
	for _, id := range identifiers {
		row, ok := rows[id]
		if !ok || row.Resource.Identifier != id {
			return p, registrationProblem(400, "invalid_target", "requested resource "+id+" is not configured")
		}
		if row.Resource.Disabled {
			return p, registrationProblem(400, "invalid_target", "requested resource "+id+" is disabled")
		}
		if !row.Linked && !opts.AllowUnlinkedResources {
			unlinked = append(unlinked, id)
		}
	}
	if len(unlinked) > 0 {
		return p, registrationProblem(400, "invalid_target", "client "+clientID+" is not linked to resource(s) "+strings.Join(unlinked, ", "))
	}
	var algConflict, kidConflict bool
	for _, id := range identifiers {
		row := rows[id].Resource
		if row.AllowedScopes != nil {
			p.scopes = slices.DeleteFunc(slices.Clone(p.scopes), func(scope string) bool { return !slices.Contains(row.AllowedScopes, scope) })
			if len(p.scopes) == 0 {
				return p, registrationProblem(400, "invalid_scope", "none of the requested scopes are allowed for resource "+id)
			}
		}
		if ttl := row.AccessTokenTTL; ttl != nil && *ttl < int64(p.lifetime/time.Second) {
			if *ttl <= 0 {
				return p, registrationProblem(400, "invalid_target", "requested resource has an invalid access token lifetime")
			}
			p.lifetime = time.Duration(*ttl) * time.Second
		}
		if ttl := row.RefreshTokenTTL; ttl != nil && *ttl > 0 && (p.refreshTTL == nil || *ttl < *p.refreshTTL) {
			p.refreshTTL = ttl
		}
		if alg := row.SigningAlgorithm; alg != nil && *alg != "" {
			algConflict = algConflict || p.algorithm != "" && p.algorithm != *alg
			p.algorithm = *alg
		}
		if kid := row.SigningKeyID; kid != nil && *kid != "" {
			kidConflict = kidConflict || p.keyID != "" && p.keyID != *kid
			p.keyID = *kid
		}
		if len(row.CustomClaims) > 0 {
			if p.claims == nil {
				p.claims = make(map[string]json.RawMessage)
			}
			maps.Copy(p.claims, row.CustomClaims)
		}
		p.bound = p.bound || row.DPoPBoundAccessTokensRequired
	}
	if algConflict {
		return p, registrationProblem(400, "invalid_request", "requested resources require conflicting signing algorithms")
	}
	if kidConflict {
		return p, registrationProblem(400, "invalid_request", "requested resources require conflicting signing keys")
	}
	return p, nil
}

func (opts Options) issueResourceMachineToken(c auth.EndpointContext, store MachineTokenStore, in tokenRequest, first MachineClient) (MachineToken, error) {
	resourceStore, ok := store.(ResourceMachineTokenStore)
	if !ok {
		return MachineToken{}, &auth.APIError{Status: 501, Code: "OAUTH_RESOURCE_TOKEN_STORE_UNAVAILABLE", Message: "The configured store cannot issue resource-targeted tokens"}
	}
	// An unfinished seed of the declared resources is retried first.
	if err := opts.seedResources(c); err != nil {
		return MachineToken{}, err
	}
	var audiences, identifiers []string
	seen := make(map[string]bool)
	for _, id := range in.resources {
		if !seen[id] {
			seen[id] = true
			audiences = append(audiences, id)
			if id != c.Auth.PublicURL()+"/oauth2/userinfo" {
				identifiers = append(identifiers, id)
			}
		}
	}
	ctx := c.Request.Context()
	// One issuance instant serves both passes, so a lifetime capped at a
	// scope's instant is the same when the policy is read again.
	now := time.Now().UTC().Truncate(time.Second)
	resolve := func(client MachineClient, rows map[string]MachineResource) (machineResourcePolicy, error) {
		if err := in.recheckClient(first, client); err != nil {
			return machineResourcePolicy{}, err
		}
		scopes, err := in.authorizedScopes(client)
		if err != nil {
			return machineResourcePolicy{}, err
		}
		return opts.Tokens.machineResourcePolicy(client, scopes, identifiers, rows, now)
	}
	var policy machineResourcePolicy
	err := resourceStore.WithMachineResources(ctx, in.id, identifiers, func(client MachineClient, rows map[string]MachineResource) (*ResourceMachineTokenRecord, error) {
		p, err := resolve(client, rows)
		policy = p
		return nil, err
	})
	if err != nil {
		return MachineToken{}, err
	}
	// Host fields are resolved from the first read's issued scopes, before
	// the token is signed or stored.
	fields, err := opts.Tokens.responseFields(ctx, TokenResponseInput{GrantType: "client_credentials", Scopes: policy.scopes, Metadata: first.Metadata})
	if err != nil {
		return MachineToken{}, err
	}
	thumb, err := opts.machineThumbprint(c, in, policy.bound)
	if err != nil {
		return MachineToken{}, err
	}
	signed := c.Auth.HasPlugin("jwt") && !opts.Tokens.OpaqueResourceTokens
	var issued, stored string
	if signed {
		// Contributed claims are resolved outside the store's transactions.
		var extra map[string]any
		extra, err = opts.accessTokenClaims(c, TokenClaimsInput{ClientID: in.id, Scopes: policy.scopes, GrantType: "client_credentials", Resources: in.resources, Metadata: first.Metadata})
		if err != nil {
			return MachineToken{}, err
		}
		issued, err = policy.sign(c, in.id, audiences, thumb, now, extra)
	} else {
		issued, stored, err = opts.Tokens.newOpaqueToken(ctx)
	}
	if err != nil {
		return MachineToken{}, err
	}
	// Key lookup and host token generators may use this same database. Run
	// them outside the transaction, then authorize the actual response again.
	err = resourceStore.WithMachineResources(ctx, in.id, identifiers, func(client MachineClient, rows map[string]MachineResource) (*ResourceMachineTokenRecord, error) {
		current, err := resolve(client, rows)
		if err != nil {
			return nil, err
		}
		if current.bound && thumb == "" {
			return nil, proofError("DPoP proof header is required")
		}
		if signed {
			if !reflect.DeepEqual(current, policy) {
				return nil, registrationProblem(400, "invalid_request", "resource policy changed during issuance, retry the request")
			}
			if !time.Now().Before(now.Add(policy.lifetime)) {
				return nil, registrationProblem(503, "temporarily_unavailable", "token expired during issuance, retry the request")
			}
			return nil, nil
		}
		// Host response fields describe the first read's scopes.
		if opts.Tokens.CustomTokenResponseFields != nil && !slices.Equal(current.scopes, policy.scopes) {
			return nil, registrationProblem(400, "invalid_request", "client scopes changed during issuance, retry the request")
		}
		policy = current
		record := MachineTokenRecord{StoredToken: stored, Scopes: current.scopes, IssuedAt: now, ExpiresAt: now.Add(current.lifetime)}
		return &ResourceMachineTokenRecord{MachineTokenRecord: record, Resources: in.resources, Thumbprint: thumb}, nil
	})
	if err != nil {
		return MachineToken{}, err
	}
	token := machineResponse(issued, thumb, policy.scopes, now, policy.lifetime)
	token.fields = fields
	return token, nil
}

func (p machineResourcePolicy) sign(c auth.EndpointContext, client string, audiences []string, thumb string, now time.Time, extra map[string]any) (string, error) {
	jti, err := randomClientCredential()
	if err != nil {
		return "", err
	}
	claims := maps.Clone(extra)
	if claims == nil {
		claims = map[string]any{}
	}
	for name, raw := range p.claims {
		if !signedAccessClaim(name) {
			claims[name] = raw
		}
	}
	// A client token has no session; the issuer stamps its own claims last.
	delete(claims, "sid")
	claims["jti"], claims["client_id"], claims["azp"], claims["scope"] = jti, client, client, strings.Join(p.scopes, " ")
	if thumb != "" {
		claims["cnf"] = map[string]string{"jkt": thumb}
	}
	return c.Auth.SignJWT(c.Request.Context(), client, auth.JWTSignOptions{
		Type: "at+jwt", Issuer: c.Auth.OAuthIssuer(), Audience: audiences, Algorithm: p.algorithm, KeyID: p.keyID,
		IssuedAt: now, ExpiresAt: now.Add(p.lifetime), Claims: claims,
	})
}

// checkAuthorizationResources checks the requested resources' policies at
// authorize, before any page is shown. The UserInfo URL is an implicit
// audience, not a registered resource.
func (opts Options) checkAuthorizationResources(c auth.EndpointContext, issue BrowserCodeIssue) error {
	store, ok := c.Store().(ResourceMachineTokenStore)
	if !ok {
		return registrationProblem(400, "invalid_target", "resource-targeted browser authorization is unavailable")
	}
	if err := opts.seedResources(c); err != nil {
		return err
	}
	userInfo := c.Auth.PublicURL() + "/oauth2/userinfo"
	ids := slices.DeleteFunc(slices.Clone(issue.Resources), func(id string) bool { return id == userInfo })
	if len(ids) == 0 {
		return nil
	}
	return store.WithMachineResources(c.Request.Context(), issue.Client.ClientID, ids, func(client MachineClient, rows map[string]MachineResource) (*ResourceMachineTokenRecord, error) {
		_, err := opts.Tokens.resourcePolicy(client.ClientID, false, issue.Scopes, ids, rows, math.MaxInt64)
		return nil, err
	})
}
