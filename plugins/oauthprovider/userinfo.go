package oauthprovider

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"unicode"

	auth "github.com/Plain-Auth/plain-auth"
)

// UserInfoOptions configures OpenID Connect profile claims and the endpoint limit.
type UserInfoOptions struct {
	RateLimit *auth.RateLimitRule
	// Extensions contribute additional claims in order. The first extension
	// contributing a name owns it. Standard claims take precedence.
	Extensions []UserInfoClaimsFunc
	// CustomClaims lets the operator override any claim except sub.
	CustomClaims UserInfoClaimsFunc
}

// UserInfoClaimsFunc supplies claims for an already validated access grant.
type UserInfoClaimsFunc func(context.Context, UserInfoInput) (map[string]any, error)

// UserInfoInput describes an authenticated access grant before pairwise subject
// presentation. RequestedClaims comes only from a stored delegated access token.
type UserInfoInput struct {
	User                    auth.User
	Client                  *ClientDetails
	Scopes, RequestedClaims []string
	Token                   map[string]any
}

// UserInfoLookup identifies either a verified OAuth JWT or a stored access-token
// digest. Endpoint is the issuer's public UserInfo URL.
type UserInfoLookup struct {
	SignedGrant               *SignedAccessGrant
	Subject, Digest, Endpoint string
	IncludeClient             bool
}

// UserInfoRecord is a consistent view of the grant, its subject policy and
// current user. Client is present when registration data was requested.
type UserInfoRecord struct {
	User   *auth.User
	Client *ClientDetails
	Issuer SignedGrantClient
	Opaque *OpaqueAccessTokenRecord
}

// UserInfoStore resolves a live access grant and its current profile in one
// snapshot. Return nil for an inactive grant. A grant without a corresponding
// user carries a nil User. Refresh tokens never qualify.
type UserInfoStore interface {
	LookupOAuthUserInfo(context.Context, UserInfoLookup) (*UserInfoRecord, error)
}

func userInfoCredentials(r *http.Request) (scheme, token string, err error) {
	if len(r.Header.Values("Authorization")) > 1 {
		return "", "", registrationProblem(400, "invalid_request", "Authorization must not be repeated")
	}
	value := strings.TrimSpace(r.Header.Get("Authorization"))
	if value != "" {
		scheme, token = "Bearer", value
		if i := strings.IndexFunc(value, unicode.IsSpace); i > 0 {
			raw, rest := value[:i], strings.TrimSpace(value[i:])
			if rest != "" && (strings.EqualFold(raw, "DPoP") || strings.EqualFold(raw, "Bearer")) {
				scheme, token = raw, rest
			}
		}
	}
	if r.Method == http.MethodPost {
		form, err := readTokenForm(r)
		if err != nil {
			return "", "", err
		}
		if list := form["access_token"]; len(list) > 0 && list[len(list)-1] != "" {
			if value != "" {
				return "", "", registrationProblem(400, "invalid_request", "Multiple access token transport methods are not allowed")
			}
			return "Bearer", list[len(list)-1], nil
		}
	}
	return scheme, token, nil
}

func (opts Options) userInfo(c auth.EndpointContext) (any, error) {
	scheme, token, err := userInfoCredentials(c.Request)
	if err != nil {
		return nil, err
	}
	if token == "" {
		return nil, opts.userInfoChallenge(c.ResponseHeader, "", "invalid_request", "access token not found")
	}
	store, ok := c.Store().(UserInfoStore)
	if !ok {
		return nil, &auth.APIError{Status: 501, Code: "OAUTH_USERINFO_STORE_UNAVAILABLE", Message: "The configured store does not support OAuth UserInfo"}
	}
	endpoint := c.Auth.PublicURL() + "/oauth2/userinfo"
	record, claims, err := opts.userInfoAccess(c, store, token, endpoint)
	if err != nil {
		return nil, err
	}
	if record == nil {
		return nil, opts.userInfoChallenge(c.ResponseHeader, scheme, "invalid_token", "Invalid access token")
	}
	verifier := opts.proofsFor(c.Store())
	confirmation, _ := claims["cnf"].(map[string]any)
	jkt, _ := confirmation["jkt"].(string)
	if len(c.Request.Header.Values("DPoP")) > 1 && (jkt != "" || strings.EqualFold(scheme, "DPoP")) {
		return nil, opts.userInfoChallenge(c.ResponseHeader, "DPoP", "invalid_dpop_proof", "DPoP proof header must not be repeated")
	}
	err = verifier.CheckBinding(c.Request.Context(), scheme, c.Request.Header.Get("DPoP"), DPoPProofRequest{Method: c.Request.Method, URL: endpoint, AccessToken: token, ExpectedThumbprint: jkt})
	if err != nil {
		var problem *auth.OAuthError
		if errors.As(err, &problem) {
			return nil, opts.userInfoChallenge(c.ResponseHeader, "DPoP", problem.Code, problem.Description)
		}
		return nil, err
	}
	scope, _ := claims["scope"].(string)
	scopes := strings.Split(scope, " ")
	if !slices.Contains(scopes, "openid") {
		return nil, registrationProblem(400, "invalid_scope", "Missing required scope")
	}
	rawSubject, _ := claims["sub"].(string)
	if rawSubject == "" || record.User == nil || record.User.ID != rawSubject {
		return nil, registrationProblem(400, "invalid_request", "user not found")
	}
	in := UserInfoInput{User: *record.User, Client: record.Client, Scopes: scopes, Token: claims}
	if record.Opaque != nil {
		in.RequestedClaims = record.Opaque.RequestedUserInfoClaims
	}
	subject := in.User.ID
	if record.Issuer.SubjectType == "pairwise" {
		subject, err = pairwiseSubject(opts.PairwiseSecret, in.User.ID, record.Issuer.RedirectURIs)
		if err != nil {
			return nil, err
		}
	}
	if opts.UserInfo.CustomClaims != nil || len(opts.UserInfo.Extensions) > 0 {
		if err := c.PopulateUserProfile(&in.User); err != nil {
			return nil, err
		}
	}
	return opts.UserInfo.projectClaims(c, in, subject)
}

func (opts Options) userInfoAccess(c auth.EndpointContext, store UserInfoStore, token, endpoint string) (*UserInfoRecord, map[string]any, error) {
	ctx := c.Request.Context()
	claims, signed, err := c.OAuthJWTPayload(token)
	if err != nil {
		return nil, nil, err
	}
	query := UserInfoLookup{Endpoint: endpoint, IncludeClient: len(opts.UserInfo.Extensions) > 0 || opts.UserInfo.CustomClaims != nil}
	if signed {
		grant, valid := signedGrant(claims)
		if !valid {
			return nil, nil, nil
		}
		query.SignedGrant = &grant
		query.Subject, _ = claims["sub"].(string)
	} else {
		query.Digest, err = opts.Tokens.storedTokenDigest(ctx, token, StoredAccessToken)
		if err != nil || query.Digest == "" {
			return nil, nil, err
		}
	}
	record, err := store.LookupOAuthUserInfo(ctx, query)
	if err != nil || record == nil {
		return nil, nil, err
	}
	if signed {
		claims["active"], claims["client_id"], claims["token_type"] = true, query.SignedGrant.ClientID, "Bearer"
		confirmation, _ := claims["cnf"].(map[string]any)
		addTokenConfirmation(claims, confirmation)
	} else {
		claims = opaqueAccessClaims(record.Opaque, query.Digest, c.Auth.OAuthIssuer(), endpoint)
		if claims["active"] != true {
			return nil, nil, nil
		}
	}
	return record, claims, nil
}

func (opts Options) userInfoChallenge(h http.Header, scheme, code, description string) error {
	params := []string{quotedParameter("error", code), quotedParameter("error_description", headerDescription(description))}
	value := "Bearer " + strings.Join(params, ", ")
	if scheme == "" || strings.EqualFold(scheme, "DPoP") {
		algorithms := opts.DPoP.SigningAlgorithms
		if algorithms == nil {
			algorithms = resourceSigningAlgorithms()
		}
		algs := quotedParameter("algs", strings.Join(algorithms, " "))
		if scheme == "" {
			value = "Bearer, DPoP " + algs
		} else {
			value = "DPoP " + strings.Join(append(params, algs), ", ")
		}
	}
	h.Set("WWW-Authenticate", value)
	for _, list := range h.Values("Access-Control-Expose-Headers") {
		for name := range strings.SplitSeq(list, ",") {
			if strings.EqualFold(strings.TrimSpace(name), "WWW-Authenticate") {
				return registrationProblem(401, code, description)
			}
		}
	}
	h.Add("Access-Control-Expose-Headers", "WWW-Authenticate")
	return registrationProblem(401, code, description)
}
