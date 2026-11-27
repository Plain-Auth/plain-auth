package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/Plain-Org/plain-auth/plugins/oauthprovider"
)

// ProtectedHandlerOptions configures a protected MCP route. The embedded
// verifier options name the issuer, its keys or introspection, and DPoP;
// Audience must be exactly the MCP resource URL.
type ProtectedHandlerOptions struct {
	oauthprovider.AccessTokenVerifierOptions
	// RequiredScopes must all be granted to every accepted token.
	RequiredScopes []string
	// ChallengeScopes are advertised in challenges for requests without a
	// token. Nil means RequiredScopes.
	ChallengeScopes []string
	// OnError answers an error that is not a token rejection, such as
	// unreadable keys. It defaults to 500 Internal Server Error.
	OnError func(http.ResponseWriter, *http.Request, error)
}

type protectedKey struct{}

// protected is what a protected handler leaves in the request context.
type protected struct {
	claims     map[string]any
	challenges *oauthprovider.ResourceChallenges
}

// jsonRPCError is the JSON-RPC error body an MCP client reads, in field order.
type jsonRPCError struct {
	JSONRPC string `json:"jsonrpc"`
	Error   struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
	ID any `json:"id"`
}

// NewProtectedHandler verifies each request's access token for the MCP
// resource, as another runtime's createMcpProtectedRequestHandler does, and
// answers a rejected request with an RFC 9728 challenge and a JSON-RPC error
// body. A verified request reaches next, which reads the claims with
// AccessTokenClaims and can ask for more scopes with WriteInsufficientScope.
// next is an http.Handler, where another runtime passes the claims as a
// second argument, and errors it would rethrow go to OnError.
func NewProtectedHandler(opts ProtectedHandlerOptions, next http.Handler) (http.Handler, error) {
	if len(opts.Audience) != 1 {
		return nil, errors.New("mcp: Audience must be the single MCP resource URL")
	}
	resource, err := validateResource(opts.Audience[0])
	if err != nil {
		return nil, err
	}
	if opts.Origin == "" {
		opts.Origin = resource.Scheme + "://" + resource.Host
	}
	verifier, err := oauthprovider.NewAccessTokenVerifier(opts.AccessTokenVerifierOptions)
	if err != nil {
		return nil, err
	}
	scopes := opts.ChallengeScopes
	if scopes == nil {
		scopes = opts.RequiredScopes
	}
	challenges, err := oauthprovider.NewResourceChallenges(opts.Audience, oauthprovider.ChallengeOptions{Scopes: scopes, DPoPSigningAlgorithms: opts.DPoP.SigningAlgorithms})
	if err != nil {
		return nil, err
	}
	onError := opts.OnError
	if onError == nil {
		onError = func(w http.ResponseWriter, _ *http.Request, _ error) {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}
	}
	origin, required := opts.Origin, opts.RequiredScopes
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, err := verifier.VerifyRequest(r.Context(), oauthprovider.ResourceRequestFrom(r, origin), required...)
		var failure *oauthprovider.ResourceFailure
		if errors.As(err, &failure) {
			if writeChallenge(w, r, challenges, *failure) {
				return
			}
		}
		if err != nil {
			onError(w, r, err)
			return
		}
		ctx := context.WithValue(r.Context(), protectedKey{}, protected{claims: claims, challenges: challenges})
		next.ServeHTTP(w, r.WithContext(ctx))
	}), nil
}

// writeChallenge writes a prepared challenge with a JSON-RPC body, or
// reports false when the failure is not a challenge.
func writeChallenge(w http.ResponseWriter, r *http.Request, challenges *oauthprovider.ResourceChallenges, failure oauthprovider.ResourceFailure) bool {
	challenge, err := challenges.Prepare(r, failure)
	if challenge == nil || err != nil {
		return false
	}
	h := w.Header()
	h.Add("WWW-Authenticate", challenge.WWWAuthenticate)
	h.Add("Access-Control-Expose-Headers", "WWW-Authenticate")
	h.Set("Content-Type", "application/json")
	w.WriteHeader(challenge.Status)
	var body jsonRPCError
	body.JSONRPC, body.Error.Code, body.Error.Message = "2.0", -32000, challenge.Message
	json.NewEncoder(w).Encode(body)
	return true
}

// AccessTokenClaims returns the claims a protected handler verified.
func AccessTokenClaims(ctx context.Context) (map[string]any, bool) {
	p, ok := ctx.Value(protectedKey{}).(protected)
	return p.claims, ok
}

// WriteInsufficientScope answers a verified request that needs more
// scopes with a 403 insufficient_scope challenge naming them, in the
// scheme the request used, as another runtime's handler turns a thrown
// insufficient-scope error into one. Only this helper produces such a
// challenge, so a hand-written 403 passes through unchanged. It fails for
// a request no protected handler served.
func WriteInsufficientScope(w http.ResponseWriter, r *http.Request, scopes ...string) error {
	p, ok := r.Context().Value(protectedKey{}).(protected)
	if !ok {
		return errors.New("mcp: the request was not served by a protected handler")
	}
	if len(scopes) == 0 {
		return errors.New("mcp: insufficient scope needs at least one scope")
	}
	if !writeChallenge(w, r, p.challenges, oauthprovider.ResourceFailure{Status: http.StatusForbidden, Code: "insufficient_scope", MissingScopes: scopes}) {
		return errors.New("mcp: invalid insufficient scope challenge")
	}
	return nil
}
