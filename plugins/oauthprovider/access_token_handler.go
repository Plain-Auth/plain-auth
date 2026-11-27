package oauthprovider

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
)

type accessTokenClaimsKey struct{}

// AccessTokenClaims returns the claims Handler verified for the request.
func AccessTokenClaims(ctx context.Context) (map[string]any, bool) {
	claims, ok := ctx.Value(accessTokenClaimsKey{}).(map[string]any)
	return claims, ok
}

// Handler protects next with VerifyRequest and the required scopes, as
// another runtime's resource client does. A verified request reaches next
// with its claims in the context; a failure gets a Bearer or DPoP
// challenge naming each audience's resource metadata, or 403
// insufficient_scope, with a JSON body; any other error is logged and
// answered 500. It refuses an invalid scope, an audience without metadata
// or a missing origin when built, where another runtime fails each
// request.
func (v *AccessTokenVerifier) Handler(next http.Handler, requiredScopes ...string) (http.Handler, error) {
	if err := checkRequiredScopes(requiredScopes); err != nil {
		return nil, err
	}
	origin := v.opts.Origin
	for _, aud := range v.opts.Audience {
		if origin != "" {
			break
		}
		if u, err := url.Parse(aud); err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" {
			origin = u.Scheme + "://" + u.Host
		}
	}
	if origin == "" {
		return nil, errors.New("oauthprovider: a protected handler needs the API's public origin")
	}
	challenges, err := NewResourceChallenges(v.opts.Audience, ChallengeOptions{MetadataMappings: v.opts.MetadataMappings, DPoPSigningAlgorithms: v.opts.DPoP.SigningAlgorithms})
	if err != nil {
		return nil, err
	}
	logger := slog.Default()
	if v.opts.Auth != nil {
		logger = v.opts.Auth.Logger()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, err := v.VerifyRequest(r.Context(), ResourceRequestFrom(r, origin), requiredScopes...)
		var failure *ResourceFailure
		if errors.As(err, &failure) {
			written, werr := challenges.Write(w, r, *failure)
			if written {
				return
			}
			err = werr
			if err == nil {
				err = failure
			}
		}
		if err != nil {
			logger.ErrorContext(r.Context(), "OAuth access token verification failed", "error", err)
			message := "access token verification failed"
			if errors.Is(err, errIntrospectionFailed) {
				message = "introspection failed"
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"message": message})
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), accessTokenClaimsKey{}, claims)))
	}), nil
}
