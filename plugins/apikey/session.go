package apikey

import (
	"context"

	"net/http"
	"slices"
	"time"

	stonewrit "github.com/Stonewrit/stonewrit-auth"
)

type sessionUserStore interface {
	APIKeySessionUser(context.Context, string) (stonewrit.User, error)
	UniqueSessionKeyConfiguration(context.Context, string, []string) (string, error)
}
type SessionProof struct{ ID, UserID, ConfigID, Digest string }
type proofContext struct{}

// SessionProofFrom returns proof established by the session resolver. A store
// can recheck this exact digest under the same lock that guards its mutation.
func SessionProofFrom(ctx context.Context) (SessionProof, bool) {
	p, ok := ctx.Value(proofContext{}).(SessionProof)
	return p, ok
}

func sessionResolver(services []*Service) *stonewrit.CredentialSessionResolver {
	byHeader := map[string][]*Service{}
	for _, service := range services {
		if service.opts.EnableSession {
			for _, name := range service.opts.Headers {
				byHeader[name] = append(byHeader[name], service)
			}
		}
	}
	if len(byHeader) == 0 {
		return nil
	}
	return &stonewrit.CredentialSessionResolver{
		Matches: func(h http.Header) bool {
			for name := range byHeader {
				if len(h.Values(name)) != 0 {
					return true
				}
			}
			return false
		},
		Resolve: func(ctx context.Context, h http.Header, meta stonewrit.RequestMeta, ttl time.Duration) (*stonewrit.CredentialSession, error) {
			var secret string
			var candidates []*Service
			for name, services := range byHeader {
				values := h.Values(name)
				if len(values) == 0 {
					continue
				}
				if len(values) != 1 || values[0] == "" || secret != "" {
					return nil, invalidSessionKey
				}
				secret, candidates = values[0], services
			}
			if len(candidates) == 0 {
				return nil, invalidSessionKey
			}
			service := candidates[0]
			if len(candidates) > 1 {
				ids := make([]string, len(candidates))
				for i, candidate := range candidates {
					ids[i] = candidate.opts.ConfigID
				}
				store := service.opts.Store.(sessionUserStore)
				id, err := store.UniqueSessionKeyConfiguration(ctx, Digest(secret), ids)
				if err != nil {
					return nil, err
				}
				index := slices.Index(ids, id)
				if index < 0 {
					return nil, invalidSessionKey
				}
				service = candidates[index]
			}
			return service.resolveSession(ctx, secret, meta, ttl)
		},
	}
}

var invalidSessionKey = problem(401, "INVALID_API_KEY", "Invalid API key")

func (s *Service) resolveSession(ctx context.Context, secret string, meta stonewrit.RequestMeta, ttl time.Duration) (*stonewrit.CredentialSession, error) {
	if len(secret) < s.opts.KeyLength {
		return nil, invalidSessionKey
	}
	v, err := s.Verify(ctx, secret, nil)
	if err != nil {
		return nil, err
	}
	if !v.Valid {
		if v.Error == nil {
			return nil, invalidSessionKey
		}
		status := 401
		if v.Error.Code == "RATE_LIMIT_EXCEEDED" || v.Error.Code == "USAGE_EXCEEDED" {
			status = 429
		}
		return nil, problem(status, v.Error.Code, v.Error.Message)
	}
	if s.opts.Organization != nil {
		return nil, problem(401, "INVALID_REFERENCE_ID_FROM_API_KEY", "An organization key cannot identify a user session")
	}
	k := v.Key
	user, err := s.opts.Store.(sessionUserStore).APIKeySessionUser(ctx, k.ReferenceID)
	if err != nil {
		return nil, err
	}
	now := current()
	expires := now.Add(ttl)
	if k.ExpiresAt != nil {
		expires = *k.ExpiresAt
	}
	proof := SessionProof{ID: k.ID, UserID: user.ID, ConfigID: k.ConfigID, Digest: Digest(secret)}
	return &stonewrit.CredentialSession{
		Identity: stonewrit.SessionResult{User: user, Session: stonewrit.Session{
			ID: k.ID, UserID: user.ID, Token: secret, IPAddress: meta.IPAddress,
			UserAgent: meta.UserAgent, CreatedAt: now, UpdatedAt: now, ExpiresAt: expires,
		}},
		Allows: func(resource, action string) bool {
			return k.Permissions == nil || slices.Contains(k.Permissions[resource], action)
		},
		Bind: func(ctx context.Context) context.Context { return context.WithValue(ctx, proofContext{}, proof) },
	}, nil
}
