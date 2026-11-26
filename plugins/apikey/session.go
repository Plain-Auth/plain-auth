package apikey

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"time"

	plainauth "github.com/Plain-Org/plain-auth"
)

type sessionUserStore interface {
	APIKeySessionUser(context.Context, string) (plainauth.User, error)
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

func sessionResolver(services []*Service) *plainauth.CredentialSessionResolver {
	var enabled []*Service
	for _, service := range services {
		if service.opts.EnableSession {
			enabled = append(enabled, service)
		}
	}
	if len(enabled) == 0 {
		return nil
	}
	return &plainauth.CredentialSessionResolver{SelectRequest: func(r *http.Request) (plainauth.CredentialVerifier, error) {
		var secret, source string
		var candidates []*Service
		for _, service := range enabled {
			value, from, err := service.credential(r)
			if err != nil {
				return nil, err
			}
			if from == "" {
				continue
			}
			if source != "" && (from != source || value != secret) {
				return nil, invalidSessionKey
			}
			secret, source = value, from
			candidates = append(candidates, service)
		}
		if len(candidates) == 0 {
			return nil, nil
		}
		return func(ctx context.Context, meta plainauth.RequestMeta, ttl time.Duration) (*plainauth.CredentialSession, error) {
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
		}, nil
	}}
}

func (s *Service) resolveSession(ctx context.Context, secret string, meta plainauth.RequestMeta, ttl time.Duration) (*plainauth.CredentialSession, error) {
	if len(secret) < s.opts.KeyLength {
		return nil, errRefusedKey
	}
	v, err := s.Verify(ctx, secret, nil)
	if errors.Is(err, errKeyValidator) {
		// A host callback can return an APIError containing private details.
		return nil, errKeyValidator
	}
	if err != nil {
		return nil, err
	}
	if !v.Valid {
		if v.Error == nil {
			return nil, invalidSessionKey
		}
		if v.Error.Code == "KEY_NOT_FOUND" {
			// Session lookup has no requested permission scope. This code
			// therefore identifies an explicit rejection by the host.
			return nil, errRefusedKey
		}
		status := 401
		if v.Error.Code == "RATE_LIMITED" || v.Error.Code == "USAGE_EXCEEDED" {
			status = 429
		}
		return nil, problem(status, v.Error.Code, v.Error.Message)
	}
	if s.opts.Organization != nil {
		return nil, errReference
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
	return &plainauth.CredentialSession{
		Identity: plainauth.SessionResult{User: user, Session: plainauth.Session{
			ID: k.ID, UserID: user.ID, Token: secret, IPAddress: meta.IPAddress,
			UserAgent: meta.UserAgent, CreatedAt: now, UpdatedAt: now, ExpiresAt: expires,
		}},
		Allows: func(resource, action string) bool {
			return k.Permissions == nil || slices.Contains(k.Permissions[resource], action)
		},
		Bind: func(ctx context.Context) context.Context { return context.WithValue(ctx, proofContext{}, proof) },
	}, nil
}
