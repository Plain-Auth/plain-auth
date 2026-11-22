package oauthprovider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/internal/jsjson"
)

// Consent records the access a user has granted to one OAuth client.
type Consent struct {
	ID                      string    `json:"id"`
	ClientID                string    `json:"clientId"`
	UserID                  *string   `json:"userId"`
	ReferenceID             *string   `json:"referenceId"`
	Resources               []string  `json:"resources"`
	RequestedUserInfoClaims []string  `json:"requestedUserInfoClaims"`
	Scopes                  []string  `json:"scopes"`
	CreatedAt               time.Time `json:"createdAt"`
	UpdatedAt               time.Time `json:"updatedAt"`
}

func (c Consent) MarshalJSON() ([]byte, error) {
	type fields Consent
	const millis = "2006-01-02T15:04:05.000Z"
	return json.Marshal(struct {
		fields
		Created string `json:"createdAt"`
		Updated string `json:"updatedAt"`
	}{fields(c), c.CreatedAt.UTC().Format(millis), c.UpdatedAt.UTC().Format(millis)})
}

// ConsentStore scopes every operation to the signed-in owner. Mutations must
// check ownership in the same transaction as the write. Scope updates must also
// enforce the registered client's current scope list, falling back to providerScopes.
// Return auth.ErrNotFound for a missing grant and auth.StatusOnlyError(401) for
// a different owner. A missing or unresolved client returns ErrClientNotFound.
type ConsentStore interface {
	OAuthConsent(ctx context.Context, userID, id string) (Consent, error)
	OAuthConsents(ctx context.Context, userID string) ([]Consent, error)
	UpdateOAuthConsent(ctx context.Context, userID, id string, scopes, providerScopes []string, now time.Time) (Consent, error)
	DeleteOAuthConsent(ctx context.Context, userID, id string) error
}

type ConsentOptions struct {
	// Scopes applies to clients with no registered scope list. An empty list permits no scopes.
	// The default allows openid, profile, email, and offline_access.
	Scopes []string
}

// ConsentManagement adds the four end-user consent endpoints to the auth mount.
func ConsentManagement(opts ConsentOptions) auth.Plugin {
	scopes := slices.Clone(opts.Scopes)
	if scopes == nil {
		scopes = []string{"openid", "profile", "email", "offline_access"}
	}
	scopes = slices.DeleteFunc(scopes, func(s string) bool { return s == "" })
	return auth.Plugin{ID: "oauth-provider", ValidateStore: func(s auth.Store) error {
		if _, ok := s.(ConsentStore); !ok {
			return errors.New("oauthprovider: consent management requires a ConsentStore")
		}
		return nil
	}, Endpoints: []auth.Endpoint{
		consentEndpoint(http.MethodGet, "get-consent", scopes),
		consentEndpoint(http.MethodGet, "get-consents", scopes),
		consentEndpoint(http.MethodPost, "update-consent", scopes),
		consentEndpoint(http.MethodPost, "delete-consent", scopes),
	}}
}

func consentEndpoint(method, action string, providerScopes []string) auth.Endpoint {
	return auth.Endpoint{Method: method, Path: "/oauth2/" + action, Handler: func(c auth.EndpointContext) (any, error) {
		ctx := c.Request.Context()
		store := c.Store().(ConsentStore)
		id, scopes, err := consentInput(c, action)
		if err != nil {
			return nil, err
		}
		session, err := c.Auth.GetSession(ctx, c.Request.Header)
		if err != nil {
			return nil, err
		}
		if session == nil {
			return nil, &auth.APIError{Status: 401, Code: "UNAUTHORIZED", Message: "Unauthorized"}
		}
		if err := session.Session.RequireOwner(); err != nil {
			return nil, err
		}
		c.ResponseHeader.Set("Cache-Control", "no-store")
		if action == "get-consents" {
			return store.OAuthConsents(ctx, session.User.ID)
		}
		if id == "" {
			return nil, &auth.OAuthError{Status: 404, Code: "not_found", Description: "missing id parameter"}
		}
		var result any
		switch action {
		case "get-consent":
			result, err = store.OAuthConsent(ctx, session.User.ID, id)
		case "update-consent":
			result, err = store.UpdateOAuthConsent(ctx, session.User.ID, id, scopes, providerScopes, time.Now().UTC().Truncate(time.Second))
		case "delete-consent":
			err = store.DeleteOAuthConsent(ctx, session.User.ID, id)
			result = auth.EmptyResponse{}
		}
		if errors.Is(err, auth.ErrNotFound) {
			return nil, &auth.OAuthError{Status: 404, Code: "not_found", Description: "no consent"}
		}
		if errors.Is(err, ErrClientNotFound) {
			return nil, &auth.OAuthError{Status: 404, Code: "not_found", Description: "client not found"}
		}
		return result, err
	}}
}

// consentInput reports every malformed field before any private record is accessed.
func consentInput(c auth.EndpointContext, action string) (string, []string, error) {
	var issues []string
	issue := func(path, want, got string) {
		issues = append(issues, "["+path+"] Invalid input: expected "+want+", received "+got)
	}
	var id string
	var scopes []string
	switch action {
	case "get-consent":
		ids := c.Request.URL.Query()["id"]
		switch len(ids) {
		case 0:
			issue("query.id", "string", "undefined")
		case 1:
			id = ids[0]
		default:
			issue("query.id", "string", "array")
		}
	case "update-consent", "delete-consent":
		var ok bool
		if id, ok = c.Body["id"].(string); !ok {
			issue("body.id", "string", consentFieldType(c.Body, "id"))
		}
		if action == "update-consent" {
			if update, ok := c.Body["update"].(map[string]any); !ok {
				issue("body.update", "object", consentFieldType(c.Body, "update"))
			} else if items, ok := update["scopes"].([]any); !ok {
				issue("body.update.scopes", "array", consentFieldType(update, "scopes"))
			} else {
				scopes = make([]string, len(items))
				for i, v := range items {
					if scopes[i], ok = v.(string); !ok {
						issue(fmt.Sprintf("body.update.scopes.%d", i), "string", jsjson.TypeName(v))
					}
				}
			}
		}
	}
	if len(issues) > 0 {
		return "", nil, &auth.APIError{Status: 400, Code: "VALIDATION_ERROR", Message: strings.Join(issues, "; ")}
	}
	return id, scopes, nil
}

func consentFieldType(obj map[string]any, key string) string {
	if value, ok := obj[key]; ok {
		return jsjson.TypeName(value)
	}
	return "undefined"
}
