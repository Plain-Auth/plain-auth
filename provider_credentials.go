package betterauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

// AccountSelection identifies a local linked-account record. UserID is only
// used by trusted server calls with nil session headers.
type AccountSelection struct {
	AccountID, UserID string
	UseAccountCookie  bool
}

// ProviderAccountCredential is internal adapter data. Credential values stay
// out of the serialized representation.
type ProviderAccountCredential struct {
	ID, UserID, ProviderID, Subject string
	OAuthTokens                     `json:"-"`
}

// ProviderCredentialStore locks a single owned account during rotation so
// concurrent refreshes cannot spend the same rotating refresh token twice.
type ProviderCredentialStore interface {
	ProviderCredential(ctx context.Context, userID, id string) (ProviderAccountCredential, error)
	UpdateProviderCredential(ctx context.Context, userID, id string, update func(ProviderAccountCredential) (ProviderAccountCredential, bool, error)) (ProviderAccountCredential, error)
}

type AccessTokenResult struct {
	AccessToken          string     `json:"accessToken"`
	AccessTokenExpiresAt *time.Time `json:"accessTokenExpiresAt,omitempty"`
	Scopes               []string   `json:"scopes"`
	IDToken              string     `json:"idToken,omitempty"`
}
type RefreshTokenResult struct {
	AccessToken           string     `json:"accessToken"`
	RefreshToken          string     `json:"refreshToken"`
	AccessTokenExpiresAt  *time.Time `json:"accessTokenExpiresAt,omitempty"`
	RefreshTokenExpiresAt *time.Time `json:"refreshTokenExpiresAt"`
	Scope                 *string    `json:"scope"`
	IDToken               *string    `json:"idToken"`
	ProviderID            string     `json:"providerId"`
	AccountID             string     `json:"accountId"`
}
type AccountInfoResult struct {
	User struct {
		Name          string  `json:"name"`
		Email         string  `json:"email"`
		EmailVerified bool    `json:"emailVerified"`
		Image         *string `json:"image,omitempty"`
	} `json:"user"`
	Account struct {
		ID         string `json:"id"`
		ProviderID string `json:"providerId"`
		AccountID  string `json:"accountId"`
	} `json:"account"`
	Data any `json:"data"`
}

func (a *Auth) providerCredentialsHTTP(ctx context.Context, route string, r *http.Request, body wireBody) (any, error) {
	if r.Method == "GET" {
		body = wireBody{}
		for k, v := range r.URL.Query() {
			if len(v) != 1 {
				return nil, validationError("Duplicate account selector")
			}
			body[k] = v[0]
		}
		if body["useAccountCookie"] == "true" {
			body["useAccountCookie"] = true
		}
	}
	var s AccountSelection
	for k, v := range body {
		switch k {
		case "accountId", "userId":
			value, ok := v.(string)
			if !ok {
				return nil, fieldTypeError(k, "string", body)
			}
			if k == "accountId" {
				s.AccountID = value
			} else {
				s.UserID = value
			}
		case "useAccountCookie":
			b, ok := v.(bool)
			if !ok || !b {
				return nil, validationError("Invalid account selector")
			}
			s.UseAccountCookie = true
		default:
			return nil, validationError("Unknown account selector")
		}
	}
	// An HTTP request is never a trusted server call, including when tests or
	// proxies construct a request with a nil Header map.
	h := r.Header
	if h == nil {
		h = http.Header{}
	}
	switch route {
	case "/get-access-token":
		return a.GetAccessToken(ctx, h, s)
	case "/refresh-token":
		return a.RefreshToken(ctx, h, s)
	default:
		return a.AccountInfo(ctx, h, s)
	}
}

func (a *Auth) selectedCredential(ctx context.Context, h http.Header, s AccountSelection, info bool) (ProviderCredentialStore, ProviderAccountCredential, OAuthProvider, error) {
	var row ProviderAccountCredential
	var p OAuthProvider
	if (s.AccountID != "") == s.UseAccountCookie {
		return nil, row, p, validationError("Select exactly one account")
	}
	userID := s.UserID
	if h != nil {
		session, err := a.requireSession(ctx, h)
		if err != nil {
			return nil, row, p, err
		}
		userID = session.User.ID
	}
	if userID == "" {
		return nil, row, p, &APIError{400, "USER_ID_OR_SESSION_REQUIRED", "Either userId or session is required"}
	}
	if s.UseAccountCookie {
		return nil, row, p, &APIError{400, "ACCOUNT_NOT_FOUND", "Account not found"}
	}
	store, ok := a.opts.Store.(ProviderCredentialStore)
	if !ok {
		return nil, row, p, &APIError{501, "ACCOUNT_STORAGE_UNAVAILABLE", "Account operation is unavailable for this store"}
	}
	row, err := store.ProviderCredential(ctx, userID, s.AccountID)
	if errors.Is(err, ErrNotFound) {
		return nil, row, p, &APIError{400, "ACCOUNT_NOT_FOUND", "Account not found"}
	}
	if err != nil {
		return nil, row, p, err
	}
	p, ok = a.opts.SocialProviders[row.ProviderID]
	if !ok {
		if info {
			return nil, row, p, &APIError{400, "PROVIDER_NOT_CONFIGURED", "Account is not associated with a configured social provider."}
		}
		return nil, row, p, &APIError{400, "PROVIDER_NOT_SUPPORTED", "Provider " + row.ProviderID + " is not supported."}
	}
	return store, row, p, nil
}

func (a *Auth) validCredential(ctx context.Context, store ProviderCredentialStore, row ProviderAccountCredential, p OAuthProvider, force bool) (ProviderAccountCredential, error) {
	due := func(r ProviderAccountCredential) bool {
		return !r.ExpiresAt.IsZero() && r.ExpiresAt.Sub(a.now()) < 5*time.Second
	}
	if force && p.DisableRefresh {
		return row, &APIError{400, "TOKEN_REFRESH_NOT_SUPPORTED", "Provider " + row.ProviderID + " does not support token refreshing."}
	}
	if !force && (!due(row) || p.DisableRefresh || row.RefreshToken == "") {
		return row, nil
	}
	ctx, cancel := context.WithTimeout(context.WithValue(ctx, oauth2.HTTPClient, p.HTTPClient), 15*time.Second)
	defer cancel()
	return store.UpdateProviderCredential(ctx, row.UserID, row.ID, func(current ProviderAccountCredential) (ProviderAccountCredential, bool, error) {
		if current.ProviderID != row.ProviderID || current.Subject != row.Subject {
			return current, false, &APIError{400, "ACCOUNT_NOT_FOUND", "Account not found"}
		}
		if !force && !due(current) {
			return current, false, nil
		}
		if current.RefreshToken == "" {
			return current, false, &APIError{400, "REFRESH_TOKEN_NOT_FOUND", "Refresh token not found"}
		}
		failure := &APIError{400, "FAILED_TO_GET_ACCESS_TOKEN", "Failed to get a valid access token"}
		if force {
			failure = &APIError{400, "FAILED_TO_REFRESH_ACCESS_TOKEN", "Failed to refresh access token"}
		}
		if !current.RefreshExpiresAt.IsZero() && !current.RefreshExpiresAt.After(a.now()) {
			return current, false, failure
		}
		var t *oauth2.Token
		var err error
		if p.Refresh != nil {
			t, err = p.Refresh(ctx, p.Config, current.RefreshToken)
		} else {
			t, err = p.Config.TokenSource(ctx, &oauth2.Token{RefreshToken: current.RefreshToken}).Token()
		}
		if err != nil || t == nil || t.AccessToken == "" {
			return current, false, failure
		}
		current.AccessToken = t.AccessToken
		current.ExpiresAt = t.Expiry
		if t.RefreshToken != "" {
			current.RefreshToken = t.RefreshToken
		}
		if id, _ := t.Extra("id_token").(string); id != "" {
			current.IDToken = id
		}
		if lifetime := refreshLifetime(t); lifetime > 0 {
			current.RefreshExpiresAt = a.now().Add(lifetime)
		}
		return current, true, nil
	})
}

func refreshLifetime(t *oauth2.Token) time.Duration {
	// Providers return a numeric count of seconds, using either key.
	for _, key := range []string{"refresh_token_expires_in", "refresh_expires_in"} {
		var secs int64
		switch n := t.Extra(key).(type) {
		case float64:
			secs = int64(n)
		case json.Number:
			secs, _ = n.Int64()
		case int64:
			secs = n
		}
		if secs > 0 && secs < 1<<31 {
			return time.Duration(secs) * time.Second
		}
	}
	return 0
}
func optionalTimestamp(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	t = t.UTC()
	return &t
}
func optionalToken(v string) *string {
	if v == "" {
		return nil
	}
	return &v
}
func accountScopes(raw string) []string {
	scopes := []string{}
	for part := range strings.SplitSeq(raw, ",") {
		if s := strings.TrimSpace(part); s != "" {
			scopes = append(scopes, s)
		}
	}
	return scopes
}

func (a *Auth) GetAccessToken(ctx context.Context, h http.Header, s AccountSelection) (AccessTokenResult, error) {
	var out AccessTokenResult
	store, row, p, err := a.selectedCredential(ctx, h, s, false)
	if err != nil {
		return out, err
	}
	row, err = a.validCredential(ctx, store, row, p, false)
	if err != nil {
		return out, err
	}
	return AccessTokenResult{AccessToken: row.AccessToken, AccessTokenExpiresAt: optionalTimestamp(row.ExpiresAt), Scopes: accountScopes(row.Scope), IDToken: row.IDToken}, nil
}

func (a *Auth) RefreshToken(ctx context.Context, h http.Header, s AccountSelection) (RefreshTokenResult, error) {
	var out RefreshTokenResult
	store, row, p, err := a.selectedCredential(ctx, h, s, false)
	if err != nil {
		return out, err
	}
	row, err = a.validCredential(ctx, store, row, p, true)
	if err != nil {
		return out, err
	}
	return RefreshTokenResult{AccessToken: row.AccessToken, RefreshToken: row.RefreshToken, AccessTokenExpiresAt: optionalTimestamp(row.ExpiresAt), RefreshTokenExpiresAt: optionalTimestamp(row.RefreshExpiresAt), Scope: optionalToken(row.Scope), IDToken: optionalToken(row.IDToken), ProviderID: row.ProviderID, AccountID: row.ID}, nil
}

func (a *Auth) AccountInfo(ctx context.Context, h http.Header, s AccountSelection) (AccountInfoResult, error) {
	var out AccountInfoResult
	store, row, p, err := a.selectedCredential(ctx, h, s, true)
	if err != nil {
		return out, err
	}
	row, err = a.validCredential(ctx, store, row, p, false)
	if err != nil {
		return out, err
	}
	if row.AccessToken == "" {
		return out, &APIError{400, "ACCESS_TOKEN_NOT_FOUND", "Access token not found"}
	}
	// This is a read of the user's already-linked credential. A stored nonce
	// permits the OIDC resolver to revalidate a previously issued signed token.
	var stored struct{ Nonce string }
	parts := strings.Split(row.IDToken, ".")
	if len(parts) == 3 {
		if b, e := base64.RawURLEncoding.DecodeString(parts[1]); e == nil {
			_ = json.Unmarshal(b, &stored)
		}
	}
	token := (&oauth2.Token{AccessToken: row.AccessToken, Expiry: row.ExpiresAt}).WithExtra(map[string]any{"id_token": row.IDToken})
	ctx, cancel := context.WithTimeout(context.WithValue(ctx, oauth2.HTTPClient, p.HTTPClient), 15*time.Second)
	defer cancel()
	profile, err := p.Resolve(ctx, token, stored.Nonce)
	if err != nil || profile.Subject != row.Subject {
		return out, &APIError{401, "FAILED_TO_GET_USER_INFO", "Failed to get user info"}
	}
	out.User.Name, out.User.Email, out.User.EmailVerified, out.User.Image = profile.Name, profile.Email, profile.EmailVerified, profile.Image
	out.Account.ID, out.Account.ProviderID, out.Account.AccountID = row.ID, row.ProviderID, row.Subject
	out.Data = profile.Data
	if out.Data == nil {
		out.Data = map[string]any{}
	}
	return out, nil
}
