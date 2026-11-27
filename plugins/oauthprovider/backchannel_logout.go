package oauthprovider

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/internal/publicnet"
)

const (
	// backchannelLogoutEvent is the event every logout token carries.
	backchannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout"
	logoutTokenLifetime    = 2 * time.Minute
	// backchannelTimeout bounds each delivery; a client gets one attempt.
	backchannelTimeout = 5 * time.Second
)

// defaultBackchannelTransport dials only public addresses, checking every
// address a client's logout host resolves to.
var defaultBackchannelTransport = sync.OnceValue(func() http.RoundTripper {
	return publicnet.Transport(errors.New("oauthprovider: backchannel_logout_uri must resolve to a public address"))
})

// backchannelSupported reports whether the issuer sends logout tokens: the
// jwt plugin signs them, and the store reports the sessions it ends.
func backchannelSupported(a *auth.Auth, store auth.Store) bool {
	if a == nil || a.JWTSigningAlgorithm() == "" {
		return false
	}
	_, reports := store.(auth.SessionEndReporter)
	_, clients := store.(ClientDirectoryStore)
	return reports && clients
}

// sessionsEnded sends a logout token to every enabled client with a
// back-channel logout URI that held tokens on an ended session. Delivery
// runs through Auth.RunInBackgroundOrAwait, inline without a background
// runner, as another runtime runs it.
func (opts Options) sessionsEnded(ctx context.Context, e auth.SessionsEnded) {
	if !slices.ContainsFunc(e.Sessions, func(s auth.EndedSession) bool { return len(s.OAuthClients) > 0 }) || !backchannelSupported(e.Auth, e.Store) {
		return
	}
	sessions := slices.Clone(e.Sessions)
	store := e.Store.(ClientDirectoryStore)
	e.Auth.RunInBackgroundOrAwait(ctx, func(ctx context.Context) error {
		// Inline delivery outlives a caller that goes away; each client is
		// still bounded by its own deadline.
		opts.sendLogoutTokens(context.WithoutCancel(ctx), e.Auth, store, sessions)
		return nil
	})
}

func (opts Options) sendLogoutTokens(ctx context.Context, a *auth.Auth, store ClientDirectoryStore, sessions []auth.EndedSession) {
	transport := opts.BackchannelTransport
	if transport == nil {
		transport = defaultBackchannelTransport()
	}
	httpClient := &http.Client{Transport: transport, Timeout: backchannelTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	now := time.Now()
	var wg sync.WaitGroup
	for _, session := range sessions {
		for _, id := range session.OAuthClients {
			client, err := store.LookupOAuthClient(ctx, id)
			if err != nil {
				if !errors.Is(err, ErrClientNotFound) {
					a.Logger().WarnContext(ctx, "Back-channel logout could not read the client", "client", id, "error", err)
				}
				continue
			}
			if client.BackchannelLogoutURI == nil || *client.BackchannelLogoutURI == "" || client.Disabled != nil && *client.Disabled {
				continue
			}
			// The subject is the one the client's ID tokens carry.
			subject := session.UserID
			if client.SubjectType != nil && *client.SubjectType == "pairwise" {
				if subject, err = pairwiseSubject(opts.PairwiseSecret, session.UserID, client.RedirectURIs); err != nil {
					a.Logger().WarnContext(ctx, "Back-channel logout could not resolve the subject", "client", id, "error", err)
					continue
				}
			}
			wg.Add(1)
			go func(uri, subject, sid string) {
				defer wg.Done()
				if err := sendLogoutToken(ctx, a, httpClient, id, uri, subject, sid, now); err != nil {
					a.Logger().WarnContext(ctx, "Back-channel logout failed", "client", id, "error", err)
				}
			}(*client.BackchannelLogoutURI, subject, session.ID)
		}
	}
	wg.Wait()
}

// errLogoutRefused reports a client that answered other than 200 or 204.
var errLogoutRefused = errors.New("the client did not accept the logout token")

// sendLogoutToken signs one logout token, as OIDC Back-Channel Logout 1.0
// section 2.4 describes, and posts it once.
func sendLogoutToken(ctx context.Context, a *auth.Auth, httpClient *http.Client, clientID, uri, subject, sid string, now time.Time) error {
	token, err := a.SignJWT(ctx, subject, auth.JWTSignOptions{Type: "logout+jwt", Issuer: a.OAuthIssuer(), Audience: []string{clientID},
		IssuedAt: now, ExpiresAt: now.Add(logoutTokenLifetime),
		Claims: map[string]any{"sid": sid, "jti": logoutTokenID(), "events": map[string]any{backchannelLogoutEvent: map[string]any{}}}})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, backchannelTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uri, strings.NewReader(url.Values{"logout_token": {token}}.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return errors.Join(errLogoutRefused, errors.New(resp.Status))
	}
	return nil
}

// logoutTokenID returns 32 random letters and digits, as another runtime's
// logout token jti is.
func logoutTokenID() string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 32)
	for i := range b {
		var n [1]byte
		// Rejection sampling keeps every letter equally likely.
		for {
			_, _ = rand.Read(n[:])
			if int(n[0]) < 256-256%len(letters) {
				break
			}
		}
		b[i] = letters[int(n[0])%len(letters)]
	}
	return string(b)
}
