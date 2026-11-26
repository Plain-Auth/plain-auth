package goapi_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"golang.org/x/oauth2"
)

// A provider with VerifyAccessToken signs in with an access token the client
// sends as idToken.token and repeats as idToken.accessToken, with no nonce:
// only that verifier runs, the token is stored as the account's access
// token, never sent as a logout hint, and it cannot sign in again within
// the hour. A token without its
// repeat, a refused token, a JWS without a nonce, and a JWS at a provider
// without VerifyIDToken fail without a verifier call, and
// DisableIDTokenSignIn closes the grant.
func TestProviderAccessTokenSignIn(t *testing.T) {
	var mu sync.Mutex
	var calls []string
	note := func(call string) {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, call)
	}
	taken := func() []string {
		mu.Lock()
		defer mu.Unlock()
		out := calls
		calls = nil
		return out
	}
	provider := func() auth.OAuthProvider {
		return auth.OAuthProvider{
			Config:             oauth2.Config{ClientID: "client", ClientSecret: "secret", Endpoint: oauth2.Endpoint{AuthURL: "https://idp.example/authorize", TokenURL: "https://idp.example/token"}},
			EndSessionEndpoint: "https://idp.example/end",
			Resolve: func(context.Context, *oauth2.Token, string) (auth.OAuthProfile, error) {
				return auth.OAuthProfile{}, errors.New("unused")
			},
			VerifyIDToken: func(_ context.Context, raw, nonce string) (auth.OAuthProfile, time.Time, error) {
				note("id:" + raw + ":" + nonce)
				return auth.OAuthProfile{Subject: "id-subject", Email: "id@example.org", EmailVerified: true}, time.Now().Add(time.Minute), nil
			},
			VerifyAccessToken: func(_ context.Context, token string) (auth.OAuthProfile, error) {
				note("access:" + token)
				if token == "at-refused" {
					return auth.OAuthProfile{}, errors.New("issued to another app")
				}
				return auth.OAuthProfile{Subject: "subject-" + token, Email: token + "@example.org", EmailVerified: true}, nil
			},
		}
	}
	n, err := newTokenAuthNode(t, provider())
	if err != nil {
		t.Fatal(err)
	}
	signIn := func(n *tokenAuthNode, idToken string) (int, string) {
		t.Helper()
		res := n.post(t, "/sign-in/social", `{"provider":"work","idToken":`+idToken+`}`)
		if res.StatusCode == 200 {
			return 200, ""
		}
		return res.StatusCode, errorCode(t, res)
	}
	if status, code := signIn(n, `{"token":"at-ada","accessToken":"at-ada"}`); status != 200 {
		t.Fatal("the access token sign-in answered", status, code)
	}
	if got := taken(); len(got) != 1 || got[0] != "access:at-ada" {
		t.Fatal("the verifiers saw", got)
	}
	var token struct{ AccessToken string }
	if err := json.NewDecoder(n.post(t, "/get-access-token", `{"accountId":"`+n.accountID(t)+`"}`).Body).Decode(&token); err != nil || token.AccessToken != "at-ada" {
		t.Fatal("the stored access token is", token.AccessToken, err)
	}
	// The stored access token never becomes a logout URL's id_token_hint.
	var logout struct{ URL string }
	if err := json.NewDecoder(n.post(t, "/sign-out", `{"disableRedirect":true}`).Body).Decode(&logout); err != nil ||
		!strings.HasPrefix(logout.URL, "https://idp.example/end") || strings.Contains(logout.URL, "id_token_hint") || strings.Contains(logout.URL, "at-ada") {
		t.Fatal("provider logout went to", logout.URL, err)
	}
	if status, code := signIn(n, `{"token":"at-ada","accessToken":"at-ada"}`); status != 401 || code != "INVALID_TOKEN" {
		t.Fatal("a reused access token answered", status, code)
	}
	taken()
	for body, want := range map[string]string{
		`{"token":"at-bob"}`:                       "FAILED_TO_GET_USER_INFO",
		`{"token":"at-bob","accessToken":"other"}`: "FAILED_TO_GET_USER_INFO",
		`{"token":"a.b.c"}`:                        "INVALID_TOKEN",
		`{"token":"a.b.c","accessToken":"a.b.c"}`:  "INVALID_TOKEN",
	} {
		if status, code := signIn(n, body); status != 401 || code != want {
			t.Fatal(body, "answered", status, code)
		}
		if got := taken(); len(got) != 0 {
			t.Fatal(body, "reached", got)
		}
	}
	if status, code := signIn(n, `{"token":"at-refused","accessToken":"at-refused"}`); status != 401 || code != "FAILED_TO_GET_USER_INFO" {
		t.Fatal("a refused access token answered", status, code)
	}
	taken()
	if status, _ := signIn(n, `{"token":"a.b.c","nonce":"n"}`); status != 200 {
		t.Fatal("an ID token with its nonce answered", status)
	}
	if got := taken(); len(got) != 1 || got[0] != "id:a.b.c:n" {
		t.Fatal("the ID token reached", got)
	}

	accessOnly := provider()
	accessOnly.VerifyIDToken = nil
	if n, err = newTokenAuthNode(t, accessOnly); err != nil {
		t.Fatal(err)
	}
	if status, code := signIn(n, `{"token":"a.b.c","nonce":"n"}`); status != 401 || code != "INVALID_TOKEN" {
		t.Fatal("a JWS at a provider without VerifyIDToken answered", status, code)
	}
	if status, _ := signIn(n, `{"token":"at-cy","accessToken":"at-cy"}`); status != 200 {
		t.Fatal("an access token at a provider without VerifyIDToken answered", status)
	}
	closed := provider()
	closed.DisableIDTokenSignIn = true
	if n, err = newTokenAuthNode(t, closed); err != nil {
		t.Fatal(err)
	}
	if status, code := signIn(n, `{"token":"at-dee","accessToken":"at-dee"}`); status != 404 || code != "ID_TOKEN_NOT_SUPPORTED" {
		t.Fatal("a closed provider answered", status, code)
	}
	if got := taken(); len(got) != 1 || got[0] != "access:at-cy" {
		t.Fatal("the verifiers saw", got)
	}
}

// A direct ID token signs in once: a copy whose segments are re-encoded,
// with padding or other spare bits, decodes to the same token and is
// refused too, while a different token still signs in.
func TestDirectIDTokenReencodedReplay(t *testing.T) {
	n, err := newTokenAuthNode(t, auth.OAuthProvider{
		Config: oauth2.Config{ClientID: "client", ClientSecret: "secret", Endpoint: oauth2.Endpoint{AuthURL: "https://idp.example/authorize", TokenURL: "https://idp.example/token"}},
		Resolve: func(context.Context, *oauth2.Token, string) (auth.OAuthProfile, error) {
			return auth.OAuthProfile{}, errors.New("unused")
		},
		// Like a JWS decoder, this verifier reads each segment leniently.
		VerifyIDToken: func(_ context.Context, raw, _ string) (auth.OAuthProfile, time.Time, error) {
			return auth.OAuthProfile{Subject: "subject", Email: "person@example.org", EmailVerified: true}, time.Now().Add(time.Minute), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	signIn := func(token string) int {
		return n.post(t, "/sign-in/social", `{"provider":"work","idToken":{"token":"`+token+`","nonce":"n"}}`).StatusCode
	}
	if status := signIn("aGk.aGk.aGk"); status != 200 {
		t.Fatal("the first sign-in answered", status)
	}
	for _, copy := range []string{"aGk.aGk.aGk", "aGk.aGk.aGl", "aGk.aGk.aGk=", "aGl.aGk.aGk"} {
		if status := signIn(copy); status != 401 {
			t.Fatal("a copy of the used token,", copy, "answered", status)
		}
	}
	if status := signIn("aGk.aGk.aGw"); status != 200 {
		t.Fatal("a different token answered", status)
	}
}
