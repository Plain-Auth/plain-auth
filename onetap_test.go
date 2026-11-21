package authn

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestOneTapConfiguredAudienceAndChallengeExpiry(t *testing.T) {
	const origin = "https://one.example"
	now := time.Now().Truncate(time.Second)
	a := &Auth{opts: Options{Secret: strings.Repeat("x", 32), BaseURL: origin}, now: func() time.Time { return now }}
	var verified bool
	var fallback OAuthProvider
	fallback.Config.ClientID = "custom-audience"
	fallback.VerifyIDToken = func(context.Context, string, string) (OAuthProfile, time.Time, error) {
		verified = true
		return OAuthProfile{}, time.Time{}, errors.New("unused")
	}
	p := NewOneTap(OneTapOptions{ClientID: "custom-audience"}, fallback)
	call := func(ep Endpoint, cookie *http.Cookie) (any, http.Header, error) {
		r := httptest.NewRequest("POST", origin+ep.Path, nil)
		r.Header.Set("Origin", origin)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		h := make(http.Header)
		v, err := ep.Handler(EndpointContext{Auth: a, Request: r, ResponseHeader: h, Body: map[string]any{"idToken": "synthetic"}})
		return v, h, err
	}
	out, h, err := call(p.Endpoints[0], nil)
	if err != nil || out.(map[string]string)["clientId"] != "custom-audience" {
		t.Fatal("explicit client ID was not used")
	}
	response := http.Response{Header: h}
	c := response.Cookies()[0]
	now = now.Add(5 * time.Minute)
	_, _, err = call(p.Endpoints[1], c)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != "INVALID_TOKEN" || verified {
		t.Fatal("expired browser proof reached the Google verifier")
	}
	blank := NewOneTap(OneTapOptions{}, OAuthProvider{})
	_, headers, err := call(blank.Endpoints[0], nil)
	if !errors.As(err, &apiErr) || apiErr.Code != "GOOGLE_CLIENT_ID_REQUIRED" || headers.Get("Set-Cookie") != "" {
		t.Fatal("browser challenge issued without a Google audience")
	}
}

func TestHostOneTapNonceIsBoundServerSide(t *testing.T) {
	const origin = "https://host.example"
	a := &Auth{opts: Options{Secret: strings.Repeat("s", 32), BaseURL: origin}, now: time.Now}
	for _, in := range []struct{ origin, id, nonce string }{{"https://other.test", "client", randomID()}, {origin + "/path", "client", randomID()}, {origin, "", randomID()}, {origin, "client", "short"}, {origin, "client", strings.Repeat("a", 257)}} {
		w := httptest.NewRecorder()
		if err := a.BindOneTapNonce(w, in.origin, in.id, in.nonce); err == nil || w.Header().Get("Set-Cookie") != "" {
			t.Fatal("invalid host challenge acquired a browser cookie")
		}
	}
	w := httptest.NewRecorder()
	nonce := randomID()
	if err := a.BindOneTapNonce(w, origin, "client", nonce); err != nil {
		t.Fatal(err)
	}
	c := w.Result().Cookies()[0]
	if c.Value == nonce || !c.HttpOnly || !c.Secure || c.Domain != "" || c.MaxAge != 300 {
		t.Fatal("host nonce lacks a protected, expiring browser binding")
	}
}
