package sqlstore

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	authn "github.com/Stonewrit/stonewrit-auth"
	"github.com/Stonewrit/stonewrit-auth/plugins/anonymous"
	"github.com/Stonewrit/stonewrit-auth/schema"
	"golang.org/x/oauth2"
)

func TestGuestOAuthStateRecovery(t *testing.T) {
	const origin = "https://auth.example"
	ctx := t.Context()
	ddl, err := schema.Generate("sqlite", []string{"anonymous"})
	if err != nil {
		t.Fatal(err)
	}
	s, err := OpenWithSchema(ctx, "sqlite", filepath.Join(t.TempDir(), "test.sqlite"), ddl)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	count := 0
	p, err := anonymous.New(anonymous.Options{OnLinkAccount: func(_ context.Context, e anonymous.Link) error {
		if e.NewUser.User.Email != "oauth@example.test" {
			t.Fatal("wrong provider owner")
		}
		count++
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	provider := authn.OAuthProvider{Config: oauth2.Config{ClientID: "client", Endpoint: oauth2.Endpoint{AuthURL: "https://issuer.example/authorize", TokenURL: "https://issuer.example/token"}}, ExchangeCode: func(context.Context, oauth2.Config, string, string, url.Values) (*oauth2.Token, error) {
		return &oauth2.Token{AccessToken: "local"}, nil
	}, Resolve: func(context.Context, *oauth2.Token, string) (authn.OAuthProfile, error) {
		return authn.OAuthProfile{Subject: "registered", Name: "Social User", Email: "oauth@example.test", EmailVerified: true}, nil
	}}
	off := false
	a, err := authn.New(authn.Options{Store: s, BaseURL: origin, Secret: strings.Repeat("a", 32), EmailAndPassword: true, RateLimit: &off, Plugins: []authn.Plugin{p}, SocialProviders: map[string]authn.OAuthProvider{"work": provider}})
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, path, body string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, origin+"/api/auth"+path, strings.NewReader(body))
		if method == "POST" {
			r.Header.Set("Origin", origin)
			r.Header.Set("Content-Type", "application/json")
		}
		for _, c := range cookies {
			r.AddCookie(c)
		}
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w
	}
	begin := func() (authn.AuthResult, *http.Cookie, string, *http.Cookie) {
		t.Helper()
		guest := request("POST", "/sign-in/anonymous", "{}")
		if guest.Code != 200 {
			t.Fatal(guest.Body.String())
		}
		var u authn.AuthResult
		if err = json.Unmarshal(guest.Body.Bytes(), &u); err != nil {
			t.Fatal(err)
		}
		gc := a.SessionCookie(u.Token, true)
		start := request("POST", "/sign-in/social", `{"provider":"work","disableRedirect":true}`, gc)
		var body map[string]any
		json.Unmarshal(start.Body.Bytes(), &body)
		if start.Code != 200 {
			t.Fatal(start.Body.String())
		}
		target, _ := url.Parse(body["url"].(string))
		return u, gc, "/callback/work?code=valid&state=" + target.Query().Get("state"), start.Result().Cookies()[0]
	}
	active := func(id string) int {
		t.Helper()
		var n int
		if err := s.db.QueryRowContext(ctx, s.bind(`SELECT COUNT(*) FROM "user" WHERE "id"=?`), id).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	g, _, callback, oauthCookie := begin()
	if w := request("GET", callback, "", oauthCookie); w.Code != 302 {
		t.Fatalf("missing-session callback: %d %s", w.Code, w.Body.String())
	}
	if count != 1 || active(g.User.ID) != 0 {
		t.Fatal("provider callback lost the guest when its primary cookie was missing")
	}
	g, gc, callback, oauthCookie := begin()
	if w := request("POST", "/sign-out", "{}", gc); w.Code != 200 {
		t.Fatal("could not revoke guest")
	}
	if w := request("GET", callback, "", oauthCookie); w.Code != 302 {
		t.Fatal(w.Body.String())
	}
	if count != 1 || active(g.User.ID) != 1 {
		t.Fatal("revoked guest still authorized a transfer")
	}
	g, _, callback, oauthCookie = begin()
	another, _, _, _ := begin()
	if w := request("GET", callback, "", oauthCookie, a.SessionCookie(another.Token, true)); w.Code != 400 {
		t.Fatalf("switched guest: got %d", w.Code)
	}
	if active(g.User.ID) != 1 || count != 1 {
		t.Fatal("OAuth switched the wrong guest")
	}
}
