package providers

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	auth "github.com/Plain-Org/plain-auth"
	"golang.org/x/oauth2"
)

// endpointsOf returns the authorize, token, profile and refresh URLs a preset
// uses; the profile and refresh URLs are the ones its requests reach.
func endpointsOf(t *testing.T, p auth.OAuthProvider) [4]string {
	t.Helper()
	var seen []string
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if !strings.Contains(r.URL.Path, "debug_token") {
			seen = append(seen, r.URL.String())
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"data":{"is_valid":true,"app_id":"client","user_id":"u"}}`))}, nil
	})}
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, client)
	_, _ = p.Resolve(ctx, &oauth2.Token{AccessToken: "access"}, "")
	profile := seen
	seen = nil
	if p.Refresh != nil {
		_, _ = p.Refresh(ctx, p.Config, "refresh")
	} else {
		_, _ = p.Config.TokenSource(ctx, &oauth2.Token{RefreshToken: "refresh"}).Token()
	}
	if len(profile) == 0 || len(seen) == 0 {
		t.Fatalf("no profile or refresh request: %v %v", profile, seen)
	}
	return [4]string{p.Config.Endpoint.AuthURL, p.Config.Endpoint.TokenURL, profile[0], seen[0]}
}

// GitLab, Salesforce and PayPal presets reach another instance or
// environment through every endpoint, including refresh; without options they
// use gitlab.com, the Salesforce production login and the PayPal sandbox.
func TestCatalogPresetEndpoints(t *testing.T) {
	must := func(p auth.OAuthProvider, err error) auth.OAuthProvider {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	gitlab := func(base string) [4]string {
		return [4]string{base + "/oauth/authorize", base + "/oauth/token", base + "/api/v4/user", base + "/oauth/token"}
	}
	salesforce := func(host string) [4]string {
		b := "https://" + host + "/services/oauth2"
		return [4]string{b + "/authorize", b + "/token", b + "/userinfo", b + "/token"}
	}
	paypal := func(web, api string) [4]string {
		return [4]string{"https://" + web + "/signin/authorize", "https://" + api + "/v1/oauth2/token", "https://" + api + "/v1/identity/oauth2/userinfo?schema=paypalv1.1", "https://" + api + "/v1/oauth2/token"}
	}
	for _, tc := range []struct {
		name string
		p    auth.OAuthProvider
		want [4]string
	}{
		{"gitlab.com", must(GitLab("client", "secret", GitLabOptions{})), gitlab("https://gitlab.com")},
		{"self-managed GitLab", must(GitLab("client", "secret", GitLabOptions{Issuer: "https://gitlab.company.com/"})), gitlab("https://gitlab.company.com")},
		{"GitLab under a path", must(GitLab("client", "secret", GitLabOptions{Issuer: "https://code.example.org/gitlab"})), gitlab("https://code.example.org/gitlab")},
		{"Salesforce production", must(Salesforce("client", "secret", SalesforceOptions{})), salesforce("login.salesforce.com")},
		{"Salesforce sandbox", must(Salesforce("client", "secret", SalesforceOptions{Sandbox: true})), salesforce("test.salesforce.com")},
		{"Salesforce My Domain", must(Salesforce("client", "secret", SalesforceOptions{LoginURL: "my-company.my.salesforce.com"})), salesforce("my-company.my.salesforce.com")},
		{"Salesforce My Domain over sandbox", must(Salesforce("client", "secret", SalesforceOptions{Sandbox: true, LoginURL: "https://my-company--dev.sandbox.my.salesforce.com/"})), salesforce("my-company--dev.sandbox.my.salesforce.com")},
		{"PayPal sandbox", PayPal("client", "secret", PayPalOptions{}), paypal("www.sandbox.paypal.com", "api-m.sandbox.paypal.com")},
		{"PayPal live", PayPal("client", "secret", PayPalOptions{Live: true}), paypal("www.paypal.com", "api-m.paypal.com")},
	} {
		if got := endpointsOf(t, tc.p); got != tc.want {
			t.Fatalf("%s endpoints are %v, want %v", tc.name, got, tc.want)
		}
	}
	facebook := Facebook("client", "secret", FacebookOptions{Fields: []string{"birthday"}})
	if got := endpointsOf(t, facebook)[2]; got != "https://graph.facebook.com/me?fields=id%2Cname%2Cemail%2Cpicture%2Cbirthday" {
		t.Fatal("the Facebook profile request is", got)
	}
	if got := endpointsOf(t, Facebook("client", "secret", FacebookOptions{}))[2]; got != "https://graph.facebook.com/me?fields=id%2Cname%2Cemail%2Cpicture" {
		t.Fatal("the default Facebook profile request is", got)
	}
}

// GitLab refuses an issuer that is not a secure URL without a query, and
// Salesforce a login URL that is not a bare host.
func TestCatalogPresetValidation(t *testing.T) {
	for _, issuer := range []string{"http://gitlab.example.org", "https://g.example?x=1", "https://g.example#f"} {
		if _, err := GitLab("client", "secret", GitLabOptions{Issuer: issuer}); err == nil {
			t.Fatal("GitLab accepted", issuer)
		}
	}
	for _, login := range []string{"evil.example/path", "user@host.example", "host.example:8443", "https://", "host.example?x"} {
		if _, err := Salesforce("client", "secret", SalesforceOptions{LoginURL: login}); err == nil {
			t.Fatal("Salesforce accepted", login)
		}
	}
}

// Discord sends its bot permissions only with the bot scope, Dropbox its
// access type, Facebook its configuration ID and Reddit its duration; a
// call's additionalParams win.
func TestCatalogPresetParams(t *testing.T) {
	discord := func() auth.OAuthProvider {
		return Discord("client", "secret", DiscordOptions{Permissions: 2048 | 16384})
	}
	if q := startAuthorization(t, "discord", discord(), nil).Query(); q.Has("permissions") {
		t.Fatal("permissions were sent without the bot scope")
	}
	withBot := discord()
	withBot.Config.Scopes = append(withBot.Config.Scopes, "bot")
	if q := startAuthorization(t, "discord", withBot, nil).Query(); q.Get("permissions") != "18432" {
		t.Fatal("the bot scope did not send the permissions:", q)
	}
	if q := startAuthorization(t, "discord", discord(), map[string]any{"scopes": []string{"bot"}}).Query(); q.Get("permissions") != "18432" {
		t.Fatal("a requested bot scope did not send the permissions:", q)
	}
	if q := startAuthorization(t, "discord", withBot, map[string]any{"additionalParams": map[string]any{"permissions": "8"}}).Query(); q.Get("permissions") != "8" {
		t.Fatal("a call's permissions did not win:", q)
	}
	consent := discord()
	consent.AuthorizationParams.Set("prompt", "consent")
	if q := startAuthorization(t, "discord", consent, nil).Query(); q.Get("prompt") != "consent" {
		t.Fatal("the prompt was not replaced:", q)
	}
	dropbox := Dropbox("client", "secret", DropboxOptions{AccessType: "offline"})
	if q := startAuthorization(t, "dropbox", dropbox, nil).Query(); q.Get("token_access_type") != "offline" {
		t.Fatal("Dropbox did not send its access type:", q)
	}
	if q := startAuthorization(t, "dropbox", dropbox, map[string]any{"additionalParams": map[string]any{"token_access_type": "online"}}).Query(); q.Get("token_access_type") != "online" {
		t.Fatal("a call's access type did not win:", q)
	}
	if q := startAuthorization(t, "facebook", Facebook("client", "secret", FacebookOptions{ConfigID: "cfg-1"}), nil).Query(); q.Get("config_id") != "cfg-1" {
		t.Fatal("Facebook did not send its configuration ID:", q)
	}
	if q := startAuthorization(t, "reddit", Reddit("client", "secret", RedditOptions{Duration: "permanent"}), nil).Query(); q.Get("duration") != "permanent" {
		t.Fatal("Reddit did not send its duration:", q)
	}
}
