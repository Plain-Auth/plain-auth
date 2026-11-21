package providers

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	auth "github.com/FineStack/finestack-auth"
	"golang.org/x/oauth2"
)

func configureProtocol(p *auth.OAuthProvider, name string) {
	switch name {
	case "vk":
		p.ExchangeCode = func(ctx context.Context, config oauth2.Config, code, verifier string, callback url.Values) (*oauth2.Token, error) {
			if len(callback["device_id"]) != 1 || callback.Get("device_id") == "" {
				return nil, errors.New("missing VK device ID")
			}
			return config.Exchange(ctx, code, oauth2.VerifierOption(verifier), oauth2.SetAuthURLParam("device_id", callback.Get("device_id")))
		}
	case "tiktok", "wechat":
		p.CustomizeAuthorization = func(target *url.URL) {
			q := target.Query()
			id := q.Get("client_id")
			q.Del("client_id")
			if name == "wechat" {
				q.Set("appid", id)
				target.Fragment = "wechat_redirect"
			} else {
				q.Set("client_key", id)
			}
			q.Set("scope", strings.Join(strings.Fields(q.Get("scope")), ","))
			target.RawQuery = q.Encode()
		}
		p.ExchangeCode = func(ctx context.Context, config oauth2.Config, code, verifier string, _ url.Values) (*oauth2.Token, error) {
			fields := url.Values{"code": {code}, "grant_type": {"authorization_code"}}
			method, target := http.MethodPost, config.Endpoint.TokenURL
			var body *strings.Reader
			if name == "wechat" {
				fields.Set("appid", config.ClientID)
				fields.Set("secret", config.ClientSecret)
				method = http.MethodGet
				target += "?" + fields.Encode()
				body = strings.NewReader("")
			} else {
				fields.Set("client_key", config.ClientID)
				fields.Set("client_secret", config.ClientSecret)
				fields.Set("redirect_uri", config.RedirectURL)
				fields.Set("code_verifier", verifier)
				body = strings.NewReader(fields.Encode())
			}
			return nonstandardToken(ctx, method, target, body)

		}
	}
}

func nonstandardToken(ctx context.Context, method, target string, body *strings.Reader) (*oauth2.Token, error) {
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, err
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	client, _ := ctx.Value(oauth2.HTTPClient).(*http.Client)
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	data, err := providerJSON(client, req)
	if err != nil {
		return nil, err
	}
	if data.text("access_token") == "" || data.text("error") != "" || (data.text("errcode") != "" && data.text("errcode") != "0") {
		return nil, errors.New("provider did not issue an access token")
	}
	token := &oauth2.Token{AccessToken: data.text("access_token"), RefreshToken: data.text("refresh_token"), TokenType: "Bearer"}
	if secs, err := strconv.ParseInt(data.text("expires_in"), 10, 32); err == nil && secs > 0 {
		token.Expiry = time.Now().Add(time.Duration(secs) * time.Second)
	}
	return token.WithExtra(map[string]any(data)), nil
}

type refreshContract struct {
	URL, Method string
	Basic       bool
	Fields      []string
}

func (f refreshContract) exchange(ctx context.Context, c oauth2.Config, refresh string) (*oauth2.Token, error) {
	if f.Method == "GET" {
		fields := url.Values{"appid": {c.ClientID}, "grant_type": {"refresh_token"}, "refresh_token": {refresh}}
		return nonstandardToken(ctx, http.MethodGet, f.URL+"?"+fields.Encode(), strings.NewReader(""))
	}
	if slices.Contains(f.Fields, "client_key") {
		fields := url.Values{"client_key": {c.ClientID}, "client_secret": {c.ClientSecret}, "grant_type": {"refresh_token"}, "refresh_token": {refresh}}
		return nonstandardToken(ctx, http.MethodPost, f.URL, strings.NewReader(fields.Encode()))
	}
	c.Endpoint.TokenURL = f.URL
	c.Endpoint.AuthStyle = oauth2.AuthStyleInParams
	if f.Basic && c.ClientSecret != "" {
		c.Endpoint.AuthStyle = oauth2.AuthStyleInHeader
	}
	return c.TokenSource(ctx, &oauth2.Token{RefreshToken: refresh}).Token()
}
