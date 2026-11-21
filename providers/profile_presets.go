package providers

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	auth "github.com/Stonewrit/stonewrit-auth"
	"golang.org/x/oauth2"
)

// These providers identify the account through an authenticated profile request.
type profilePreset struct {
	authorize, token, userInfo string
	scopes                     []string
}

var profilePresets = map[string]profilePreset{
	"gumroad": {
		authorize: "https://gumroad.com/oauth/authorize", token: "https://api.gumroad.com/oauth/token",
		userInfo: "https://api.gumroad.com/v2/user", scopes: []string{"view_profile"},
	},
	"hubspot": {
		authorize: "https://app.hubspot.com/oauth/authorize", token: "https://api.hubspot.com/oauth/2026-09/token",
		userInfo: "https://api.hubspot.com/oauth/2026-09/token/introspect", scopes: []string{"oauth"},
	},
	"patreon": {
		authorize: "https://www.patreon.com/oauth2/authorize", token: "https://www.patreon.com/api/oauth2/token",
		userInfo: "https://www.patreon.com/api/oauth2/v2/identity?fields[user]=email,full_name,image_url,is_email_verified", scopes: []string{"identity[email]"},
	},
	"slack-oidc": {
		authorize: "https://slack.com/openid/connect/authorize", token: "https://slack.com/api/openid.connect.token",
		userInfo: "https://slack.com/api/openid.connect.userInfo", scopes: []string{"openid", "profile", "email"},
	},
	"yandex": {
		authorize: "https://oauth.yandex.com/authorize", token: "https://oauth.yandex.com/token",
		userInfo: "https://login.yandex.ru/info?format=json", scopes: []string{"login:info", "login:email", "login:avatar"},
	},
}

func (p profilePreset) provider(name, clientID, secret string) auth.OAuthProvider {
	return auth.OAuthProvider{
		Config: oauth2.Config{
			ClientID: clientID, ClientSecret: secret, Scopes: slices.Clone(p.scopes),
			Endpoint: oauth2.Endpoint{AuthURL: p.authorize, TokenURL: p.token, AuthStyle: oauth2.AuthStyleInParams},
		},
		OmitNonce: name != "slack-oidc",
		Resolve: func(ctx context.Context, token *oauth2.Token, _ string) (auth.OAuthProfile, error) {
			if token == nil || token.AccessToken == "" {
				return auth.OAuthProfile{}, errors.New("profile requires an access token")
			}
			method, scheme, form := http.MethodGet, "Bearer", ""
			switch name {
			case "hubspot":
				method, scheme = http.MethodPost, ""
				form = url.Values{"client_id": {clientID}, "client_secret": {secret}, "token": {token.AccessToken}, "token_type_hint": {"access_token"}}.Encode()
			case "slack-oidc":
				method = http.MethodPost
			case "yandex":
				scheme = "OAuth"
			}
			req, err := http.NewRequestWithContext(ctx, method, p.userInfo, strings.NewReader(form))
			if err != nil {
				return auth.OAuthProfile{}, err
			}
			if scheme != "" {
				req.Header.Set("Authorization", scheme+" "+token.AccessToken)
			}
			req.Header.Set("Accept", "application/json")
			if method == http.MethodPost {
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
			client, _ := ctx.Value(oauth2.HTTPClient).(*http.Client)
			if client == nil {
				client = &http.Client{Timeout: 15 * time.Second}
			}
			// Credentials in introspection requests must stay at the configured endpoint.
			profileClient := *client
			profileClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			body, err := providerJSON(&profileClient, req)
			if err != nil {
				return auth.OAuthProfile{}, err
			}
			if name == "hubspot" && (!body.verified("active") || body.text("client_id") != clientID || body.text("token_use") != "access_token") {
				return auth.OAuthProfile{}, errors.New("HubSpot access token is inactive or belongs to another client")
			}
			return presetProfile(name, body)
		},
	}
}

func presetProfile(name string, p profileData) (auth.OAuthProfile, error) {
	var out auth.OAuthProfile
	var photo string
	subjectKey := "id"
	switch name {
	case "gumroad":
		if !p.verified("success") {
			return out, errors.New("Gumroad profile unavailable")
		}
		user := p.object("user")
		out.Subject, out.Name, out.Email = user.text("user_id"), user.text("name"), user.text("email")
		photo = user.text("profile_url")
	case "hubspot":
		out.Subject = p.text("user_id")
		if out.Subject == "" {
			out.Subject = p.object("signed_access_token").text("userId")
		}
		out.Email = p.text("user")
		out.Name = out.Email
	case "patreon":
		data := p.object("data")
		user := data.object("attributes")
		out.Subject, out.Name, out.Email = data.text("id"), user.text("full_name"), user.text("email")
		out.EmailVerified, photo = user.verified("is_email_verified"), user.text("image_url")
	case "slack-oidc":
		if ok, exists := p["ok"]; exists && ok != true {
			return out, errors.New("Slack profile unavailable")
		}
		subjectKey = "sub"
		out.Subject, out.Name, out.Email = p.text("sub"), p.text("name"), p.text("email")
		out.EmailVerified, photo = p.verified("email_verified"), p.text("picture", "https://slack.com/user_image_512")
	case "yandex":
		out.Subject, out.Name, out.Email = p.text("id"), p.text("display_name", "real_name", "first_name", "login"), p.text("default_email")
		if emails, ok := p["emails"].([]any); out.Email == "" && ok && len(emails) > 0 {
			out.Email, _ = emails[0].(string)
		}
		if avatar := p.text("default_avatar_id"); avatar != "" && !p.verified("is_avatar_empty") {
			photo = "https://avatars.yandex.net/get-yapic/" + url.PathEscape(avatar) + "/islands-200"
		}
	}
	if strings.TrimSpace(out.Subject) == "" || strings.TrimSpace(out.Email) == "" {
		return auth.OAuthProfile{}, errors.New("provider profile is missing a subject or email")
	}
	fields := map[string]any{subjectKey: out.Subject, "name": out.Name, "email": out.Email, "emailVerified": out.EmailVerified}
	if photo != "" {
		out.Image = &photo
		fields["image"] = photo
	}
	out.Data = fields
	return out, nil
}
