package providers

import (
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	auth "github.com/nabuhadba/go-better-auth"
	"golang.org/x/oauth2"
)

type catalogEntry struct {
	Refresh                                            *refreshContract
	Authorization, Token, Profile, Method, ProfileBody string
	PKCE, Basic                                        bool
	Scopes                                             []string
	Params, Headers                                    map[string]string
}

//go:embed catalog.json
var catalogJSON []byte
var catalog = func() map[string]catalogEntry {
	var entries map[string]catalogEntry
	if err := json.Unmarshal(catalogJSON, &entries); err != nil {
		panic(err)
	}
	return entries
}()

// Names returns the stable identifiers supported by New.
func Names() []string {
	ids := []string{"apple", "github", "google", "microsoft", "paybin", "twitch"}
	for id := range catalog {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}

// New configures the default authorization-code flow for a named provider.
// More specific constructors expose tenant configuration and OIDC discovery.
func New(name, clientID, secret string) (auth.OAuthProvider, error) {
	switch name {
	case "twitch":
		return Twitch(clientID, secret), nil
	case "paybin":
		return Paybin(clientID, secret, "")
	case "google":
		return Google(clientID, secret), nil
	case "github":
		return GitHub(clientID, secret), nil
	case "apple":
		return Apple(clientID, secret), nil
	case "microsoft":
		return Microsoft(clientID, secret, MicrosoftOptions{})
	}
	entry, ok := catalog[name]
	if !ok {
		return auth.OAuthProvider{}, fmt.Errorf("unknown provider %q", name)
	}
	style := oauth2.AuthStyleInParams
	if entry.Basic && (name != "cloudflare" || secret != "") {
		style = oauth2.AuthStyleInHeader
	}
	params := url.Values{}
	for k, v := range entry.Params {
		params.Set(k, v)
	}
	endpoint := entry.Authorization
	if at := strings.IndexByte(endpoint, '#'); at >= 0 {
		endpoint = endpoint[:at]
	}
	p := auth.OAuthProvider{
		Config:      oauth2.Config{ClientID: clientID, ClientSecret: secret, Endpoint: oauth2.Endpoint{AuthURL: endpoint, TokenURL: entry.Token, AuthStyle: style}, Scopes: slices.Clone(entry.Scopes)},
		DisablePKCE: !entry.PKCE, OmitNonce: true, AuthorizationParams: params, AllowVerifiedEmailLink: true,
		Resolve: func(ctx context.Context, t *oauth2.Token, _ string) (auth.OAuthProfile, error) {
			return entry.resolve(ctx, name, clientID, secret, t)
		},
	}
	configureProtocol(&p, name)
	p.DisableRefresh = entry.Refresh == nil
	if entry.Refresh != nil {
		p.Refresh = entry.Refresh.exchange
	}
	return p, nil
}

func (e catalogEntry) resolve(ctx context.Context, name, clientID, secret string, t *oauth2.Token) (auth.OAuthProfile, error) {
	var result auth.OAuthProfile
	client, _ := ctx.Value(oauth2.HTTPClient).(*http.Client)
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	target, body := e.Profile, e.ProfileBody
	if name == "vk" {
		body = url.Values{"access_token": {t.AccessToken}, "client_id": {clientID}}.Encode()
	}
	if name == "wechat" {
		openID, _ := t.Extra("openid").(string)
		if openID == "" {
			return result, errors.New("missing WeChat openid")
		}
		target += "?" + url.Values{"access_token": {t.AccessToken}, "openid": {openID}, "lang": {"zh_CN"}}.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, e.Method, target, strings.NewReader(body))
	if err != nil {
		return result, err
	}
	for k, v := range e.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Accept", "application/json")
	switch name {
	case "vk":
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	case "wechat":
	default:
		req.Header.Set("Authorization", "Bearer "+t.AccessToken)
	}
	if e.ProfileBody != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if name == "reddit" {
		req.Header.Set("User-Agent", "authn-go")
	}
	var fbSubject string
	if name == "facebook" {
		target := "https://graph.facebook.com/debug_token?" + url.Values{"access_token": {clientID + "|" + secret}, "input_token": {t.AccessToken}}.Encode()
		debugReq, err := http.NewRequestWithContext(ctx, "GET", target, nil)
		if err != nil {
			return result, err
		}
		verified, err := providerJSON(client, debugReq)
		data := verified.object("data")
		if err != nil || !data.verified("is_valid") || data.text("app_id") != clientID || data.text("user_id") == "" {
			return result, errors.New("Facebook token binding failed")
		}
		fbSubject = data.text("user_id")
	}
	p, err := providerJSON(client, req)
	if err != nil {
		return result, err
	}
	if name == "facebook" && p.text("id") != fbSubject {
		return result, errors.New("Facebook account binding failed")
	}
	if name == "wechat" && (p.text("openid") != t.Extra("openid") || (p.text("errcode") != "" && p.text("errcode") != "0")) {
		return result, errors.New("WeChat account binding failed")
	}
	if name == "twitter" {
		second, err := http.NewRequestWithContext(ctx, "GET", "https://api.x.com/2/users/me?user.fields=confirmed_email", nil)
		if err != nil {
			return result, err
		}
		second.Header.Set("Authorization", "Bearer "+t.AccessToken)
		confirmed, err := providerJSON(client, second)
		if err == nil && confirmed.object("data").text("confirmed_email") != "" {
			p["confirmed_email"] = confirmed.object("data").text("confirmed_email")
		}
	}
	if name == "paypal" {
		if raw, _ := t.Extra("id_token").(string); raw != "" {
			// The access-token-authenticated UserInfo supplies the identity. The
			// optional back-channel ID token must refer to the same subject.
			parts := strings.Split(raw, ".")
			var claims struct{ Sub string }
			if len(parts) != 3 {
				return result, errors.New("invalid PayPal ID token")
			}
			body, err := base64.RawURLEncoding.DecodeString(parts[1])
			if err != nil || json.Unmarshal(body, &claims) != nil || claims.Sub == "" || claims.Sub != p.text("sub", "user_id") {
				return result, errors.New("PayPal UserInfo subject mismatch")
			}
		}
	}
	profile, err := mapProfile(name, p)
	switch name {
	case "twitter":
		if confirmed := p.text("confirmed_email"); confirmed != "" {
			p.object("data")["email"] = confirmed
		}
		delete(p, "confirmed_email")
		profile.Data = p
	case "cloudflare":
		profile.Data = p.object("result")
	case "notion":
		profile.Data = p.object("bot").object("owner").object("user")
	case "kick":
		profile.Data = p.first("data")
	case "linear":
		profile.Data = p.object("data").object("viewer")
	case "discord":
		if profile.Image != nil {
			p["image_url"] = *profile.Image
		}
		profile.Data = p
	default:
		profile.Data = p
	}
	return profile, err
}

func providerJSON(client *http.Client, req *http.Request) (profileData, error) {
	res, err := client.Do(req)
	if err != nil {
		return nil, errors.New("provider request failed")
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, fmt.Errorf("provider request returned HTTP %d", res.StatusCode)
	}
	dec := json.NewDecoder(io.LimitReader(res.Body, 1<<20))
	dec.UseNumber()
	var p profileData
	err = dec.Decode(&p)
	return p, err
}

type profileData map[string]any

func (p profileData) text(keys ...string) string {
	for _, k := range keys {
		switch v := p[k].(type) {
		case string:
			if v != "" {
				return v
			}
		case json.Number:
			return v.String()
		}
	}
	return ""
}
func (p profileData) object(key string) profileData { v, _ := p[key].(map[string]any); return v }
func (p profileData) first(key string) profileData {
	v, _ := p[key].([]any)
	if len(v) == 0 {
		return nil
	}
	obj, _ := v[0].(map[string]any)
	return obj
}
func (p profileData) verified(key string) bool { v, ok := p[key].(bool); return ok && v }

func mapProfile(id string, p profileData) (auth.OAuthProfile, error) {
	var result auth.OAuthProfile
	var image string
	switch id {
	case "atlassian":
		result.Subject = p.text("account_id")
		result.Name = p.text("name")
		image = p.text("picture")
	case "twitch", "paybin", "cognito":
		result.Subject = p.text("sub")
		result.Name = p.text("name", "preferred_username")
		if id == "twitch" {
			result.Name = p.text("preferred_username")
		}
		if id == "cognito" {
			result.Name = p.text("name", "given_name", "username")
		}
		result.EmailVerified = p.verified("email_verified") || (id == "cognito" && p.text("email_verified") == "true")
		image = p.text("picture")
	case "facebook":
		result.Subject = p.text("id")
		result.Name = p.text("name")
		image = p.object("picture").object("data").text("url")
		result.EmailVerified = p.verified("email_verified")
	case "twitter":
		confirmed := p.text("confirmed_email")
		p = p.object("data")
		result.Subject = p.text("id")
		result.Name = p.text("name")
		image = p.text("profile_image_url")
		result.EmailVerified = confirmed != ""
		result.Email = confirmed
		if result.Email == "" {
			result.Email = p.text("email")
		}
		if result.Email == "" {
			result.Email = result.Subject + "@twitter.placeholder.invalid"
		}
	case "vk":
		p = p.object("user")
		result.Subject = p.text("user_id")
		result.Name = p.text("first_name") + " " + p.text("last_name")
		image = p.text("avatar")
	case "tiktok":
		p = p.object("data").object("user")
		result.Subject = p.text("open_id")
		result.Name = p.text("display_name", "username")
		image = p.text("avatar_large_url")
		result.Email = p.text("email")
		if result.Email == "" {
			result.Email = result.Subject + "@tiktok.placeholder.invalid"
		}
	case "wechat":
		result.Subject = p.text("unionid", "openid")
		result.Name = p.text("nickname")
		image = p.text("headimgurl")
		result.Email = p.text("email")
		if result.Email == "" {
			result.Email = result.Subject + "@wechat.placeholder.invalid"
		}
	case "cloudflare":
		if !p.verified("success") {
			return result, errors.New("Cloudflare user profile unavailable")
		}
		p = p.object("result")
		result.Subject = p.text("id")
		result.Name = strings.TrimSpace(p.text("first_name") + " " + p.text("last_name"))
		if result.Name == "" {
			result.Name = p.text("email")
		}
	case "kakao":
		result.Subject = p.text("id")
		p = p.object("kakao_account")
		profile := p.object("profile")
		result.Name = profile.text("nickname")
		if result.Name == "" {
			result.Name = p.text("name")
		}
		image = profile.text("profile_image_url", "thumbnail_image_url")
		result.EmailVerified = p.verified("is_email_valid") && p.verified("is_email_verified")
	case "line":
		result.Subject = p.text("sub")
		result.Name = p.text("name")
		image = p.text("picture")
	case "notion":
		p = p.object("bot").object("owner").object("user")
		result.Subject = p.text("id")
		result.Name = p.text("name")
		result.Email = p.object("person").text("email")
		image = p.text("avatar_url")
	case "paypal":
		result.Subject = p.text("user_id")
		result.Name = p.text("name")
		image = p.text("picture")
		result.EmailVerified = p.verified("email_verified")
	case "discord":
		result.Subject = p.text("id")
		result.Name = p.text("global_name", "username")
		result.EmailVerified = p.verified("verified")
		if avatar := p.text("avatar"); avatar != "" {
			format := "png"
			if strings.HasPrefix(avatar, "a_") {
				format = "gif"
			}
			image = "https://cdn.discordapp.com/avatars/" + url.PathEscape(result.Subject) + "/" + url.PathEscape(avatar) + "." + format
		} else if d := p.text("discriminator"); d == "0" {
			snow, err := strconv.ParseUint(result.Subject, 10, 64)
			if err != nil {
				return result, err
			}
			image = fmt.Sprintf("https://cdn.discordapp.com/embed/avatars/%d.png", (snow>>22)%6)
		} else {
			v, err := strconv.Atoi(d)
			if err != nil {
				return result, err
			}
			image = fmt.Sprintf("https://cdn.discordapp.com/embed/avatars/%d.png", v%5)
		}
	case "dropbox":
		result.Subject = p.text("account_id")
		result.Name = p.object("name").text("display_name")
		image = p.text("profile_photo_url")
		result.EmailVerified = p.verified("email_verified")
	case "figma":
		result.Subject = p.text("id")
		result.Name = p.text("handle")
		image = p.text("img_url")
	case "gitlab":
		if p.text("state") != "active" || p.verified("locked") {
			return result, errors.New("inactive GitLab account")
		}
		result.Subject = p.text("id")
		result.Name = p.text("name", "username")
		image = p.text("avatar_url")
		result.EmailVerified = p.verified("email_verified")
	case "huggingface", "linkedin", "vercel":
		result.Subject = p.text("sub")
		result.Name = p.text("name", "preferred_username")
		image = p.text("picture")
		result.EmailVerified = p.verified("email_verified")
	case "kick":
		p = p.first("data")
		result.Subject = p.text("user_id")
		result.Name = p.text("name")
		image = p.text("profile_picture")
	case "linear":
		p = p.object("data").object("viewer")
		result.Subject = p.text("id")
		result.Name = p.text("name")
		image = p.text("avatarUrl")
	case "naver":
		if p.text("resultcode") != "00" {
			return result, errors.New("Naver profile unavailable")
		}
		p = p.object("response")
		result.Subject = p.text("id")
		result.Name = p.text("name", "nickname")
		image = p.text("profile_image")
	case "polar":
		result.Subject = p.text("id")
		result.Name = p.text("public_name", "username")
		image = p.text("avatar_url")
		result.EmailVerified = p.verified("email_verified")
	case "railway":
		result.Subject = p.text("sub")
		result.Name = p.text("name")
		image = p.text("picture")
	case "reddit":
		result.Subject = p.text("id")
		result.Name = p.text("name")
		image, _, _ = strings.Cut(p.text("icon_img"), "?")
		result.Email = result.Subject + "@reddit.placeholder.invalid"
	case "roblox":
		result.Subject = p.text("sub")
		result.Name = p.text("nickname", "preferred_username")
		image = p.text("picture")
		result.Email = result.Subject + "@roblox.placeholder.invalid"
	case "salesforce":
		result.Subject = p.text("user_id")
		result.Name = p.text("name")
		image = p.object("photos").text("picture", "thumbnail")
		result.EmailVerified = p.verified("email_verified")
	case "slack":
		result.Subject = p.text("https://slack.com/user_id")
		result.Name = p.text("name")
		image = p.text("picture", "https://slack.com/user_image_512")
		result.EmailVerified = p.verified("email_verified")
	case "spotify":
		result.Subject = p.text("id")
		result.Name = p.text("display_name")
		image = p.first("images").text("url")
	case "zoom":
		result.Subject = p.text("id")
		result.Name = p.text("display_name")
		image = p.text("pic_url")
		result.EmailVerified = p.verified("verified") || p.text("verified") == "1"
	default:
		return result, errors.New("unsupported userinfo format")
	}
	if result.Subject == "" {
		return result, errors.New("provider returned no stable user identifier")
	}
	if result.Email == "" {
		result.Email = p.text("email")
	}
	if image != "" {
		result.Image = &image
	}
	return result, nil
}
