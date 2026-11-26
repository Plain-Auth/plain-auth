package providers

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	auth "github.com/Plain-Org/plain-auth"
)

// GitLabOptions points the GitLab preset at a self-managed instance.
type GitLabOptions struct {
	// Issuer is the instance's base URL, such as https://gitlab.company.com,
	// optionally with a path; empty selects https://gitlab.com.
	Issuer string
}

// GitLab configures GitLab sign-in, on gitlab.com or a self-managed instance.
func GitLab(clientID, secret string, o GitLabOptions) (auth.OAuthProvider, error) {
	entry := catalog["gitlab"]
	if o.Issuer != "" {
		issuer := strings.TrimRight(o.Issuer, "/")
		if !secureEndpoint(issuer) || strings.ContainsAny(issuer, "?#") {
			return auth.OAuthProvider{}, errors.New("invalid GitLab issuer")
		}
		entry = entry.at("https://gitlab.com", issuer)
	}
	return fromCatalog("gitlab", clientID, secret, entry), nil
}

// SalesforceOptions selects the Salesforce login host.
type SalesforceOptions struct {
	// Sandbox uses test.salesforce.com instead of login.salesforce.com.
	Sandbox bool
	// LoginURL is a My Domain host, such as my-company.my.salesforce.com,
	// for the authorize, token and user info endpoints. It wins over Sandbox.
	LoginURL string
}

// Salesforce configures Salesforce sign-in for production, a sandbox or a My
// Domain host.
func Salesforce(clientID, secret string, o SalesforceOptions) (auth.OAuthProvider, error) {
	host := "login.salesforce.com"
	if o.Sandbox {
		host = "test.salesforce.com"
	}
	if o.LoginURL != "" {
		host = strings.TrimRight(strings.TrimPrefix(o.LoginURL, "https://"), "/")
		if u, err := url.Parse("https://" + host); host == "" || err != nil || u.Hostname() != host {
			return auth.OAuthProvider{}, errors.New("invalid Salesforce login URL")
		}
	}
	return fromCatalog("salesforce", clientID, secret, catalog["salesforce"].at("https://login.salesforce.com", "https://"+host)), nil
}

// PayPalOptions selects the PayPal environment.
type PayPalOptions struct {
	// Live uses the live endpoints; the default is the sandbox.
	Live bool
}

// PayPal configures PayPal sign-in against the sandbox or the live
// environment.
func PayPal(clientID, secret string, o PayPalOptions) auth.OAuthProvider {
	entry := catalog["paypal"]
	if o.Live {
		entry = entry.at("https://www.sandbox.paypal.com", "https://www.paypal.com").at("https://api-m.sandbox.paypal.com", "https://api-m.paypal.com")
	}
	return fromCatalog("paypal", clientID, secret, entry)
}

// DiscordOptions configures the Discord preset.
type DiscordOptions struct {
	// Permissions is the bot permission bit set, sent as permissions only
	// when the bot scope is requested; zero sends none.
	Permissions uint64
}

// Discord configures Discord sign-in.
func Discord(clientID, secret string, o DiscordOptions) auth.OAuthProvider {
	p := fromCatalog("discord", clientID, secret, catalog["discord"])
	if o.Permissions != 0 {
		p.CustomizeAuthorization = func(target *url.URL) {
			q := target.Query()
			if !q.Has("permissions") && slices.Contains(strings.Fields(q.Get("scope")), "bot") {
				target.RawQuery += "&permissions=" + strconv.FormatUint(o.Permissions, 10)
			}
		}
	}
	return p
}

// DropboxOptions configures the Dropbox preset.
type DropboxOptions struct {
	// AccessType is sent as token_access_type: offline, online or legacy.
	AccessType string
}

// Dropbox configures Dropbox sign-in.
func Dropbox(clientID, secret string, o DropboxOptions) auth.OAuthProvider {
	p := fromCatalog("dropbox", clientID, secret, catalog["dropbox"])
	if o.AccessType != "" {
		p.AuthorizationParams.Set("token_access_type", o.AccessType)
	}
	return p
}

// FacebookOptions configures the Facebook preset.
type FacebookOptions struct {
	// Fields are more Graph profile fields to request beyond id, name, email
	// and picture.
	Fields []string
	// ConfigID is sent as config_id, for a Facebook Login for Business
	// configuration.
	ConfigID string
	// Audiences lists the app's other Facebook App IDs whose Limited Login
	// ID tokens and access tokens may sign in directly; the client ID is
	// always accepted.
	Audiences []string
	// HTTPClient fetches the Limited Login signing keys.
	HTTPClient *http.Client
}

// Facebook configures Facebook sign-in: the browser flow, and direct
// sign-in with an iOS Limited Login ID token or an access token. Each access
// token is first checked with Graph's debug_token, which needs the secret.
func Facebook(clientID, secret string, o FacebookOptions) auth.OAuthProvider {
	entry := catalog["facebook"]
	if len(o.Fields) > 0 {
		entry.Profile = "https://graph.facebook.com/me?" + url.Values{"fields": {strings.Join(append([]string{"id", "name", "email", "picture"}, o.Fields...), ",")}}.Encode()
	}
	p := fromCatalog("facebook", clientID, secret, entry)
	if o.ConfigID != "" {
		p.AuthorizationParams.Set("config_id", o.ConfigID)
	}
	facebookLogin(&p, clientIDs(clientID, o.Audiences), secret, entry.Profile, o.HTTPClient)
	return p
}

// RedditOptions configures the Reddit preset.
type RedditOptions struct {
	// Duration is sent as duration: temporary or permanent, the latter for a
	// refresh token.
	Duration string
}

// Reddit configures Reddit sign-in.
func Reddit(clientID, secret string, o RedditOptions) auth.OAuthProvider {
	p := fromCatalog("reddit", clientID, secret, catalog["reddit"])
	if o.Duration != "" {
		p.AuthorizationParams.Set("duration", o.Duration)
	}
	return p
}
