package client

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	auth "github.com/Stonewrit/stonewrit-auth"
	"github.com/Stonewrit/stonewrit-auth/plugins/sso"
)

// StartSAMLLogout revokes this browser's recorded SAML session and returns
// the signed IdP URL to open in the same browser. It does not follow the redirect.
func (c *Client) StartSAMLLogout(ctx context.Context, providerID, callbackURL string) (string, error) {
	if !sso.MutableProviderID(providerID) {
		return "", errors.New("client: invalid SAML provider")
	}
	client := *c
	client.http = &http.Client{Transport: c.http.Transport, Jar: c.http.Jar, Timeout: c.http.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	form := map[string]string{}
	if callbackURL != "" {
		form["callbackURL"] = callbackURL
	}
	header, err := client.DoWithHeaders(ctx, "POST", "/sso/saml2/logout/"+providerID, form, nil)
	var api *auth.APIError
	if !errors.As(err, &api) || api.Status != http.StatusFound {
		if err == nil {
			err = errors.New("client: missing SAML logout redirect")
		}
		return "", err
	}
	target, e := url.Parse(header.Get("Location"))
	if e != nil || target.Scheme != "https" || target.Hostname() == "" || target.User != nil {
		return "", errors.New("client: invalid SAML logout redirect")
	}
	return target.String(), nil
}
