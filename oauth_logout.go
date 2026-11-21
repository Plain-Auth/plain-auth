package stonewrit

import (
	"context"
	"net/http"
	"net/url"
	"sort"
)

// ProviderLogoutResult is returned after local sign-out when a linked provider
// has an end-session endpoint. Redirect reports whether the client should follow URL.
type ProviderLogoutResult struct {
	Success  bool   `json:"success"`
	URL      string `json:"url"`
	Redirect bool   `json:"redirect"`
}

func (a *Auth) prepareProviderLogout(ctx context.Context, h http.Header, body wireBody) (ProviderLogoutResult, error) {
	var local ProviderLogoutResult
	disable, ok := body["disableRedirect"].(bool)
	if _, present := body["disableRedirect"]; present && !ok {
		return local, fieldTypeError("disableRedirect", "boolean", body)
	}
	state, ok := body["state"].(string)
	if _, present := body["state"]; present && !ok {
		return local, fieldTypeError("state", "string", body)
	}
	var enabled bool
	for _, provider := range a.opts.SocialProviders {
		if provider.EndSessionEndpoint != "" && !provider.DisableProviderLogout {
			enabled = true
			break
		}
	}
	if !enabled || a.cookieToken(h) == "" {
		return local, nil
	}
	owner, err := a.requireOwnerSession(ctx, h)
	if err != nil {
		return local, nil
	}
	store, ok := a.opts.Store.(LinkedAccountStore)
	if !ok {
		return local, nil
	}
	accounts, err := store.ListUserAccounts(ctx, owner.User.ID)
	if err != nil {
		return local, nil
	}
	sort.SliceStable(accounts, func(i, j int) bool { return accounts[i].UpdatedAt.After(accounts[j].UpdatedAt) })
	for _, account := range accounts {
		p := a.opts.SocialProviders[account.ProviderID]
		if p.DisableProviderLogout || p.EndSessionEndpoint == "" {
			continue
		}
		_, row, _, err := a.selectedCredential(ctx, nil, AccountSelection{UserID: owner.User.ID, AccountID: account.ID}, true)
		if err != nil || row.ProviderID != account.ProviderID || row.UserID != owner.User.ID {
			continue
		}
		target, err := url.Parse(p.EndSessionEndpoint)
		if err != nil {
			continue
		}
		query := target.Query()
		if row.IDToken != "" {
			query.Set("id_token_hint", row.IDToken)
		}
		callback, _ := body["callbackURL"].(string)
		if callback == "" {
			callback = p.PostLogoutRedirectURI
		}
		if callback != "" {
			if !a.trustedURL(callback, true) {
				continue
			}
			base, err := url.Parse(a.opts.BaseURL + a.opts.BasePath)
			if err != nil {
				continue
			}
			resolved, err := base.Parse(callback)
			if err != nil {
				continue
			}
			query.Set("post_logout_redirect_uri", resolved.String())
			query.Set("client_id", p.Config.ClientID)
			if state != "" {
				query.Set("state", state)
			}
		} else if row.IDToken == "" {
			query.Set("client_id", p.Config.ClientID)
		}
		target.RawQuery = query.Encode()
		return ProviderLogoutResult{Success: true, URL: target.String(), Redirect: !disable}, nil
	}
	return local, nil
}
