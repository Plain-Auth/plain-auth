package plainauth

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// accountCookie is what StoreAccountCookie keeps in account_data: the linked
// provider account a browser's sign-in used. Its tokens stay in the store.
type accountCookie struct {
	UserID, ProviderID, Subject string
	ExpiresAt                   time.Time
}

const accountCookiePurpose = "account-cookie"

// accountCookieAge is the reference's account cookie lifetime: the session
// cookie cache's, or five minutes.
func (a *Auth) accountCookieAge() time.Duration {
	if a.opts.SessionCookieCache != nil && a.opts.SessionCookieCache.MaxAge > 0 {
		return a.opts.SessionCookieCache.MaxAge
	}
	return 5 * time.Minute
}

// setAccountCookie records in h the provider account a sign-in used, and
// expires copies r carries in other scopes.
func (a *Auth) setAccountCookie(h http.Header, r *http.Request, userID, provider, subject string) {
	if !a.opts.StoreAccountCookie || userID == "" || provider == "" || subject == "" {
		return
	}
	age := a.accountCookieAge()
	raw, err := json.Marshal(accountCookie{UserID: userID, ProviderID: provider, Subject: subject, ExpiresAt: a.now().Add(age)})
	if err != nil {
		return
	}
	value, err := a.sealRecord(accountCookiePurpose, raw)
	if err != nil {
		return
	}
	cookie := a.browserCookie("account_data", value, int(age/time.Second))
	expireOtherScopes(h, r, cookie)
	h.Add("Set-Cookie", cookie.String())
}

// cookieAccount returns the local account record, provider and subject the
// account_data cookie in h names for userID. A missing, altered, expired or
// foreign cookie, or an account since unlinked, is ACCOUNT_NOT_FOUND.
func (a *Auth) cookieAccount(ctx context.Context, h http.Header, userID string) (accountCookie, string, error) {
	notFound := &APIError{400, "ACCOUNT_NOT_FOUND", "Account not found"}
	if !a.opts.StoreAccountCookie || h == nil {
		return accountCookie{}, "", notFound
	}
	cookies := (&http.Request{Header: h}).CookiesNamed(a.browserCookie("account_data", "", 0).Name)
	if len(cookies) != 1 {
		return accountCookie{}, "", notFound
	}
	raw, err := a.openRecord(accountCookiePurpose, cookies[0].Value)
	var c accountCookie
	if err != nil || json.Unmarshal(raw, &c) != nil || c.UserID != userID || !c.ExpiresAt.After(a.now()) {
		return accountCookie{}, "", notFound
	}
	accounts, err := a.opts.Store.(LinkedAccountStore).ListUserAccounts(ctx, userID)
	if err != nil {
		return accountCookie{}, "", err
	}
	for _, account := range accounts {
		if account.ProviderID == c.ProviderID && account.AccountID == c.Subject {
			return c, account.ID, nil
		}
	}
	return accountCookie{}, "", notFound
}
