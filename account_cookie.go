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

// openAccountCookie opens the one account_data cookie in h, expired or not.
func (a *Auth) openAccountCookie(h http.Header) (accountCookie, bool) {
	var c accountCookie
	if !a.opts.StoreAccountCookie || h == nil {
		return c, false
	}
	cookies := (&http.Request{Header: h}).CookiesNamed(a.browserCookie("account_data", "", 0).Name)
	if len(cookies) != 1 {
		return c, false
	}
	raw, err := a.openRecord(accountCookiePurpose, cookies[0].Value)
	if err != nil || json.Unmarshal(raw, &c) != nil {
		return accountCookie{}, false
	}
	return c, true
}

// readAccountCookie opens the one unexpired account_data cookie in h.
func (a *Auth) readAccountCookie(h http.Header) (accountCookie, bool) {
	c, ok := a.openAccountCookie(h)
	if !ok || !c.ExpiresAt.After(a.now()) {
		return accountCookie{}, false
	}
	return c, true
}

// renewAccountCookie follows a re-issued session cache for userID: it
// re-issues the browser's account_data with a fresh lifetime when the cookie
// belongs to userID, and expires it when it belongs to another user. A
// missing, altered or expired cookie is left alone.
func (a *Auth) renewAccountCookie(h http.Header, r *http.Request, userID string) {
	c, ok := a.readAccountCookie(r.Header)
	if !ok {
		return
	}
	if c.UserID == userID {
		a.setAccountCookie(h, r, c.UserID, c.ProviderID, c.Subject)
		return
	}
	expired := a.browserCookie("account_data", "", -1)
	expireOtherScopes(h, r, expired)
	h.Add("Set-Cookie", expired.String())
}

// accountCookieRefresh is the HTTP response in which a token refresh of the
// account that account_data selected renews that cookie.
type accountCookieRefresh struct {
	h http.Header
	r *http.Request
}

type accountCookieRefreshKey struct{ a *Auth }

// renewRefreshedAccountCookie re-issues account_data after a committed token
// refresh of row, when an HTTP request selected row through the cookie. A
// refresh of another account under the same request, such as a nested
// direct call, leaves the cookie alone.
func (a *Auth) renewRefreshedAccountCookie(ctx context.Context, row ProviderAccountCredential) {
	out, ok := ctx.Value(accountCookieRefreshKey{a}).(accountCookieRefresh)
	if !ok {
		return
	}
	// The cookie was live when it selected the account; a slow refresh may
	// finish after it expires, and still renews it.
	if c, ok := a.openAccountCookie(out.r.Header); ok && c.UserID == row.UserID && c.ProviderID == row.ProviderID && c.Subject == row.Subject {
		a.setAccountCookie(out.h, out.r, row.UserID, row.ProviderID, row.Subject)
	}
}

// cookieAccount returns the local account record, provider and subject the
// account_data cookie in h names for userID. A missing, altered, expired or
// foreign cookie, or an account since unlinked, is ACCOUNT_NOT_FOUND.
func (a *Auth) cookieAccount(ctx context.Context, h http.Header, userID string) (accountCookie, string, error) {
	notFound := &APIError{400, "ACCOUNT_NOT_FOUND", "Account not found"}
	c, ok := a.readAccountCookie(h)
	if !ok || c.UserID != userID {
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
