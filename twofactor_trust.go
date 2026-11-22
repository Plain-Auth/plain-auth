package plainauth

import (
	"net/http"
	"strings"
	"time"
)

// TrustedDeviceCookieName returns the incoming cookie name for this instance.
// Native callers can pass its opaque value through RequestMeta.TrustedDeviceCookie.
func (a *Auth) TrustedDeviceCookieName() string { return a.prefixedCookieName("trust_device") }
func (a *Auth) trustedDeviceCookie(owner, grant string, maxAge int) *http.Cookie {
	name := a.TrustedDeviceCookieName()
	c := a.sessionCookie(name+"|"+owner+"|"+grant, false)
	c.Name = name
	c.MaxAge = maxAge
	if maxAge < 0 {
		c.Value = ""
	}
	return c
}
func (a *Auth) readTrustedGrant(signed, owner string) string {
	if signed == "" {
		return ""
	}
	body := a.VerifySignedSessionToken(signed)
	grant, ok := strings.CutPrefix(body, a.TrustedDeviceCookieName()+"|"+owner+"|")
	if !ok || !strings.HasPrefix(grant, "trust-device-") || len(grant) > 128 {
		return ""
	}
	return grant
}
func (a *Auth) rotateTrustedGrant(ch *FactorChange, owner string, now time.Time) *http.Cookie {
	ch.CreateTrustedGrant = "trust-device-" + randomID()
	ch.TrustedUntil = now.Add(a.factorOptions.TrustDeviceMaxAge)
	return a.trustedDeviceCookie(owner, ch.CreateTrustedGrant, int(a.factorOptions.TrustDeviceMaxAge.Seconds()))
}
