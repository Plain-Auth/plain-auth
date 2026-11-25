package plainauth

import (
	"net/http"
	"strings"
)

// TrustedDeviceCookieName returns the incoming cookie name for this instance.
// Native callers can pass its opaque value through RequestMeta.TrustedDeviceCookie.
func (a *Auth) TrustedDeviceCookieName() string { return a.prefixedCookieName("trust_device") }
func (a *Auth) trustedDeviceCookie(owner, grant string, maxAge int) *http.Cookie {
	c := a.SignedCookie("trust_device", a.TrustedDeviceCookieName()+"|"+owner+"|"+grant, maxAge)
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

// rotateTrustedGrant replaces the presented grant, if any, with the pinned
// one and returns its cookie.
func (a *Auth) rotateTrustedGrant(ch *FactorChange, owner string, pins factorPins) *http.Cookie {
	ch.CreateTrustedGrant, ch.TrustedGrantID, ch.TrustedUntil = pins.grant, pins.grantID, pins.grantUntil
	return a.trustedDeviceCookie(owner, pins.grant, int(a.factorOptions.TrustDeviceMaxAge.Seconds()))
}
