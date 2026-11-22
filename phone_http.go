package plainauth

import "net/http"

func phoneAccountEndpoints(rule *RateLimitRule) []Endpoint {
	var endpoints []Endpoint
	for _, path := range []string{"/phone-number/verify", "/phone-number/request-password-reset", "/phone-number/reset-password", "/sign-in/phone-number"} {
		ep := Endpoint{Method: "POST", Path: path, Handler: func(c EndpointContext) (any, error) { return c.Auth.phoneHTTP(c, path) }}
		if path != "/sign-in/phone-number" {
			ep.RateLimit = rule
		}
		endpoints = append(endpoints, ep)
	}
	return endpoints
}
func (a *Auth) phoneHTTP(c EndpointContext, path string) (any, error) {
	r, b := c.Request, wireBody(c.Body)
	ctx := r.Context()
	number, err := requiredString(b, "phoneNumber")
	if err != nil {
		return nil, err
	}
	meta := RequestMeta{UserAgent: r.UserAgent(), IPAddress: a.clientIP(r)}
	if cookie, err := r.Cookie(a.TrustedDeviceCookieName()); err == nil {
		meta.TrustedDeviceCookie = cookie.Value
	}
	switch path {
	case "/phone-number/verify":
		code, err := requiredString(b, "code")
		if err != nil {
			return nil, err
		}
		fields := a.userFieldInput(c.Body)
		for _, key := range phoneVerificationKeys {
			delete(fields, key)
		}
		in := PhoneVerificationInput{PhoneNumber: number, Code: code, AdditionalFields: fields}
		for name, target := range map[string]*bool{"disableSession": &in.DisableSession, "updatePhoneNumber": &in.UpdatePhoneNumber} {
			if v, ok := b[name]; ok {
				flag, ok := v.(bool)
				if !ok {
					return nil, fieldTypeError(name, "boolean", b)
				}
				*target = flag
			}
		}
		result, err := a.verifyPhoneNumber(ctx, r.Header, in, meta, b["phoneNumberVerified"])
		if err != nil {
			return nil, err
		}
		if result.Factor != nil {
			if result.Factor.Challenge != nil {
				return a.writeCredentialResult(c.ResponseHeader, r, b, *result.Factor, nil, false)
			}
			if ck := result.Factor.TrustedDeviceCookie; ck != nil {
				c.ResponseHeader.Add("Set-Cookie", ck.String())
			}
		}
		if result.Token != nil && !in.UpdatePhoneNumber {
			if err := a.addSessionCookieHeaders(c.ResponseHeader, r, *result.Token, true); err != nil {
				return nil, err
			}
			a.writeRememberPreference(c.ResponseHeader, r, true)
		}
		return result, nil
	case "/sign-in/phone-number":
		pw, err := requiredString(b, "password")
		if err != nil {
			return nil, err
		}
		if value, present := b["rememberMe"]; present {
			flag, ok := value.(bool)
			if !ok {
				return nil, fieldTypeError("rememberMe", "boolean", b)
			}
			meta.RememberMe = &flag
		}
		result, err := a.SignInPhoneNumber(ctx, number, pw, meta)
		if err != nil {
			return nil, err
		}
		v, err := a.writeCredentialResult(c.ResponseHeader, r, b, result, meta.RememberMe, false)
		if data, ok := v.(map[string]any); ok {
			delete(data, "redirect")
			delete(data, "url")
		}
		return v, err
	case "/phone-number/request-password-reset":
		return map[string]bool{"status": true}, a.RequestPhonePasswordReset(ctx, number)
	case "/phone-number/reset-password":
		code, err := requiredString(b, "otp")
		if err != nil {
			return nil, err
		}
		pw, err := requiredString(b, "newPassword")
		if err != nil {
			return nil, err
		}
		return map[string]bool{"status": true}, a.resetPhonePassword(ctx, number, code, pw, c.Request)
	}
	return nil, &APIError{http.StatusNotFound, "NOT_FOUND", "Not found"}
}
