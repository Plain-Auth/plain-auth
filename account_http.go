package plainauth

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/Plain-Org/plain-auth/internal/httporigin"
)

const resetRequestMessage = "If this email exists in our system, check your email for the reset link"

// Redirect is an endpoint result answered with a 302 and this Location.
type Redirect string

func requiredString(body wireBody, key string) (string, error) {
	s, ok := body[key].(string)
	if !ok {
		return "", fieldTypeError(key, "string", body)
	}
	return s, nil
}

func (a *Auth) handleAccountRequest(route string, w http.ResponseWriter, r *http.Request, b wireBody, ip string) (any, error) {
	ctx := r.Context()
	ok := map[string]bool{"status": true}
	query := r.URL.Query()
	switch route {
	case "/change-email":
		if b == nil {
			return nil, validationError("[body] Invalid input: expected object, received undefined")
		}
		email, err := requiredString(b, "newEmail")
		if err != nil {
			return nil, err
		}
		if !emailPattern.MatchString(strings.ToLower(email)) || strings.Contains(email, "..") {
			return nil, validationError("[body.newEmail] Invalid email address")
		}
		callback, _ := b["callbackURL"].(string)
		changed, err := a.changeEmail(ctx, r.Header, email, callback)
		// An address changed at once is published in fresh session cookies,
		// so a cached session view shows it straight away.
		if changed {
			if token := a.cookieToken(r.Header); token != "" {
				if cookieErr := a.writeSessionCookieHeaders(w.Header(), r, token, !a.dontRemember(r)); err == nil {
					err = cookieErr
				}
			}
		}
		return ok, err
	case "/delete-user", "/delete-user/callback":
		params := DeleteUserInput{}
		if route == "/delete-user/callback" {
			if err := a.validateCallbacks(ctx, nil, query); err != nil {
				return nil, err
			}
			params.Token = query.Get("token")
			params.CallbackURL = query.Get("callbackURL")
			if params.Token == "" {
				return nil, validationError("Missing token")
			}
		} else {
			for _, f := range []struct {
				key string
				dst *string
			}{{"token", &params.Token}, {"password", &params.Password}, {"callbackURL", &params.CallbackURL}} {
				if _, exists := b[f.key]; exists {
					value, err := requiredString(b, f.key)
					if err != nil {
						return nil, err
					}
					*f.dst = value
				}
			}
		}
		deleted, err := a.DeleteUser(ctx, r.Header, params)
		if err != nil {
			return nil, err
		}
		if deleted {
			a.expireSessionCookies(w, r)
			if route == "/delete-user/callback" && params.CallbackURL != "" {
				return Redirect(params.CallbackURL), nil
			}
			return map[string]any{"success": true, "message": "User deleted"}, nil
		}
		return map[string]any{"success": true, "message": "Verification email sent"}, nil
	case "/verify-password":
		password, err := requiredString(b, "password")
		if err != nil {
			return nil, err
		}
		return ok, a.VerifyPassword(ctx, r.Header, password)
	case "/update-user":
		if b == nil {
			return nil, validationError("[body] Invalid input: expected record, received undefined")
		}
		var update ProfileUpdate
		if a.username != nil {
			var err error
			update, err = usernamePatch(b)
			if err != nil {
				return nil, err
			}
		}
		if a.phoneNumber != nil {
			if value, present := b["phoneNumber"]; present {
				if value != nil {
					return nil, &APIError{400, "PHONE_NUMBER_CANNOT_BE_UPDATED", "Phone number cannot be updated"}
				}
				update.ClearPhoneNumber = true
			}
		}
		// As in the reference, a caller needs a session before the fields
		// are judged; a falsy email is ignored like any unknown key.
		if _, err := a.requireSession(ctx, r.Header); err != nil {
			return nil, err
		}
		if email, exists := b["email"]; exists && !emptyUserInput(email) {
			return nil, &APIError{400, "EMAIL_CAN_NOT_BE_UPDATED", "Email can not be updated"}
		}
		if err := a.refusedUserField(b, false); err != nil {
			return nil, err
		}
		if _, exists := b["name"]; exists {
			name, err := requiredString(b, "name")
			if err != nil {
				return nil, err
			}
			update.Name = &name
		}
		if image, exists := b["image"]; exists {
			if image == nil {
				update.ClearImage = true
			} else {
				image, err := requiredString(b, "image")
				if err != nil {
					return nil, err
				}
				update.Image = &image
			}
		}
		update.AdditionalFields = a.userFieldInput(b)
		if err := a.UpdateUser(ctx, r.Header, update); err != nil {
			return nil, err
		}
		if token := a.cookieToken(r.Header); token != "" {
			persistent := !a.dontRemember(r)
			if err := a.writeSessionCookieHeaders(w.Header(), r, token, persistent); err != nil {
				return nil, err
			}
			if !persistent {
				a.writeRememberPreference(w.Header(), r, false)
			}
		}
		return ok, nil
	case "/change-password":
		if b == nil {
			return nil, validationError("[body] Invalid input: expected object, received undefined")
		}
		// Every problem is reported, in the order of the reference schema.
		var issues []string
		password, okNew := b["newPassword"].(string)
		if !okNew {
			issues = append(issues, fieldTypeError("newPassword", "string", b).Message)
		}
		current, okCurrent := b["currentPassword"].(string)
		if !okCurrent {
			issues = append(issues, fieldTypeError("currentPassword", "string", b).Message)
		}
		revoke := false
		if v, exists := b["revokeOtherSessions"]; exists {
			if flag, isBool := v.(bool); isBool {
				revoke = flag
			} else {
				issues = append(issues, fieldTypeError("revokeOtherSessions", "boolean", b).Message)
			}
		}
		if len(issues) > 0 {
			return nil, validationError(strings.Join(issues, "; "))
		}
		remember := !a.dontRemember(r)
		result, err := a.ChangePassword(ctx, r.Header, ChangePasswordInput{CurrentPassword: current, NewPassword: password, RevokeOtherSessions: revoke}, RequestMeta{IPAddress: ip, UserAgent: r.UserAgent(), RememberMe: &remember})
		if err != nil {
			return nil, err
		}
		response := map[string]any{"user": result.User, "token": nil}
		if result.Token != "" {
			response["token"] = result.Token
			if err := a.setSessionCookie(w, r, result.Token, remember); err != nil {
				return nil, err
			}
		}
		return response, nil
	case "/request-password-reset", "/send-verification-email":
		email, err := requiredString(b, "email")
		if err != nil {
			return nil, err
		}
		if !emailPattern.MatchString(email) || strings.Contains(email, "..") {
			return nil, validationError("[body.email] Invalid email address")
		}
		if route == "/request-password-reset" {
			redirect, _ := b["redirectTo"].(string)
			return map[string]any{"status": true, "message": resetRequestMessage}, a.RequestPasswordReset(ctx, email, redirect)
		}
		callback, _ := b["callbackURL"].(string)
		return ok, a.SendVerificationEmail(ctx, r.Header, email, callback)
	case "/reset-password":
		if b == nil {
			return nil, validationError("[body] Invalid input: expected object, received undefined")
		}
		var issues []string
		password, okPassword := b["newPassword"].(string)
		if !okPassword {
			issues = append(issues, fieldTypeError("newPassword", "string", b).Message)
		}
		token, okType := b["token"].(string)
		if _, supplied := b["token"]; supplied && !okType {
			issues = append(issues, fieldTypeError("token", "string", b).Message)
		}
		if len(issues) > 0 {
			return nil, validationError(strings.Join(issues, "; "))
		}
		if token == "" {
			token = query.Get("token")
		}
		return ok, a.resetPassword(ctx, token, password, r)
	case "/reset-password/:token", "/verify-email":
		// The query is validated before the callback's trust, as in the
		// reference; an empty token is an invalid one, not a missing one.
		if route == "/verify-email" {
			switch {
			case len(query["token"]) == 0:
				return nil, validationError("[query.token] Invalid input: expected string, received undefined")
			case len(query["token"]) > 1:
				return nil, validationError("[query.token] Invalid input: expected string, received array")
			case len(query["callbackURL"]) > 1:
				return nil, validationError("[query.callbackURL] Invalid input: expected string, received array")
			}
		}
		if route == "/reset-password/:token" {
			switch len(query["callbackURL"]) {
			case 0:
				return nil, validationError("[query.callbackURL] Invalid input: expected string, received undefined")
			case 1:
			default:
				return nil, validationError("[query.callbackURL] Invalid input: expected string, received array")
			}
		}
		if err := a.validateCallbacks(ctx, nil, query); err != nil {
			return nil, err
		}
		callback := query.Get("callbackURL")
		if route == "/verify-email" {
			result, err := a.applyEmailProof(r, w.Header(), query.Get("token"), callback)
			if callback != "" {
				var apiErr *APIError
				if errors.As(err, &apiErr) {
					return redirectQuery(callback, "error", apiErr.Code), nil
				}
				if err == nil {
					return Redirect(callback), nil
				}
			}
			return result, err
		}
		// The reset callback validates a link without spending it. The POST that
		// actually replaces the password is the single-use operation.
		s, err := a.accountStore()
		if err != nil {
			return nil, err
		}
		token := r.URL.Path[strings.LastIndexByte(r.URL.Path, '/')+1:]
		origin, err := a.origin(ctx)
		if err != nil {
			return nil, err
		}
		base, _ := url.Parse(origin)
		if callback == "" {
			return redirectQuery(origin+strings.TrimRight(a.opts.BasePath, "/")+"/error", "error", "INVALID_TOKEN"), nil
		}
		cb, _ := url.Parse(callback)
		dest := callback
		if !cb.IsAbs() {
			dest = base.ResolveReference(cb).String()
		}
		_, err = s.FindPasswordResetToken(ctx, token, a.now().UTC())
		if errors.Is(err, ErrNotFound) {
			return redirectQuery(dest, "error", "INVALID_TOKEN"), nil
		}
		if err != nil {
			return nil, err
		}
		return redirectQuery(dest, "token", token), nil
	}
	return nil, &APIError{404, "NOT_FOUND", "Not Found"}
}

func redirectQuery(target, key, value string) Redirect {
	return Redirect(httporigin.SetQuery(target, url.Values{key: {value}}))
}

func (a *Auth) dontRemember(r *http.Request) bool {
	c, err := r.Cookie(a.prefixedCookieName("dont_remember"))
	return err == nil && a.VerifySignedSessionToken(c.Value) == "true"
}
