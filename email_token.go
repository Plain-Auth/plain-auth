package plainauth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

type verificationClaims struct {
	ProfileUpdatedAtMillis *int64 `json:"profileUpdatedAtMs,omitempty"`
	Email                  string `json:"email"`
	UserID                 string `json:"userId"`
	UpdateTo               string `json:"updateTo,omitempty"`
	RequestType            string `json:"requestType,omitempty"`
	jwt.RegisteredClaims
}

func (a *Auth) sendVerificationOnSignup(required bool) bool {
	if a.opts.SendVerificationOnSignUp != nil {
		return *a.opts.SendVerificationOnSignUp
	}
	return required
}

func (a *Auth) sendEmailProof(ctx context.Context, u User, newEmail, requestType, callback string, send MailSender) error {
	if callback == "" {
		callback = "/"
	}
	if !a.trustedURL(ctx, callback, true) {
		return &APIError{403, "INVALID_CALLBACK_URL", "Invalid callbackURL"}
	}
	now := a.now()
	claims := verificationClaims{Email: strings.ToLower(u.Email), UserID: u.ID, UpdateTo: newEmail, RequestType: requestType, RegisteredClaims: jwt.RegisteredClaims{
		IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(a.opts.EmailVerificationTokenTTL)),
	}}
	if a.opts.AutoSignInAfterVerification && requestType == "" && newEmail == "" && !u.UpdatedAt.IsZero() {
		revision := u.UpdatedAt.UnixMilli()
		claims.ProfileUpdatedAtMillis = &revision
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	delete(token.Header, "typ")
	raw, err := token.SignedString([]byte(a.opts.Secret))
	if err != nil {
		return err
	}
	link := a.opts.BaseURL + strings.TrimSuffix(a.opts.BasePath, "/") + "/verify-email?" + url.Values{"callbackURL": {callback}, "token": {raw}}.Encode()
	if requestType == "change-email-verification" {
		u.Email = newEmail
	}
	return send(ctx, MailLink{User: u, Token: raw, URL: link, NewEmail: newEmail, Request: a.requestCopy(ctx)})
}

func (a *Auth) parseEmailProof(raw string) (verificationClaims, error) {
	var claims verificationClaims
	token, err := jwt.ParseWithClaims(raw, &claims, func(*jwt.Token) (any, error) {
		if len(a.opts.Secrets) < 2 {
			return []byte(a.opts.Secret), nil
		}
		keys := jwt.VerificationKeySet{}
		for _, k := range a.opts.Secrets {
			keys.Keys = append(keys.Keys, []byte(k.Value))
		}
		return keys, nil
	}, jwt.WithValidMethods([]string{"HS256"}), jwt.WithExpirationRequired(), jwt.WithTimeFunc(a.now))
	if errors.Is(err, jwt.ErrTokenExpired) && !errors.Is(err, jwt.ErrTokenSignatureInvalid) {
		return claims, &APIError{401, "TOKEN_EXPIRED", "Token expired"}
	}
	if err != nil || !token.Valid || claims.Email == "" || claims.UserID == "" {
		return claims, &APIError{401, "INVALID_TOKEN", "Invalid token"}
	}
	return claims, nil
}

// VerifyEmail validates a plain address verification link, including its
// original owner. Existing accounts remain verified when a link is revisited.
func (a *Auth) VerifyEmail(ctx context.Context, raw string) error {
	claims, err := a.parseEmailProof(raw)
	if err != nil {
		return err
	}
	if claims.UpdateTo != "" || claims.RequestType != "" {
		return &APIError{401, "INVALID_TOKEN", "Invalid token"}
	}
	if a.opts.AutoSignInAfterVerification || a.hasVerificationObservers() {
		_, _, err := a.consumeVerification(ctx, claims, raw, nil)
		return err
	}
	return a.verifyAddress(ctx, claims)
}

func (a *Auth) verifyAddress(ctx context.Context, claims verificationClaims) error {
	s, err := a.accountStore()
	if err != nil {
		return err
	}
	var verified User // set when hooks run for this change
	if a.dbHooks.user.update.set() {
		verified, err = s.FindAccountUser(ctx, claims.Email)
		if errors.Is(err, ErrNotFound) || err == nil && verified.ID != claims.UserID {
			return &APIError{401, "INVALID_TOKEN", "Invalid token"}
		}
		if err != nil {
			return err
		}
		if verified.EmailVerified {
			verified = User{}
		} else {
			verified.EmailVerified = true
			if _, _, err := a.beforeUserUpdate(ctx, verified, nil, false); errors.Is(err, ErrSkipWrite) {
				// A declined verification leaves the address unverified.
				return nil
			} else if err != nil {
				return err
			}
		}
	}
	err = s.VerifyAccountEmail(ctx, claims.UserID, claims.Email, a.now().UTC())
	if errors.Is(err, ErrNotFound) {
		return &APIError{401, "INVALID_TOKEN", "Invalid token"}
	}
	if err == nil && verified.ID != "" {
		err = a.afterUserUpdate(ctx, verified, nil)
	}
	return err
}

func (a *Auth) applyEmailProof(r *http.Request, response http.Header, raw, callback string) (map[string]any, error) {
	ctx, h := r.Context(), r.Header
	claims, err := a.parseEmailProof(raw)
	if err != nil {
		return nil, err
	}
	if claims.UpdateTo == "" && claims.RequestType == "" {
		if a.opts.AutoSignInAfterVerification || a.hasVerificationObservers() {
			return map[string]any{"status": true, "user": nil}, a.verifyEmailBrowser(r, response, claims, raw)
		}
		return map[string]any{"status": true, "user": nil}, a.verifyAddress(ctx, claims)
	}
	if !a.opts.ChangeEmailEnabled || !emailPattern.MatchString(claims.UpdateTo) || strings.Contains(claims.UpdateTo, "..") {
		return nil, &APIError{401, "INVALID_TOKEN", "Invalid token"}
	}
	store, err := a.accountStore()
	if err != nil {
		return nil, err
	}
	user, err := store.FindAccountUser(ctx, claims.Email)
	if errors.Is(err, ErrNotFound) || (err == nil && (user.ID != claims.UserID || strings.ToLower(user.Email) != strings.ToLower(claims.Email))) {
		return nil, &APIError{401, "INVALID_TOKEN", "Invalid token"}
	}
	if err != nil {
		return nil, err
	}
	session, err := a.GetSession(ctx, h)
	if err != nil {
		return nil, err
	}
	if session != nil && session.User.ID != user.ID {
		return nil, &APIError{401, "INVALID_USER", "Invalid user"}
	}
	switch claims.RequestType {
	case "change-email-confirmation":
		if a.opts.SendVerificationEmail == nil {
			return nil, &APIError{400, "VERIFICATION_EMAIL_NOT_ENABLED", "Verification email isn't enabled"}
		}
		return map[string]any{"status": true}, a.sendEmailProof(ctx, user, claims.UpdateTo, "change-email-verification", callback, a.opts.SendVerificationEmail)
	case "change-email-verification":
		store, err := a.lifecycleStore()
		if err != nil {
			return nil, err
		}
		row := user
		row.Email = claims.UpdateTo
		if _, _, err := a.beforeUserUpdate(ctx, row, nil, false); errors.Is(err, ErrSkipWrite) {
			// A declined change keeps the current address and still answers success.
			return map[string]any{"status": true, "user": user}, nil
		} else if err != nil {
			return nil, err
		}
		u, err := store.ChangeAccountEmail(ctx, user.ID, user.Email, claims.UpdateTo, user.EmailVerified, a.now().UTC())
		if errors.Is(err, ErrEmailTaken) || errors.Is(err, ErrNotFound) {
			return nil, &APIError{401, "INVALID_TOKEN", "Invalid token"}
		}
		if err == nil {
			err = a.afterUserUpdate(ctx, u, nil)
		}
		if err == nil && u.EmailVerified {
			err = runEmailVerificationHook(ctx, a.opts.AfterEmailVerification, u, r)
		}
		return map[string]any{"status": true, "user": u}, err
	default:
		return nil, &APIError{401, "INVALID_TOKEN", "Invalid token"}
	}
}
