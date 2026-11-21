package stonewrit

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var ErrPasswordAlreadySet = errors.New("authn: password already set")

// AccountLifecycleStore provides owner-bound account writes. Session-based
// mutations check the current session and user in the same transaction.
type AccountLifecycleStore interface {
	SetInitialPassword(ctx context.Context, userID, sessionToken, newHash string, now time.Time) error
	SaveDeletionToken(ctx context.Context, t PasswordResetToken) error
	DeleteAccount(ctx context.Context, userID, sessionToken, expectedHash, deleteToken string, now time.Time) error
	ChangeAccountEmail(ctx context.Context, userID, currentEmail, newEmail string, verified bool, now time.Time) (User, error)
}

func (a *Auth) lifecycleStore() (AccountLifecycleStore, error) {
	s, ok := a.opts.Store.(AccountLifecycleStore)
	if !ok {
		return nil, &APIError{501, "ACCOUNT_STORAGE_UNAVAILABLE", "Account operation is unavailable for this store"}
	}
	return s, nil
}

// SetPassword is a server-only operation for adding a first credential to an
// existing account. An existing password requires ChangePassword instead.
func (a *Auth) SetPassword(ctx context.Context, h http.Header, password string) error {
	session, err := a.requireOwnerSession(ctx, h)
	if err != nil {
		return err
	}
	if err = a.validatePasswordLength(password, true); err != nil {
		return err
	}
	s, err := a.lifecycleStore()
	if err != nil {
		return err
	}
	hash, err := a.hashCredential(ctx, "/set-password", password)
	if err != nil {
		return err
	}
	err = s.SetInitialPassword(ctx, session.User.ID, session.Session.Token, hash, a.now().UTC())
	if errors.Is(err, ErrPasswordAlreadySet) {
		return &APIError{400, "PASSWORD_ALREADY_SET", "User already has a password set"}
	}
	if errors.Is(err, ErrNotFound) {
		return &APIError{401, "UNAUTHORIZED", "Unauthorized"}
	}
	return err
}

type DeleteUserInput struct{ Password, Token, CallbackURL string }

// DeleteUser either requests confirmation or deletes the authenticated account.
// The return value is true when deletion is complete.
func (a *Auth) DeleteUser(ctx context.Context, h http.Header, in DeleteUserInput) (bool, error) {
	if !a.opts.DeleteUserEnabled {
		return false, &APIError{404, "NOT_FOUND", "Not found"}
	}
	session, err := a.requireOwnerSession(ctx, h)
	if err != nil {
		return false, err
	}
	s, err := a.lifecycleStore()
	if err != nil {
		return false, err
	}
	now := a.now().UTC()
	var hash string
	if in.Password != "" {
		hash, err = a.checkedAccountHash(ctx, session.User, in.Password)
		if err != nil {
			return false, err
		}
	}
	if in.Token == "" && a.opts.SendDeleteAccountVerification != nil {
		callback := in.CallbackURL
		if callback == "" {
			callback = "/"
		}
		if !a.trustedURL(callback, true) {
			return false, &APIError{403, "INVALID_CALLBACK_URL", "Invalid callbackURL"}
		}
		t := PasswordResetToken{ID: randomID(), Token: randomID(), UserID: session.User.ID, CreatedAt: now, ExpiresAt: now.Add(a.opts.DeleteTokenTTL)}
		if err := s.SaveDeletionToken(ctx, t); err != nil {
			return false, err
		}
		query := url.Values{"callbackURL": {callback}, "token": {t.Token}}
		link := a.opts.BaseURL + strings.TrimSuffix(a.opts.BasePath, "/") + "/delete-user/callback?" + query.Encode()
		return false, a.opts.SendDeleteAccountVerification(ctx, MailLink{User: session.User, URL: link, Token: t.Token})
	}
	if in.Token == "" && hash == "" && now.Sub(session.Session.CreatedAt) >= a.opts.FreshAge {
		return false, &APIError{400, "SESSION_EXPIRED", "Session expired. Re-authenticate to perform this action."}
	}
	err = s.DeleteAccount(ctx, session.User.ID, session.Session.Token, hash, in.Token, now)
	if errors.Is(err, ErrNotFound) {
		return false, &APIError{404, "INVALID_TOKEN", "Invalid token"}
	}
	return err == nil, err
}

// ChangeEmail requests confirmation for a new address. The token is bound to
// both the current owner and their current address.
func (a *Auth) ChangeEmail(ctx context.Context, h http.Header, newEmail, callback string) error {
	if !a.opts.ChangeEmailEnabled {
		return &APIError{400, "CHANGE_EMAIL_DISABLED", "Change email is disabled"}
	}
	session, err := a.requireOwnerSession(ctx, h)
	if err != nil {
		return err
	}
	newEmail = strings.ToLower(newEmail)
	if !emailPattern.MatchString(newEmail) || strings.Contains(newEmail, "..") {
		return &APIError{400, "INVALID_EMAIL", "Invalid email"}
	}
	if newEmail == session.User.Email {
		return &APIError{400, "BAD_REQUEST", "Email is the same"}
	}
	if callback != "" && !a.trustedURL(callback, true) {
		return &APIError{403, "INVALID_CALLBACK_URL", "Invalid callbackURL"}
	}
	immediate := !session.User.EmailVerified && a.opts.UpdateEmailWithoutVerification
	if !immediate && a.opts.SendVerificationEmail == nil {
		return &APIError{400, "VERIFICATION_EMAIL_NOT_ENABLED", "Verification email isn't enabled"}
	}
	s, err := a.accountStore()
	if err != nil {
		return err
	}
	if _, err = s.FindAccountUser(ctx, newEmail); err == nil {
		return nil
	} else if !errors.Is(err, ErrNotFound) {
		return err
	}
	if immediate {
		lifecycle, err := a.lifecycleStore()
		if err != nil {
			return err
		}
		u, err := lifecycle.ChangeAccountEmail(ctx, session.User.ID, session.User.Email, newEmail, false, a.now().UTC())
		if errors.Is(err, ErrEmailTaken) {
			return nil
		}
		if err != nil {
			return err
		}
		if a.opts.SendVerificationEmail != nil {
			return a.sendEmailProof(ctx, u, "", "", callback, a.opts.SendVerificationEmail)
		}
		return nil
	}
	if session.User.EmailVerified && a.opts.SendChangeEmailConfirmation != nil {
		return a.sendEmailProof(ctx, session.User, newEmail, "change-email-confirmation", callback, a.opts.SendChangeEmailConfirmation)
	}
	return a.sendEmailProof(ctx, session.User, newEmail, "change-email-verification", callback, a.opts.SendVerificationEmail)
}
