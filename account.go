package stonewrit

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ProfileUpdate changes the supplied fields. A Clear flag removes its field and
// takes precedence over a supplied value.
type ProfileUpdate struct {
	Username, DisplayUsername                       *string
	Name, Image                                     *string
	ClearImage, ClearUsername, ClearDisplayUsername bool
}

// PasswordResetToken records a reset link and its owner in verification storage.
type PasswordResetToken struct {
	ID, Token, UserID, Email string
	CreatedAt, ExpiresAt     time.Time
}

// AccountStore extends a credential store with atomic profile, credential and
// verification operations. Its password methods serialize credential changes
// with creation of sessions for the old password. Expired or spent tokens,
// changed passwords, and mismatched account bindings return ErrNotFound.
type AccountStore interface {
	UpdateProfile(context.Context, string, ProfileUpdate, time.Time) error
	CreateCredentialSession(ctx context.Context, expectedHash string, session StoredSession) error
	ChangeCredential(ctx context.Context, userID, oldHash, newHash string, replacement *StoredSession) error
	FindAccountUser(ctx context.Context, email string) (User, error)
	SavePasswordResetToken(context.Context, PasswordResetToken) error
	FindPasswordResetToken(ctx context.Context, token string, now time.Time) (PasswordResetToken, error)
	FinishPasswordReset(ctx context.Context, token, newHash string, now time.Time, revokeSessions bool) error
	VerifyAccountEmail(ctx context.Context, userID, email string, now time.Time) error
}

// MailLink is delivered to the application's configured mail sender. Its Token
// and URL are sensitive and should only be delivered to User.Email.
type MailLink struct {
	User                 User
	URL, Token, NewEmail string
}

type MailSender func(context.Context, MailLink) error

func (a *Auth) accountStore() (AccountStore, error) {
	s, ok := a.opts.Store.(AccountStore)
	if !ok {
		return nil, &APIError{501, "ACCOUNT_STORAGE_UNAVAILABLE", "Account operation is unavailable for this store"}
	}
	return s, nil
}

// UpdateUser applies the permitted profile fields to the current account.
func (a *Auth) UpdateUser(ctx context.Context, h http.Header, update ProfileUpdate) error {
	session, err := a.requireSession(ctx, h)
	if err != nil {
		return err
	}
	if a.username != nil && update.hasUsernameChange() {
		if session.Session.ImpersonatedBy != nil {
			return &APIError{403, "FORBIDDEN", "Account owner session required"}
		}
		if update.ClearUsername {
			update.Username = nil
		}
		if update.ClearDisplayUsername {
			update.DisplayUsername = nil
		}
		f, err := a.username.fields(ctx, update.Username, update.DisplayUsername, false)
		if err != nil {
			return err
		}
		update.Username, update.DisplayUsername = f.Username, nil
		if f.DisplayUsernameFields != nil {
			update.DisplayUsername = f.DisplayUsername
		}
		if a.username.DisableDisplay {
			update.ClearDisplayUsername = false
		}
		if update.hasUsernameChange() {
			err := a.opts.Store.(UsernameStore).UpdateUsernameProfile(ctx, session.User.ID, session.Session.Token, update, a.now().UTC(), a.username.Immutable)
			if errors.Is(err, ErrNotFound) {
				return &APIError{401, "UNAUTHORIZED", "Unauthorized"}
			}
			return usernameWriteError(err)
		}
	}
	update.Username, update.DisplayUsername = nil, nil
	update.ClearUsername, update.ClearDisplayUsername = false, false
	if update.Name == nil && update.Image == nil && !update.ClearImage {
		return &APIError{400, "BAD_REQUEST", "No fields to update"}
	}
	s, err := a.accountStore()
	if err != nil {
		return err
	}
	return s.UpdateProfile(ctx, session.User.ID, update, a.now().UTC())
}

// VerifyPassword reauthenticates a signed-in user with their current password.
func (a *Auth) VerifyPassword(ctx context.Context, h http.Header, password string) error {
	session, err := a.requireOwnerSession(ctx, h)
	if err != nil {
		return err
	}
	_, err = a.checkedAccountHash(ctx, session.User, password)
	return err
}

func (a *Auth) checkedAccountHash(ctx context.Context, user User, password string) (string, error) {
	if err := a.validatePasswordLength(password, false); err != nil {
		return "", err
	}
	u, hash, err := a.opts.Store.Credential(ctx, user.Email)
	if errors.Is(err, ErrNotFound) {
		return "", &APIError{400, "INVALID_PASSWORD", "Invalid password"}
	}
	if err != nil {
		return "", err
	}
	if u.ID != user.ID {
		return "", &APIError{400, "INVALID_PASSWORD", "Invalid password"}
	}
	ok, err := a.checkCredential(ctx, hash, password)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", &APIError{400, "INVALID_PASSWORD", "Invalid password"}
	}
	return hash, nil
}

type ChangePasswordInput struct {
	CurrentPassword, NewPassword string
	RevokeOtherSessions          bool
}

// ChangePassword optionally revokes all prior sessions and issues a replacement
// for the caller in the same transaction as the password update.
func (a *Auth) ChangePassword(ctx context.Context, h http.Header, in ChangePasswordInput, meta RequestMeta) (AuthResult, error) {
	session, err := a.requireOwnerSession(ctx, h)
	if err != nil {
		return AuthResult{}, err
	}
	if err := a.validatePasswordLength(in.NewPassword, true); err != nil {
		return AuthResult{}, err
	}
	s, err := a.accountStore()
	if err != nil {
		return AuthResult{}, err
	}
	old, err := a.checkedAccountHash(ctx, session.User, in.CurrentPassword)
	if err != nil {
		return AuthResult{}, err
	}
	hash, err := a.hashCredential(ctx, "/change-password", in.NewPassword)
	if err != nil {
		return AuthResult{}, err
	}
	result := AuthResult{User: session.User}
	var replacement *StoredSession
	if in.RevokeOtherSessions {
		row, token := a.newSession(session.User.ID, meta)
		replacement, result.Token = &row, token
	}
	if bound, ok := s.(interface {
		ChangeCredentialForSession(context.Context, string, string, string, *StoredSession, string, time.Time) error
	}); ok {
		err = bound.ChangeCredentialForSession(ctx, session.User.ID, old, hash, replacement, session.Session.Token, a.now().UTC())
	} else {
		err = s.ChangeCredential(ctx, session.User.ID, old, hash, replacement)
	}
	if errors.Is(err, ErrNotFound) {
		return AuthResult{}, &APIError{400, "INVALID_PASSWORD", "Invalid password"}
	}
	return result, err
}

// RequestPasswordReset privately delivers a one-time link for a registered email.
func (a *Auth) RequestPasswordReset(ctx context.Context, email, redirectTo string) error {
	if a.opts.SendResetPassword == nil {
		return &APIError{400, "RESET_PASSWORD_DISABLED", "Reset password isn't enabled"}
	}
	if redirectTo != "" && !a.trustedURL(redirectTo, true) {
		return &APIError{403, "INVALID_REDIRECT_URL", "Invalid redirectURL"}
	}
	s, err := a.accountStore()
	if err != nil {
		return err
	}
	user, err := s.FindAccountUser(ctx, email)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	now := a.now().UTC()
	t := PasswordResetToken{ID: randomID(), Token: randomID(), UserID: user.ID, Email: user.Email, CreatedAt: now, ExpiresAt: now.Add(a.opts.PasswordResetTokenTTL)}
	if err := s.SavePasswordResetToken(ctx, t); err != nil {
		return err
	}
	base := a.opts.BaseURL + strings.TrimRight(a.opts.BasePath, "/")
	link := base + "/reset-password/" + t.Token + "?" + url.Values{"callbackURL": {redirectTo}}.Encode()
	return a.opts.SendResetPassword(ctx, MailLink{User: user, URL: link, Token: t.Token})
}

// ResetPassword consumes an unexpired recovery token atomically with the credential update.
func (a *Auth) ResetPassword(ctx context.Context, token, newPassword string) error {
	s, err := a.accountStore()
	if err != nil {
		return err
	}
	row, err := s.FindPasswordResetToken(ctx, token, a.now().UTC())
	if errors.Is(err, ErrNotFound) {
		return &APIError{400, "INVALID_TOKEN", "Invalid token"}
	}
	if err != nil {
		return err
	}
	if err := a.validatePasswordLength(newPassword, true); err != nil {
		return err
	}
	hash, err := a.hashCredential(ctx, "/reset-password", newPassword)
	if err != nil {
		return err
	}
	err = s.FinishPasswordReset(ctx, row.Token, hash, a.now().UTC(), a.opts.RevokeSessionsOnPasswordReset)
	if errors.Is(err, ErrNotFound) {
		return &APIError{400, "INVALID_TOKEN", "Invalid token"}
	}
	return err
}

// SendVerificationEmail delivers a verification link bound to the email's current owner.
func (a *Auth) SendVerificationEmail(ctx context.Context, h http.Header, email, callback string) error {
	if a.opts.SendVerificationEmail == nil {
		return &APIError{400, "VERIFICATION_EMAIL_NOT_ENABLED", "Verification email isn't enabled"}
	}
	if callback == "" {
		callback = "/"
	}
	if !a.trustedURL(callback, true) {
		return &APIError{403, "INVALID_CALLBACK_URL", "Invalid callbackURL"}
	}
	s, err := a.accountStore()
	if err != nil {
		return err
	}
	session, err := a.GetSession(ctx, h)
	if err != nil {
		return err
	}
	var u User
	if session != nil {
		u = session.User
		if !strings.EqualFold(u.Email, email) {
			return &APIError{400, "EMAIL_MISMATCH", "Email mismatch"}
		}
		if u.EmailVerified {
			return &APIError{400, "EMAIL_ALREADY_VERIFIED", "Email is already verified"}
		}
	} else {
		// Give unauthenticated user lookups a common
		// 500ms response floor, including the path that skips mail delivery.
		start := time.Now()
		defer func() {
			timer := time.NewTimer(500*time.Millisecond - time.Since(start))
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-ctx.Done():
			}
		}()
		u, err = s.FindAccountUser(ctx, email)
		if errors.Is(err, ErrNotFound) || (err == nil && u.EmailVerified) {
			return nil
		}
		if err != nil {
			return err
		}
	}
	return a.sendEmailProof(ctx, u, "", "", callback, a.opts.SendVerificationEmail)
}
