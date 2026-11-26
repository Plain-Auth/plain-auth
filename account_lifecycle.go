package plainauth

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

// DeletionTokenStore spends an account deletion token before any deletion
// hook runs. The token is spent whoever presents it, as in the reference,
// and ErrNotFound reports one that is unknown, expired or issued to
// another user. A store without it checks the token while deleting.
type DeletionTokenStore interface {
	ConsumeDeletionToken(ctx context.Context, userID, token string, now time.Time) error
}

// DeletionTokenFinder reads an account deletion token without spending it,
// for verification delete hooks. A token that is unknown, expired or issued
// to another user is ErrNotFound.
type DeletionTokenFinder interface {
	FindDeletionToken(ctx context.Context, userID, token string, now time.Time) (PasswordResetToken, error)
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
	now := a.now().UTC()
	if a.dbHooks.account.create.set() {
		draft := LinkedAccount{ProviderID: "credential", AccountID: session.User.ID, UserID: session.User.ID, CreatedAt: now, UpdatedAt: now}
		if err := a.beforeAccount(ctx, a.dbHooks.account.create, draft); errors.Is(err, ErrSkipWrite) {
			return &APIError{400, "FAILED_TO_UPDATE_USER", "Failed to update user"}
		} else if err != nil {
			return err
		}
	}
	err = s.SetInitialPassword(ctx, session.User.ID, session.Session.Token, hash, now)
	if errors.Is(err, ErrPasswordAlreadySet) {
		return &APIError{400, "PASSWORD_ALREADY_SET", "User already has a password set"}
	}
	if errors.Is(err, ErrNotFound) {
		return &APIError{401, "UNAUTHORIZED", "Unauthorized"}
	}
	if err != nil {
		return err
	}
	return a.afterCredentialAccount(ctx, a.dbHooks.account.create, session.User.ID)
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
		hash, err = a.checkedAccountHash(ctx, session.User, in.Password, errCredentialAccountMissing)
		if err != nil {
			return false, err
		}
	}
	// A mailed token is spent first, so an expired one, or one opened by
	// another account, runs no deletion hook.
	tokenKey := in.Token
	if in.Token != "" {
		if tokenKey, err = a.verificationKey(ctx, deleteAccountPrefix, in.Token); err != nil {
			return false, err
		}
	}
	deleteToken := tokenKey
	if consumer, ok := s.(DeletionTokenStore); ok && in.Token != "" {
		find := func() (VerificationRecord, error) {
			finder, ok := s.(DeletionTokenFinder)
			if !ok {
				return VerificationRecord{}, ErrNotFound
			}
			t, err := finder.FindDeletionToken(ctx, session.User.ID, tokenKey, now)
			return tokenRecord("delete-account", t), err
		}
		refused, err := a.spendVerification(ctx, find, func() error { return consumer.ConsumeDeletionToken(ctx, session.User.ID, tokenKey, now) })
		if err != nil {
			return false, err
		}
		if refused {
			return false, &APIError{404, "INVALID_TOKEN", "Invalid token"}
		}
		deleteToken = ""
	}
	if in.Token == "" && a.opts.SendDeleteAccountVerification != nil {
		callback := in.CallbackURL
		if callback == "" {
			callback = "/"
		}
		if !a.trustedURL(ctx, callback, true) {
			return false, &APIError{403, "INVALID_CALLBACK_URL", "Invalid callbackURL"}
		}
		token := randomID()
		key, err := a.verificationKey(ctx, deleteAccountPrefix, token)
		if err != nil {
			return false, err
		}
		t := PasswordResetToken{ID: randomID(), Token: key, UserID: session.User.ID, CreatedAt: now, ExpiresAt: now.Add(a.opts.DeleteTokenTTL)}
		base, err := a.publicURL(ctx)
		if err != nil {
			return false, err
		}
		// A declined link answers as a sent one, with nothing stored or mailed.
		declined, err := a.createVerification(ctx, tokenRecord("delete-account", t), func() error { return s.SaveDeletionToken(ctx, t) })
		if err != nil || declined {
			return false, err
		}
		query := url.Values{"callbackURL": {callback}, "token": {token}}
		link := base + "/delete-user/callback?" + query.Encode()
		return false, a.deliverMail(ctx, "Could not deliver account deletion email", MailLink{User: session.User, URL: link, Token: token, Request: a.requestCopy(ctx)}, a.opts.SendDeleteAccountVerification)
	}
	if in.Token == "" && hash == "" && !a.freshSession(session.Session) {
		return false, &APIError{400, "SESSION_EXPIRED", "Session expired. Re-authenticate to perform this action."}
	}
	if a.opts.BeforeDeleteUser != nil {
		if err := a.opts.BeforeDeleteUser(ctx, session.User, a.requestCopy(ctx)); err != nil {
			return false, err
		}
	}
	declined, err := a.deleteUserWithHooks(ctx, session.User, func() error {
		return s.DeleteAccount(ctx, session.User.ID, session.Session.Token, hash, deleteToken, now)
	})
	if errors.Is(err, ErrNotFound) {
		return false, &APIError{404, "INVALID_TOKEN", "Invalid token"}
	}
	if err == nil && !declined && a.opts.AfterDeleteUser != nil {
		err = a.opts.AfterDeleteUser(ctx, session.User, a.requestCopy(ctx))
	}
	// A declined deletion answers like a completed one, as in the reference.
	return err == nil || declined, err
}

// ChangeEmail requests confirmation for a new address. The token is bound to
// both the current owner and their current address.
func (a *Auth) ChangeEmail(ctx context.Context, h http.Header, newEmail, callback string) error {
	_, err := a.changeEmail(ctx, h, newEmail, callback)
	return err
}

// changeEmail also reports whether the address changed at once, so the
// HTTP handler can re-issue the session cookies with the new address.
func (a *Auth) changeEmail(ctx context.Context, h http.Header, newEmail, callback string) (bool, error) {
	session, err := a.requireOwnerSession(ctx, h)
	if err != nil {
		return false, err
	}
	if !a.opts.ChangeEmailEnabled {
		return false, &APIError{400, "CHANGE_EMAIL_DISABLED", "Change email is disabled"}
	}
	if !emailPattern.MatchString(newEmail) {
		return false, &APIError{400, "INVALID_EMAIL", "Invalid email"}
	}
	newEmail = strings.ToLower(newEmail)
	if newEmail == session.User.Email {
		return false, &APIError{Status: 400, Message: "Email is the same"}
	}
	if callback != "" && !a.trustedURL(ctx, callback, true) {
		return false, &APIError{403, "INVALID_CALLBACK_URL", "Invalid callbackURL"}
	}
	immediate := !session.User.EmailVerified && a.opts.UpdateEmailWithoutVerification
	if !immediate && a.opts.SendVerificationEmail == nil {
		return false, &APIError{Status: 400, Message: "Verification email isn't enabled"}
	}
	s, err := a.accountStore()
	if err != nil {
		return false, err
	}
	// An address another account holds answers like a free one, without
	// mail or change, so the route does not reveal who is registered.
	if _, err = s.FindAccountUser(ctx, newEmail); err == nil {
		return false, nil
	} else if !errors.Is(err, ErrNotFound) {
		return false, err
	}
	if immediate {
		lifecycle, err := a.lifecycleStore()
		if err != nil {
			return false, err
		}
		row := session.User
		row.Email = newEmail
		if _, _, err := a.beforeUserUpdate(ctx, row, nil, false); errors.Is(err, ErrSkipWrite) {
			return false, nil
		} else if err != nil {
			return false, err
		}
		u, err := lifecycle.ChangeAccountEmail(ctx, session.User.ID, session.User.Email, newEmail, false, a.now().UTC())
		if errors.Is(err, ErrEmailTaken) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if err := a.afterUserUpdate(ctx, u, nil); err != nil {
			return true, err
		}
		if a.opts.SendVerificationEmail != nil {
			return true, a.deliverEmailProof(ctx, "Could not deliver verification email for a changed address", u, "", "", callback, a.opts.SendVerificationEmail)
		}
		return true, nil
	}
	if session.User.EmailVerified && a.opts.SendChangeEmailConfirmation != nil {
		return false, a.deliverEmailProof(ctx, "Could not deliver email change confirmation", session.User, newEmail, "change-email-confirmation", callback, a.opts.SendChangeEmailConfirmation)
	}
	return false, a.deliverEmailProof(ctx, "Could not deliver email change verification", session.User, newEmail, "change-email-verification", callback, a.opts.SendVerificationEmail)
}
