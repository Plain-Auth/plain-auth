package plainauth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"
)

// ProfileUpdate changes the supplied fields. A Clear flag removes its field and
// takes precedence over a supplied value.
type ProfileUpdate struct {
	AdditionalFields                                map[string]any
	validatedFields                                 UserFieldValues
	ClearPhoneNumber                                bool
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
	// Request is a copy of the HTTP request that caused the mail, without its
	// body, or nil for a direct Go call.
	Request *http.Request `json:"-"`
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
	values, err := a.prepareUserFields(update.AdditionalFields, false, false)
	if err != nil {
		return err
	}
	update.validatedFields = values
	if values.Present() {
		if err := session.Session.RequireOwner(); err != nil {
			return err
		}
	}
	if update.ClearPhoneNumber {
		if a.phoneNumber == nil {
			return &APIError{400, "BAD_REQUEST", "Phone number is not enabled"}
		}
		if err := session.Session.RequireOwner(); err != nil {
			return err
		}
	}
	if session.Session.IsApplicationCredential() && (update.hasUsernameChange() || !session.Session.AllowsCredentialAction("user", "update")) {
		return &APIError{403, "OWNER_SESSION_REQUIRED", "This profile operation requires a direct login"}
	}
	if !a.dbHooks.user.update.set() {
		return a.writeProfile(ctx, session, update)
	}
	row := session.User
	if update.Name != nil {
		row.Name = *update.Name
	}
	if update.ClearImage {
		row.Image = nil
	} else if update.Image != nil {
		row.Image = update.Image
	}
	input := serverInput(a.opts.UserAdditionalFields, update.AdditionalFields)
	edited, fields, err := a.beforeUserUpdate(ctx, row, input, true)
	if errors.Is(err, ErrSkipWrite) {
		// A declined profile update answers like a stored one.
		return nil
	}
	if err != nil {
		return err
	}
	if edited.Name != row.Name {
		update.Name = &edited.Name
	}
	if !reflect.DeepEqual(edited.Image, row.Image) {
		update.Image, update.ClearImage = edited.Image, edited.Image == nil
	}
	if !reflect.DeepEqual(fields, cloneFields(input)) {
		if update.validatedFields, err = a.prepareUserFields(fields, false, true); err != nil {
			return err
		}
		update.AdditionalFields = fields
	}
	if err := a.writeProfile(ctx, session, update); err != nil {
		return err
	}
	stored, err := a.GetSession(ctx, h)
	if err != nil || stored == nil {
		return err
	}
	return a.afterUserUpdate(ctx, stored.User, fields)
}

// writeProfile stores a validated profile update for the signed-in user.
func (a *Auth) writeProfile(ctx context.Context, session *SessionResult, update ProfileUpdate) error {
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
	if update.ClearPhoneNumber {
		err := a.opts.Store.(PhoneAccountStore).ClearPhoneProfile(ctx, session.User.ID, session.Session.Token, update, a.now().UTC())
		if errors.Is(err, ErrNotFound) {
			return &APIError{401, "UNAUTHORIZED", "Unauthorized"}
		}
		return err
	}
	if update.validatedFields.Present() {
		err := a.opts.Store.(UserFieldStore).UpdateUserFields(ctx, session.User.ID, &session.Session, update, a.now().UTC())
		if errors.Is(err, ErrNotFound) {
			return &APIError{401, "UNAUTHORIZED", "Unauthorized"}
		}
		return err
	}
	if update.Name == nil && update.Image == nil && !update.ClearImage {
		return &APIError{Status: 400, Message: "No fields to update"}
	}
	if session.Session.IsApplicationCredential() {
		store, ok := a.opts.Store.(interface {
			UpdateCredentialProfile(context.Context, string, ProfileUpdate, time.Time) error
		})
		access := session.Session.credentialAccess
		if !ok || access == nil || access.bind == nil {
			return &APIError{403, "OWNER_SESSION_REQUIRED", "This profile operation requires a direct login"}
		}
		return store.UpdateCredentialProfile(access.bind(ctx), session.User.ID, update, a.now().UTC())
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
	_, err = a.checkedAccountHash(ctx, session.User, password, errInvalidPassword)
	return err
}

var (
	errInvalidPassword          = &APIError{400, "INVALID_PASSWORD", "Invalid password"}
	errCredentialAccountMissing = &APIError{400, "CREDENTIAL_ACCOUNT_NOT_FOUND", "Credential account not found"}
)

// checkedAccountHash verifies the user's current password and returns its
// hash. A user without a password answers missing, as the routes differ:
// changing the password or deleting the user names the missing credential,
// while verifying a password answers as for a wrong one.
func (a *Auth) checkedAccountHash(ctx context.Context, user User, password string, missing *APIError) (string, error) {
	if err := a.validatePasswordLength(password, false); err != nil {
		return "", err
	}
	u, hash, err := a.opts.Store.Credential(ctx, user.Email)
	if errors.Is(err, ErrNotFound) || err == nil && (u.ID != user.ID || hash == "") {
		return "", missing
	}
	if err != nil {
		return "", err
	}
	ok, err := a.checkCredential(ctx, hash, password)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", errInvalidPassword
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
	// The current password is checked before the new one is hashed, so a
	// wrong one costs no hash; the answer already says it was wrong.
	old, err := a.checkedAccountHash(ctx, session.User, in.CurrentPassword, errCredentialAccountMissing)
	if err != nil {
		return AuthResult{}, err
	}
	hash, err := a.hashCredential(ctx, "/change-password", in.NewPassword)
	if err != nil {
		return AuthResult{}, err
	}
	if a.dbHooks.account.update.set() {
		credential, err := a.credentialAccount(ctx, session.User.ID)
		if err != nil {
			return AuthResult{}, err
		}
		credential.UpdatedAt = a.now().UTC().Truncate(time.Millisecond)
		if err := a.beforeAccount(ctx, a.dbHooks.account.update, credential); errors.Is(err, ErrSkipWrite) {
			// A password change that silently did nothing would leave the old password working.
			return AuthResult{}, &APIError{400, "FAILED_TO_UPDATE_USER", "Failed to update user"}
		} else if err != nil {
			return AuthResult{}, err
		}
	}
	result := AuthResult{User: session.User}
	var replacement *StoredSession
	var replacementFields map[string]any
	if in.RevokeOtherSessions {
		row, token := a.newSession(session.User.ID, meta)
		if row, replacementFields, err = a.beforeSessionCreate(ctx, row, nil, &APIError{500, "FAILED_TO_GET_SESSION", "Failed to get session"}); err != nil {
			return AuthResult{}, err
		}
		replacement, result.Token = &row, token
	}
	change := func(replacement *StoredSession) error {
		if bound, ok := s.(interface {
			ChangeCredentialForSession(context.Context, string, string, string, *StoredSession, string, time.Time) error
		}); ok {
			return bound.ChangeCredentialForSession(ctx, session.User.ID, old, hash, replacement, session.Session.Token, a.now().UTC())
		}
		return s.ChangeCredential(ctx, session.User.ID, old, hash, replacement)
	}
	if replacement == nil {
		err = change(nil)
	} else {
		// Revocation replaces every session of the account.
		var skipped bool
		skipped, err = a.deleteSessionsWithHooks(ctx, func() ([]Session, error) { return a.userSessionRows(ctx, session.User.ID, "") }, func() error {
			return change(replacement)
		})
		if skipped {
			// A declined revocation still changes the password and keeps every session.
			replacement, result.Token = nil, ""
			err = change(nil)
		}
	}
	if errors.Is(err, ErrNotFound) {
		return AuthResult{}, &APIError{400, "INVALID_PASSWORD", "Invalid password"}
	}
	if err == nil {
		err = a.afterCredentialAccount(ctx, a.dbHooks.account.update, session.User.ID)
	}
	if err == nil && replacement != nil {
		err = a.afterSessionCreate(ctx, *replacement, replacementFields)
	}
	return result, err
}

// RequestPasswordReset privately delivers a one-time link for a registered email.
func (a *Auth) RequestPasswordReset(ctx context.Context, email, redirectTo string) error {
	if a.opts.SendResetPassword == nil {
		return &APIError{400, "RESET_PASSWORD_DISABLED", "Reset password isn't enabled"}
	}
	if redirectTo != "" && !a.trustedURL(ctx, redirectTo, true) {
		return &APIError{403, "INVALID_REDIRECT_URL", "Invalid redirectURL"}
	}
	s, err := a.accountStore()
	if err != nil {
		return err
	}
	user, err := s.FindAccountUser(ctx, email)
	now := a.now().UTC()
	if errors.Is(err, ErrNotFound) {
		// The same token lookup a reset link would make, so an unknown
		// address does not answer faster than a registered one.
		_, _ = s.FindPasswordResetToken(ctx, randomID(), now)
		return nil
	}
	if err != nil {
		return err
	}
	t := PasswordResetToken{ID: randomID(), Token: randomID(), UserID: user.ID, Email: user.Email, CreatedAt: now, ExpiresAt: now.Add(a.opts.PasswordResetTokenTTL)}
	base, err := a.publicURL(ctx)
	if err != nil {
		return err
	}
	// A declined link answers as a sent one, with nothing stored or mailed.
	err = a.createVerification(ctx, tokenRecord("reset-password", t), func() error { return s.SavePasswordResetToken(ctx, t) })
	if errors.Is(err, ErrSkipWrite) {
		return nil
	}
	if err != nil {
		return err
	}
	link := base + "/reset-password/" + t.Token + "?" + url.Values{"callbackURL": {redirectTo}}.Encode()
	return a.deliverMail(ctx, "Could not deliver password reset email", MailLink{User: user, URL: link, Token: t.Token, Request: a.requestCopy(ctx)}, a.opts.SendResetPassword)
}

// ResetPassword consumes an unexpired recovery token atomically with the credential update.
func (a *Auth) ResetPassword(ctx context.Context, token, newPassword string) error {
	return a.resetPassword(ctx, token, newPassword, nil)
}

func (a *Auth) resetPassword(ctx context.Context, token, newPassword string, request *http.Request) error {
	if token == "" {
		return &APIError{400, "INVALID_TOKEN", "Invalid token"}
	}
	if err := a.validatePasswordLength(newPassword, true); err != nil {
		return err
	}
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
	hash, err := a.hashCredential(ctx, "/reset-password", newPassword)
	if err != nil {
		return err
	}
	now := a.now().UTC()
	// The token names its owner, so the hooks run before the reset commits,
	// starting with the link's own, which the reset spends first.
	spent := tokenRecord("reset-password", row)
	if err := a.beforeVerification(ctx, a.dbHooks.verification.delete, spent); errors.Is(err, ErrSkipWrite) {
		return &APIError{400, "INVALID_TOKEN", "Invalid token"}
	} else if err != nil {
		return err
	}
	credentialHooks := a.dbHooks.account.update
	if a.dbHooks.account.create.set() || a.dbHooks.account.update.set() {
		credential, err := a.credentialAccount(ctx, row.UserID)
		if err != nil {
			return err
		}
		if credential.ID == "" {
			// A reset adds the credential when the account has none.
			credentialHooks = a.dbHooks.account.create
			credential.CreatedAt = now
		}
		credential.UpdatedAt = now
		if err := a.beforeAccount(ctx, credentialHooks, credential); errors.Is(err, ErrSkipWrite) {
			return &APIError{400, "FAILED_TO_UPDATE_USER", "Failed to update user"}
		} else if err != nil {
			return err
		}
	}
	revoke := a.opts.RevokeSessionsOnPasswordReset
	var revoked []Session
	if revoke && a.dbHooks.session.delete.set() {
		if revoked, err = a.userSessionRows(ctx, row.UserID, ""); err != nil {
			return err
		}
		for _, session := range revoked {
			if err := runBefore(ctx, a, a.dbHooks.session.delete, &SessionRecord{Session: session, Fields: map[string]any{}}); errors.Is(err, ErrSkipWrite) {
				// A declined revocation still resets the password and keeps every session.
				revoke, revoked = false, nil
				break
			} else if err != nil {
				return err
			}
		}
	}
	var owner User
	if a.opts.OnPasswordReset == nil {
		err = s.FinishPasswordReset(ctx, row.Token, hash, now, revoke)
	} else if store, ok := s.(interface {
		FinishPasswordResetWithUser(context.Context, string, string, time.Time, bool) (User, error)
	}); ok {
		owner, err = store.FinishPasswordResetWithUser(ctx, row.Token, hash, now, revoke)
	} else {
		// Older custom account stores bind each token to its original owner.
		// Read the projection before consumption and confirm its immutable ID.
		owner, err = s.FindAccountUser(ctx, row.Email)
		if err == nil && owner.ID != row.UserID {
			err = ErrNotFound
		}
		if err == nil {
			err = s.FinishPasswordReset(ctx, row.Token, hash, now, revoke)
		}
	}
	if errors.Is(err, ErrNotFound) {
		return &APIError{400, "INVALID_TOKEN", "Invalid token"}
	}
	if err == nil {
		err = runAfter(ctx, a, a.dbHooks.verification.delete, spent)
	}
	if err == nil {
		err = a.afterCredentialAccount(ctx, credentialHooks, row.UserID)
	}
	for _, session := range revoked {
		if err != nil {
			break
		}
		err = runAfter(ctx, a, a.dbHooks.session.delete, SessionRecord{Session: session, Fields: map[string]any{}})
	}
	if err != nil || a.opts.OnPasswordReset == nil {
		return err
	}
	return a.notifyPasswordReset(ctx, owner, request)
}

// SendVerificationEmail delivers a verification link bound to the email's current owner.
func (a *Auth) SendVerificationEmail(ctx context.Context, h http.Header, email, callback string) error {
	if a.opts.SendVerificationEmail == nil {
		return &APIError{400, "VERIFICATION_EMAIL_NOT_ENABLED", "Verification email isn't enabled"}
	}
	if callback == "" {
		callback = "/"
	}
	if !a.trustedURL(ctx, callback, true) {
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

// The caller has finished its transaction. The observer may read the new
// credential state or start a separate transaction through another pool.
func (a *Auth) notifyPasswordReset(ctx context.Context, user User, request *http.Request) (err error) {
	if user.ID == "" || user.Email == "" {
		return errors.New("auth: password reset store did not return the account owner")
	}
	defer func() {
		if recover() != nil {
			err = errors.New("auth: password reset callback panicked")
		}
	}()
	return a.opts.OnPasswordReset(ctx, user, accountObserverRequest(ctx, request))
}

// accountObserverRequest retains HTTP metadata after the credential-setting
// operation without sharing its headers or exposing a replayable password body.
type requestCopyKey struct{ a *Auth }

// requestCopy returns a body-free copy of the HTTP request ctx belongs to, or
// nil for a direct Go call. Mail senders and account callbacks receive it.
func (a *Auth) requestCopy(ctx context.Context) *http.Request {
	r, _ := ctx.Value(requestCopyKey{a}).(*http.Request)
	return accountObserverRequest(ctx, r)
}

func accountObserverRequest(ctx context.Context, request *http.Request) *http.Request {
	if request == nil {
		return nil
	}
	metadata := request.Clone(ctx)
	metadata.Body, metadata.GetBody, metadata.ContentLength = http.NoBody, nil, 0
	metadata.Form, metadata.PostForm, metadata.MultipartForm = nil, nil, nil
	metadata.Header.Del("Content-Length")
	return metadata
}
