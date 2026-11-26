package passkey

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/mail"
	"strings"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	wa "github.com/go-webauthn/webauthn/webauthn"
)

// RegistrationUser is the identity proposed at the beginning of a ceremony.
type RegistrationUser struct{ ID, Name, DisplayName string }

// RegistrationOptions configures trusted identity resolution and post-attestation decisions.
type RegistrationOptions struct {
	// AllowWithoutSession enables enrollment resolved by a trusted application callback.
	AllowWithoutSession bool
	ResolveUser         func(auth.EndpointContext, *string) (RegistrationUser, error)
	AfterVerification   func(auth.EndpointContext, VerifiedRegistration) (RegistrationDecision, error)
	// Extensions adds WebAuthn extension inputs to each GET
	// /passkey/generate-register-options response. Registration always asks
	// for credProps as well, as the other runtime's server does. An
	// authentication-only input such as AppID fails the request. See
	// ExtensionsResolver.
	Extensions ExtensionsResolver
}

// VerifiedRegistration contains the saved identity context and successfully verified authenticator data.
type VerifiedRegistration struct {
	User       RegistrationUser
	Context    *string
	Credential wa.Credential
	// AAGUID identifies the authenticator model, in the canonical lowercase
	// form stored on the passkey (Record.AAGUID). It is the all-zero AAGUID
	// when the authenticator does not name its model, and empty when the
	// response carries none. Pass it to AuthenticatorName for a default label.
	AAGUID   string
	Response json.RawMessage
}

// RegistrationDecision chooses the account and optional label for a verified credential.
type RegistrationDecision struct {
	// AllowExistingAccount explicitly authorizes a resolver-initiated enrollment on an existing account.
	AllowExistingAccount bool
	UserID, Name         string
	// NewAccount is inserted atomically with the passkey. A collision never links to the existing email.
	NewAccount *RegistrationAccount
}

// RegistrationAccount describes a new passwordless account with an initially unverified email.
type RegistrationAccount struct{ Name, Email string }

// RegistrationStore persists the credential and optional new user/session in one transaction.
// Implementations must revalidate the source session, if present, and enforce credential uniqueness.
// It returns ErrUserNotFound when the record's account does not exist and create is nil.
type RegistrationStore interface {
	CommitPasskeyRegistration(ctx context.Context, record Record, sourceToken string, create *auth.User, session *auth.StoredSession, now time.Time) (auth.User, error)
}

var (
	errResolver = problem(400, "RESOLVE_USER_REQUIRED", "Passkey registration requires either an authenticated session or a resolveUser callback when requireSession is false")
	errIdentity = problem(400, "RESOLVED_USER_INVALID", "Resolved user is invalid")
	errOwner    = problem(401, "YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY", "You are not allowed to register this passkey")
)

func (s service) registrationSession(c auth.EndpointContext) (*auth.SessionResult, error) {
	if !s.registration.AllowWithoutSession {
		return c.RequireFreshSession()
	}
	ss, err := c.Auth.GetSession(c.Request.Context(), c.Request.Header)
	if err != nil || ss == nil {
		return ss, err
	}
	return c.RequireFreshSession()
}
func (s service) registrationActor(c auth.EndpointContext) (actor, ceremony, error) {
	state := ceremony{Kind: "registration"}
	if values, ok := c.Request.URL.Query()["context"]; ok && len(values) > 0 {
		v := values[0]
		state.Context = &v
	}
	ss, err := s.registrationSession(c)
	if err != nil {
		return actor{}, state, err
	}
	var u RegistrationUser
	if ss != nil {
		u = RegistrationUser{ID: ss.User.ID, Name: ss.User.Email, DisplayName: ss.User.Email}
		state.SessionID = ss.Session.ID
	} else {
		if s.registration.ResolveUser == nil {
			return actor{}, state, errResolver
		}
		u, err = s.registration.ResolveUser(c, state.Context)
		if err != nil {
			return actor{}, state, err
		}
		if u.ID == "" || u.Name == "" {
			return actor{}, state, errIdentity
		}
		state.PreAuth = true
	}
	state.UserID, state.Name, state.DisplayName = u.ID, u.Name, u.DisplayName
	who := s.actor(auth.User{ID: u.ID, Name: u.Name})
	who.display = u.DisplayName
	if state.PreAuth {
		who.handle = make([]byte, 16)
		rand.Read(who.handle)
	}
	return who, state, nil
}

const handleIDPrefix = "pk1_"

// New pre-authentication records carry their random opaque WebAuthn handle in the row ID.
// The resulting identifier fits the canonical 36-character MySQL primary key.
func recordHandle(id string) []byte {
	if len(id) != len(handleIDPrefix)+32 || !strings.HasPrefix(id, handleIDPrefix) {
		return nil
	}
	b, err := hex.DecodeString(id[len(handleIDPrefix):])
	if err != nil {
		return nil
	}
	return b
}
func (s service) persistRegistration(c auth.EndpointContext, state ceremony, ss *auth.SessionResult, cred *wa.Credential, raw []byte, r Record, createSession bool, now time.Time) (any, error) {
	d := RegistrationDecision{}
	if s.registration.AfterVerification != nil {
		var err error
		aaguid := ""
		if r.AAGUID != nil {
			aaguid = *r.AAGUID
		}
		d, err = s.registration.AfterVerification(c, VerifiedRegistration{User: RegistrationUser{state.UserID, state.Name, state.DisplayName}, Context: state.Context, Credential: *cred, AAGUID: aaguid, Response: json.RawMessage(raw)})
		if err != nil {
			return nil, err
		}
	}
	if d.UserID != "" {
		r.UserID = d.UserID
	}
	if ss != nil && ss.User.ID != r.UserID {
		return nil, errOwner
	}
	if r.Name == nil {
		if n := strings.TrimSpace(d.Name); n != "" {
			r.Name = &n
		}
	}
	if state.PreAuth && ss == nil && d.NewAccount == nil && !d.AllowExistingAccount {
		return nil, errOwner
	}
	var fresh *auth.User
	if d.NewAccount != nil {
		if !state.PreAuth || ss != nil {
			return nil, errOwner
		}
		if !c.SignUpAllowed() {
			return nil, problem(403, "SIGN_UP_DISABLED", "Sign up is disabled")
		}
		email := strings.ToLower(d.NewAccount.Email)
		parsed, err := mail.ParseAddress(email)
		if err != nil || parsed.Address != email || !strings.Contains(email, "@") {
			return nil, errIdentity
		}
		fresh = &auth.User{ID: r.UserID, Name: d.NewAccount.Name, Email: email, CreatedAt: now, UpdatedAt: now}
		check := auth.UserInfoValidation{Action: auth.UserInfoCreateUser, Method: "passkey", User: auth.UserRecord{User: *fresh}, Request: c.Request}
		if err := c.Auth.ValidateUserInfo(c.Request.Context(), check); err != nil {
			return nil, err
		}
	}
	source := ""
	if ss != nil {
		source = ss.Session.Token
	}
	if state.PreAuth {
		r.ID = handleIDPrefix + hex.EncodeToString(state.Data.UserID)
	}
	store, capable := c.Store().(RegistrationStore)
	if !capable {
		if state.PreAuth || createSession || fresh != nil {
			return nil, problem(500, "FAILED_TO_VERIFY_REGISTRATION", "Store does not support transactional registration")
		}
		return r, c.Store().(Store).CreatePasskey(c.Request.Context(), r, source, now)
	}
	if !createSession {
		_, err := store.CommitPasskeyRegistration(c.Request.Context(), r, source, fresh, nil, now)
		return r, err
	}
	result, err := c.IssueSessionOr(ErrSessionCreation, r.UserID, func(ctx context.Context, newSession auth.StoredSession) (auth.User, error) {
		return store.CommitPasskeyRegistration(ctx, r, source, fresh, &newSession, now)
	})
	if err != nil {
		return nil, err
	}
	return RegistrationResult{Record: r, Session: &result.Session, User: &result.User}, nil
}

// RegistrationResult includes the public passkey and, when requested, the newly established session.
type RegistrationResult struct {
	Record
	Session *auth.Session `json:"session,omitempty"`
	User    *auth.User    `json:"user,omitempty"`
}
