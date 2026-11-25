// Package passkey authenticates users with WebAuthn public-key credentials.
package passkey

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	authn "github.com/Plain-Org/plain-auth"
	"github.com/go-webauthn/webauthn/protocol"
	wa "github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

// Record is the canonical stored passkey. CredentialID contains unpadded
// base64url and PublicKey contains the base64-encoded COSE public key.
type Record struct {
	ID           string     `json:"id"`
	Name         *string    `json:"name,omitempty"`
	PublicKey    string     `json:"publicKey"`
	UserID       string     `json:"userId"`
	CredentialID string     `json:"credentialID"`
	Counter      uint32     `json:"counter"`
	DeviceType   string     `json:"deviceType"`
	BackedUp     bool       `json:"backedUp"`
	Transports   *string    `json:"transports,omitempty"`
	CreatedAt    *time.Time `json:"createdAt,omitempty"`
	AAGUID       *string    `json:"aaguid,omitempty"`
}

type Store interface {
	CheckPasskeySchema(context.Context) error
	// SavePasskeyChallenge stores a ceremony under key, the hex of the
	// challenge cookie's SHA-256, until its expiry. It gives the row the ID
	// ChallengeRecordID(key), which the challenge's verification hooks name.
	SavePasskeyChallenge(context.Context, string, []byte, time.Time, time.Time) error
	TakePasskeyChallenge(context.Context, string, time.Time) ([]byte, error)
	ListPasskeys(context.Context, string) ([]Record, error)
	LookupPasskey(context.Context, string) (Record, error)
	CreatePasskey(context.Context, Record, string, time.Time) error
	FinishPasskeyLogin(context.Context, Record, uint32, bool, authn.StoredSession) (authn.User, error)
	ManagePasskey(ctx context.Context, userID, sessionToken, id string, newName *string, now time.Time) (Record, error)
}

// ChallengeFinder reads a passkey challenge without spending it, for
// verification delete hooks. FindPasskeyChallenge returns the row ID, the
// stored ceremony and the expiry of the challenge TakePasskeyChallenge would
// take under key at now, without locking it, and plainauth.ErrNotFound when
// none is live. New requires it for verification delete hooks with this plugin.
type ChallengeFinder interface {
	FindPasskeyChallenge(ctx context.Context, key string, now time.Time) (id string, ceremony []byte, expiresAt time.Time, err error)
}

// ChallengeRecordID is the ID of the challenge stored under key: "pk-" and
// the hex of the first 16 bytes of the key's SHA-256. A store gives the
// challenge's row this ID, so its verification hooks name the row.
func ChallengeRecordID(key string) string {
	sum := sha256.Sum256([]byte(key))
	return "pk-" + hex.EncodeToString(sum[:16])
}

// challengeRecord is a challenge as a verification record. It names the
// signed-in user the ceremony is for, and none for a first-use registration,
// whose account may not exist yet, or a signed-out sign-in. It never carries
// the challenge or the ceremony.
func challengeRecord(id, kind string, state ceremony, expiresAt time.Time) authn.VerificationRecord {
	rec := authn.VerificationRecord{ID: id, Identifier: "passkey-" + kind, ExpiresAt: expiresAt}
	if !state.PreAuth {
		rec.UserID = state.UserID
	}
	return rec
}

type Options struct {
	Registration            RegistrationOptions
	RPID                    string
	RPName                  string
	Origins                 []string
	RequireUserVerification bool
	ChallengeLifetime       time.Duration
}

type service struct {
	registration RegistrationOptions
	web          *wa.WebAuthn
	ttl          time.Duration
}
type ceremony struct {
	PreAuth           bool
	Context           *string
	Name, DisplayName string
	Kind              string
	UserID            string
	SessionID         string
	Data              wa.SessionData
}

type actor struct {
	display string
	authn.User
	handle      []byte
	credentials wa.Credentials
}

func (u actor) WebAuthnID() []byte   { return u.handle }
func (u actor) WebAuthnName() string { return u.Name }
func (u actor) WebAuthnDisplayName() string {
	if u.display != "" {
		return u.display
	}
	return u.Name
}
func (u actor) WebAuthnCredentials() []wa.Credential { return u.credentials }
func (s service) actor(user authn.User) actor {
	sum := sha256.Sum256([]byte("passkey-user\x00" + s.web.Config.RPID + "\x00" + user.ID))
	return actor{User: user, handle: sum[:]}
}
func problem(status int, code, msg string) *authn.APIError {
	return &authn.APIError{Status: status, Code: code, Message: msg}
}

var (
	ErrChallenge      = problem(400, "CHALLENGE_NOT_FOUND", "Challenge not found")
	ErrRegistration   = problem(400, "FAILED_TO_VERIFY_REGISTRATION", "Failed to verify registration")
	ErrAuthentication = problem(401, "AUTHENTICATION_FAILED", "Authentication failed")
	ErrMissing        = problem(401, "PASSKEY_NOT_FOUND", "Passkey not found")
	ErrSession        = problem(401, "SESSION_REQUIRED", "Passkey registration requires an authenticated session")
	ErrDuplicate      = problem(400, "PREVIOUSLY_REGISTERED", "Previously registered")
)

// New constructs the plugin with an explicit relying-party ID and exact list
// of allowed browser origins. Loopback HTTP is supported for local development.
func New(o Options) (authn.Plugin, error) {
	if o.RPID == "" || o.RPName == "" || len(o.Origins) == 0 {
		return authn.Plugin{}, errors.New("passkey: RPID, RPName and Origins are required")
	}
	origins := slices.Clone(o.Origins)
	for _, raw := range origins {
		u, err := url.Parse(raw)
		if err != nil || u.User != nil || u.Hostname() == "" || u.Scheme+"://"+u.Host != raw || strings.Contains(raw, "*") {
			return authn.Plugin{}, errors.New("passkey: invalid browser origin")
		}
		host := strings.ToLower(u.Hostname())
		ip := net.ParseIP(host)
		loop := host == "localhost" || (ip != nil && ip.IsLoopback())
		if (u.Scheme != "https" && !(u.Scheme == "http" && loop)) || (host != o.RPID && !strings.HasSuffix(host, "."+o.RPID)) {
			return authn.Plugin{}, errors.New("passkey: origin must be a secure origin within the relying-party ID")
		}
	}
	if o.ChallengeLifetime == 0 {
		o.ChallengeLifetime = 5 * time.Minute
	}
	if o.ChallengeLifetime < time.Second {
		return authn.Plugin{}, errors.New("passkey: challenge lifetime must be at least a second")
	}
	uv := protocol.VerificationPreferred
	if o.RequireUserVerification {
		uv = protocol.VerificationRequired
	}
	timeout := wa.TimeoutConfig{Enforce: true, Timeout: o.ChallengeLifetime, TimeoutUVD: o.ChallengeLifetime}
	web, err := wa.New(&wa.Config{RPID: o.RPID, RPDisplayName: o.RPName, RPOrigins: origins,
		AuthenticatorSelection: protocol.AuthenticatorSelection{ResidentKey: protocol.ResidentKeyRequirementPreferred, UserVerification: uv},
		Timeouts:               wa.TimeoutsConfig{Registration: timeout, Login: timeout}})
	if err != nil {
		return authn.Plugin{}, err
	}
	var enrollmentMetadata json.RawMessage
	if o.Registration.AllowWithoutSession {
		enrollmentMetadata = json.RawMessage(`{"security":[{},{"apiKeyCookie":[]}]}`)
	}
	s := service{web: web, ttl: o.ChallengeLifetime, registration: o.Registration}
	return authn.Plugin{ID: "passkey", ValidateStore: func(store authn.Store) error {
		backend, ok := store.(Store)
		if !ok {
			return errors.New("passkey: configured store does not support passkeys")
		}
		if o.Registration.AllowWithoutSession {
			if _, ok := store.(RegistrationStore); !ok {
				return errors.New("passkey: pre-authentication registration requires a transactional registration store")
			}
		}
		return backend.CheckPasskeySchema(context.Background())
	},
		ValidateVerificationStore: func(store authn.Store, hooks authn.VerificationHookSet) error {
			if _, ok := store.(ChallengeFinder); hooks.Delete && !ok {
				return errors.New("auth: verification delete hooks with the passkey plugin require a store implementing FindPasskeyChallenge")
			}
			return nil
		},
		Endpoints: []authn.Endpoint{
			{Method: "GET", Path: "/passkey/generate-register-options", OpenAPI: enrollmentMetadata, Handler: s.beginRegistration},
			{Method: "POST", Path: "/passkey/verify-registration", OpenAPI: enrollmentMetadata, Handler: s.finishRegistration},
			{Method: "GET", Path: "/passkey/generate-authenticate-options", Handler: s.beginLogin},
			{Method: "POST", Path: "/passkey/verify-authentication", Handler: s.finishLogin},
			{Method: "GET", Path: "/passkey/list-user-passkeys", Handler: s.list},
			{Method: "POST", Path: "/passkey/update-passkey", Handler: s.rename},
			{Method: "POST", Path: "/passkey/delete-passkey", Handler: s.remove},
		}}, nil
}
func session(c authn.EndpointContext) (*authn.SessionResult, error) {
	u, err := c.Auth.GetSession(c.Request.Context(), c.Request.Header)
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, ErrSession
	}
	return u, u.Session.RequireOwner()
}
func challengeCookie(c authn.EndpointContext, token string, age int) *http.Cookie {
	return c.Auth.SignedCookie("passkey_challenge", token, age)
}
func (s service) remember(c authn.EndpointContext, state ceremony) error {
	now := time.Now().UTC().Truncate(time.Millisecond)
	nonce := "passkey:" + state.Kind + ":" + rand.Text()
	sum := sha256.Sum256([]byte(nonce))
	key := hex.EncodeToString(sum[:])
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	expires := now.Add(s.ttl)
	declined, err := c.CreateVerification(challengeRecord(ChallengeRecordID(key), state.Kind, state, expires), func(ctx context.Context) error {
		return c.Store().(Store).SavePasskeyChallenge(ctx, key, data, now, expires)
	})
	if err != nil {
		return err
	}
	if declined {
		// A declined challenge is never stored: its options redeem nothing,
		// and no earlier ceremony's cookie answers them.
		expired := challengeCookie(c, "", -1)
		expired.Value = ""
		c.ResponseHeader.Add("Set-Cookie", expired.String())
		return nil
	}
	c.ResponseHeader.Add("Set-Cookie", challengeCookie(c, nonce, int(s.ttl/time.Second)).String())
	return nil
}
func (s service) take(c authn.EndpointContext, kind string) (ceremony, error) {
	var state ceremony
	template := challengeCookie(c, "", -1)
	cookie, err := c.Request.Cookie(template.Name)
	if err != nil {
		return state, ErrChallenge
	}
	nonce := c.Auth.VerifySignedSessionToken(cookie.Value)
	if !strings.HasPrefix(nonce, "passkey:"+kind+":") {
		return state, ErrChallenge
	}
	sum := sha256.Sum256([]byte(nonce))
	key := hex.EncodeToString(sum[:])
	store := c.Store().(Store)
	var data []byte
	// The challenge is spent, with its delete hooks, before the credential
	// is checked.
	refused, err := c.SpendVerification(func(ctx context.Context) (authn.VerificationRecord, error) {
		finder, ok := store.(ChallengeFinder)
		if !ok {
			return authn.VerificationRecord{}, authn.ErrNotFound
		}
		id, body, expires, err := finder.FindPasskeyChallenge(ctx, key, time.Now().UTC())
		if err != nil {
			return authn.VerificationRecord{}, err
		}
		var saved ceremony
		_ = json.Unmarshal(body, &saved) // a malformed ceremony names no owner; it is refused once spent
		return challengeRecord(id, kind, saved, expires), nil
	}, func(ctx context.Context) error {
		body, err := store.TakePasskeyChallenge(ctx, key, time.Now().UTC())
		if errors.Is(err, ErrChallenge) {
			return authn.ErrNotFound
		}
		if err == nil {
			data = body // only a committed spend clears the cookie
		}
		return err
	})
	if data != nil {
		// A spent challenge's cookie is cleared, even when an after hook failed.
		template.Value = ""
		c.ResponseHeader.Add("Set-Cookie", template.String())
	}
	if err != nil {
		return state, err
	}
	if refused {
		return state, ErrChallenge
	}
	if json.Unmarshal(data, &state) != nil || state.Kind != kind || state.Data.RelyingPartyID != s.web.Config.RPID {
		return state, ErrChallenge
	}
	return state, nil
}
func (r Record) credential() (wa.Credential, error) {
	var out wa.Credential
	id, err := base64.RawURLEncoding.DecodeString(r.CredentialID)
	if err != nil {
		return out, err
	}
	key, err := base64.StdEncoding.DecodeString(r.PublicKey)
	if err != nil {
		return out, err
	}
	out.ID, out.PublicKey = id, key
	out.Authenticator.SignCount = r.Counter
	if r.AAGUID != nil && *r.AAGUID != "" {
		id, err := uuid.Parse(*r.AAGUID)
		if err != nil {
			return out, err
		}
		out.Authenticator.AAGUID = id[:]
	}
	if r.Transports != nil && *r.Transports != "" {
		for t := range strings.SplitSeq(*r.Transports, ",") {
			out.Transport = append(out.Transport, protocol.AuthenticatorTransport(t))
		}
	}
	out.Flags.BackupEligible = r.DeviceType == "multiDevice"
	out.Flags.BackupState = r.BackedUp
	return out, nil
}
func (s service) beginRegistration(c authn.EndpointContext) (any, error) {
	user, state, err := s.registrationActor(c)
	if err != nil {
		return nil, err
	}
	records, err := c.Store().(Store).ListPasskeys(c.Request.Context(), user.ID)
	if err != nil {
		return nil, err
	}
	for _, r := range records {
		cred, err := r.credential()
		if err != nil {
			return nil, err
		}
		user.credentials = append(user.credentials, cred)
	}
	opts := []wa.RegistrationOption{wa.WithExclusions(user.credentials.CredentialDescriptors())}
	q := c.Request.URL.Query()
	if name := q.Get("name"); name != "" {
		user.Name = name
	}
	if attachment := q.Get("authenticatorAttachment"); attachment != "" {
		if attachment != "platform" && attachment != "cross-platform" {
			return nil, ErrRegistration
		}
		cfg := s.web.Config.AuthenticatorSelection
		cfg.AuthenticatorAttachment = protocol.AuthenticatorAttachment(attachment)
		opts = append(opts, wa.WithAuthenticatorSelection(cfg))
	}
	creation, data, err := s.web.BeginRegistration(user, opts...)
	if err != nil {
		return nil, err
	}
	state.Data = *data
	err = s.remember(c, state)
	return creation.Response, err
}
func responseBytes(c authn.EndpointContext) ([]byte, error) {
	resp, ok := c.Body["response"].(map[string]any)
	if !ok {
		return nil, errors.New("invalid credential response")
	}
	return json.Marshal(resp)
}
func (s service) finishRegistration(c authn.EndpointContext) (any, error) {
	ss, err := s.registrationSession(c)
	if err != nil {
		return nil, err
	}
	state, err := s.take(c, "registration")
	if err != nil {
		return nil, err
	}
	if !state.PreAuth && (ss == nil || state.SessionID != ss.Session.ID || state.UserID != ss.User.ID) {
		return nil, ErrSession
	}
	if state.PreAuth && (!s.registration.AllowWithoutSession || ss != nil && state.UserID != ss.User.ID) {
		return nil, errOwner
	}
	createSession := false
	if v, ok := c.Body["createSession"]; ok {
		flag, valid := v.(bool)
		if !valid {
			return nil, ErrRegistration
		}
		createSession = flag
	}
	data, err := responseBytes(c)
	if err != nil {
		return nil, ErrRegistration
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(data)
	if err != nil {
		return nil, ErrRegistration
	}
	who := s.actor(authn.User{ID: state.UserID, Name: state.Name})
	if state.PreAuth {
		who.handle = state.Data.UserID
	}
	cred, err := s.web.CreateCredential(who, state.Data, parsed)
	if err != nil {
		return nil, ErrRegistration
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	sum := sha256.Sum256(cred.ID)
	r := Record{ID: hex.EncodeToString(sum[:16]), UserID: state.UserID, CredentialID: base64.RawURLEncoding.EncodeToString(cred.ID), PublicKey: base64.StdEncoding.EncodeToString(cred.PublicKey), Counter: cred.Authenticator.SignCount, DeviceType: "singleDevice", BackedUp: cred.Flags.BackupState, CreatedAt: &now}
	if cred.Flags.BackupEligible {
		r.DeviceType = "multiDevice"
	}
	if name, ok := c.Body["name"].(string); ok && strings.TrimSpace(name) != "" {
		name = strings.TrimSpace(name)
		r.Name = &name
	}
	var names []string
	for _, t := range cred.Transport {
		names = append(names, string(t))
	}
	trans := strings.Join(names, ",")
	r.Transports = &trans
	if id, err := uuid.FromBytes(cred.Authenticator.AAGUID); err == nil {
		aaguid := id.String()
		r.AAGUID = &aaguid
	}
	return s.persistRegistration(c, state, ss, cred, data, r, createSession, now)
}
func (s service) beginLogin(c authn.EndpointContext) (any, error) {
	ss, err := c.Auth.GetSession(c.Request.Context(), c.Request.Header)
	if err != nil {
		return nil, err
	}
	opts := []wa.LoginOption{wa.WithUserVerification(s.web.Config.AuthenticatorSelection.UserVerification)}
	state := ceremony{Kind: "authentication"}
	if ss != nil {
		state.UserID = ss.User.ID
		keys, err := c.Store().(Store).ListPasskeys(c.Request.Context(), ss.User.ID)
		if err != nil {
			return nil, err
		}
		var credentials wa.Credentials
		for _, r := range keys {
			cred, err := r.credential()
			if err != nil {
				return nil, err
			}
			credentials = append(credentials, cred)
		}
		if len(credentials) > 0 {
			opts = append(opts, wa.WithAllowedCredentials(credentials.CredentialDescriptors()))
		}
	}
	assertion, data, err := s.web.BeginDiscoverableLogin(opts...)
	if err != nil {
		return nil, err
	}
	state.Data = *data
	err = s.remember(c, state)
	return assertion.Response, err
}
func (s service) finishLogin(c authn.EndpointContext) (any, error) {
	state, err := s.take(c, "authentication")
	if err != nil {
		return nil, err
	}
	raw, err := responseBytes(c)
	if err != nil {
		return nil, ErrAuthentication
	}
	response, err := protocol.ParseCredentialRequestResponseBytes(raw)
	if err != nil {
		return nil, ErrAuthentication
	}
	store := c.Store().(Store)
	record, err := store.LookupPasskey(c.Request.Context(), base64.RawURLEncoding.EncodeToString(response.RawID))
	if err != nil {
		return nil, err
	}
	if state.UserID != "" && state.UserID != record.UserID {
		return nil, ErrAuthentication
	}
	user := s.actor(authn.User{ID: record.UserID})
	if h := recordHandle(record.ID); h != nil {
		user.handle = h
	}
	stored, err := record.credential()
	if err != nil {
		return nil, err
	}
	user.credentials = wa.Credentials{stored}
	if len(state.Data.AllowedCredentialIDs) > 1 {
		rows, err := store.ListPasskeys(c.Request.Context(), record.UserID)
		if err != nil {
			return nil, err
		}
		user.credentials = nil
		for _, row := range rows {
			cred, err := row.credential()
			if err != nil {
				return nil, err
			}
			user.credentials = append(user.credentials, cred)
		}
	}
	_, verified, err := s.web.ValidatePasskeyLogin(func(id, handle []byte) (wa.User, error) {
		if !bytes.Equal(id, stored.ID) || !bytes.Equal(handle, user.handle) {
			return nil, ErrAuthentication
		}
		return user, nil
	}, state.Data, response)
	if err != nil || verified.Authenticator.CloneWarning {
		return nil, ErrAuthentication
	}
	return c.IssueSession(user.ID, func(ctx context.Context, ss authn.StoredSession) (authn.User, error) {
		return store.FinishPasskeyLogin(ctx, record, verified.Authenticator.SignCount, verified.Flags.BackupState, ss)
	})
}
func (s service) list(c authn.EndpointContext) (any, error) {
	ss, err := session(c)
	if err != nil {
		return nil, err
	}
	return c.Store().(Store).ListPasskeys(c.Request.Context(), ss.User.ID)
}
func (s service) rename(c authn.EndpointContext) (any, error) { return s.manage(c, true) }
func (s service) remove(c authn.EndpointContext) (any, error) { return s.manage(c, false) }
func (s service) manage(c authn.EndpointContext, rename bool) (any, error) {
	ss, err := session(c)
	if err != nil {
		return nil, err
	}
	id, ok := c.Body["id"].(string)
	if !ok || id == "" {
		return nil, ErrMissing
	}
	var name *string
	if rename {
		value, ok := c.Body["name"].(string)
		value = strings.TrimSpace(value)
		if !ok || value == "" {
			return nil, problem(400, "VALIDATION_ERROR", "Invalid passkey name")
		}
		name = &value
	}
	r, err := c.Store().(Store).ManagePasskey(c.Request.Context(), ss.User.ID, ss.Session.Token, id, name, time.Now())
	if err != nil {
		return nil, err
	}
	if rename {
		return map[string]Record{"passkey": r}, nil
	}
	return map[string]bool{"status": true}, nil
}
