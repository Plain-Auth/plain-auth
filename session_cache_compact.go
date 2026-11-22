package stonewrit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Stonewrit/stonewrit-auth/internal/jsjson"
)

// SessionCookieCacheStrategy selects the wire format of a browser session snapshot.
type SessionCookieCacheStrategy string

const (
	SessionCacheCompact SessionCookieCacheStrategy = "compact"
	SessionCacheJWT     SessionCookieCacheStrategy = "jwt"
	SessionCacheJWE     SessionCookieCacheStrategy = "jwe"
)

// SessionCookieCacheOptions configures authenticated snapshots for browser session views.
// GetSession and authenticated operations continue to read the backing store.
type SessionCookieCacheOptions struct {
	// Strategy defaults to compact. JWT signs the snapshot with HS256.
	// JWE encrypts it using a symmetric key derived for this cookie.
	Strategy SessionCookieCacheStrategy
	// MaxAge defaults to five minutes for persistent logins. A browser-session
	// cookie holds a one-minute compact snapshot or a five-minute JWT or JWE.
	MaxAge time.Duration
	// Version defaults to "1". Change it across replicas to invalidate older snapshots.
	Version string
	// VersionFor derives the version from the session and user being issued or read.
	// It may perform I/O with ctx and must be safe for concurrent requests.
	// Choose either Version or VersionFor.
	VersionFor func(ctx context.Context, session Session, user User) (string, error)
}

func prepareSessionCookieCache(o *Options) error {
	if o.SessionCookieCache == nil {
		return nil
	}
	cache := *o.SessionCookieCache
	switch cache.Strategy {
	case "":
		cache.Strategy = SessionCacheCompact
	case SessionCacheCompact, SessionCacheJWT, SessionCacheJWE:
	default:
		return errors.New("auth: invalid session cookie cache strategy")
	}
	if cache.MaxAge == 0 {
		cache.MaxAge = 5 * time.Minute
	}
	if cache.MaxAge < time.Second || cache.MaxAge%time.Second != 0 {
		return errors.New("auth: session cookie cache max age must be a positive whole number of seconds")
	}
	if cache.Version != "" && cache.VersionFor != nil {
		return errors.New("auth: choose either a fixed session cache version or VersionFor")
	}
	if cache.Version == "" && cache.VersionFor == nil {
		cache.Version = "1"
	}
	o.SessionCookieCache = &cache
	return nil
}

type sessionCachePayload struct {
	Session   Session `json:"session"`
	User      User    `json:"user"`
	UpdatedAt int64   `json:"updatedAt"`
	Version   string  `json:"version"`
}

// JavaScript revives timestamp strings into Date objects before verifying the
// signature. Its UTC millisecond spelling must be stable even at .000 or .120.
func (p sessionCachePayload) marshal(claims *sessionJOSEClaims) ([]byte, error) {
	const millisecondUTC = "2006-01-02T15:04:05.000Z"
	type sessionWire struct {
		Session
		CreatedAt string `json:"createdAt"`
		UpdatedAt string `json:"updatedAt"`
		ExpiresAt string `json:"expiresAt"`
	}
	type userWire struct {
		User
		CreatedAt string `json:"createdAt"`
		UpdatedAt string `json:"updatedAt"`
	}
	return jsjson.Marshal(struct {
		*sessionJOSEClaims
		Session   sessionWire `json:"session"`
		User      userWire    `json:"user"`
		UpdatedAt int64       `json:"updatedAt"`
		Version   string      `json:"version"`
	}{
		sessionJOSEClaims: claims,
		Session: sessionWire{
			Session:   p.Session,
			CreatedAt: p.Session.CreatedAt.UTC().Format(millisecondUTC),
			UpdatedAt: p.Session.UpdatedAt.UTC().Format(millisecondUTC),
			ExpiresAt: p.Session.ExpiresAt.UTC().Format(millisecondUTC),
		},
		User: userWire{
			User:      p.User,
			CreatedAt: p.User.CreatedAt.UTC().Format(millisecondUTC),
			UpdatedAt: p.User.UpdatedAt.UTC().Format(millisecondUTC),
		},
		UpdatedAt: p.UpdatedAt,
		Version:   p.Version,
	})
}

type compactSessionEnvelope struct {
	Payload   json.RawMessage `json:"session"`
	ExpiresAt int64           `json:"expiresAt"`
	Signature string          `json:"signature"`
}

const maxSessionChunkSize = 4050
const maxSessionChunks = 100

// SessionCacheStore opts a store into browser snapshots. Return false when
// changes in storage require live validation even for a public session view.
type SessionCacheStore interface {
	AllowSessionCookieCache(context.Context) (bool, error)
}

func (a *Auth) canCacheSessionView(r *http.Request) bool {
	if a.opts.SessionCookieCache == nil || a.admin != nil || a.factorStore != nil ||
		a.phoneNumber != nil || a.username != nil || a.anonymous != nil ||
		a.serviceJWT != nil && !a.serviceJWT.DisableHeader || r.Header.Get("Authorization") != "" {
		return false
	}
	for _, p := range a.opts.Plugins {
		if p.OnReadSession != nil {
			return false
		}
	}
	store, ok := a.opts.Store.(SessionCacheStore)
	if !ok {
		return false
	}
	allow, err := store.AllowSessionCookieCache(r.Context())
	return allow && err == nil
}

// Preserve the issuer's JSON field order when computing the compact wire signature.
func (e compactSessionEnvelope) signingInput() []byte {
	p := e.Payload
	if len(p) < 3 || p[0] != '{' || p[len(p)-1] != '}' {
		return nil
	}
	output := make([]byte, 0, len(p)+32)
	output = append(output, p[:len(p)-1]...)
	output = append(output, `,"expiresAt":`...)
	output = strconv.AppendInt(output, e.ExpiresAt, 10)
	return append(output, '}')
}

func sessionCacheMAC(key string, input []byte) []byte {
	h := hmac.New(sha256.New, []byte(key))
	h.Write(input)
	return h.Sum(nil)
}

func (a *Auth) cachedSessionView(r *http.Request, token string) (*SessionResult, error) {
	// A bearer or plugin-derived credential alone cannot activate a browser cache.
	cookies := r.CookiesNamed(a.cookieName())
	if len(cookies) != 1 || a.VerifySignedSessionToken(cookies[0].Value) != token {
		return nil, nil
	}
	encoded := readSessionCacheCookie(r, a.prefixedCookieName("session_data"))
	if encoded == "" {
		return nil, nil
	}
	now := a.now()
	var raw []byte
	if a.opts.SessionCookieCache.Strategy == SessionCacheCompact {
		raw = a.readCompactSnapshot(encoded, now)
	} else {
		raw = a.readJOSESnapshot(encoded, now)
	}
	if len(raw) == 0 {
		return nil, nil
	}
	// Track presence separately for required zero-valued profile fields.
	var payload struct {
		Session Session `json:"session"`
		User    struct {
			User
			Name     *string `json:"name"`
			Verified *bool   `json:"emailVerified"`
		} `json:"user"`
		UpdatedAt int64  `json:"updatedAt"`
		Version   string `json:"version"`
	}
	if json.Unmarshal(raw, &payload) != nil || payload.User.Name == nil || payload.User.Verified == nil {
		return nil, nil
	}
	if payload.Version == "" {
		payload.Version = "1"
	}
	user := payload.User.User
	user.Name, user.EmailVerified = *payload.User.Name, *payload.User.Verified
	ss := payload.Session
	if payload.UpdatedAt <= 0 || ss.ID == "" || ss.Token != token ||
		ss.UserID == "" || ss.UserID != user.ID || !ss.ExpiresAt.After(now) ||
		ss.CreatedAt.IsZero() || ss.UpdatedAt.IsZero() || user.Email == "" || user.CreatedAt.IsZero() || user.UpdatedAt.IsZero() ||
		!ordinaryCacheFields(ss, user) {
		return nil, nil
	}
	result := &SessionResult{Session: ss, User: user}
	expected, err := a.opts.SessionCookieCache.versionFor(r.Context(), *result)
	if err != nil {
		return nil, err
	}
	if expected != payload.Version {
		return nil, errSessionCacheVersionChanged
	}
	return result, nil
}

func (a *Auth) readCompactSnapshot(encoded string, now time.Time) []byte {
	wire, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil
	}
	var envelope compactSessionEnvelope
	if json.Unmarshal(wire, &envelope) != nil || envelope.ExpiresAt <= now.UnixMilli() {
		return nil
	}
	input := envelope.signingInput()
	signature, err := base64.RawURLEncoding.DecodeString(envelope.Signature)
	if err != nil || len(input) == 0 || len(signature) != sha256.Size {
		return nil
	}
	match := hmac.Equal(sessionCacheMAC(a.opts.Secret, input), signature)
	for i := 1; !match && i < len(a.opts.Secrets); i++ {
		match = hmac.Equal(sessionCacheMAC(a.opts.Secrets[i].Value, input), signature)
	}
	if !match {
		return nil
	}
	return envelope.Payload
}

func readSessionCacheCookie(r *http.Request, name string) string {
	var chunks [maxSessionChunks]string
	last := -1
	var base string
	seenBase := false
	for _, c := range r.Cookies() {
		if c.Name == name {
			if seenBase || last >= 0 || len(c.Value) > maxSessionChunkSize {
				return ""
			}
			seenBase, base = true, c.Value
			continue
		}
		suffix, ok := strings.CutPrefix(c.Name, name+".")
		if !ok {
			continue
		}
		index, err := strconv.ParseUint(suffix, 10, 53)
		if err != nil || strconv.FormatUint(index, 10) != suffix {
			continue
		}
		if seenBase || index >= maxSessionChunks || c.Value == "" || len(c.Value) > maxSessionChunkSize || chunks[index] != "" {
			return ""
		}
		chunks[index] = c.Value
		last = max(last, int(index))
	}
	if seenBase {
		return base
	}
	if last < 0 {
		return ""
	}
	for _, chunk := range chunks[:last+1] {
		if chunk == "" {
			return ""
		}
	}
	return strings.Join(chunks[:last+1], "")
}

func (a *Auth) cacheIssuedSession(h http.Header, r *http.Request, c *http.Cookie) error {
	if !a.canCacheSessionView(r) {
		a.expireStoredSessionData(h, r, false)
		return nil
	}
	token := a.VerifySignedSessionToken(c.Value)
	if token == "" {
		return nil
	}
	ctx := r.Context()
	row, user, err := a.opts.Store.Session(ctx, token)
	if err != nil || row.Token != token || row.UserID != user.ID || !row.ExpiresAt.After(a.now()) {
		a.expireStoredSessionData(h, r, false)
		return nil
	}
	return a.writeCachedSessionView(h, r, SessionResult{Session: row.Session, User: user}, c.MaxAge > 0)
}

func (a *Auth) writeCachedSessionView(h http.Header, r *http.Request, data SessionResult, persistent bool) error {
	cookies, err := a.prepareSessionCache(r.Context(), data, persistent)
	if err != nil {
		return err
	}
	a.setSessionCacheCookies(h, r, cookies)
	return nil
}

func (a *Auth) setSessionCacheCookies(h http.Header, r *http.Request, cookies []*http.Cookie) {
	replacements := make(map[string]bool, len(cookies))
	for _, c := range cookies {
		replacements[c.Name] = true
	}
	a.reconcileSessionDataCookies(h, r, false, replacements)
	for _, c := range cookies {
		h.Add("Set-Cookie", c.String())
	}
}

func (a *Auth) prepareSessionCache(ctx context.Context, data SessionResult, persistent bool) ([]*http.Cookie, error) {
	if data.Session.ID == "" || data.Session.Token == "" || data.User.ID == "" || data.Session.UserID != data.User.ID || !ordinaryCacheFields(data.Session, data.User) {
		return nil, nil
	}
	if prepared, ok := ctx.Value(signupCacheKey{}).(signupCacheVersion); ok && prepared.input.session.Token == data.Session.Token {
		// A store can transform a profile or another writer can update it after
		// registration. Defer caching to the next live read in that case.
		if prepared.input != signupVersionInput(data) {
			return nil, nil
		}
		return a.encodeSessionCache(data, persistent, prepared.version), nil
	}
	version, err := a.opts.SessionCookieCache.versionFor(ctx, data)
	if err != nil {
		return nil, err
	}
	return a.encodeSessionCache(data, persistent, version), nil
}

func (a *Auth) encodeSessionCache(data SessionResult, persistent bool, version string) []*http.Cookie {
	cache := a.opts.SessionCookieCache
	now := a.now()
	ttl := cache.MaxAge
	maxAge := int(ttl / time.Second)
	if !persistent {
		ttl = 5 * time.Minute
		if cache.Strategy == SessionCacheCompact {
			ttl = time.Minute
		}
		maxAge = 0
	}
	payload := sessionCachePayload{Session: data.Session, User: data.User, UpdatedAt: now.UnixMilli(), Version: version}
	var value string
	var err error
	if cache.Strategy == SessionCacheCompact {
		value, err = a.writeCompactSnapshot(payload, now.Add(ttl))
	} else {
		value, err = a.writeJOSESnapshot(payload, now, ttl)
	}
	if err != nil {
		return nil
	}
	cookie := a.browserCookie("session_data", "", maxAge)
	base := cookie.Name
	cookie.Name = base + ".99"
	chunkSize := maxSessionChunkSize - len(cookie.String())
	if chunkSize <= 0 || len(value) > maxSessionChunks*chunkSize {
		return nil
	}
	if len(value) <= chunkSize {
		cookie.Name, cookie.Value = base, value
		return []*http.Cookie{cookie}
	}
	var cookies []*http.Cookie
	for i := 0; len(value) > 0; i++ {
		end := min(len(value), chunkSize)
		part := *cookie
		part.Name, part.Value = base+"."+strconv.Itoa(i), value[:end]
		cookies = append(cookies, &part)
		value = value[end:]
	}
	return cookies
}

func (a *Auth) writeCompactSnapshot(payload sessionCachePayload, expiry time.Time) (string, error) {
	raw, err := payload.marshal(nil)
	if err != nil {
		return "", err
	}
	envelope := compactSessionEnvelope{Payload: raw, ExpiresAt: expiry.UnixMilli()}
	envelope.Signature = base64.RawURLEncoding.EncodeToString(sessionCacheMAC(a.opts.Secret, envelope.signingInput()))
	wire, err := jsjson.Marshal(envelope)
	if err != nil {
		return "", err
	}
	if base64.RawURLEncoding.EncodedLen(len(wire)) > maxSessionChunkSize*maxSessionChunks {
		return "", errors.New("auth: browser session snapshot exceeds cookie capacity")
	}
	return base64.RawURLEncoding.EncodeToString(wire), nil
}

// Only release core fields. An issuer sharing the signing keys may have
// installed extensions that require live projection on a different node.
func ordinaryCacheFields(s Session, u User) bool {
	return s.ImpersonatedBy == nil && s.CredentialType == "" &&
		s.ActiveOrganizationID == nil && s.ActiveTeamID == nil &&
		u.AdminUserFields == nil && u.TwoFactorEnabled == nil && u.PhoneNumberFields == nil &&
		u.UsernameFields == nil && u.IsAnonymous == nil && u.LastLoginMethod == nil
}
