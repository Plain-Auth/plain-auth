package scim

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf16"
)

// ManagedOptions enables the server-only directory credential catalog.
type ManagedOptions struct {
	CredentialHashSecret  string
	MaxActiveCredentials  int
	LastUsedWriteInterval *time.Duration
}
type ManagedConnection struct {
	CreationRequestID     string     `json:"creationRequestId"`
	ConnectionID          string     `json:"connectionId"`
	ProvisioningDomainID  string     `json:"provisioningDomainId"`
	Status                string     `json:"status"`
	CreatedAt             time.Time  `json:"createdAt"`
	CreatedBy             string     `json:"createdBy"`
	DecommissionStartedAt *time.Time `json:"decommissionStartedAt"`
	DecommissionStartedBy *string    `json:"decommissionStartedBy"`
	DecommissionedAt      *time.Time `json:"decommissionedAt"`
	DecommissionedBy      *string    `json:"decommissionedBy"`
}
type ManagedCredential struct {
	CredentialID string     `json:"credentialId"`
	Status       string     `json:"status"`
	Scopes       []string   `json:"scopes"`
	ExpiresAt    time.Time  `json:"expiresAt"`
	CreatedAt    time.Time  `json:"createdAt"`
	CreatedBy    string     `json:"createdBy"`
	LastUsedAt   *time.Time `json:"lastUsedAt"`
	RevokedAt    *time.Time `json:"revokedAt"`
	RevokedBy    *string    `json:"revokedBy"`
}
type ManagedState struct {
	Connection  ManagedConnection   `json:"connection"`
	Credentials []ManagedCredential `json:"credentials"`
}
type IssuedCredential struct {
	Connection ManagedConnection `json:"connection"`
	Credential ManagedCredential `json:"credential"`
	Token      string            `json:"token"`
}
type ManagedEvent struct {
	Sequence     int       `json:"sequence"`
	Type         string    `json:"type"`
	ActorID      string    `json:"actorId"`
	CredentialID *string   `json:"credentialId"`
	CreatedAt    time.Time `json:"createdAt"`
}
type EventQuery struct {
	Limit, Offset int
	SortDirection string
}
type ManagedEvents struct {
	Events []ManagedEvent `json:"events"`
	Total  int            `json:"total"`
	Limit  int            `json:"limit"`
	Offset int            `json:"offset"`
}
type CredentialPolicy struct {
	Scopes    []string
	ExpiresAt time.Time
}

// ManagedIssue contains only the digest to persist and the ownership policy.
// A nonempty CreationRequestID creates a new connection and its initial credential.
type ManagedIssue struct {
	Directory
	CreationRequestID, CredentialID, ActorID, TokenDigest string
	CredentialPolicy
	MaxActive int
	CreatedAt time.Time
}
type ManagedStore interface {
	SCIMIssueCredential(context.Context, ManagedIssue) (ManagedConnection, ManagedCredential, error)
	SCIMManagedConnections(context.Context, string) ([]ManagedConnection, error)
	SCIMManagedState(context.Context, Directory) (ManagedState, error)
	SCIMRevokeCredential(context.Context, Directory, string, string) (ManagedState, error)
	SCIMManagedEvents(context.Context, Directory, EventQuery) (ManagedEvents, error)
	SCIMVerifyCredential(context.Context, string, string, time.Duration) (*Principal, error)
}
type Catalog struct {
	store    ManagedStore
	secret   []byte
	limit    int
	interval time.Duration
}

var ErrManagedNotFound = &Error{Status: 404, Detail: "Managed SCIM connection or credential not found"}
var ErrManagedConflict = &Error{Status: 409, Detail: "Managed SCIM connection or credential changed or reached its limit"}
var ErrCreationRequestConflict = &Error{Status: 409, Detail: "The managed SCIM creation request ID was already used"}
var managedTokenPattern = regexp.MustCompile(`^(ba_scim_credential_[a-zA-Z0-9_-]+)\.[a-zA-Z0-9_-]+$`)

func newCatalog(s Store, o *ManagedOptions) (*Catalog, error) {
	ms, ok := s.(ManagedStore)
	if !ok {
		return nil, errors.New("scim: managed credential store is required")
	}
	// Count UTF-16 code units, as another runtime counts a string's length.
	if len(utf16.Encode([]rune(o.CredentialHashSecret))) < 32 {
		return nil, errors.New("scim: managed credential digest secret needs at least 32 characters")
	}
	limit := o.MaxActiveCredentials
	if limit == 0 {
		limit = 5
	}
	if limit < 1 || limit > 100 {
		return nil, errors.New("scim: managed credential limit must be 1 through 100")
	}
	interval := 5 * time.Minute
	if o.LastUsedWriteInterval != nil {
		interval = *o.LastUsedWriteInterval
		if interval < 0 {
			return nil, errors.New("scim: last-used interval must be nonnegative")
		}
	}
	return &Catalog{store: ms, secret: []byte(o.CredentialHashSecret), limit: limit, interval: interval}, nil
}

// Catalog returns the server-only administrative capability when configured.
// Hosts authorize their own administrators before invoking any catalog method.
func (h *Handler) Catalog() *Catalog { return h.catalog }
func managedRandom(bytes int) string {
	b := make([]byte, bytes)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
func (c *Catalog) digest(token string) string {
	h := hmac.New(sha256.New, c.secret)
	_, _ = h.Write([]byte(token))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}
func (c *Catalog) verify(ctx context.Context, token string) (*Principal, error) {
	m := managedTokenPattern.FindStringSubmatch(token)
	if m == nil {
		return nil, nil
	}
	return c.store.SCIMVerifyCredential(ctx, m[1], c.digest(token), c.interval)
}

// managedDirectory reports a trimmed managed connection in a domain.
func managedDirectory(d Directory) bool {
	_, domain := apiText(d.ProvisioningDomainID, 1)
	_, id := apiText(d.ID, 1)
	return domain && id && strings.HasPrefix(d.ID, managedConnectionPrefix)
}
func (c *Catalog) Create(ctx context.Context, domain, requestID, actor string, policy CredentialPolicy) (IssuedCredential, error) {
	domain, okDomain := apiText(domain, 1)
	requestID, okRequest := apiText(requestID, 16)
	if !okDomain || !okRequest {
		return IssuedCredential{}, invalid("invalidValue", "Supply a domain and a creation request ID of 16 to 255 characters")
	}
	d := Directory{ID: managedConnectionPrefix + managedRandom(24), ProvisioningDomainID: domain}
	return c.issue(ctx, d, requestID, actor, policy)
}
func (c *Catalog) Rotate(ctx context.Context, d Directory, actor string, policy CredentialPolicy) (IssuedCredential, error) {
	if d = trimmedDirectory(d); !managedDirectory(d) {
		return IssuedCredential{}, ErrManagedNotFound
	}
	return c.issue(ctx, d, "", actor, policy)
}
func (c *Catalog) issue(ctx context.Context, d Directory, requestID, actor string, p CredentialPolicy) (IssuedCredential, error) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	p.ExpiresAt = p.ExpiresAt.UTC().Truncate(time.Millisecond)
	actor, okActor := apiText(actor, 1)
	if !validScopes(p.Scopes) || !okActor || !p.ExpiresAt.After(now) {
		return IssuedCredential{}, invalid("invalidValue", "A valid actor, unique scopes and future expiry are required")
	}
	id := managedCredentialPrefix + managedRandom(24)
	token := id + "." + managedRandom(36)
	p.Scopes = slices.Clone(p.Scopes)
	i := ManagedIssue{Directory: d, CreationRequestID: requestID, ActorID: actor, CredentialID: id, TokenDigest: c.digest(token), CredentialPolicy: p, MaxActive: c.limit, CreatedAt: now}
	connection, credential, e := c.store.SCIMIssueCredential(ctx, i)
	if e != nil {
		return IssuedCredential{}, e
	}
	return IssuedCredential{Connection: connection, Credential: credential, Token: token}, nil
}
func (c *Catalog) List(ctx context.Context, domain string) ([]ManagedConnection, error) {
	domain, ok := apiText(domain, 1)
	if !ok {
		return nil, invalid("invalidValue", "A valid provisioning domain is required")
	}
	return c.store.SCIMManagedConnections(ctx, domain)
}
func (c *Catalog) Get(ctx context.Context, d Directory) (ManagedState, error) {
	if d = trimmedDirectory(d); !managedDirectory(d) {
		return ManagedState{}, ErrManagedNotFound
	}
	return c.store.SCIMManagedState(ctx, d)
}
func (c *Catalog) Revoke(ctx context.Context, d Directory, id, actor string) (ManagedState, error) {
	d = trimmedDirectory(d)
	id, okID := apiText(id, 1)
	if !managedDirectory(d) || !okID || !strings.HasPrefix(id, managedCredentialPrefix) {
		return ManagedState{}, ErrManagedNotFound
	}
	actor, okActor := apiText(actor, 1)
	if !okActor {
		return ManagedState{}, invalid("invalidValue", "A valid actor is required")
	}
	return c.store.SCIMRevokeCredential(ctx, d, id, actor)
}
func (c *Catalog) Events(ctx context.Context, d Directory, q EventQuery) (ManagedEvents, error) {
	if d = trimmedDirectory(d); !managedDirectory(d) {
		return ManagedEvents{}, ErrManagedNotFound
	}
	if q.Limit == 0 {
		q.Limit = 100
	}
	if q.Limit < 1 || q.Limit > 100 || q.Offset < 0 || q.SortDirection != "" && q.SortDirection != "asc" && q.SortDirection != "desc" {
		return ManagedEvents{}, invalid("invalidValue", "Invalid audit event page")
	}
	return c.store.SCIMManagedEvents(ctx, d, q)
}
