// Package scim provisions directory-owned Users and Groups through the SCIM 2.0 protocol.
package scim

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	auth "github.com/Plain-Org/plain-auth"
)

const (
	MediaType   = "application/scim+json"
	UserSchema  = "urn:ietf:params:scim:schemas:core:2.0:User"
	PatchSchema = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	listSchema  = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	errorSchema = "urn:ietf:params:scim:api:messages:2.0:Error"
	UsersRead   = "scim.users.read"
	UsersWrite  = "scim.users.write"
)

type Directory struct{ ID, ProvisioningDomainID string }
type Credential struct {
	ID, Token string
	Scopes    []string
	ExpiresAt time.Time
}
type Connection struct {
	Directory
	Credentials []Credential
}
type Options struct {
	Managed           *ManagedOptions
	VerifyBearerToken VerifyBearerToken
	// AcceptLegacyEntraGroupSchema accepts one classic Entra marker only on Group creation.
	AcceptLegacyEntraGroupSchema bool
	Store                        Store
	Connections                  []Connection
}

// Profile contains the mutable attributes of one normalized directory user.
// Attributes holds canonical schemas, name, emails and optional profile fields.
type Profile struct {
	UserName, DisplayName, ExternalID, PrimaryEmail string
	Active                                          bool
	Attributes                                      map[string]any
}
type Record struct {
	Profile
	ID                   string
	CreatedAt, UpdatedAt time.Time
}
type Filter struct{ Attribute, Value string }
type Query struct {
	Filters       []Filter
	Offset, Count int
}
type Store interface {
	SCIMGet(context.Context, Directory, string) (Record, error)
	SCIMList(context.Context, Directory, Query) ([]Record, int, error)
	SCIMCreate(context.Context, Directory, Profile) (Record, error)
	// SCIMUpdate calls change on the locked current record and commits all updates atomically.
	SCIMUpdate(ctx context.Context, d Directory, id string, change func(Record) (Profile, error)) (Record, error)
	SCIMDelete(context.Context, Directory, string) error
}

type Error struct {
	Status       int
	Type, Detail string
}

func (e *Error) Error() string { return e.Detail }

var (
	ErrNotFound       = &Error{404, "", "SCIM User not found"}
	ErrConflict       = &Error{409, "uniqueness", "A resource with the same unique attributes already exists"}
	ErrDomain         = &Error{409, "", "The connection provisioningDomainId changed after the connection was first used"}
	ErrDecommissioned = &Error{401, "", "SCIM connection is decommissioned"}
)

func invalid(kind, detail string) *Error { return &Error{400, kind, detail} }

type staticBearer struct {
	digest    [32]byte
	principal Principal
}
type Handler struct {
	catalog     *Catalog
	host        *auth.Auth
	store       Store
	groups      GroupStore
	legacyGroup bool
	path, base  string
	credentials []staticBearer
	declared    map[string]Directory
	verify      VerifyBearerToken
}

// New wraps host with SCIM routes under its configured public auth mount.
// Other paths continue to the original host handler.
func New(host *auth.Auth, opts Options) (*Handler, error) {
	if host == nil || opts.Store == nil || len(opts.Connections) == 0 && opts.VerifyBearerToken == nil && opts.Managed == nil {
		return nil, errors.New("scim: auth host, directory store and a credential source are required")
	}
	path := strings.TrimRight(host.BasePath(), "/") + "/scim/v2"
	base, err := host.CallbackURL(path)
	if err != nil {
		return nil, err
	}
	h := &Handler{host: host, store: opts.Store, path: path, base: base, legacyGroup: opts.AcceptLegacyEntraGroupSchema, declared: map[string]Directory{}, verify: opts.VerifyBearerToken}
	if opts.Managed != nil {
		h.catalog, err = newCatalog(opts.Store, opts.Managed)
		if err != nil {
			return nil, err
		}
	}
	h.groups, _ = opts.Store.(GroupStore)
	usedTokens := map[[32]byte]bool{}
	for _, c := range opts.Connections {
		if _, exists := h.declared[c.ID]; !identifier(c.ID) || exists || len(c.Credentials) == 0 && h.verify == nil || strings.HasPrefix(c.ID, managedConnectionPrefix) {
			return nil, errors.New("scim: invalid or duplicate static connection")
		}
		if c.ProvisioningDomainID == "" {
			c.ProvisioningDomainID = c.ID
		}
		if !identifier(c.ProvisioningDomainID) {
			return nil, errors.New("scim: invalid provisioning domain")
		}
		h.declared[c.ID] = c.Directory
		ids := map[string]bool{}
		for _, v := range c.Credentials {
			digest := sha256.Sum256([]byte(v.Token))
			if !identifier(v.ID) || ids[v.ID] || v.Token == "" || strings.IndexFunc(v.Token, unicode.IsSpace) >= 0 || usedTokens[digest] {
				return nil, errors.New("scim: invalid or duplicate bearer credential")
			}
			ids[v.ID], usedTokens[digest] = true, true
			scopes := allScopes
			if v.Scopes != nil {
				if !validScopes(v.Scopes) {
					return nil, errors.New("scim: expected non-empty, unique, supported operation scopes")
				}
				scopes = v.Scopes
			}
			p := staticBearer{digest: digest, principal: Principal{Kind: "static-bearer", Directory: c.Directory, CredentialID: v.ID, Scopes: slices.Clone(scopes), ExpiresAt: v.ExpiresAt}}
			h.credentials = append(h.credentials, p)
		}
	}
	return h, nil
}
func identifier(v string) bool {
	return v != "" && utf8.RuneCountInString(v) <= 255 && strings.TrimSpace(v) == v
}
func (h *Handler) authorize(r *http.Request, scope, route string) (Principal, error) {
	fields := strings.Fields(r.Header.Get("Authorization"))
	if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") || len(r.Header.Values("Authorization")) != 1 {
		return Principal{}, &Error{401, "", "SCIM bearer token is required"}
	}
	token := fields[1]
	digest := sha256.Sum256([]byte(token))
	var got *Principal
	for i := range h.credentials {
		p := &h.credentials[i]
		if subtle.ConstantTimeCompare(digest[:], p.digest[:]) == 1 && (p.principal.ExpiresAt.IsZero() || p.principal.ExpiresAt.After(time.Now())) {
			got = &p.principal
		}
	}
	if got == nil && h.catalog != nil && strings.HasPrefix(token, managedCredentialPrefix) {
		var e error
		got, e = h.catalog.verify(r.Context(), token)
		if e != nil {
			return Principal{}, e
		}
	}
	if got == nil && h.verify != nil && !strings.HasPrefix(token, managedCredentialPrefix) {
		var e error
		got, e = h.verifyDynamic(r.Context(), BearerInput{Token: token, Method: r.Method, Path: route, Headers: r.Header.Clone()})
		if e != nil {
			return Principal{}, e
		}
	}
	if got == nil {
		return Principal{}, &Error{401, "", "Invalid SCIM bearer token"}
	}
	if !slices.Contains(got.Scopes, scope) {
		return Principal{}, &Error{403, "", "The SCIM bearer token is missing the " + scope + " scope"}
	}
	return *got, nil
}
