// Package scim provisions directory-owned Users through the SCIM 2.0 protocol.
package scim

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	auth "github.com/Stonewrit/stonewrit-auth"
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
	Store       Store
	Connections []Connection
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

type principal struct {
	digest      [32]byte
	directory   Directory
	read, write bool
	expiry      time.Time
}
type Handler struct {
	host        *auth.Auth
	store       Store
	path, base  string
	credentials []principal
}

// New wraps host with SCIM routes under its configured public auth mount.
// Other paths continue to the original host handler.
func New(host *auth.Auth, opts Options) (*Handler, error) {
	if host == nil || opts.Store == nil || len(opts.Connections) == 0 {
		return nil, errors.New("scim: auth host, directory store and at least one connection are required")
	}
	path := strings.TrimRight(host.BasePath(), "/") + "/scim/v2"
	base, err := host.CallbackURL(path)
	if err != nil {
		return nil, err
	}
	h := &Handler{host: host, store: opts.Store, path: path, base: base}
	usedConnections := map[string]bool{}
	usedTokens := map[[32]byte]bool{}
	for _, c := range opts.Connections {
		if !identifier(c.ID) || usedConnections[c.ID] || len(c.Credentials) == 0 || strings.HasPrefix(c.ID, "ba_scim_connection_") {
			return nil, errors.New("scim: invalid or duplicate static connection")
		}
		usedConnections[c.ID] = true
		if c.ProvisioningDomainID == "" {
			c.ProvisioningDomainID = c.ID
		}
		if !identifier(c.ProvisioningDomainID) {
			return nil, errors.New("scim: invalid provisioning domain")
		}
		ids := map[string]bool{}
		for _, v := range c.Credentials {
			digest := sha256.Sum256([]byte(v.Token))
			if !identifier(v.ID) || ids[v.ID] || v.Token == "" || strings.IndexFunc(v.Token, unicode.IsSpace) >= 0 || usedTokens[digest] {
				return nil, errors.New("scim: invalid or duplicate bearer credential")
			}
			ids[v.ID], usedTokens[digest] = true, true
			p := principal{digest: digest, directory: c.Directory, expiry: v.ExpiresAt}
			if v.Scopes == nil {
				p.read, p.write = true, true
			} else {
				if len(v.Scopes) == 0 {
					return nil, errors.New("scim: empty operation scope list")
				}
				seen := map[string]bool{}
				for _, scope := range v.Scopes {
					if seen[scope] {
						return nil, errors.New("scim: duplicate operation scope")
					}
					seen[scope] = true
					switch scope {
					case UsersRead:
						p.read = true
					case UsersWrite:
						p.write = true
					case "scim.groups.read", "scim.groups.write":
					default:
						return nil, errors.New("scim: unknown operation scope")
					}
				}
			}
			h.credentials = append(h.credentials, p)
		}
	}
	return h, nil
}
func identifier(v string) bool {
	return v != "" && utf8.RuneCountInString(v) <= 255 && strings.TrimSpace(v) == v
}
func (h *Handler) authorize(r *http.Request) (Directory, error) {
	fields := strings.Fields(r.Header.Get("Authorization"))
	if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") || len(r.Header.Values("Authorization")) != 1 {
		return Directory{}, &Error{401, "", "SCIM bearer token is required"}
	}
	digest := sha256.Sum256([]byte(fields[1]))
	var got *principal
	for i := range h.credentials {
		p := &h.credentials[i]
		if subtle.ConstantTimeCompare(digest[:], p.digest[:]) == 1 && (p.expiry.IsZero() || p.expiry.After(time.Now())) {
			got = p
		}
	}
	if got == nil {
		return Directory{}, &Error{401, "", "Invalid SCIM bearer token"}
	}
	if r.Method == http.MethodGet && !got.read {
		return Directory{}, &Error{403, "", "The SCIM bearer token is missing the " + UsersRead + " scope"}
	}
	if r.Method != http.MethodGet && !got.write {
		return Directory{}, &Error{403, "", "The SCIM bearer token is missing the " + UsersWrite + " scope"}
	}
	return got.directory, nil
}
