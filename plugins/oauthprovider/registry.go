package oauthprovider

import (
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
)

// ResourceStore persists OAuth audiences and their links to registered clients.
// Return auth.ErrNotFound for a missing resource. Link must enforce both foreign
// keys and report whether the pair was already linked.
type ResourceStore interface {
	CreateOAuthResource(context.Context, Resource) error
	OAuthResource(context.Context, string) (Resource, error)
	ListOAuthResources(context.Context) ([]Resource, error)
	UpdateOAuthResource(context.Context, string, ResourcePatch, time.Time) (Resource, error)
	DeleteOAuthResource(context.Context, string) error
	LinkOAuthClientResource(context.Context, string, string, time.Time) (alreadyLinked bool, err error)
	UnlinkOAuthClientResource(context.Context, string, string) error
}

var (
	ErrResourceExists = errors.New("OAuth resource already exists")
	ErrClientNotFound = errors.New("OAuth client not found")
)

// ResourceAccess describes a server-side privilege check. Identifier is empty for
// create and list. Headers, session and user belong to the authenticated caller.
type ResourceAccess struct {
	Action     string
	Identifier string
	Headers    http.Header
	auth.SessionResult
}

type ResourceManagerOptions struct {
	// Privileges restricts an action after the caller's session has been verified.
	// By default any authenticated session supplied by the host application is accepted.
	Privileges func(context.Context, ResourceAccess) (bool, error)
	// IdentifierValidator overrides the default absolute resource URI check.
	IdentifierValidator func(context.Context, string) (bool, error)
}

// ResourceManager is a server-side API. Its methods are never added to the auth router.
type ResourceManager struct {
	auth  *auth.Auth
	store ResourceStore
	opts  ResourceManagerOptions
}

func NewResourceManager(a *auth.Auth, store ResourceStore, opts ResourceManagerOptions) (*ResourceManager, error) {
	if a == nil || store == nil {
		return nil, errors.New("oauthprovider: resource management requires auth and a resource store")
	}
	return &ResourceManager{auth: a, store: store, opts: opts}, nil
}

func (m *ResourceManager) authorize(ctx context.Context, h http.Header, action, id string) error {
	session, err := m.auth.GetSession(ctx, h)
	if err != nil {
		return err
	}
	if session != nil {
		if h == nil {
			return invalidResource("request headers are required")
		}
		if m.opts.Privileges == nil {
			return nil
		}
		allowed, err := m.opts.Privileges(ctx, ResourceAccess{
			Action: action, Identifier: id, Headers: h.Clone(), SessionResult: *session,
		})
		if err != nil || allowed {
			return err
		}
	}
	return &auth.APIError{Status: http.StatusUnauthorized, Code: "unauthorized", Message: "Unauthorized"}
}

// ValidResourceIdentifier accepts absolute resource URIs, including URNs, without a fragment.
func ValidResourceIdentifier(id string) bool {
	u, err := url.Parse(id)
	if err != nil || !u.IsAbs() || strings.ContainsAny(id, "# \t\r\n") {
		return false
	}
	if _, err := url.QueryUnescape(u.RawQuery); err != nil {
		return false
	}
	switch strings.ToLower(u.Scheme) {
	case "data", "javascript", "vbscript":
		return false
	case "http", "https":
		return u.Hostname() != ""
	}
	return true
}

func resourceError(err error, id, client string) error {
	switch {
	case errors.Is(err, ErrResourceExists):
		return invalidResource("resource " + id + " already exists")
	case errors.Is(err, auth.ErrNotFound):
		return &auth.APIError{Status: http.StatusNotFound, Code: "not_found", Message: "resource " + id + " not found"}
	case errors.Is(err, ErrClientNotFound):
		return &auth.APIError{Status: http.StatusNotFound, Code: "not_found", Message: "client " + client + " not found"}
	default:
		return err
	}
}

func resourceNow() time.Time { return time.Now().UTC().Truncate(time.Millisecond) }

// Create registers an audience. Its identifier is immutable. An omitted name defaults to the identifier.
func (m *ResourceManager) Create(ctx context.Context, h http.Header, id string, fields ResourcePatch) (Resource, error) {
	if err := m.authorize(ctx, h, "create", ""); err != nil {
		return Resource{}, err
	}
	if id == "" {
		return Resource{}, invalidResource("identifier is required")
	}
	var valid bool
	if m.opts.IdentifierValidator != nil {
		var err error
		valid, err = m.opts.IdentifierValidator(ctx, id)
		if err != nil {
			return Resource{}, err
		}
	} else {
		valid = ValidResourceIdentifier(id)
	}
	if !valid {
		return Resource{}, &auth.APIError{Status: http.StatusBadRequest, Code: "invalid_target", Message: "invalid resource identifier"}
	}
	now := resourceNow()
	r := Resource{ID: rand.Text(), Identifier: id, Name: id, PolicyVersion: 1, CreatedAt: now, UpdatedAt: now}
	if err := fields.Apply(&r); err != nil {
		return Resource{}, err
	}
	if err := m.store.CreateOAuthResource(ctx, r); err != nil {
		return Resource{}, resourceError(err, id, "")
	}
	return r, nil
}

func (m *ResourceManager) List(ctx context.Context, h http.Header) ([]Resource, error) {
	if err := m.authorize(ctx, h, "list", ""); err != nil {
		return nil, err
	}
	return m.store.ListOAuthResources(ctx)
}

func (m *ResourceManager) Get(ctx context.Context, h http.Header, id string) (Resource, error) {
	if err := m.authorize(ctx, h, "read", id); err != nil {
		return Resource{}, err
	}
	r, err := m.store.OAuthResource(ctx, id)
	return r, resourceError(err, id, "")
}

func (m *ResourceManager) Update(ctx context.Context, h http.Header, id string, fields ResourcePatch) (Resource, error) {
	if err := m.authorize(ctx, h, "update", id); err != nil {
		return Resource{}, err
	}
	r, err := m.store.UpdateOAuthResource(ctx, id, fields, resourceNow())
	return r, resourceError(err, id, "")
}

func (m *ResourceManager) Delete(ctx context.Context, h http.Header, id string) error {
	if err := m.authorize(ctx, h, "delete", id); err != nil {
		return err
	}
	return resourceError(m.store.DeleteOAuthResource(ctx, id), id, "")
}

type ResourceLink struct {
	Linked        bool `json:"linked"`
	AlreadyLinked bool `json:"alreadyLinked,omitempty"`
}

// Link grants a registered client access to the resource. Repeated calls succeed.
func (m *ResourceManager) Link(ctx context.Context, h http.Header, id, client string) (ResourceLink, error) {
	if err := m.authorize(ctx, h, "link", id); err != nil {
		return ResourceLink{}, err
	}
	existed, err := m.store.LinkOAuthClientResource(ctx, id, client, resourceNow())
	if err != nil {
		return ResourceLink{}, resourceError(err, id, client)
	}
	return ResourceLink{Linked: true, AlreadyLinked: existed}, nil
}

// Unlink removes a grant. It also succeeds if either object or the grant has already been removed.
func (m *ResourceManager) Unlink(ctx context.Context, h http.Header, id, client string) error {
	if err := m.authorize(ctx, h, "unlink", id); err != nil {
		return err
	}
	return m.store.UnlinkOAuthClientResource(ctx, id, client)
}
