// Package apikey provides user- and organization-owned credentials with independent
// expiration, scoped permissions, usage budgets and per-key rate limits.
package apikey

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"sync/atomic"
	"time"
	"unicode/utf16"

	plainauth "github.com/Plain-Org/plain-auth"
)

type Permissions map[string][]string

// Key is safe to include in management and verification responses.
type Key struct {
	ID                  string         `json:"id"`
	ConfigID            string         `json:"configId"`
	ReferenceID         string         `json:"referenceId"`
	Name                *string        `json:"name"`
	Prefix              *string        `json:"prefix"`
	Start               *string        `json:"start"`
	Enabled             bool           `json:"enabled"`
	RateLimitEnabled    bool           `json:"rateLimitEnabled"`
	RateLimitTimeWindow *int64         `json:"rateLimitTimeWindow"`
	RateLimitMax        *int64         `json:"rateLimitMax"`
	RequestCount        int64          `json:"requestCount"`
	Remaining           *int64         `json:"remaining"`
	RefillInterval      *int64         `json:"refillInterval"`
	RefillAmount        *int64         `json:"refillAmount"`
	LastRefillAt        *time.Time     `json:"lastRefillAt"`
	LastRequest         *time.Time     `json:"lastRequest"`
	ExpiresAt           *time.Time     `json:"expiresAt"`
	CreatedAt           time.Time      `json:"createdAt"`
	UpdatedAt           time.Time      `json:"updatedAt"`
	Permissions         Permissions    `json:"permissions"`
	Metadata            map[string]any `json:"metadata"`
}

// Created includes the only recoverable copy of the secret.
type Created struct {
	Key
	Secret string `json:"key"`
}

type Owner struct {
	UserID, SessionToken, OrganizationID, Action string
	Organization                                 *OrganizationOptions
}
type Lookup struct{ ConfigID, ID, Digest string }
type Mutation uint8

const (
	Read Mutation = iota
	Save
	Remove
)

type PageOptions struct {
	OrganizationID        string
	Limit, Offset         *int
	SortBy, SortDirection string
}
type Page struct {
	Keys   []Key `json:"apiKeys"`
	Total  int   `json:"total"`
	Limit  *int  `json:"limit,omitempty"`
	Offset *int  `json:"offset,omitempty"`
}

// Store rechecks ownership and session validity and serializes the decision on
// each key with its write. An empty owner is supported only for digest lookup.
type Store interface {
	CheckAPIKeySchema(context.Context) error
	CreateAPIKey(context.Context, Owner, Key, string) error
	WithAPIKey(context.Context, Owner, Lookup, time.Time, func(*Key) (Mutation, error)) error
	ListAPIKeys(context.Context, Owner, string, time.Time, PageOptions) (Page, error)
	// DeleteExpiredAPIKeys removes the keys of config that expired at or
	// before now, or of every configuration when config is empty.
	DeleteExpiredAPIKeys(ctx context.Context, config string, now time.Time) (int64, error)
}

// Generation describes the authorized owner and requested settings for one new key.
// Prefix is the caller's effective prefix. The generator returns the entire credential.
type Generation struct {
	UserID, OrganizationID, ConfigID, Prefix string
	Length                                   int
}

// GeneratorStore checks current issuance authority before the application generator
// runs. CreateAPIKey must recheck authority and reject duplicate digests atomically.
type GeneratorStore interface {
	CheckAPIKeyCreator(context.Context, Owner) error
}

type Options struct {
	// GenerateKey runs once per authorized attempt. Return the whole credential
	// using KeyLength to 4096 printable, non-space ASCII bytes.
	GenerateKey func(context.Context, Generation) (string, error)
	// DefaultPermissionsFor works out a new key's permissions from its
	// owner's reference ID: the user ID, or the organization ID for
	// organization keys. It runs once per creation that passed its checks and
	// issuance authorization, after GenerateKey and outside store
	// transactions. Permissions set by server code win over its result, and a
	// nil result gives the key no permissions. It cannot be combined with
	// DefaultPermissions.
	DefaultPermissionsFor func(ctx context.Context, referenceID string) (Permissions, error)
	// ExtractKey returns (credential, present, error). It replaces Headers for this
	// configuration. Report malformed supplied credentials as present or return an error.
	ExtractKey func(*http.Request) (string, bool, error)

	Organization  *OrganizationOptions
	EnableSession bool
	// ValidateKey lets the host reject a credential before storage, permission
	// and usage checks. The callback may run concurrently on different requests.
	ValidateKey func(context.Context, string) (bool, error)
	// Headers names the request headers accepted by Middleware. The default is X-API-Key.
	Headers []string
	Store   Store
	// ConfigID names this configuration; empty means "default".
	ConfigID string
	// DefaultPrefix starts every key whose request names no prefix. It must
	// use letters, digits, _ or - and fit the prefix lengths.
	DefaultPrefix string
	// KeyLength is the number of random letters in a generated key, 64 by
	// default. Below 32 is refused (a deviation, for safety), so a key keeps
	// at least 182 bits of randomness.
	KeyLength int
	// StartLength is how many leading characters, prefix included, are
	// stored and shown as start, 6 by default. It must leave at least 24
	// characters of the key hidden.
	StartLength int
	// HideStart stores no starting characters, so start is null.
	HideStart                                                      bool
	RequireName, EnableMetadata, DisableCustomExpiration           bool
	DisableRateLimit                                               bool
	MinNameLength, MaxNameLength, MinPrefixLength, MaxPrefixLength int
	MinExpiration, MaxExpiration, DefaultExpiration, RateWindow    time.Duration
	RateMax                                                        int64
	DefaultPermissions                                             Permissions
	// DeferUpdates hands work that need not finish before the answer to
	// BackgroundTasks: deleting a key that verification finds expired or used
	// up, and the expired-key sweep. Usage counters still commit with the
	// verification, so budgets and rate limits stay exact.
	DeferUpdates bool
	// BackgroundTasks runs deferred work with the contract of
	// plainauth.Options.BackgroundTasks: it gets a ready task and must run it
	// once, usually on another goroutine. DeferUpdates requires it.
	BackgroundTasks func(task func())
}
type Service struct {
	opts  Options
	swept atomic.Int64 // Unix milliseconds of the last expired-key sweep
}

// sweepInterval is how often key operations purge expired keys, and
// sweepTimeout how long a purge may wait, for example behind another
// transaction's row locks.
const sweepInterval, sweepTimeout = 10 * time.Second, 2 * time.Second

// sweep deletes the expired keys of every configuration in the store, at
// most once every ten seconds per service. It runs after the operation,
// outside any transaction: before the answer, giving up after
// sweepTimeout, or on the task runner with DeferUpdates, where nothing waits
// on it and it has no deadline. A failure is ignored: the keys it leaves are
// still refused, and a later sweep retries.
func (s *Service) sweep(ctx context.Context) {
	now := current()
	last := s.swept.Load()
	if last != 0 && now.UnixMilli()-last < sweepInterval.Milliseconds() || !s.swept.CompareAndSwap(last, now.UnixMilli()) {
		return
	}
	ctx = context.WithoutCancel(ctx)
	if s.opts.DeferUpdates {
		s.opts.BackgroundTasks(func() { _, _ = s.opts.Store.DeleteExpiredAPIKeys(ctx, "", now) })
		return
	}
	ctx, cancel := context.WithTimeout(ctx, sweepTimeout)
	defer cancel()
	_, _ = s.opts.Store.DeleteExpiredAPIKeys(ctx, "", now)
}

// removeSpent deletes the key with digest while it is still expired, or
// still used up with no refill. A failure is ignored: the key stays refused,
// and a later verification or sweep retries.
func (s *Service) removeSpent(ctx context.Context, digest string) {
	_ = s.opts.Store.WithAPIKey(ctx, s.forAction(Owner{}, ""), Lookup{ConfigID: s.opts.ConfigID, Digest: digest}, current(), func(k *Key) (Mutation, error) {
		if k.ExpiresAt != nil && !k.ExpiresAt.After(current()) || k.Remaining != nil && *k.Remaining <= 0 && k.RefillAmount == nil {
			return Remove, nil
		}
		return Read, nil
	})
}

// DeleteAllExpired removes the expired keys of every configuration in the
// service's store, as the server-only expired-key purge does. DeleteExpired
// keeps to the service's own configuration.
func (s *Service) DeleteAllExpired(ctx context.Context) (int64, error) {
	now := current()
	s.swept.Store(now.UnixMilli())
	return s.opts.Store.DeleteExpiredAPIKeys(ctx, "", now)
}

var safePrefix = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

func New(o Options) (*Service, error) {
	if o.Store == nil {
		return nil, errors.New("apikey: a store is required")
	}
	if o.EnableSession {
		if _, ok := o.Store.(sessionUserStore); !ok {
			return nil, errors.New("apikey: session authentication requires a credential-aware account store")
		}
	}
	if o.GenerateKey != nil {
		if _, ok := o.Store.(GeneratorStore); !ok {
			return nil, errors.New("apikey: custom generation requires issuer authorization and digest reservation")
		}
	}
	if o.DefaultPermissionsFor != nil {
		if o.DefaultPermissions != nil {
			return nil, errors.New("apikey: set DefaultPermissions or DefaultPermissionsFor, not both")
		}
		if _, ok := o.Store.(GeneratorStore); !ok {
			return nil, errors.New("apikey: default permission callbacks require issuer authorization")
		}
	}
	if o.DeferUpdates && o.BackgroundTasks == nil {
		return nil, errors.New("apikey: DeferUpdates requires BackgroundTasks")
	}
	if o.ConfigID == "" {
		o.ConfigID = "default"
	}
	if o.KeyLength == 0 {
		o.KeyLength = 64
	}
	if o.StartLength == 0 {
		o.StartLength = 6
	}
	if o.MinNameLength == 0 {
		o.MinNameLength = 1
	}
	if o.MaxNameLength == 0 {
		o.MaxNameLength = 32
	}
	if o.MinPrefixLength == 0 {
		o.MinPrefixLength = 1
	}
	if o.MaxPrefixLength == 0 {
		o.MaxPrefixLength = 32
	}
	if o.MinExpiration == 0 {
		o.MinExpiration = 24 * time.Hour
	}
	if o.MaxExpiration == 0 {
		o.MaxExpiration = 365 * 24 * time.Hour
	}
	if o.RateWindow == 0 {
		o.RateWindow = 24 * time.Hour
	}
	if o.RateMax == 0 {
		o.RateMax = 10
	}
	if len(o.ConfigID) > 191 || o.KeyLength < 32 || o.KeyLength > 1024 ||
		o.StartLength < 1 || o.StartLength > o.KeyLength-24 {
		return nil, errors.New("apikey: invalid generation or display length")
	}
	if o.MinNameLength < 1 || o.MaxNameLength < o.MinNameLength ||
		o.MinPrefixLength < 1 || o.MaxPrefixLength < o.MinPrefixLength || o.MaxPrefixLength > 128 {
		return nil, errors.New("apikey: invalid name or prefix length")
	}
	if o.MinExpiration < time.Second || o.MaxExpiration < o.MinExpiration || o.DefaultExpiration < 0 ||
		o.RateWindow.Milliseconds() < 1 || o.RateWindow.Milliseconds() > 2147483647 || o.RateMax < 1 || o.RateMax > 2147483647 {
		return nil, errors.New("apikey: invalid expiration or rate policy")
	}
	if o.DefaultPrefix != "" && (!safePrefix.MatchString(o.DefaultPrefix) || len(o.DefaultPrefix) < o.MinPrefixLength || len(o.DefaultPrefix) > o.MaxPrefixLength) {
		return nil, errors.New("apikey: invalid default prefix")
	}
	o.DefaultPermissions = clonePermissions(o.DefaultPermissions)
	headers, err := headerNames(o.Headers)
	if err != nil {
		return nil, err
	}
	o.Headers = headers
	if o.Organization != nil {
		org := *o.Organization
		org.Roles = clonePermissions(o.Organization.Roles)
		if org.RolesFrom != nil {
			if org.CreatorRole != "" || org.Roles != nil {
				return nil, errors.New("apikey: take organization roles from RolesFrom or from CreatorRole and Roles, not both")
			}
			org.policy, org.stored = org.RolesFrom.RoleSettings()
			org.linked = true
		}
		if org.CreatorRole == "" {
			org.CreatorRole = "owner"
		}
		for _, actions := range org.Roles {
			for _, action := range actions {
				switch action {
				case CreateAction, ReadAction, UpdateAction, DeleteAction:
				default:
					return nil, errors.New("apikey: unknown organization action")
				}
			}
		}
		o.Organization = &org
	}
	service := &Service{opts: o}
	if err := service.configureReference(context.Background()); err != nil {
		return nil, err
	}
	return service, nil
}

func clonePermissions(source Permissions) Permissions {
	if source == nil {
		return nil
	}
	destination := make(Permissions, len(source))
	for resource, actions := range source {
		destination[resource] = slices.Clone(actions)
	}
	return destination
}

type Policy struct {
	Enabled, RateLimitEnabled             *bool
	RateLimitMax, Remaining, RefillAmount *int64
	RateWindow, RefillInterval            *time.Duration
	Permissions                           Permissions
}

type CreateInput struct {
	OrganizationID string
	Name, Prefix   string
	ExpiresIn      time.Duration
	Metadata       map[string]any
	Policy         Policy
}
type UpdateInput struct {
	Name      *string
	ExpiresIn *time.Duration
	Metadata  map[string]any
	Policy    Policy
}

func (in UpdateInput) empty() bool {
	p := in.Policy
	return in.Name == nil && in.ExpiresIn == nil && in.Metadata == nil &&
		p.Enabled == nil && p.RateLimitEnabled == nil && p.RateLimitMax == nil &&
		p.Remaining == nil && p.RefillAmount == nil && p.RateWindow == nil &&
		p.RefillInterval == nil && p.Permissions == nil
}

func problem(status int, code, msg string) *plainauth.APIError {
	return &plainauth.APIError{Status: status, Code: code, Message: msg}
}

// ErrKeyCollision indicates the generated credential is already reserved or stored.
var ErrKeyCollision = problem(409, "API_KEY_ALREADY_ISSUED", "The generated credential has already been issued")
var errGenerator = errors.New("apikey: invalid credential generator result")
var errDefaultPermissions = errors.New("apikey: default permission callback failed")
var errExtractor = errors.New("apikey: credential extraction failed")

// Keep application error text and nested HTTP error types out of wire responses.
// Native callers can identify their own sentinel and cancellation with errors.Is.
type hookFailure struct{ kind, cause error }

func (e hookFailure) Error() string        { return e.kind.Error() }
func (e hookFailure) Is(target error) bool { return target == e.kind || errors.Is(e.cause, target) }

func portableSecret(secret string) bool {
	if secret == "" || len(secret) > 4096 {
		return false
	}
	for i := 0; i < len(secret); i++ {
		if secret[i] < 0x21 || secret[i] > 0x7e {
			return false
		}
	}
	return true
}

var errKeyValidator = errors.New("apikey: application key validator failed")

// Digest is the only stored form of a key. There is no plain-text mode (a
// deviation, for safety): a row that holds a plain secret never matches, so
// rotate such keys before switching.
func Digest(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
func ptr[T any](v T) *T { return &v }
func textPtr(v string) *string {
	if v == "" {
		return nil
	}
	return &v
}
func current() time.Time { return time.Now().UTC().Truncate(time.Millisecond) }

func randomSecret(length int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	buf := make([]byte, 0, length)
	// 208 is the largest multiple of 52 below 256.
	var raw [64]byte
	for len(buf) < length {
		rand.Read(raw[:])
		for _, v := range raw {
			if v < 208 {
				buf = append(buf, letters[int(v)%len(letters)])
				if len(buf) == length {
					break
				}
			}
		}
	}
	return string(buf)
}
func (s *Service) apply(k *Key, in UpdateInput, now time.Time) error {
	if in.Name != nil {
		// Creation drops an empty name first, so every name here is checked.
		if n := len(utf16.Encode([]rune(*in.Name))); n < s.opts.MinNameLength || n > s.opts.MaxNameLength || n == 0 {
			return errNameLength
		}
		k.Name = textPtr(*in.Name)
	}
	if in.ExpiresIn != nil {
		d := *in.ExpiresIn
		if s.opts.DisableCustomExpiration {
			return errExpirationDisabled
		}
		if d != 0 && d < s.opts.MinExpiration {
			return errExpiresTooSmall
		}
		if d > s.opts.MaxExpiration {
			return errExpiresTooLarge
		}
		k.ExpiresAt = nil
		if d != 0 {
			k.ExpiresAt = ptr(now.Add(d))
		}
	}
	if in.Metadata != nil {
		if !s.opts.EnableMetadata {
			return errMetadataDisabled
		}
		k.Metadata = in.Metadata
	}
	p := in.Policy
	if p.Enabled != nil {
		k.Enabled = *p.Enabled
	}
	if p.RateLimitEnabled != nil {
		k.RateLimitEnabled = *p.RateLimitEnabled
	}
	if p.Remaining != nil {
		// A Go Policy has no body validator, so the declared code is the
		// typed answer; another runtime's validator answers VALIDATION_ERROR.
		if *p.Remaining < 0 || *p.Remaining > 2147483647 {
			return errRemaining
		}
		k.Remaining = p.Remaining
	}
	// A rate maximum must allow at least one request, and both rate settings
	// must fit the integer columns; other values are refused rather than
	// stored.
	if p.RateLimitMax != nil {
		if *p.RateLimitMax < 1 || *p.RateLimitMax > 2147483647 {
			return problem(400, "VALIDATION_ERROR", "Invalid rate limit")
		}
		k.RateLimitMax = p.RateLimitMax
	}
	if p.RateWindow != nil {
		ms := p.RateWindow.Milliseconds()
		if ms < 1 || ms > 2147483647 {
			return problem(400, "VALIDATION_ERROR", "Invalid rate window")
		}
		k.RateLimitTimeWindow = &ms
	}
	// The codes follow the error table's use, not their wording: an amount
	// without an interval is REFILL_AMOUNT_AND_INTERVAL_REQUIRED.
	if p.RefillAmount != nil && p.RefillInterval == nil {
		return errRefillAmount
	}
	if p.RefillInterval != nil && p.RefillAmount == nil {
		return errRefillInterval
	}
	if p.RefillInterval != nil {
		ms := p.RefillInterval.Milliseconds()
		if ms < 1 || ms > 2147483647 || *p.RefillAmount < 1 || *p.RefillAmount > 2147483647 {
			return problem(400, "VALIDATION_ERROR", "Invalid refill policy")
		}
		k.RefillInterval = &ms
		k.RefillAmount = p.RefillAmount
	}
	if p.Permissions != nil {
		k.Permissions = p.Permissions
	}
	return nil
}

// Create issues a key for an authenticated user selected by trusted server code.
func (s *Service) Create(ctx context.Context, userID string, in CreateInput) (*Created, error) {
	return s.create(ctx, Owner{UserID: userID}, in)
}
func (s *Service) create(ctx context.Context, owner Owner, in CreateInput) (*Created, error) {
	if owner.UserID == "" {
		return nil, ErrSession
	}
	owner = s.forAction(owner, CreateAction)
	owner.OrganizationID = in.OrganizationID
	if owner.Organization != nil && owner.OrganizationID == "" {
		return nil, ErrOrganizationRequired
	}
	if owner.Organization == nil && owner.OrganizationID != "" {
		return nil, invalidField("organizationId")
	}
	prefix := in.Prefix
	if prefix == "" {
		prefix = s.opts.DefaultPrefix
	}
	if prefix != "" && !safePrefix.MatchString(prefix) {
		return nil, errPrefixFormat
	}
	if prefix != "" && (len(prefix) < s.opts.MinPrefixLength || len(prefix) > s.opts.MaxPrefixLength) {
		return nil, errPrefixLength
	}
	now := current()
	k := Key{
		ID: rand.Text(), ConfigID: s.opts.ConfigID, ReferenceID: owner.ReferenceID(), Prefix: textPtr(prefix),
		CreatedAt: now, UpdatedAt: now, Enabled: true, RateLimitEnabled: !s.opts.DisableRateLimit,
		RateLimitTimeWindow: ptr(s.opts.RateWindow.Milliseconds()), RateLimitMax: ptr(s.opts.RateMax),
		Permissions: clonePermissions(s.opts.DefaultPermissions),
	}
	if s.opts.DefaultExpiration > 0 {
		k.ExpiresAt = ptr(now.Add(s.opts.DefaultExpiration))
	}
	if in.Name == "" && s.opts.RequireName {
		return nil, errNameRequired
	}
	up := UpdateInput{Metadata: in.Metadata, Policy: in.Policy}
	if in.Name != "" {
		up.Name = &in.Name
	}
	if in.ExpiresIn != 0 {
		up.ExpiresIn = &in.ExpiresIn
	}
	if err := s.apply(&k, up, now); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var secret string
	if s.opts.GenerateKey != nil || s.opts.DefaultPermissionsFor != nil {
		// Host code runs only for an authorized creator.
		if err := s.opts.Store.(GeneratorStore).CheckAPIKeyCreator(ctx, owner); err != nil {
			return nil, err
		}
	}
	if generate := s.opts.GenerateKey; generate != nil {
		var err error
		secret, err = generate(ctx, Generation{UserID: owner.UserID, OrganizationID: owner.OrganizationID, ConfigID: k.ConfigID, Prefix: prefix, Length: s.opts.KeyLength})
		if err != nil {
			return nil, hookFailure{errGenerator, err}
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if len(secret) < s.opts.KeyLength || !portableSecret(secret) {
			return nil, errGenerator
		}
	} else {
		secret = prefix + randomSecret(s.opts.KeyLength)
	}
	if resolve := s.opts.DefaultPermissionsFor; resolve != nil {
		defaults, err := resolve(ctx, owner.ReferenceID())
		if err != nil {
			return nil, hookFailure{errDefaultPermissions, err}
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if in.Policy.Permissions == nil {
			k.Permissions = clonePermissions(defaults)
		}
	}
	if !s.opts.HideStart {
		k.Start = ptr(secret[:s.opts.StartLength])
	}
	if err := s.opts.Store.CreateAPIKey(ctx, owner, k, Digest(secret)); err != nil {
		return nil, err
	}
	s.sweep(ctx)
	return &Created{Key: k, Secret: secret}, nil
}

func (s *Service) Get(ctx context.Context, userID, id string) (*Key, error) {
	return s.manage(ctx, Owner{UserID: userID}, id, Read, UpdateInput{})
}
func (s *Service) Update(ctx context.Context, userID, id string, in UpdateInput) (*Key, error) {
	return s.manage(ctx, Owner{UserID: userID}, id, Save, in)
}
func (s *Service) Delete(ctx context.Context, userID, id string) error {
	_, err := s.manage(ctx, Owner{UserID: userID}, id, Remove, UpdateInput{})
	return err
}
func (s *Service) manage(ctx context.Context, owner Owner, id string, action Mutation, in UpdateInput) (*Key, error) {
	if owner.UserID == "" {
		return nil, ErrSession
	}
	if id == "" {
		return nil, ErrMissing
	}
	operation := ReadAction
	switch action {
	case Save:
		operation = UpdateAction
	case Remove:
		operation = DeleteAction
	}
	owner = s.forAction(owner, operation)
	now := current()
	var result *Key
	err := s.opts.Store.WithAPIKey(ctx, owner, Lookup{ConfigID: s.opts.ConfigID, ID: id}, now, func(k *Key) (Mutation, error) {
		if action == Save {
			if in.empty() {
				return Read, errNoValues
			}
			if err := s.apply(k, in, now); err != nil {
				return Read, err
			}
			k.UpdatedAt = now
		}
		result = k
		return action, nil
	})
	if err == nil {
		s.sweep(ctx)
	}
	return result, err
}
func (s *Service) List(ctx context.Context, userID string, o PageOptions) (Page, error) {
	return s.list(ctx, Owner{UserID: userID}, o)
}
func (s *Service) list(ctx context.Context, owner Owner, o PageOptions) (Page, error) {
	page, err := s.listKeys(ctx, owner, o)
	if err == nil {
		s.sweep(ctx)
	}
	return page, err
}

// listKeys reads one page of the owner's keys without the expired-key sweep.
func (s *Service) listKeys(ctx context.Context, owner Owner, o PageOptions) (Page, error) {
	if owner.UserID == "" {
		return Page{}, ErrSession
	}
	if o.Limit != nil && *o.Limit < 0 || o.Offset != nil && *o.Offset < 0 {
		return Page{}, problem(400, "VALIDATION_ERROR", "Invalid pagination")
	}
	owner = s.forAction(owner, ReadAction)
	owner.OrganizationID = o.OrganizationID
	if owner.Organization != nil && owner.OrganizationID == "" {
		return Page{}, ErrOrganizationRequired
	}
	if owner.Organization == nil && owner.OrganizationID != "" {
		return Page{}, invalidField("organizationId")
	}
	return s.opts.Store.ListAPIKeys(ctx, owner, s.opts.ConfigID, current(), o)
}
func (s *Service) DeleteExpired(ctx context.Context) (int64, error) {
	return s.opts.Store.DeleteExpiredAPIKeys(ctx, s.opts.ConfigID, current())
}

type VerifyError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	// Details holds tryAgainIn for a RATE_LIMITED answer.
	Details *RetryDetails `json:"details,omitempty"`
}

// RetryDetails tells a rate-limited caller when to try again.
type RetryDetails struct {
	// TryAgainIn is the number of milliseconds until the key's window reopens.
	TryAgainIn int64 `json:"tryAgainIn"`
}
type Verification struct {
	Valid bool         `json:"valid"`
	Key   *Key         `json:"key"`
	Error *VerifyError `json:"error"`
}

// Verify checks the secret and every required resource/action. Successful
// verification consumes one use in the same transaction as the rate check.
func (s *Service) Verify(ctx context.Context, secret string, required Permissions) (Verification, error) {
	result := Verification{}
	invalid := func(code, msg string) { result.Error = &VerifyError{Code: code, Message: msg} }
	if secret == "" || len(secret) > 4096 {
		invalid("INVALID_API_KEY", "Invalid API key.")
		return result, nil
	}
	if s.opts.ValidateKey != nil {
		allowed, err := s.opts.ValidateKey(ctx, secret)
		if err != nil {
			return Verification{}, fmt.Errorf("%w: %w", errKeyValidator, err)
		}
		if !allowed {
			invalid("KEY_NOT_FOUND", "API Key not found")
			return result, nil
		}
	}
	now := current()
	// An expired or used-up key is deleted in the verification's own
	// transaction, or afterwards by the task runner with DeferUpdates.
	spent := false
	remove := func() Mutation {
		if s.opts.DeferUpdates {
			spent = true
			return Read
		}
		return Remove
	}
	err := s.opts.Store.WithAPIKey(ctx, s.forAction(Owner{}, ""), Lookup{ConfigID: s.opts.ConfigID, Digest: Digest(secret)}, now, func(k *Key) (Mutation, error) {
		// Evaluate time-based policies after obtaining the key lock.
		spent = false
		now = current()
		if !k.Enabled {
			invalid("KEY_DISABLED", "API Key is disabled")
			return Read, nil
		}
		if k.ExpiresAt != nil && !k.ExpiresAt.After(now) {
			invalid("KEY_EXPIRED", "API Key has expired")
			return remove(), nil
		}
		for res, actions := range required {
			granted, ok := k.Permissions[res]
			if !ok {
				invalid("KEY_NOT_FOUND", "API Key not found")
				return Read, nil
			}
			for _, action := range actions {
				if !slices.Contains(granted, action) {
					invalid("KEY_NOT_FOUND", "API Key not found")
					return Read, nil
				}
			}
		}
		if k.Remaining != nil {
			remaining := *k.Remaining
			if k.RefillInterval != nil && k.RefillAmount != nil && *k.RefillInterval > 0 {
				since := k.CreatedAt
				if k.LastRefillAt != nil {
					since = *k.LastRefillAt
				}
				if now.Sub(since).Milliseconds() > *k.RefillInterval {
					remaining = *k.RefillAmount
					k.LastRefillAt = &now
				}
			}
			if remaining <= 0 {
				invalid("USAGE_EXCEEDED", "API Key has reached its usage limit")
				if k.RefillAmount == nil {
					return remove(), nil
				}
				return Read, nil
			}
			k.Remaining = ptr(remaining - 1)
		}
		// A key without a maximum or a window has no rate limit and keeps its
		// last request time. A limit turned off for the service or for the
		// key still records the request.
		unbounded := k.RateLimitMax == nil || k.RateLimitTimeWindow == nil
		limited := !s.opts.DisableRateLimit && k.RateLimitEnabled
		if limited && !unbounded {
			if k.LastRequest == nil || now.Sub(*k.LastRequest).Milliseconds() > *k.RateLimitTimeWindow {
				k.RequestCount = 1
			} else if k.RequestCount >= *k.RateLimitMax {
				// The code is RATE_LIMITED, with the table's RATE_LIMIT_EXCEEDED
				// message, as another runtime answers a spent rate budget.
				invalid("RATE_LIMITED", "Rate limit exceeded.")
				result.Error.Details = &RetryDetails{TryAgainIn: *k.RateLimitTimeWindow - now.Sub(*k.LastRequest).Milliseconds()}
				return Read, nil
			} else {
				k.RequestCount++
			}
		}
		if !limited || !unbounded {
			k.LastRequest = &now
		}
		k.UpdatedAt = now
		result.Valid = true
		result.Key = k
		return Save, nil
	})
	if errors.Is(err, ErrMissing) {
		invalid("INVALID_API_KEY", "Invalid API key.")
		return result, nil
	}
	if errors.Is(err, ErrBanned) {
		invalid("USER_BANNED", "User is banned")
		return result, nil
	}
	if err != nil {
		return Verification{}, fmt.Errorf("verify API key: %w", err)
	}
	if s.opts.DeferUpdates {
		if spent {
			digest, background := Digest(secret), context.WithoutCancel(ctx)
			s.opts.BackgroundTasks(func() { s.removeSpent(background, digest) })
		}
		// As other key operations do, only a valid key sweeps.
		if result.Valid {
			s.sweep(ctx)
		}
	}
	return result, nil
}
