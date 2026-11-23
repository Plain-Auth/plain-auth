package plainauth

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"strings"
)

// DatabaseHooks run your code around the writes that create users and
// sessions, for HTTP requests and direct Go calls alike. Plugin hooks run
// first, in plugin order, then the Options hooks.
//
// A before hook runs just before the write and may edit the row or return
// ErrSkipWrite to cancel it. An after hook runs once the row is stored. Hooks
// never run inside a database transaction, so they may use the Auth and the
// store. When one operation stores several rows, such as a sign-up's user and
// first session, every before hook runs before anything is written.
//
// New refuses a hook that an enabled feature would bypass, naming the
// feature. Update and delete hooks are not supported yet.
type DatabaseHooks struct {
	User    ModelHooks[UserRecord]
	Session ModelHooks[SessionRecord]
}

// ModelHooks holds the hooks for one model's create, update and delete writes.
type ModelHooks[T any] struct {
	Create, Update, Delete OperationHooks[T]
}

// OperationHooks run before and after one kind of write. c describes the HTTP
// endpoint call that caused the write, or is nil for a direct Go call.
//
// Before may change the fields the write stores; changing any other field
// fails the write with a 500. It returns ErrSkipWrite to cancel the write,
// an APIError to answer with that error, or another error to fail it.
//
// After receives the stored row. An error from After is returned to the
// caller; the row stays stored, but a session that has not been delivered
// yet is removed.
type OperationHooks[T any] struct {
	Before func(ctx context.Context, row *T, c *HookContext) error
	After  func(ctx context.Context, row T, c *HookContext) error
}

// UserRecord is a user row in a database hook. When creating a user, a hook
// may change Name, Email, Image, EmailVerified and Fields.
type UserRecord struct {
	User
	// Fields holds the Options.UserAdditionalFields values this write sets,
	// by name. Defaults for the fields it omits are applied after the hooks.
	Fields map[string]any
}

// SessionRecord is a session row in a database hook. When creating a
// session, a hook may change ExpiresAt, IPAddress, UserAgent and Fields.
type SessionRecord struct {
	Session
	// Fields holds the Options.SessionAdditionalFields values this write sets,
	// by name. Defaults for the fields it omits are applied after the hooks.
	Fields map[string]any
}

// ErrSkipWrite cancels a write from a database before hook. The operation
// then fails with its usual error for a write that did not happen, such as
// FAILED_TO_CREATE_USER.
var ErrSkipWrite = errors.New("plainauth: write skipped by a database hook")

type databaseHook[F any] struct {
	run    F
	source string
}

type operationChain[T any] struct {
	before []databaseHook[func(context.Context, *T, *HookContext) error]
	after  []databaseHook[func(context.Context, T, *HookContext) error]
}

func (o *operationChain[T]) add(h OperationHooks[T], source string) {
	if h.Before != nil {
		o.before = append(o.before, databaseHook[func(context.Context, *T, *HookContext) error]{h.Before, source})
	}
	if h.After != nil {
		o.after = append(o.after, databaseHook[func(context.Context, T, *HookContext) error]{h.After, source})
	}
}

func (o operationChain[T]) set() bool { return len(o.before)+len(o.after) > 0 }

type modelChain[T any] struct{ create, update, delete operationChain[T] }

func (m *modelChain[T]) add(h ModelHooks[T], source string) {
	m.create.add(h.Create, source)
	m.update.add(h.Update, source)
	m.delete.add(h.Delete, source)
}

type databaseHookChains struct {
	user    modelChain[UserRecord]
	session modelChain[SessionRecord]
}

func (d databaseHookChains) set() bool {
	return d.user.create.set() || d.user.update.set() || d.user.delete.set() ||
		d.session.create.set() || d.session.update.set() || d.session.delete.set()
}

func composeDatabaseHooks(opts Options) databaseHookChains {
	var d databaseHookChains
	add := func(h DatabaseHooks, source string) {
		d.user.add(h.User, source)
		d.session.add(h.Session, source)
	}
	for _, p := range opts.Plugins {
		add(p.DatabaseHooks, "plugin:"+p.ID)
	}
	add(opts.DatabaseHooks, "user")
	return d
}

// checkDatabaseHooks refuses a hook that an enabled feature would bypass.
func (a *Auth) checkDatabaseHooks() error {
	d := a.dbHooks
	if d.user.update.set() || d.user.delete.set() || d.session.update.set() || d.session.delete.set() {
		return errors.New("auth: database hooks for updating and deleting users and sessions are not supported yet")
	}
	var bypass []string
	need := func(feature string, enabled bool) {
		if enabled {
			bypass = append(bypass, feature)
		}
	}
	if d.user.create.set() || d.session.create.set() {
		if _, ok := a.opts.Store.(signUpUserFinder); !ok {
			return errors.New("auth: user and session create database hooks require a store implementing FindAccountUser")
		}
		need("social sign-in", len(a.opts.SocialProviders) > 0)
		for _, id := range []string{"magic-link", "email-otp", "phone-number", "one-tap", "sso", "admin"} {
			need(id, a.HasPlugin(id))
		}
	}
	if d.user.create.set() {
		need("passkey", a.HasPlugin("passkey"))
		need("siwe", a.HasPlugin("siwe"))
	}
	if d.session.create.set() {
		need("two-factor", a.HasPlugin("two-factor"))
		need("device-authorization", a.HasPlugin("device-authorization"))
		need("AutoSignInAfterVerification", a.opts.AutoSignInAfterVerification)
	}
	if len(bypass) > 0 {
		return fmt.Errorf("auth: user and session create database hooks do not run yet for %s", strings.Join(bypass, ", "))
	}
	return nil
}

// HasDatabaseHooks reports whether the instance or a plugin configured any
// database hook. A handler that wraps the Auth and writes users or sessions
// itself refuses a host with hooks it would bypass.
func (a *Auth) HasDatabaseHooks() bool { return a.dbHooks.set() }

type hookContextKey struct{ a *Auth }

// hookContext returns the endpoint call that caused a write, or nil for a direct Go call.
func (a *Auth) hookContext(ctx context.Context) *HookContext {
	c, _ := ctx.Value(hookContextKey{a}).(*HookContext)
	return c
}

func runBefore[T any](ctx context.Context, a *Auth, chain operationChain[T], row *T) error {
	c := a.hookContext(ctx)
	for _, h := range chain.before {
		if err := a.callDatabaseHook(ctx, h.source, func() error { return h.run(ctx, row, c) }); err != nil {
			return err
		}
	}
	return nil
}

func runAfter[T any](ctx context.Context, a *Auth, chain operationChain[T], row T) error {
	c := a.hookContext(ctx)
	for _, h := range chain.after {
		if err := a.callDatabaseHook(ctx, h.source, func() error { return h.run(ctx, row, c) }); err != nil {
			return err
		}
	}
	return nil
}

func (a *Auth) callDatabaseHook(ctx context.Context, source string, run func() error) (err error) {
	defer func() {
		if p := recover(); p != nil {
			a.Logger().ErrorContext(ctx, "auth: database hook panicked", "source", source, "panic", p)
			err = errDatabaseHookFailed
		}
	}()
	return run()
}

var (
	errDatabaseHookFailed = errors.New("auth: database hook failed")
	errDatabaseHookEdit   = errors.New("auth: a database hook changed a field this write cannot set")
)

// beforeUserCreate runs the user create before hooks on user and its
// additional field input, which the caller has already validated. It returns
// the edited user and the field input to prepare as trusted values.
func (a *Auth) beforeUserCreate(ctx context.Context, user User, fields map[string]any) (User, map[string]any, error) {
	chain := a.dbHooks.user.create
	if len(chain.before) == 0 {
		return user, fields, nil
	}
	rec := UserRecord{User: user, Fields: cloneFields(fields)}
	if err := runBefore(ctx, a, chain, &rec); err != nil {
		return user, fields, err
	}
	edited := rec.User
	check := user
	check.Name, check.Email, check.Image, check.EmailVerified = edited.Name, edited.Email, edited.Image, edited.EmailVerified
	if !reflect.DeepEqual(check, edited) {
		a.Logger().ErrorContext(ctx, errDatabaseHookEdit.Error(), "model", "user")
		return user, fields, errDatabaseHookEdit
	}
	edited.Email = strings.ToLower(edited.Email)
	if len(edited.Email) > 254 || strings.Contains(edited.Email, "..") || !emailPattern.MatchString(edited.Email) {
		return user, fields, &APIError{400, "INVALID_EMAIL", "Invalid email"}
	}
	return edited, rec.Fields, nil
}

// serverInput returns the caller's additional field input without the
// server-only fields, which a hook may set but a caller may not.
func serverInput(fields map[string]UserField, input map[string]any) map[string]any {
	out := make(map[string]any, len(input))
	for name, value := range input {
		if f, ok := fields[name]; ok && !f.ServerOnly {
			out[name] = value
		}
	}
	return out
}

// cloneFields returns a copy of fields that a hook can always write to.
func cloneFields(fields map[string]any) map[string]any {
	if fields == nil {
		return map[string]any{}
	}
	return maps.Clone(fields)
}

// beforeSessionCreate runs the session create before hooks on row, whose
// explicit additional field values are fields. A skipped write returns skipped.
func (a *Auth) beforeSessionCreate(ctx context.Context, row StoredSession, fields map[string]any, skipped *APIError) (StoredSession, map[string]any, error) {
	chain := a.dbHooks.session.create
	if len(chain.before) == 0 {
		return row, fields, nil
	}
	rec := SessionRecord{Session: row.Session, Fields: cloneFields(fields)}
	if err := runBefore(ctx, a, chain, &rec); err != nil {
		if errors.Is(err, ErrSkipWrite) {
			return row, nil, skipped
		}
		return row, nil, err
	}
	edited := rec.Session
	check := row.Session
	check.ExpiresAt, check.IPAddress, check.UserAgent = edited.ExpiresAt, edited.IPAddress, edited.UserAgent
	if !reflect.DeepEqual(check, edited) {
		a.Logger().ErrorContext(ctx, errDatabaseHookEdit.Error(), "model", "session")
		return row, nil, errDatabaseHookEdit
	}
	row.Session = edited
	if !reflect.DeepEqual(rec.Fields, cloneFields(fields)) {
		prepared, err := a.WithTrustedSessionFields(row, rec.Fields)
		if err != nil {
			return row, nil, &APIError{400, "VALIDATION_ERROR", err.Error()}
		}
		row = prepared
	}
	return row, rec.Fields, nil
}

func (a *Auth) afterUserCreate(ctx context.Context, user User, fields map[string]any) error {
	return runAfter(ctx, a, a.dbHooks.user.create, UserRecord{User: user, Fields: fields})
}

// afterSessionCreate runs the session create after hooks. On failure it removes
// the session, which the caller has not delivered yet.
func (a *Auth) afterSessionCreate(ctx context.Context, row StoredSession, fields map[string]any) error {
	if err := runAfter(ctx, a, a.dbHooks.session.create, SessionRecord{Session: row.Session, Fields: fields}); err != nil {
		return a.discardUnpublishedSession(ctx, row.Token, err)
	}
	return nil
}

// createSessionWithHooks runs the session create hooks around write, which
// stores row. A skipped write returns skipped.
func (a *Auth) createSessionWithHooks(ctx context.Context, row StoredSession, skipped *APIError, write func(StoredSession) error) (StoredSession, error) {
	row, fields, err := a.beforeSessionCreate(ctx, row, nil, skipped)
	if err != nil {
		return row, err
	}
	if err := write(row); err != nil {
		return row, err
	}
	return row, a.afterSessionCreate(ctx, row, fields)
}
