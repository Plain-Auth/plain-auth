package plainauth

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
)

// DatabaseHooks run your code around the writes that create, update and
// delete users, sessions and accounts, for HTTP requests and direct Go calls
// alike. Plugin hooks run
// first, in plugin order, then the Options hooks.
//
// A before hook runs just before the write and may edit the row or return
// ErrSkipWrite to cancel it. An after hook runs once the row is stored. Hooks
// never run inside a database transaction, so they may use the Auth and the
// store. When one operation stores several rows, such as a sign-up's user and
// first session, every before hook runs before anything is written.
//
// New refuses a hook that an enabled feature would bypass, naming the
// feature. User update and delete hooks are not supported yet.
type DatabaseHooks struct {
	User    ModelHooks[UserRecord]
	Session ModelHooks[SessionRecord]
	// Account hooks observe and may cancel credential and linked account
	// writes. They may not change the account.
	Account ModelHooks[LinkedAccount]
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
// may change Name, Email, Image, EmailVerified and Fields, except during a
// sign-in the store decides, such as social sign-in or a magic link, which
// allows only Name and Image and leaves Fields empty. When updating a
// profile, a hook may change Name, Image and Fields. Email changes and
// verification allow no edits.
type UserRecord struct {
	User
	// Fields holds the Options.UserAdditionalFields values this write sets,
	// by name. Defaults for the fields it omits are applied after the hooks.
	Fields map[string]any
}

// SessionRecord is a session row in a database hook. When creating a
// session, a hook may change ExpiresAt, IPAddress, UserAgent and Fields. A
// refresh lets it change ExpiresAt, and a field update the Fields a caller
// may set.
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
	account modelChain[LinkedAccount]
}

func (d databaseHookChains) set() bool {
	return d.user.create.set() || d.user.update.set() || d.user.delete.set() ||
		d.session.create.set() || d.session.update.set() || d.session.delete.set() ||
		d.account.create.set() || d.account.update.set() || d.account.delete.set()
}

func composeDatabaseHooks(opts Options) databaseHookChains {
	var d databaseHookChains
	add := func(h DatabaseHooks, source string) {
		d.user.add(h.User, source)
		d.session.add(h.Session, source)
		d.account.add(h.Account, source)
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
		need("admin", a.HasPlugin("admin"))
	}
	if _, plans := a.opts.Store.(LoginPlanner); !plans && (len(d.user.create.before) > 0 || len(d.session.create.before) > 0) {
		// These sign-ins decide inside the store's transaction whether to
		// create the user. Their before hooks need a store that plans logins.
		var decided []string
		if len(a.opts.SocialProviders) > 0 {
			decided = append(decided, "social sign-in")
		}
		for _, id := range []string{"magic-link", "email-otp", "phone-number", "one-tap", "sso", "two-factor", "device-authorization"} {
			if a.HasPlugin(id) {
				decided = append(decided, id)
			}
		}
		if a.opts.AutoSignInAfterVerification {
			decided = append(decided, "AutoSignInAfterVerification")
		}
		if len(decided) > 0 {
			return fmt.Errorf("auth: user and session create before hooks for %s need a store implementing LoginPlanner", strings.Join(decided, ", "))
		}
	}
	if d.user.create.set() {
		need("passkey", a.HasPlugin("passkey"))
		need("siwe", a.HasPlugin("siwe"))
	}
	if d.session.create.set() && a.hasVerificationObservers() {
		// Observed verifications issue their session in a separate store call.
		for _, p := range a.opts.Plugins {
			if p.emailOTP != nil && p.emailOTP.AutoSignInAfterVerification {
				need("email-otp AutoSignInAfterVerification with BeforeEmailVerification or AfterEmailVerification", true)
			}
		}
		need("AutoSignInAfterVerification with BeforeEmailVerification or AfterEmailVerification", a.opts.AutoSignInAfterVerification)
	}
	if len(bypass) > 0 {
		return fmt.Errorf("auth: user and session create database hooks do not run yet for %s", strings.Join(bypass, ", "))
	}
	if d.user.update.set() {
		need("social sign-in", len(a.opts.SocialProviders) > 0)
		for _, id := range []string{"magic-link", "email-otp", "phone-number", "one-tap", "sso", "admin", "two-factor", "last-login-method"} {
			need(id, a.HasPlugin(id))
		}
		need("AutoSignInAfterVerification", a.opts.AutoSignInAfterVerification)
		need("BeforeEmailVerification and AfterEmailVerification", a.hasVerificationObservers())
	}
	if d.session.update.set() {
		need("organization", a.HasPlugin("organization"))
		need("admin", a.HasPlugin("admin"))
	}
	if d.session.delete.set() {
		for _, id := range []string{"admin", "anonymous", "magic-link", "sso", "two-factor"} {
			need(id, a.HasPlugin(id))
		}
		need("RevokeSessionsOnPasswordReset", a.opts.RevokeSessionsOnPasswordReset)
	}
	if d.user.delete.set() {
		need("admin", a.HasPlugin("admin"))
		need("anonymous", a.HasPlugin("anonymous"))
	}
	if d.account.create.set() || d.account.update.set() || d.account.delete.set() {
		if _, ok := a.opts.Store.(LinkedAccountStore); !ok {
			return errors.New("auth: account database hooks require a store implementing ListUserAccounts")
		}
		// These flows write linked accounts inside the store's transaction.
		need("social sign-in", len(a.opts.SocialProviders) > 0)
		for _, id := range []string{"one-tap", "sso", "admin", "siwe", "magic-link", "anonymous"} {
			need(id, a.HasPlugin(id))
		}
	}
	if d.account.create.set() || d.account.update.set() {
		need("SendResetPassword", a.opts.SendResetPassword != nil)
		need("email-otp", a.HasPlugin("email-otp"))
		need("phone-number", a.HasPlugin("phone-number"))
	}
	if len(bypass) > 0 {
		return fmt.Errorf("auth: these database hooks do not run yet for %s", strings.Join(bypass, ", "))
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
func (a *Auth) beforeSessionCreate(ctx context.Context, row StoredSession, fields map[string]any, skipped error) (StoredSession, map[string]any, error) {
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

// beforeUserUpdate runs the user update before hooks on row, the user with the
// change applied, and fields, the additional field values the update sets. A
// profile update lets hooks change Name, Image and fields; other updates allow
// no edits.
func (a *Auth) beforeUserUpdate(ctx context.Context, row User, fields map[string]any, profile bool) (User, map[string]any, error) {
	chain := a.dbHooks.user.update
	if len(chain.before) == 0 {
		return row, fields, nil
	}
	rec := UserRecord{User: row, Fields: cloneFields(fields)}
	if err := runBefore(ctx, a, chain, &rec); err != nil {
		return row, fields, err
	}
	edited, check := rec.User, row
	if profile {
		check.Name, check.Image = edited.Name, edited.Image
	}
	if !reflect.DeepEqual(check, edited) || !profile && !reflect.DeepEqual(rec.Fields, cloneFields(fields)) {
		a.Logger().ErrorContext(ctx, errDatabaseHookEdit.Error(), "model", "user")
		return row, fields, errDatabaseHookEdit
	}
	return edited, rec.Fields, nil
}

// deleteUserWithHooks runs the session and user delete hooks around del,
// which removes the user with every session. A skip from any before hook
// cancels the whole deletion and reports true.
func (a *Auth) deleteUserWithHooks(ctx context.Context, user User, del func() error) (bool, error) {
	d := a.dbHooks
	if !d.user.delete.set() && !d.session.delete.set() && !d.account.delete.set() {
		return false, del()
	}
	var sessions []Session
	var accounts []LinkedAccount
	var err error
	if d.session.delete.set() {
		if sessions, err = a.userSessionRows(ctx, user.ID, ""); err != nil {
			return false, err
		}
	}
	if d.account.delete.set() {
		if accounts, err = a.opts.Store.(LinkedAccountStore).ListUserAccounts(ctx, user.ID); err != nil {
			return false, err
		}
	}
	for _, row := range sessions {
		if err := runBefore(ctx, a, d.session.delete, &SessionRecord{Session: row, Fields: map[string]any{}}); err != nil {
			return errors.Is(err, ErrSkipWrite), skipless(err)
		}
	}
	for _, row := range accounts {
		if err := a.beforeAccount(ctx, d.account.delete, row); err != nil {
			return errors.Is(err, ErrSkipWrite), skipless(err)
		}
	}
	if err := runBefore(ctx, a, d.user.delete, &UserRecord{User: user, Fields: map[string]any{}}); err != nil {
		return errors.Is(err, ErrSkipWrite), skipless(err)
	}
	if err := del(); err != nil {
		return false, err
	}
	for _, row := range sessions {
		if err := runAfter(ctx, a, d.session.delete, SessionRecord{Session: row, Fields: map[string]any{}}); err != nil {
			return false, err
		}
	}
	for _, row := range accounts {
		if err := runAfter(ctx, a, d.account.delete, row); err != nil {
			return false, err
		}
	}
	return false, runAfter(ctx, a, d.user.delete, UserRecord{User: user, Fields: map[string]any{}})
}

// skipless returns err unless it is ErrSkipWrite.
func skipless(err error) error {
	if errors.Is(err, ErrSkipWrite) {
		return nil
	}
	return err
}

func (a *Auth) afterUserUpdate(ctx context.Context, row User, fields map[string]any) error {
	return runAfter(ctx, a, a.dbHooks.user.update, UserRecord{User: row, Fields: cloneFields(fields)})
}

// beforeSessionUpdate runs the session update before hooks on row, the session
// with the change applied, and fields, the additional field values the update
// sets. A refresh lets hooks change only ExpiresAt; a field update only fields.
func (a *Auth) beforeSessionUpdate(ctx context.Context, row Session, fields map[string]any, refresh bool) (Session, map[string]any, error) {
	chain := a.dbHooks.session.update
	if len(chain.before) == 0 {
		return row, fields, nil
	}
	rec := SessionRecord{Session: row, Fields: cloneFields(fields)}
	if err := runBefore(ctx, a, chain, &rec); err != nil {
		return row, fields, err
	}
	edited, check := rec.Session, row
	if refresh {
		check.ExpiresAt = edited.ExpiresAt
	}
	if !reflect.DeepEqual(check, edited) || refresh && !reflect.DeepEqual(rec.Fields, cloneFields(fields)) {
		a.Logger().ErrorContext(ctx, errDatabaseHookEdit.Error(), "model", "session")
		return row, fields, errDatabaseHookEdit
	}
	return edited, rec.Fields, nil
}

func (a *Auth) afterSessionUpdate(ctx context.Context, row Session, fields map[string]any) error {
	return runAfter(ctx, a, a.dbHooks.session.update, SessionRecord{Session: row, Fields: cloneFields(fields)})
}

// deleteSessionsWithHooks runs the session delete hooks around del. load
// reads the sessions del removes, and runs only when delete hooks are set. A
// skip from any before hook cancels the whole delete and reports true.
func (a *Auth) deleteSessionsWithHooks(ctx context.Context, load func() ([]Session, error), del func() error) (bool, error) {
	chain := a.dbHooks.session.delete
	if !chain.set() {
		return false, del()
	}
	rows, err := load()
	if err != nil {
		return false, err
	}
	for _, row := range rows {
		rec := SessionRecord{Session: row, Fields: map[string]any{}}
		if err := runBefore(ctx, a, chain, &rec); err != nil {
			if errors.Is(err, ErrSkipWrite) {
				return true, nil
			}
			return false, err
		}
	}
	if err := del(); err != nil {
		return false, err
	}
	for _, row := range rows {
		if err := runAfter(ctx, a, chain, SessionRecord{Session: row, Fields: map[string]any{}}); err != nil {
			return false, err
		}
	}
	return false, nil
}

// sessionRows reads the stored sessions with these tokens. Unknown and
// repeated tokens are skipped.
func (a *Auth) sessionRows(ctx context.Context, tokens ...string) ([]Session, error) {
	var rows []Session
	seen := make(map[string]bool, len(tokens))
	for _, token := range tokens {
		if token == "" || seen[token] {
			continue
		}
		seen[token] = true
		row, _, err := a.opts.Store.Session(ctx, token)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		row.Token = token
		rows = append(rows, row.Session)
	}
	return rows, nil
}

// userSessionRows reads userID's stored sessions except the one with token except.
func (a *Auth) userSessionRows(ctx context.Context, userID, except string) ([]Session, error) {
	list, err := a.opts.Store.ListSessions(ctx, userID)
	if err != nil {
		return nil, err
	}
	var rows []Session
	for _, s := range list {
		if except == "" || s.Token != except {
			rows = append(rows, s.Session)
		}
	}
	return rows, nil
}

// beforeAccount runs one account operation's before hooks on row. Hooks may
// not change the account.
func (a *Auth) beforeAccount(ctx context.Context, chain operationChain[LinkedAccount], row LinkedAccount) error {
	if len(chain.before) == 0 {
		return nil
	}
	rec := row
	rec.AdditionalFields, rec.Scopes = maps.Clone(row.AdditionalFields), slices.Clone(row.Scopes)
	if err := runBefore(ctx, a, chain, &rec); err != nil {
		return err
	}
	if !reflect.DeepEqual(rec, row) {
		a.Logger().ErrorContext(ctx, errDatabaseHookEdit.Error(), "model", "account")
		return errDatabaseHookEdit
	}
	return nil
}

// credentialAccount returns userID's stored credential account, or a draft
// with no ID when it has none.
func (a *Auth) credentialAccount(ctx context.Context, userID string) (LinkedAccount, error) {
	store, ok := a.opts.Store.(LinkedAccountStore)
	if !ok {
		return LinkedAccount{}, errors.New("auth: account database hooks require a store implementing ListUserAccounts")
	}
	accounts, err := store.ListUserAccounts(ctx, userID)
	if err != nil {
		return LinkedAccount{}, err
	}
	for _, account := range accounts {
		if account.ProviderID == "credential" {
			return account, nil
		}
	}
	return LinkedAccount{ProviderID: "credential", AccountID: userID, UserID: userID}, nil
}

// afterCredentialAccount runs the after hooks of one credential account write
// with the stored row.
func (a *Auth) afterCredentialAccount(ctx context.Context, chain operationChain[LinkedAccount], userID string) error {
	if len(chain.after) == 0 {
		return nil
	}
	row, err := a.credentialAccount(ctx, userID)
	if err != nil {
		return err
	}
	return runAfter(ctx, a, chain, row)
}

// afterDecidedSignIn runs the create after hooks for a sign-in whose store
// decided inside its own transaction whether to create the user. created
// reports that it did, and token names the session it issued, if any. On
// failure the undelivered session is removed.
func (a *Auth) afterDecidedSignIn(ctx context.Context, user User, created bool, token string) error {
	if created {
		if err := a.afterUserCreate(ctx, user, nil); err != nil {
			if token != "" {
				return a.discardUnpublishedSession(ctx, token, err)
			}
			return err
		}
	}
	if token == "" || len(a.dbHooks.session.create.after) == 0 {
		return nil
	}
	row, _, err := a.opts.Store.Session(ctx, token)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return a.discardUnpublishedSession(ctx, token, err)
	}
	row.Token = token
	return a.afterSessionCreate(ctx, row, nil)
}

// createSessionWithHooks runs the session create hooks around write, which
// stores row. A skipped write returns skipped.
func (a *Auth) createSessionWithHooks(ctx context.Context, row StoredSession, skipped error, write func(StoredSession) error) (StoredSession, error) {
	row, fields, err := a.beforeSessionCreate(ctx, row, nil, skipped)
	if err != nil {
		return row, err
	}
	if err := write(row); err != nil {
		return row, err
	}
	return row, a.afterSessionCreate(ctx, row, fields)
}
