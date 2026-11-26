package plainauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/Plain-Org/plain-auth/plugins/access"
)

// AdminUserFields is present on profiles managed by the administration plugin.
type AdminUserFields struct {
	Role       string     `json:"role"`
	Banned     bool       `json:"banned"`
	BanReason  *string    `json:"banReason"`
	BanExpires *time.Time `json:"banExpires"`
}

type AdminPermissions map[string][]string
type AdminOptions struct {
	// DefaultRole is stored on accounts created without a role, by sign-up
	// or by an administrator. It defaults to "user" and must be a key of
	// Roles.
	DefaultRole string
	// AdminRoles lists the protected roles. Impersonating a holder needs
	// user:impersonate-admins or AllowImpersonatingAdmins, and only another
	// protected operator can change a holder's phone number. It defaults to
	// ["admin"] and replaces that default when set. Each name must match a
	// key of Roles exactly, including case.
	AdminRoles []string
	// AdminUserIDs grants every administrative permission to these account
	// IDs and protects them like AdminRoles holders.
	AdminUserIDs []string
	// Roles maps role names to grants. Nil selects DefaultAdminRoles; a
	// non-nil map replaces the built-in roles.
	Roles map[string]AdminPermissions
	// DefaultBanReason is stored when a ban gives no reason. It defaults to
	// "No reason".
	DefaultBanReason string
	// BannedUserMessage is the BANNED_USER message a banned account
	// receives.
	BannedUserMessage string
	// BannedUserMessageFunc, when set, builds the BANNED_USER message from
	// the banned account, with its role, ban fields and public additional
	// fields, for example to quote BanReason. It runs after the store call
	// that refused the session has returned, never inside a store
	// transaction; its result is what endpoint after hooks, OnAPIError and
	// the HTTP error response see, and the error_description of a magic-link
	// error redirect. An empty result or a panic keeps BannedUserMessage, as
	// do native Go calls. The store must implement AdminUserReader.
	BannedUserMessageFunc func(ctx context.Context, user User) string
	// DefaultBanDuration sets the expiry of a ban that gives no duration.
	// Zero keeps the ban until an administrator lifts it.
	DefaultBanDuration time.Duration
	// ImpersonationSessionDuration bounds an impersonation session. It
	// defaults to one hour.
	ImpersonationSessionDuration time.Duration
	// AllowImpersonatingAdmins lets an operator with user:impersonate
	// impersonate holders of AdminRoles and AdminUserIDs.
	AllowImpersonatingAdmins bool
}

// AdminQuery configures a paginated search. Field and operator names are validated by the SQL adapter.
type AdminQuery struct {
	Limit, Offset                                                                                int
	SearchField, SearchOperator, SearchValue, FilterField, FilterOperator, SortBy, SortDirection string
	FilterValues                                                                                 []string
}

type AdminPage struct {
	Users  []User `json:"users"`
	Total  int    `json:"total"`
	Limit  int    `json:"limit,omitempty"`
	Offset int    `json:"offset,omitempty"`
}

type AdminTransaction interface {
	User(string) (User, error)
	Users(AdminQuery) (AdminPage, error)
	CreateUser(User, string) error
	UpdateUser(User) error
	SetPassword(string, string) error
	UserSessions(string) ([]Session, error)
	RevokeSession(string) error
	RevokeListedSession(userID, sessionID string) error
	RevokeUserSessions(string) error
	DeleteUser(string) error
	Impersonate(StoredSession, Session) error
	RestoreSession(current Session, originalToken string, now time.Time) (SessionResult, error)
}

type AdminStore interface {
	Store
	WithAdminConfig(defaultRole, denialMessage string) (AdminStore, error)
	// AdminTransaction locks and validates the authoritative actor session and
	// account, serializing target mutations with account deletion and sign-in.
	AdminTransaction(ctx context.Context, actorToken, targetID string, now time.Time, fn func(AdminTransaction, SessionResult) error) error
}

var adminDefaults = AdminPermissions{"user": {"create", "list", "set-role", "ban", "impersonate", "delete", "set-password", "set-email", "set-phone", "get", "update"}, "session": {"list", "revoke", "delete"}}

// BannedUserError refuses a session to a banned account. It unwraps to the
// BANNED_USER APIError, and UserID names the account so the message can be
// built once the store call has returned.
type BannedUserError struct {
	*APIError
	UserID string `json:"-"`
}

func (e *BannedUserError) Unwrap() error { return e.APIError }

// AdminUserReader reads one account with its role and ban fields, outside
// any session or transaction. ErrNotFound reports an unknown ID.
type AdminUserReader interface {
	AdminUser(ctx context.Context, userID string) (User, error)
}

// adminUser reads an account with its admin and public additional fields.
func (a *Auth) adminUser(ctx context.Context, id string) (User, error) {
	reader, ok := a.adminStore.(AdminUserReader)
	if !ok {
		return User{}, errors.New("admin: store does not support reading users by ID")
	}
	u, err := reader.AdminUser(ctx, id)
	if err != nil {
		return User{}, err
	}
	return u, a.readUserExtras(ctx, &u)
}

// bannedUserMessage builds a banned account's message with
// BannedUserMessageFunc. It runs after the store call returned, never inside
// a store transaction.
func (a *Auth) bannedUserMessage(ctx context.Context, err error) (out error) {
	var banned *BannedUserError
	if a.admin == nil || a.admin.BannedUserMessageFunc == nil || !errors.As(err, &banned) {
		return err
	}
	u, readErr := a.adminUser(ctx, banned.UserID)
	if readErr != nil {
		return err
	}
	defer func() {
		if recover() != nil {
			a.Logger().ErrorContext(ctx, "Banned user message callback panicked")
			out = err
		}
	}()
	msg := a.admin.BannedUserMessageFunc(ctx, u)
	if msg == "" {
		return err
	}
	return &BannedUserError{APIError: &APIError{Status: banned.Status, Code: banned.Code, Message: msg}, UserID: banned.UserID}
}

// AdminUserHasPermission reports whether the stored account userID holds
// every permission, for trusted server code without a session. It reads the
// account's current role and honours AdminUserIDs. POST /admin/has-permission
// checks the caller's own session and ignores userId and role, as another
// runtime does over HTTP; do not expose this method directly as an HTTP
// handler. The store must implement AdminUserReader.
func (a *Auth) AdminUserHasPermission(ctx context.Context, userID string, permissions AdminPermissions) (bool, error) {
	if a.adminStore == nil {
		return false, adminError(404, "NOT_FOUND", "Not found")
	}
	if len(permissions) == 0 {
		return false, validationError("Permission set is required")
	}
	if userID == "" {
		return false, validationError("User ID is required")
	}
	u, err := a.adminUser(ctx, userID)
	if errors.Is(err, ErrNotFound) {
		return false, &APIError{400, "USER_NOT_FOUND", "User not found"}
	}
	if err != nil {
		return false, err
	}
	return a.admin.HasPermission(u.ID, u.Role, permissions), nil
}

// DefaultAdminRoles returns an independent copy of the built-in "admin" and
// "user" roles that AdminOptions uses when Roles is nil. The admin role
// grants every built-in action except user:impersonate-admins, and the user
// role grants none.
func DefaultAdminRoles() map[string]AdminPermissions {
	return map[string]AdminPermissions{"admin": cloneAdminPermissions(adminDefaults), "user": {"user": {}, "session": {}}}
}

func cloneAdminPermissions(p AdminPermissions) AdminPermissions {
	out := make(AdminPermissions, len(p))
	for k, v := range p {
		out[k] = slices.Clone(v)
	}
	return out
}

func NewAdmin(options AdminOptions) (Plugin, error) {
	if options.DefaultRole == "" {
		options.DefaultRole = "user"
	}
	if options.DefaultBanReason == "" {
		options.DefaultBanReason = "No reason"
	}
	if options.BannedUserMessage == "" {
		options.BannedUserMessage = "You have been banned from this application. Please contact support if you believe this is an error."
	}
	if options.DefaultBanDuration < 0 || options.ImpersonationSessionDuration < 0 {
		return Plugin{}, errors.New("authn: admin durations must be nonnegative")
	}
	if options.ImpersonationSessionDuration == 0 {
		options.ImpersonationSessionDuration = time.Hour
	}
	if options.Roles == nil {
		options.Roles = DefaultAdminRoles()
	}
	roles := make(map[string]AdminPermissions, len(options.Roles))
	for role, rules := range options.Roles {
		if role == "" || strings.Contains(role, ",") {
			return Plugin{}, errors.New("authn: invalid administrative role name")
		}
		roles[role] = cloneAdminPermissions(rules)
	}
	options.Roles = roles
	if options.AdminRoles == nil {
		options.AdminRoles = []string{"admin"}
	}
	options.AdminRoles = slices.Clone(options.AdminRoles)
	options.AdminUserIDs = slices.Clone(options.AdminUserIDs)
	// Names match exactly, including case: a protected role that differed
	// from a configured role only in case would protect no account.
	for _, role := range append(slices.Clone(options.AdminRoles), options.DefaultRole) {
		if _, ok := roles[role]; !ok {
			return Plugin{}, errors.New("authn: administrative and default roles must be defined")
		}
	}
	p := Plugin{ID: "admin", StoredUserFields: map[string]UserField{"role": {Type: FieldString}, "banned": {Type: FieldBoolean}, "banReason": {Type: FieldString}, "banExpires": {Type: FieldDate}}, admin: &options}
	for _, name := range []string{"set-role", "get-user", "create-user", "update-user", "list-users", "list-user-sessions", "unban-user", "ban-user", "impersonate-user", "stop-impersonating", "revoke-user-session", "revoke-user-sessions", "remove-user", "set-user-password", "has-permission"} {
		method := http.MethodPost
		if name == "get-user" || name == "list-users" {
			method = http.MethodGet
		}
		p.Endpoints = append(p.Endpoints, Endpoint{Method: method, Path: "/admin/" + name, Handler: func(c EndpointContext) (any, error) { return c.Auth.adminHTTP(c, name) }})
	}
	return p, nil
}

// HasPermission evaluates one complete grant against each assigned role.
// Resource/action grants from different roles remain independent.
func (o AdminOptions) HasPermission(id, role string, want AdminPermissions) bool {
	if slices.Contains(o.AdminUserIDs, id) && id != "" {
		return true
	}
	if role == "" {
		role = o.DefaultRole
	}
	if role == "" {
		role = "user"
	}
	roles := o.Roles
	if roles == nil {
		roles = DefaultAdminRoles()
	}
	for _, name := range strings.Split(role, ",") {
		if access.Statements(roles[name]).AllowsAll(access.Statements(want)) {
			return true
		}
	}
	return false
}

func adminError(status int, code, message string) error {
	return &APIError{Status: status, Code: code, Message: message}
}
func adminMissing() error { return adminError(404, "USER_NOT_FOUND", "User not found") }

type adminGrant struct{ resource, action, code, message string }

var adminActions = map[string]adminGrant{
	"create-user":          {"user", "create", "YOU_ARE_NOT_ALLOWED_TO_CREATE_USERS", "You are not allowed to create users"},
	"get-user":             {"user", "get", "YOU_ARE_NOT_ALLOWED_TO_GET_USER", "You are not allowed to get user"},
	"update-user":          {"user", "update", "YOU_ARE_NOT_ALLOWED_TO_UPDATE_USERS", "You are not allowed to update users"},
	"set-role":             {"user", "set-role", "YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE", "You are not allowed to change users role"},
	"list-users":           {"user", "list", "YOU_ARE_NOT_ALLOWED_TO_LIST_USERS", "You are not allowed to list users"},
	"ban-user":             {"user", "ban", "YOU_ARE_NOT_ALLOWED_TO_BAN_USERS", "You are not allowed to ban users"},
	"unban-user":           {"user", "ban", "YOU_ARE_NOT_ALLOWED_TO_BAN_USERS", "You are not allowed to ban users"},
	"impersonate-user":     {"user", "impersonate", "YOU_ARE_NOT_ALLOWED_TO_IMPERSONATE_USERS", "You are not allowed to impersonate users"},
	"list-user-sessions":   {"session", "list", "YOU_ARE_NOT_ALLOWED_TO_LIST_USERS_SESSIONS", "You are not allowed to list users sessions"},
	"revoke-user-session":  {"session", "revoke", "YOU_ARE_NOT_ALLOWED_TO_REVOKE_USERS_SESSIONS", "You are not allowed to revoke users sessions"},
	"revoke-user-sessions": {"session", "revoke", "YOU_ARE_NOT_ALLOWED_TO_REVOKE_USERS_SESSIONS", "You are not allowed to revoke users sessions"},
	"remove-user":          {"user", "delete", "YOU_ARE_NOT_ALLOWED_TO_DELETE_USERS", "You are not allowed to delete users"},
	"set-user-password":    {"user", "set-password", "YOU_ARE_NOT_ALLOWED_TO_SET_USERS_PASSWORD", "You are not allowed to set users password"},
	"set-email":            {"user", "set-email", "YOU_ARE_NOT_ALLOWED_TO_SET_USERS_EMAIL", "You are not allowed to update users email"},
}

// AdminRequest invokes an administrative operation using an authenticated caller.
// Operation is the endpoint name without "/admin/". Data contains approved public profile fields.
type AdminRequest struct {
	Operation, UserID, Name, Email, Password, SessionToken, BanReason string
	Role                                                              []string
	BanDuration                                                       time.Duration
	Data                                                              map[string]any
	Query                                                             AdminQuery
	Permissions                                                       AdminPermissions
}

type AdminResult struct {
	User                  *User
	Session               *SessionResult
	Sessions              []Session
	Page                  *AdminPage
	Allowed               bool
	original, persistence string
}

func (a *Auth) requireAdminGrant(actor User, operation string) error {
	g := adminActions[operation]
	if !a.admin.HasPermission(actor.ID, actor.Role, AdminPermissions{g.resource: {g.action}}) {
		return adminError(403, g.code, g.message)
	}
	return nil
}

const adminHandlePrefix = "revoke."

// A revocation handle contains only row identifiers and an expiration. Its
// authenticated purpose binds it to the operator and separates it from a login.
type adminSessionHandle struct {
	UserID    string    `json:"user"`
	SessionID string    `json:"session"`
	ExpiresAt time.Time `json:"expires"`
}

func (a *Auth) listAdminSessions(tx AdminTransaction, operator, user string) ([]Session, error) {
	rows, err := tx.UserSessions(user)
	if err != nil {
		return nil, err
	}
	for i, row := range rows {
		data, err := json.Marshal(adminSessionHandle{row.UserID, row.ID, row.ExpiresAt})
		if err != nil {
			return nil, err
		}
		handle, err := a.sealRecord("admin-session-revoke:"+operator, data)
		if err != nil {
			return nil, err
		}
		rows[i].Token = adminHandlePrefix + handle
	}
	return rows, nil
}

func (a *Auth) revokeAdminSession(tx AdminTransaction, operator, credential string, now time.Time) error {
	handle, ok := strings.CutPrefix(credential, adminHandlePrefix)
	if !ok {
		return tx.RevokeSession(credential)
	}
	data, err := a.openRecord("admin-session-revoke:"+operator, handle)
	var ref adminSessionHandle
	if err != nil || json.Unmarshal(data, &ref) != nil || ref.UserID == "" || ref.SessionID == "" || !ref.ExpiresAt.After(now) {
		return validationError("Invalid session revocation handle")
	}
	return tx.RevokeListedSession(ref.UserID, ref.SessionID)
}

// Admin runs the same transaction and permission checks as the administrative HTTP endpoints.
// For impersonation and restoration, use the HTTP handler to receive the browser credentials.
func (a *Auth) Admin(ctx context.Context, headers http.Header, req AdminRequest) (AdminResult, error) {
	return a.executeAdmin(ctx, headers, req, RequestMeta{})
}

func (a *Auth) executeAdmin(ctx context.Context, h http.Header, req AdminRequest, meta RequestMeta) (AdminResult, error) {
	var out AdminResult
	if a.adminStore == nil {
		return out, adminError(404, "NOT_FOUND", "Not found")
	}
	op := req.Operation
	if op == "set-role" {
		req.Data = nil
	}
	if _, ok := adminActions[op]; !ok && op != "has-permission" && op != "stop-impersonating" || op == "set-email" {
		return out, adminError(404, "NOT_FOUND", "Not found")
	}
	token := a.cookieToken(h)
	if token == "" {
		return out, adminError(401, "UNAUTHORIZED", "Unauthorized")
	}
	now := a.now().UTC().Truncate(time.Millisecond)
	plan := &adminCreatePlan{}
	body := func(tx AdminTransaction, actor SessionResult) error {
		out = AdminResult{}
		if err := a.configureAdminProjection(tx, op); err != nil {
			return err
		}
		if op == "has-permission" {
			if len(req.Permissions) == 0 {
				return validationError("Permission set is required")
			}
			out.Allowed = actor.Session.ImpersonatedBy == nil && a.admin.HasPermission(actor.User.ID, actor.User.Role, req.Permissions)
			return nil
		}
		if op == "stop-impersonating" {
			if actor.Session.ImpersonatedBy == nil {
				return &APIError{Status: 400, Message: "You are not impersonating anyone"}
			}
			original, mode := a.adminReturnCredential(h, actor.Session.Token)
			if original == "" {
				return adminError(401, "UNAUTHORIZED", "Invalid return session")
			}
			res, err := tx.RestoreSession(actor.Session, original, now)
			if err != nil {
				return err
			}
			out.Session = &res
			out.persistence = mode
			return nil
		}
		if actor.Session.ImpersonatedBy != nil {
			return adminError(403, "FORBIDDEN", "Administrative actions require a direct session")
		}
		if err := a.requireAdminGrant(actor.User, op); err != nil {
			return err
		}
		switch op {
		case "list-users":
			page, err := tx.Users(req.Query)
			out.Page = &page
			return err
		case "revoke-user-session":
			if req.SessionToken == "" {
				return validationError("Session token is required")
			}
			return a.revokeAdminSession(tx, actor.User.ID, req.SessionToken, now)
		case "create-user":
			var err error
			out.User, err = a.createAdministrativeUser(ctx, tx, &actor.User, req, now, plan)
			return err
		}
		if req.UserID == "" {
			return validationError("User ID is required")
		}
		if op == "list-user-sessions" {
			var err error
			out.Sessions, err = a.listAdminSessions(tx, actor.User.ID, req.UserID)
			return err
		}
		if op == "revoke-user-sessions" {
			return tx.RevokeUserSessions(req.UserID)
		}
		if op == "set-user-password" {
			// The length is checked before the account is looked up.
			if err := a.validatePasswordLength(req.Password, true); err != nil {
				return err
			}
		}
		// set-role and update-user check their values after this lookup, so a
		// missing account answers USER_NOT_FOUND first.
		u, err := tx.User(req.UserID)
		if err != nil {
			return err
		}
		switch op {
		case "get-user":
			out.User = &u
			return nil
		case "remove-user":
			if u.ID == actor.User.ID {
				return adminError(400, "YOU_CANNOT_REMOVE_YOURSELF", "You cannot remove yourself")
			}
			return tx.DeleteUser(u.ID)
		case "impersonate-user":
			targetAdmin := a.admin.protectedIdentity(u)
			if targetAdmin && !a.admin.AllowImpersonatingAdmins && !a.admin.HasPermission(actor.User.ID, actor.User.Role, AdminPermissions{"user": {"impersonate-admins"}}) {
				return adminError(403, "YOU_CANNOT_IMPERSONATE_ADMINS", "You cannot impersonate admins")
			}
			ss, _ := a.newSession(u.ID, meta)
			ss.ExpiresAt = now.Add(a.admin.ImpersonationSessionDuration)
			ss.ImpersonatedBy = &actor.User.ID
			if err := tx.Impersonate(ss, actor.Session); err != nil {
				return err
			}
			out.Session = &SessionResult{User: u, Session: ss.Session}
			out.original = token
			return nil
		case "set-user-password":
			hash, err := a.hashCredential(ctx, "/admin/set-user-password", req.Password)
			if err != nil {
				return err
			}
			return tx.SetPassword(u.ID, hash)
		case "update-user", "set-role":
			if err := a.adminUpdateFields(ctx, &actor.User, &u, req, false); err != nil {
				return err
			}
		case "ban-user":
			if u.ID == actor.User.ID {
				return adminError(400, "YOU_CANNOT_BAN_YOURSELF", "You cannot ban yourself")
			}
			why := req.BanReason
			if why == "" {
				why = a.admin.DefaultBanReason
			}
			u.Banned = true
			u.BanReason = &why
			u.BanExpires = nil
			ttl := req.BanDuration
			if ttl == 0 {
				ttl = a.admin.DefaultBanDuration
			}
			if ttl < 0 {
				return validationError("Invalid ban duration")
			}
			if ttl > 0 {
				until := now.Add(ttl)
				u.BanExpires = &until
			}
		case "unban-user":
			u.Banned = false
			u.BanReason = nil
			u.BanExpires = nil
		}
		u.UpdatedAt = now
		if err := tx.UpdateUser(u); err != nil {
			return err
		}
		if u.Banned {
			if err := tx.RevokeUserSessions(u.ID); err != nil {
				return err
			}
		}
		out.User = &u
		return nil
	}
	err := a.adminStore.AdminTransaction(ctx, token, req.UserID, now, body)
	if errors.Is(err, errAdminPlanned) {
		// The gate sees the user the actor may create, outside the transaction.
		if err = a.validateAdminUser(ctx, plan, req); err == nil {
			err = a.adminStore.AdminTransaction(ctx, token, req.UserID, now, body)
		}
	}
	err = usernameWriteError(err)
	if errors.Is(err, ErrEmailTaken) {
		err = adminError(400, "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL", "User already exists. Use another email.")
	}
	if errors.Is(err, ErrNotFound) {
		err = adminMissing()
	}
	if err != nil {
		return AdminResult{}, err
	}
	return out, nil
}
