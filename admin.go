package fineauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"
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
	DefaultRole                                      string
	AdminRoles, AdminUserIDs                         []string
	Roles                                            map[string]AdminPermissions
	DefaultBanReason, BannedUserMessage              string
	DefaultBanDuration, ImpersonationSessionDuration time.Duration
	AllowImpersonatingAdmins                         bool
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
		options.Roles = map[string]AdminPermissions{"admin": adminDefaults, "user": {}}
	}
	roles := make(map[string]AdminPermissions, len(options.Roles))
	for role, rules := range options.Roles {
		if role == "" || strings.Contains(role, ",") {
			return Plugin{}, errors.New("authn: invalid administrative role name")
		}
		roles[role] = make(AdminPermissions, len(rules))
		for k, v := range rules {
			roles[role][k] = slices.Clone(v)
		}
	}
	options.Roles = roles
	if options.AdminRoles == nil {
		options.AdminRoles = []string{"admin"}
	}
	options.AdminRoles = slices.Clone(options.AdminRoles)
	options.AdminUserIDs = slices.Clone(options.AdminUserIDs)
	for _, role := range append(slices.Clone(options.AdminRoles), options.DefaultRole) {
		if _, ok := roles[role]; !ok {
			return Plugin{}, errors.New("authn: administrative and default roles must be defined")
		}
	}
	p := Plugin{ID: "admin", admin: &options}
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
		roles = map[string]AdminPermissions{"admin": adminDefaults, "user": {}}
	}
	for _, name := range strings.Split(role, ",") {
		rules, ok := roles[name]
		if !ok {
			continue
		}
		allowed := len(want) > 0
		for resource, actions := range want {
			grants, exists := rules[resource]
			if !exists {
				allowed = false
			}
			for _, action := range actions {
				if !slices.Contains(grants, action) {
					allowed = false
				}
			}
		}
		if allowed {
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
	err := a.adminStore.AdminTransaction(ctx, token, req.UserID, now, func(tx AdminTransaction, actor SessionResult) error {
		out = AdminResult{}
		if op == "has-permission" {
			if len(req.Permissions) == 0 {
				return validationError("Permission set is required")
			}
			out.Allowed = actor.Session.ImpersonatedBy == nil && a.admin.HasPermission(actor.User.ID, actor.User.Role, req.Permissions)
			return nil
		}
		if op == "stop-impersonating" {
			if actor.Session.ImpersonatedBy == nil {
				return adminError(400, "NOT_IMPERSONATING", "You are not impersonating anyone")
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
			u := User{ID: randomID(), Name: req.Name, Email: strings.ToLower(req.Email), CreatedAt: now, UpdatedAt: now, AdminUserFields: &AdminUserFields{Role: a.admin.DefaultRole}}
			if len(u.Email) > 254 || strings.Contains(u.Email, "..") || !emailPattern.MatchString(u.Email) || req.Name == "" {
				return validationError("A valid email and name are required")
			}
			if err := a.adminUpdateFields(actor.User, &u, req, true); err != nil {
				return err
			}
			var hash string
			if req.Password != "" {
				if err := a.validatePasswordLength(req.Password, false); err != nil {
					return err
				}
				var err error
				hash, err = a.hashCredential(ctx, "/admin/create-user", req.Password)
				if err != nil {
					return err
				}
			}
			if err := tx.CreateUser(u, hash); err != nil {
				return err
			}
			out.User = &u
			return nil
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
			targetAdmin := slices.Contains(a.admin.AdminUserIDs, u.ID)
			for _, role := range strings.Split(u.Role, ",") {
				if slices.Contains(a.admin.AdminRoles, role) {
					targetAdmin = true
				}
			}
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
			if err := a.validatePasswordLength(req.Password, true); err != nil {
				return err
			}
			hash, err := a.hashCredential(ctx, "/admin/set-user-password", req.Password)
			if err != nil {
				return err
			}
			return tx.SetPassword(u.ID, hash)
		case "update-user", "set-role":
			if err := a.adminUpdateFields(actor.User, &u, req, false); err != nil {
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
	})
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
