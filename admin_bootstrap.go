package plainauth

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/Plain-Org/plain-auth/internal/sessionfields"
)

// ErrAdminExists indicates that an account already holds a role the
// bootstrap would grant.
var ErrAdminExists = errors.New("an administrative account already exists")

// AdminBootstrapStore creates the first holder of the bootstrap roles. It
// refuses with ErrAdminExists when an account already holds one of the
// user's roles, so concurrent bootstraps create at most one.
type AdminBootstrapStore interface {
	CreateFirstAdmin(context.Context, User, string) error
}

// AdminBootstrapFieldStore creates the first holder of the bootstrap roles
// together with additional user field columns.
type AdminBootstrapFieldStore interface {
	CreateFirstAdminWithFields(ctx context.Context, user User, hash string, fields UserFieldValues) error
}

// AdminBootstrap describes the administrator BootstrapAdminAccount creates.
type AdminBootstrap struct {
	Name, Email, Password string
	// Roles are the roles granted; empty grants "admin".
	Roles         []string
	EmailVerified bool
	Image         *string
	// UserFields declares the application's additional user fields; Values
	// sets some of them, and declared defaults fill the rest.
	UserFields map[string]UserField
	Values     map[string]any
}

// BootstrapAdmin provisions the first default administrator through a trusted
// database connection, with the "admin" role and an unverified email.
// Applications should use the authenticated admin service for subsequent
// grants. This operation is available only through Go and authctl.
func BootstrapAdmin(ctx context.Context, s AdminBootstrapStore, name, email, password string) (User, error) {
	return BootstrapAdminAccount(ctx, s, AdminBootstrap{Name: name, Email: email, Password: password})
}

// BootstrapAdminAccount provisions an administrator through a trusted
// database connection. The store refuses with ErrAdminExists when an account
// already holds one of the roles. No hooks run; use Auth.BootstrapAdmin for
// an instance's hooks and password hasher.
func BootstrapAdminAccount(ctx context.Context, s AdminBootstrapStore, in AdminBootstrap) (User, error) {
	if s == nil {
		return User{}, errors.New("a name and valid email address are required")
	}
	roles := in.Roles
	if len(roles) == 0 {
		roles = []string{"admin"}
	}
	for _, role := range roles {
		if role == "" || strings.TrimSpace(role) != role || strings.Contains(role, ",") {
			return User{}, errors.New("each role must be a nonempty name without commas or surrounding spaces")
		}
	}
	declared, err := sessionfields.NormalizeUser(in.UserFields)
	if err != nil {
		return User{}, err
	}
	fields, err := (&Auth{opts: Options{UserAdditionalFields: declared}}).prepareUserFields(in.Values, true, true)
	if err != nil {
		return User{}, err
	}
	return bootstrapAdmin(ctx, in.Name, in.Email, in.Password, HashPassword, func(ctx context.Context, u User, hash string) (User, error) {
		u.Role, u.EmailVerified, u.Image = strings.Join(roles, ","), in.EmailVerified, in.Image
		if len(fields.columns) == 0 {
			return u, s.CreateFirstAdmin(ctx, u, hash)
		}
		withFields, ok := s.(AdminBootstrapFieldStore)
		if !ok {
			return User{}, errors.New("auth: the store cannot write additional user fields while creating an administrator")
		}
		return u, withFields.CreateFirstAdminWithFields(ctx, u, hash, fields)
	})
}

// BootstrapAdmin provisions the first administrator using the instance's
// password policy and credential hasher, with the same minimum as authctl.
func (a *Auth) BootstrapAdmin(ctx context.Context, name, email, password string) (User, error) {
	store, ok := a.opts.Store.(AdminBootstrapStore)
	if !ok {
		return User{}, errors.New("authn: store does not support administrator bootstrap")
	}
	derive := func(ctx context.Context, raw string) (string, error) {
		if err := a.validatePasswordLength(raw, true); err != nil {
			return "", err
		}
		return a.hashCredential(ctx, "/admin/create-user", raw)
	}
	return bootstrapAdmin(ctx, name, email, password, derive, func(ctx context.Context, u User, hash string) (User, error) {
		if err := a.ValidateUserInfo(ctx, UserInfoValidation{Action: UserInfoCreateUser, Method: "admin", User: UserRecord{User: u}}); err != nil {
			return User{}, err
		}
		u, fields, err := a.beforeUserCreate(ctx, u, nil)
		if errors.Is(err, ErrSkipWrite) {
			return User{}, errors.New("authn: a database hook skipped creating the administrator")
		}
		if err == nil && len(fields) > 0 {
			// The bootstrap stores no additional user fields.
			err = errDatabaseHookEdit
		}
		if err == nil && (u.AdminUserFields == nil || u.Role != "admin") {
			err = errDatabaseHookEdit
		}
		if err != nil {
			return User{}, err
		}
		if err := store.CreateFirstAdmin(ctx, u, hash); err != nil {
			return User{}, err
		}
		return u, a.afterUserCreate(ctx, u, fields)
	})
}

func bootstrapAdmin(ctx context.Context, name, email, password string, derive func(context.Context, string) (string, error), create func(context.Context, User, string) (User, error)) (User, error) {
	email = strings.ToLower(email)
	if strings.TrimSpace(name) == "" || len(email) > 254 || strings.Contains(email, "..") || !emailPattern.MatchString(email) {
		return User{}, errors.New("a name and valid email address are required")
	}
	if strings.TrimSpace(password) == "" {
		return User{}, errors.New("a nonblank administrator password is required")
	}
	policy := Auth{opts: Options{MinPasswordLength: 16, MaxPasswordLength: 128}}
	if err := policy.validatePasswordLength(password, true); err != nil {
		return User{}, err
	}
	if err := ctx.Err(); err != nil {
		return User{}, err
	}
	hash, err := derive(ctx, password)
	if err != nil {
		return User{}, err
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	u := User{ID: randomID(), Name: name, Email: email, CreatedAt: now, UpdatedAt: now, AdminUserFields: &AdminUserFields{Role: "admin"}}
	return create(ctx, u, hash)
}
