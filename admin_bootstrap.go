package plainauth

import (
	"context"
	"errors"
	"strings"
	"time"
)

// ErrAdminExists indicates that the target database already has an admin role holder.
var ErrAdminExists = errors.New("an administrative account already exists")

type AdminBootstrapStore interface {
	CreateFirstAdmin(context.Context, User, string) error
}

// BootstrapAdmin provisions the first default administrator through a trusted
// database connection. Applications should use the authenticated admin service
// for subsequent grants. This operation is available only through Go and authctl.
func BootstrapAdmin(ctx context.Context, s AdminBootstrapStore, name, email, password string) (User, error) {
	if s == nil {
		return User{}, errors.New("a name and valid email address are required")
	}
	return bootstrapAdmin(ctx, name, email, password, HashPassword, func(ctx context.Context, u User, hash string) (User, error) {
		return u, s.CreateFirstAdmin(ctx, u, hash)
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
