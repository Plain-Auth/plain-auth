package stonewrit

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
	email = strings.ToLower(email)
	if s == nil || strings.TrimSpace(name) == "" || len(email) > 254 || strings.Contains(email, "..") || !emailPattern.MatchString(email) {
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
	hash, err := hashPassword(password)
	if err != nil {
		return User{}, err
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	u := User{ID: randomID(), Name: name, Email: email, CreatedAt: now, UpdatedAt: now, AdminUserFields: &AdminUserFields{Role: "admin"}}
	if err = s.CreateFirstAdmin(ctx, u, hash); err != nil {
		return User{}, err
	}
	return u, nil
}
