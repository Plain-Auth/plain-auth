package plainauth

import (
	"context"
	"errors"
	"strings"
	"time"
)

// AdminCreateUserRequest contains a trusted or session-authorized administrative request.
type AdminCreateUserRequest struct {
	Name     string         `json:"name"`
	Email    string         `json:"email"`
	Password string         `json:"password,omitempty"`
	Role     []string       `json:"role,omitempty"`
	Data     map[string]any `json:"data,omitempty"`
}

// AdminUserCreator writes a profile and its optional password in one transaction.
type AdminUserCreator interface {
	CreateUser(User, string) error
}

// AdminUserFieldTransaction persists validated columns during creation and
// projects the public columns from the same row as the ordinary User fields.
type AdminUserFieldTransaction interface {
	CreateAdminUserWithFields(User, string, UserFieldValues) error
	User(string) (User, error)
	SelectAdminUserFields(map[string]UserField, func(*User, map[string]any) error) error
}

// AdminHostCreateStore runs the explicitly trusted, in-process create operation.
type AdminHostCreateStore interface {
	AdminCreateTransaction(context.Context, time.Time, func(AdminUserCreator) error) error
}

// AdminCreateUser lets trusted application code provision an account, including
// server-owned fields. Do not expose this method directly as an HTTP handler.
func (a *Auth) AdminCreateUser(ctx context.Context, in AdminCreateUserRequest) (*User, error) {
	if a.adminStore == nil {
		return nil, adminError(404, "NOT_FOUND", "Not found")
	}
	store, ok := a.adminStore.(AdminHostCreateStore)
	if !ok {
		return nil, errors.New("admin: store does not support host account creation")
	}
	now := a.now().UTC().Truncate(time.Millisecond)
	var result *User
	req := AdminRequest{
		Operation: "create-user",
		Name:      in.Name, Email: in.Email, Password: in.Password,
		Role: in.Role, Data: in.Data,
	}
	err := store.AdminCreateTransaction(ctx, now, func(tx AdminUserCreator) error {
		if err := a.configureAdminProjection(tx, req.Operation); err != nil {
			return err
		}
		var err error
		result, err = a.createAdministrativeUser(ctx, tx, nil, req, now)
		return err
	})
	if errors.Is(err, ErrEmailTaken) {
		return nil, adminError(400, "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL", "User already exists. Use another email.")
	}
	if err != nil {
		return nil, usernameWriteError(err)
	}
	return result, nil
}

func (a *Auth) requireAdminFieldGrant(actor *User, operation string) error {
	// Only the trusted native provisioning entry point supplies a nil actor.
	if actor == nil {
		return nil
	}
	return a.requireAdminGrant(*actor, operation)
}

func (a *Auth) createAdministrativeUser(ctx context.Context, tx AdminUserCreator, actor *User, req AdminRequest, now time.Time) (*User, error) {
	u := User{
		ID: randomID(), Name: req.Name, Email: strings.ToLower(req.Email),
		CreatedAt: now, UpdatedAt: now,
		AdminUserFields: &AdminUserFields{Role: a.admin.DefaultRole},
	}
	if len(u.Email) > 254 || strings.Contains(u.Email, "..") || !emailPattern.MatchString(u.Email) || req.Name == "" {
		return nil, validationError("A valid email and name are required")
	}
	if err := a.adminUpdateFields(ctx, actor, &u, req, true); err != nil {
		return nil, err
	}
	values, err := a.prepareUserFields(a.userFieldInput(req.Data), true, actor == nil)
	if err != nil {
		return nil, err
	}
	var hash string
	if req.Password != "" {
		if err := a.validatePasswordLength(req.Password, false); err != nil {
			return nil, err
		}
		hash, err = a.hashCredential(ctx, "/admin/create-user", req.Password)
		if err != nil {
			return nil, err
		}
	}
	if !values.Present() {
		if err := tx.CreateUser(u, hash); err != nil {
			return nil, err
		}
		return &u, nil
	}
	fields, ok := tx.(AdminUserFieldTransaction)
	if !ok {
		return nil, errors.New("admin: transaction does not support configured user fields")
	}
	if err := fields.CreateAdminUserWithFields(u, hash, values); err != nil {
		return nil, err
	}
	stored, err := fields.User(u.ID)
	if err != nil {
		return nil, err
	}
	return &stored, nil
}

func (a *Auth) configureAdminProjection(tx AdminUserCreator, op string) error {
	if len(a.opts.UserAdditionalFields) > 0 && (op == "get-user" || op == "list-users" || op == "create-user") {
		fields, ok := tx.(AdminUserFieldTransaction)
		if !ok {
			return errors.New("admin: transaction does not support configured user fields")
		}
		if err := fields.SelectAdminUserFields(a.opts.UserAdditionalFields, a.projectPublicUser); err != nil {
			return err
		}
	}
	if a.phoneNumber != nil {
		projection, ok := tx.(interface{ SelectPhoneFields() })
		if !ok {
			return errors.New("admin: store does not support phone fields")
		}
		projection.SelectPhoneFields()
	}
	if a.username != nil {
		// Composite stores enable these fields only for this authorized transaction.
		if projection, ok := tx.(interface{ SelectUsernameFields(bool) }); ok {
			projection.SelectUsernameFields(!a.username.DisableDisplay)
		}
	}
	return nil
}
