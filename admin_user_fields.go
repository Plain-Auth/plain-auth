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
	plan := &adminCreatePlan{}
	body := func(tx AdminUserCreator) error {
		if err := a.configureAdminProjection(tx, req.Operation); err != nil {
			return err
		}
		var err error
		result, err = a.createAdministrativeUser(ctx, tx, nil, req, now, plan)
		return err
	}
	err := store.AdminCreateTransaction(ctx, now, body)
	if errors.Is(err, errAdminPlanned) {
		if err = a.validateAdminUser(ctx, plan, req); err == nil {
			err = store.AdminCreateTransaction(ctx, now, body)
		}
	}
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

// adminCreatePlan carries an administrative user between the run that
// builds it and the run that stores it after ValidateUserInfo admitted it.
type adminCreatePlan struct {
	user     *User
	hash     string
	values   UserFieldValues
	fields   map[string]any
	approved bool
}

var errAdminPlanned = errors.New("admin: user planned for ValidateUserInfo")

// validateAdminUser runs ValidateUserInfo on a planned administrative user.
func (a *Auth) validateAdminUser(ctx context.Context, plan *adminCreatePlan, req AdminRequest) error {
	if err := a.ValidateUserInfo(ctx, UserInfoValidation{Action: UserInfoCreateUser, Method: "admin", User: UserRecord{User: *plan.user, Fields: plan.fields}}); err != nil {
		return err
	}
	plan.approved = true
	return nil
}

// createAdministrativeUser builds and inserts a user. With ValidateUserInfo
// set, a first run inserts and rolls back with errAdminPlanned, so the gate
// runs outside the transaction; the approved run stores the same user.
func (a *Auth) createAdministrativeUser(ctx context.Context, tx AdminUserCreator, actor *User, req AdminRequest, now time.Time, plan *adminCreatePlan) (*User, error) {
	u := User{
		ID: randomID(), Name: req.Name, Email: strings.ToLower(req.Email),
		CreatedAt: now, UpdatedAt: now,
		AdminUserFields: &AdminUserFields{Role: a.admin.DefaultRole},
	}
	if plan.approved {
		u.ID = plan.user.ID
	}
	if len(u.Email) > 254 || strings.Contains(u.Email, "..") || !emailPattern.MatchString(u.Email) || req.Name == "" {
		return nil, validationError("A valid email and name are required")
	}
	if err := a.adminUpdateFields(ctx, actor, &u, req, true); err != nil {
		return nil, err
	}
	// The approved run stores the values the gate saw, computed defaults
	// included. A session actor cannot set server-only fields.
	input := a.userFieldInput(req.Data)
	values := plan.values
	var err error
	if !plan.approved {
		if values, err = a.prepareUserFields(input, true, actor == nil); err != nil {
			return nil, err
		}
	}
	if actor != nil {
		input = serverInput(a.opts.UserAdditionalFields, input)
	}
	var hash string
	if plan.approved {
		hash = plan.hash
	} else if req.Password != "" {
		if err := a.validatePasswordLength(req.Password, false); err != nil {
			return nil, err
		}
		hash, err = a.hashCredential(ctx, "/admin/create-user", req.Password)
		if err != nil {
			return nil, err
		}
	}
	// planned ends the first run once the insert shows the email is free.
	planned := func(stored *User) (*User, error) {
		if a.opts.ValidateUserInfo == nil || plan.approved {
			return stored, nil
		}
		plan.user, plan.hash, plan.values, plan.fields = stored, hash, values, input
		return nil, errAdminPlanned
	}
	if !values.Present() {
		if err := tx.CreateUser(u, hash); err != nil {
			return nil, err
		}
		return planned(&u)
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
	return planned(&stored)
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
