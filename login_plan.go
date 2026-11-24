package plainauth

import (
	"context"
	"errors"
)

// LoginPlan lets the create before hooks run, outside any transaction, for a
// sign-in whose store decides inside its transaction whether to create the
// user or which session to issue: social sign-in, One Tap, SSO, magic links,
// email codes, phone verification, two-factor sign-in and verification,
// device grants and the sign-in after an email link.
//
// The Auth runs the store method twice with a plan in its context. The dry
// run records the user and session the sign-in would insert and rolls back.
// The hooks then run on those rows, and the approved run inserts them with
// the hooks' edits. If the approved run would write different rows, because
// another request changed the data in between, it fails with
// ErrLoginPlanChanged and the Auth starts again.
//
// A store supports plans by implementing LoginPlanner and, in those sign-in
// methods, calling Attempt when it begins each transaction attempt,
// including retries, PlanUser just before inserting a new user, PlanSession
// just before inserting the session and Commit just before committing,
// returning their errors. The methods do nothing on a nil plan, so a store
// can call them with LoginPlanFrom(ctx) unconditionally.
type LoginPlan struct {
	approved                bool
	user                    *User
	session                 *StoredSession
	wroteUser, wroteSession bool
}

// LoginPlanner is implemented by a store whose sign-in methods support plans.
type LoginPlanner interface{ PlansLogins() }

var (
	// ErrLoginPlanned ends a dry run. The store rolls back and returns it.
	ErrLoginPlanned = errors.New("plainauth: sign-in planned and rolled back")
	// ErrLoginPlanChanged ends an approved run whose writes differ from the dry run.
	ErrLoginPlanChanged = errors.New("plainauth: sign-in changed while its hooks ran")
)

type loginPlanKey struct{}

// LoginPlanFrom returns the plan of the sign-in ctx belongs to, or nil.
func LoginPlanFrom(ctx context.Context) *LoginPlan {
	p, _ := ctx.Value(loginPlanKey{}).(*LoginPlan)
	return p
}

// Attempt is called when a store begins a transaction attempt. It forgets
// what an earlier, rolled-back attempt of the same run recorded or wrote.
func (p *LoginPlan) Attempt() {
	if p == nil {
		return
	}
	if p.approved {
		p.wroteUser, p.wroteSession = false, false
	} else {
		p.user, p.session = nil, nil
	}
}

// PlanUser is called with the user a store is about to insert. A dry run
// records it; an approved run applies the hooks' edits to it.
func (p *LoginPlan) PlanUser(u *User) error {
	if p == nil {
		return nil
	}
	if !p.approved {
		planned := *u
		p.user = &planned
		return nil
	}
	if p.user == nil || p.user.ID != u.ID || p.wroteUser {
		return ErrLoginPlanChanged
	}
	p.wroteUser = true
	u.Name, u.Image = p.user.Name, p.user.Image
	return nil
}

// PlanSession is called with the session a store is about to insert. A dry
// run records it; an approved run replaces it with the hooks' version.
func (p *LoginPlan) PlanSession(s *StoredSession) error {
	if p == nil {
		return nil
	}
	if !p.approved {
		planned := *s
		p.session = &planned
		return nil
	}
	if p.session == nil || p.session.ID != s.ID || p.session.UserID != s.UserID || p.wroteSession {
		return ErrLoginPlanChanged
	}
	p.wroteSession = true
	*s = *p.session
	return nil
}

// Commit is called just before a store commits. It returns ErrLoginPlanned
// for a dry run, and ErrLoginPlanChanged when an approved run did not write
// what the dry run planned.
func (p *LoginPlan) Commit() error {
	if p == nil {
		return nil
	}
	if !p.approved {
		return ErrLoginPlanned
	}
	if (p.user != nil) != p.wroteUser || (p.session != nil) != p.wroteSession {
		return ErrLoginPlanChanged
	}
	return nil
}

var (
	errPlannedUserSkipped    = &APIError{500, "FAILED_TO_CREATE_USER", "Failed to create user"}
	errPlannedSessionSkipped = &APIError{500, "FAILED_TO_CREATE_SESSION", "Failed to create session"}
)

// planSignIn runs a store-decided sign-in. With create before hooks it runs
// store twice, with the hooks between a dry run and the approved run, and
// starts again when the data changed in between. A skipped user or session
// returns errPlannedUserSkipped or errPlannedSessionSkipped.
func (a *Auth) planSignIn(ctx context.Context, store func(context.Context) error) error {
	if len(a.dbHooks.user.create.before) == 0 && len(a.dbHooks.session.create.before) == 0 {
		return store(ctx)
	}
	for range 3 {
		plan := &LoginPlan{}
		err := store(context.WithValue(ctx, loginPlanKey{}, plan))
		if !errors.Is(err, ErrLoginPlanned) {
			return err
		}
		if err := a.approveLoginPlan(ctx, plan); err != nil {
			return err
		}
		err = store(context.WithValue(ctx, loginPlanKey{}, plan))
		if !errors.Is(err, ErrLoginPlanChanged) {
			return err
		}
	}
	return errors.New("auth: the sign-in kept changing while its hooks ran")
}

// approveLoginPlan runs the create before hooks on a dry run's rows. The
// store chose these users' email, its verification and their fields, which
// decide how the sign-in continues, so hooks may change only Name and Image.
func (a *Auth) approveLoginPlan(ctx context.Context, plan *LoginPlan) error {
	if plan.user != nil {
		edited, fields, err := a.beforeUserCreate(ctx, *plan.user, nil)
		if errors.Is(err, ErrSkipWrite) {
			return errPlannedUserSkipped
		}
		if err != nil {
			return err
		}
		if edited.Email != plan.user.Email || edited.EmailVerified != plan.user.EmailVerified || len(fields) > 0 {
			a.Logger().ErrorContext(ctx, errDatabaseHookEdit.Error(), "model", "user")
			return errDatabaseHookEdit
		}
		plan.user = &edited
	}
	if plan.session != nil {
		row, _, err := a.beforeSessionCreate(ctx, *plan.session, nil, errPlannedSessionSkipped)
		if err != nil {
			return err
		}
		plan.session = &row
	}
	plan.approved = true
	return nil
}
