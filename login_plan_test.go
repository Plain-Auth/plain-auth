package plainauth

import (
	"errors"
	"testing"
)

// A store that retries its transaction inside one run calls Attempt, so the
// plan forgets what the rolled-back attempt recorded or wrote.
func TestLoginPlanAttempts(t *testing.T) {
	user := User{ID: "candidate", Name: "Draft"}
	session := StoredSession{Session: Session{ID: "session", UserID: "candidate"}}
	plan := &LoginPlan{}

	// Dry run: the first attempt records a user, then retries and finds an existing owner.
	plan.Attempt()
	if err := plan.PlanUser(&user); err != nil {
		t.Fatal(err)
	}
	plan.Attempt()
	owned := StoredSession{Session: Session{ID: "session", UserID: "existing"}}
	if err := plan.PlanSession(&owned); err != nil {
		t.Fatal(err)
	}
	if err := plan.Commit(); !errors.Is(err, ErrLoginPlanned) {
		t.Fatal("a dry run committed", err)
	}
	if plan.user != nil || plan.session == nil || plan.session.UserID != "existing" {
		t.Fatal("the dry run kept a row from a rolled-back attempt")
	}

	// Approved run: a rolled-back attempt that wrote the planned rows may write them again.
	plan = &LoginPlan{user: &User{ID: "candidate", Name: "Edited"}, session: &session, approved: true}
	for range 2 {
		plan.Attempt()
		draft := User{ID: "candidate", Name: "Draft"}
		if err := plan.PlanUser(&draft); err != nil || draft.Name != "Edited" {
			t.Fatal("a retried attempt could not write the planned user", err)
		}
		if err := plan.PlanSession(&StoredSession{Session: Session{ID: "session", UserID: "candidate"}}); err != nil {
			t.Fatal("a retried attempt could not write the planned session", err)
		}
	}
	if err := plan.Commit(); err != nil {
		t.Fatal(err)
	}
	// Writing a different owner or skipping the planned user is a change.
	plan.Attempt()
	if err := plan.PlanSession(&StoredSession{Session: Session{ID: "session", UserID: "someone-else"}}); !errors.Is(err, ErrLoginPlanChanged) {
		t.Fatal("a different owner was accepted", err)
	}
	plan.Attempt()
	if err := plan.Commit(); !errors.Is(err, ErrLoginPlanChanged) {
		t.Fatal("an attempt that skipped the planned rows committed", err)
	}
	// Nil plans do nothing.
	var none *LoginPlan
	none.Attempt()
	if none.PlanUser(&user) != nil || none.PlanSession(&session) != nil || none.Commit() != nil {
		t.Fatal("a nil plan interfered")
	}
}
