package plainauth

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"
)

// A VerificationGate stops a store call at the first record whose before
// hooks have yet to run, runs them outside the call without the gate or a
// sign-in plan in their context, and calls again bound to what they said;
// once the call returns nil, the after hooks run for what it was allowed to
// write, in the order it asked.
func TestVerificationGate(t *testing.T) {
	var events []string
	var o Options
	skip, edit := map[string]bool{}, false
	var fail error
	var seen []VerificationRecord
	note := func(ctx context.Context, event string, rec *VerificationRecord, c *HookContext) error {
		events = append(events, event+":"+rec.ID)
		seen = append(seen, *rec)
		if VerificationGateFrom(ctx) != nil || LoginPlanFrom(ctx) != nil {
			t.Error("a hook ran with the gate or a sign-in plan in its context")
		}
		if c == nil || c.Path != "/gated" {
			t.Error("a hook lost its HookContext")
		}
		if skip[event+":"+rec.ID] {
			return ErrSkipWrite
		}
		return fail
	}
	v := &o.DatabaseHooks.Verification
	v.Create.Before = func(ctx context.Context, r *VerificationRecord, c *HookContext) error {
		err := note(ctx, "create-before", r, c)
		if edit {
			r.UserID = "someone-else"
		}
		return err
	}
	v.Create.After = func(ctx context.Context, r VerificationRecord, c *HookContext) error {
		return note(ctx, "create-after", &r, c)
	}
	v.Delete.Before = func(ctx context.Context, r *VerificationRecord, c *HookContext) error {
		return note(ctx, "delete-before", r, c)
	}
	v.Delete.After = func(ctx context.Context, r VerificationRecord, c *HookContext) error {
		return note(ctx, "delete-after", &r, c)
	}
	logs := &bytes.Buffer{}
	o.Logger = slog.New(slog.NewTextHandler(logs, nil))
	a := &Auth{opts: o, dbHooks: composeDatabaseHooks(o), now: time.Now}
	base := context.WithValue(context.Background(), hookContextKey{a}, &HookContext{Path: "/gated"})
	base = context.WithValue(base, loginPlanKey{}, &LoginPlan{})
	same := func(want ...string) {
		t.Helper()
		if len(events)+len(want) > 0 && !reflect.DeepEqual(events, want) {
			t.Fatalf("ran %q, want %q", events, want)
		}
		events = nil
	}
	at := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	rec := func(id string) VerificationRecord {
		return VerificationRecord{ID: id, Identifier: "ledger", UserID: "owner", ExpiresAt: at}
	}
	// gated runs call through a fresh gate and its after hooks, as
	// EndpointContext.GateVerifications does.
	gated := func(call func(context.Context) error) error {
		g := a.newVerificationGate()
		if err := g.run(base, call); err != nil {
			return err
		}
		return g.after(base)
	}
	// store asks the gate about each record, stopping as a store does.
	store := func(ask func(*VerificationGate) (bool, error)) func(context.Context) error {
		return func(ctx context.Context) error {
			events = append(events, "call")
			ok, err := ask(VerificationGateFrom(ctx))
			if err != nil {
				return err
			}
			if !ok {
				events = append(events, "declined")
			}
			return nil
		}
	}

	// Without verification hooks there is no gate, and every record is allowed.
	none := &Auth{now: time.Now}
	var g *VerificationGate = none.newVerificationGate()
	if g != nil {
		t.Fatal("a gate was made without verification hooks")
	}
	for _, ask := range []func(VerificationRecord) (bool, error){g.Create, g.Update, g.Delete} {
		if ok, err := ask(rec("x")); !ok || err != nil {
			t.Fatal("a nil gate refused a record:", err)
		}
	}
	if time.Since(g.Now()) > time.Minute || VerificationGateFrom(context.Background()) != nil {
		t.Fatal("a nil gate reported", g.Now())
	}
	calls := 0
	outer := a.newVerificationGate()
	if err := g.run(context.WithValue(base, verificationGateKey{}, outer), func(ctx context.Context) error {
		calls++
		if VerificationGateFrom(ctx) != nil {
			t.Error("a nil gate let an outer gate through")
		}
		return nil
	}); err != nil || calls != 1 || g.after(base) != nil {
		t.Fatal("a nil gate ran", calls, "calls")
	}

	// The first ask stops the call; the hooks run once outside; the call runs
	// again and the after hooks follow.
	if err := gated(store(func(g *VerificationGate) (bool, error) { return g.Create(rec("a")) })); err != nil {
		t.Fatal(err)
	}
	same("call", "create-before:a", "call", "create-after:a")
	// Two records in one call run their hooks in one pass, in ask order; a
	// record asked twice in a run runs its after hooks once.
	if err := gated(store(func(g *VerificationGate) (bool, error) {
		ok1, e1 := g.Create(rec("b"))
		ok2, e2 := g.Delete(rec("c"))
		if _, e3 := g.Create(rec("b")); e3 != nil && !errors.Is(e3, ErrVerificationPending) {
			return false, e3
		}
		return ok1 && ok2, errors.Join(e1, e2)
	})); err != nil {
		t.Fatal(err)
	}
	same("call", "create-before:b", "delete-before:c", "call", "create-after:b", "delete-after:c")
	// A declined record is reported false and runs no after hook; a new gate
	// asks again.
	skip["create-before:d"] = true
	for range 2 {
		if err := gated(store(func(g *VerificationGate) (bool, error) { return g.Create(rec("d")) })); err != nil {
			t.Fatal(err)
		}
		same("call", "create-before:d", "call", "declined")
	}
	delete(skip, "create-before:d")
	// A record that changed is asked about again; one that changes on every
	// run fails after four.
	run := 0
	if err := gated(store(func(g *VerificationGate) (bool, error) {
		run++
		r := rec("e")
		if run > 1 {
			r.ExpiresAt = at.Add(time.Millisecond)
		}
		return g.Create(r)
	})); err != nil {
		t.Fatal(err)
	}
	same("call", "create-before:e", "call", "create-before:e", "call", "create-after:e")
	run = 0
	err := gated(store(func(g *VerificationGate) (bool, error) {
		run++
		r := rec("f")
		r.ExpiresAt = at.Add(time.Duration(run) * time.Millisecond)
		return g.Create(r)
	}))
	if err == nil || !strings.Contains(err.Error(), "kept changing") || run != 4 {
		t.Fatal("a record that kept changing answered", err, "after", run, "runs")
	}
	events = nil
	// A before hook's error ends the call; a hook may not change the record.
	fail = errors.New("hook failed")
	if err := gated(store(func(g *VerificationGate) (bool, error) { return g.Create(rec("g")) })); !errors.Is(err, fail) {
		t.Fatal("a before hook's error answered", err)
	}
	fail = nil
	same("call", "create-before:g")
	edit = true
	if err := gated(store(func(g *VerificationGate) (bool, error) { return g.Create(rec("h")) })); !errors.Is(err, errDatabaseHookEdit) {
		t.Fatal("an edited record answered", err)
	}
	edit = false
	same("call", "create-before:h")
	// An expiry in another zone with nanoseconds is seen in UTC to the millisecond.
	seen = nil
	odd := rec("i")
	odd.ExpiresAt = time.Date(2030, 1, 2, 4, 4, 5, 123456789, time.FixedZone("UTC+1", 3600))
	if err := gated(store(func(g *VerificationGate) (bool, error) { return g.Delete(odd) })); err != nil {
		t.Fatal(err)
	}
	same("call", "delete-before:i", "call", "delete-after:i")
	want := rec("i")
	want.ExpiresAt = at.Add(123 * time.Millisecond)
	if len(seen) != 2 || seen[0] != want || seen[1] != want {
		t.Fatal("the hooks saw", seen)
	}
	// Errors pass through: a stop with nothing pending, and any other error.
	other := errors.New("store failed")
	for _, e := range []error{ErrVerificationPending, other} {
		if err := gated(func(context.Context) error { return e }); err != e {
			t.Fatal("a store error came back as", err)
		}
	}
	// A store that commits while a record awaits its hooks is refused.
	if err := gated(func(ctx context.Context) error {
		VerificationGateFrom(ctx).Create(rec("j"))
		return nil
	}); !errors.Is(err, errVerificationUnasked) || !strings.Contains(logs.String(), "awaited its before hooks") {
		t.Fatal("a store that ignored a stop answered", err)
	}
	same()

	// With only after hooks, nothing stops; an ask for an operation with no
	// hooks is allowed and runs none.
	o.DatabaseHooks.Verification = ModelHooks[VerificationRecord]{Create: OperationHooks[VerificationRecord]{After: v.Create.After}}
	a = &Auth{opts: o, dbHooks: composeDatabaseHooks(o), now: time.Now}
	base = context.WithValue(context.Background(), hookContextKey{a}, &HookContext{Path: "/gated"})
	if err := gated(store(func(g *VerificationGate) (bool, error) {
		ok, err := g.Delete(rec("k"))
		if !ok || err != nil {
			return ok, err
		}
		return g.Create(rec("l"))
	})); err != nil {
		t.Fatal(err)
	}
	same("call", "create-after:l")
	// A store that retries its transaction inside one call starts each
	// attempt afresh, so only the last attempt's records run after hooks.
	if err := gated(func(ctx context.Context) error {
		g := VerificationGateFrom(ctx)
		g.Create(rec("rolled-back"))
		g.Attempt()
		_, err := g.Create(rec("committed"))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	same("create-after:committed")
}
