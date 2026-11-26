package plainauth

import (
	"context"
	"errors"
	"slices"
	"time"
)

// ErrVerificationPending ends a store call that a VerificationGate stopped
// because a record it was about to write awaits its before hooks. The store
// returns it, alone or joined with errors.Join, after rolling back, never
// retries it and commits nothing.
var ErrVerificationPending = errors.New("plainauth: a verification record awaits its before hooks")

var errVerificationUnasked = errors.New("auth: a store committed while a verification record awaited its before hooks")

// VerificationGate runs the verification database hooks of the records a
// store creates, updates or deletes inside its own transaction, where no hook
// may run. A plugin makes such a store call through
// EndpointContext.GateVerifications; the store finds the gate with
// VerificationGateFrom.
//
// Just before each write, after every check that could refuse the call, the
// store asks Create, Update or Delete. The first time the gate is asked about
// a record whose before hooks are set, it answers ErrVerificationPending. The
// store first asks about the call's other records, so that their hooks run in
// one pass, then returns the error and rolls back. The hooks then run outside
// the transaction and the call runs again. On that run the same record gets
// their answer, and a record that changed is asked about again. A declined
// record is left as it is, and the store goes on as its plugin documents:
// without that write, or with the plugin's refusal. Once the call returns
// nil, the after hooks run for the records it was allowed to write, in the
// order it asked.
//
// A record's fields must be the same on every run, so a store dates a record
// it creates from Now or from values fixed before the call, and judges expiry
// with its own clock. A record names the stored row by its ID, kind, owner
// and expiry, and never carries what redeems it. A nil gate allows every
// record and runs no hook, so a store calls it unconditionally.
type VerificationGate struct {
	a       *Auth
	now     time.Time
	answers []gateAnswer // what the before hooks said, kept for the request
	pending []gateEntry  // the records the current run waits on
	allowed []gateEntry  // the records the current run may write, in the order asked
}

type gateOp uint8

const (
	gateCreate gateOp = iota
	gateUpdate
	gateDelete
)

type gateEntry struct {
	op  gateOp
	rec VerificationRecord
}

type gateAnswer struct {
	gateEntry
	ok bool
}

type verificationGateKey struct{}

// VerificationGateFrom returns the gate of the store call ctx belongs to, or nil.
func VerificationGateFrom(ctx context.Context) *VerificationGate {
	g, _ := ctx.Value(verificationGateKey{}).(*VerificationGate)
	return g
}

// Now returns the time the gate was made, in UTC to the millisecond, or the
// current time for a nil gate. It is fixed for the request.
func (g *VerificationGate) Now() time.Time {
	if g == nil {
		return time.Now().UTC()
	}
	return g.now
}

// Create reports whether the store may store rec. false means a before hook
// declined it; ErrVerificationPending means the hooks have yet to see it.
func (g *VerificationGate) Create(rec VerificationRecord) (bool, error) {
	return g.ask(gateCreate, rec)
}

// Update reports, as Create does, whether the store may change rec, which
// carries the record as the change leaves it.
func (g *VerificationGate) Update(rec VerificationRecord) (bool, error) {
	return g.ask(gateUpdate, rec)
}

// Delete reports, as Create does, whether the store may spend or remove rec.
func (g *VerificationGate) Delete(rec VerificationRecord) (bool, error) {
	return g.ask(gateDelete, rec)
}

func (g *VerificationGate) chain(op gateOp) operationChain[VerificationRecord] {
	v := g.a.dbHooks.verification
	switch op {
	case gateCreate:
		return v.create
	case gateUpdate:
		return v.update
	}
	return v.delete
}

func (g *VerificationGate) ask(op gateOp, rec VerificationRecord) (bool, error) {
	if g == nil {
		return true, nil
	}
	chain := g.chain(op)
	if !chain.set() {
		return true, nil
	}
	rec.ExpiresAt = rec.ExpiresAt.UTC().Truncate(time.Millisecond)
	e := gateEntry{op, rec}
	if len(chain.before) > 0 {
		i := slices.IndexFunc(g.answers, func(a gateAnswer) bool { return a.gateEntry == e })
		if i < 0 {
			if !slices.Contains(g.pending, e) {
				g.pending = append(g.pending, e)
			}
			return false, ErrVerificationPending
		}
		if !g.answers[i].ok {
			return false, nil
		}
	}
	if !slices.Contains(g.allowed, e) { // a two-pass call asks twice; its after hooks run once
		g.allowed = append(g.allowed, e)
	}
	return true, nil
}

// gateHookContext strips the gate and any sign-in plan, so that a hook
// calling the Auth starts afresh. It keeps the HookContext.
func gateHookContext(ctx context.Context) context.Context {
	ctx = context.WithValue(ctx, verificationGateKey{}, (*VerificationGate)(nil))
	return context.WithValue(ctx, loginPlanKey{}, (*LoginPlan)(nil))
}

// run calls call with g in its context. It calls again after each stop, once
// the queued before hooks ran outside. A nil g hides an outer gate. It runs no
// after hook.
func (g *VerificationGate) run(ctx context.Context, call func(context.Context) error) error {
	inner := context.WithValue(ctx, verificationGateKey{}, g)
	if g == nil {
		return call(inner)
	}
	for range 4 {
		g.pending, g.allowed = nil, nil
		err := call(inner)
		if len(g.pending) == 0 {
			return err
		}
		if err == nil {
			// The store committed although it was told to stop: fail closed,
			// and run no after hook.
			g.allowed = nil
			g.a.Logger().ErrorContext(ctx, errVerificationUnasked.Error())
			return errVerificationUnasked
		}
		if !errors.Is(err, ErrVerificationPending) {
			return err
		}
		hookCtx := gateHookContext(ctx)
		for _, e := range g.pending {
			err := g.a.beforeVerification(hookCtx, g.chain(e.op), e.rec)
			if err != nil && !errors.Is(err, ErrSkipWrite) {
				return err
			}
			g.answers = append(g.answers, gateAnswer{e, err == nil})
		}
	}
	return errors.New("auth: the verification records kept changing while their hooks ran")
}

// after runs the after hooks of the records the last run was allowed to write.
func (g *VerificationGate) after(ctx context.Context) error {
	if g == nil {
		return nil
	}
	allowed := g.allowed
	g.allowed = nil
	for _, e := range allowed {
		if err := runAfter(gateHookContext(ctx), g.a, g.chain(e.op), e.rec); err != nil {
			return err
		}
	}
	return nil
}

// newVerificationGate returns a gate for one request, or nil when no
// verification hook is set.
func (a *Auth) newVerificationGate() *VerificationGate {
	if !a.dbHooks.verification.set() {
		return nil
	}
	return &VerificationGate{a: a, now: a.now().UTC().Truncate(time.Millisecond)}
}
