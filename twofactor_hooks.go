package plainauth

import (
	"context"
	"errors"
	"time"
)

// A two-factor call judges, stores and spends its verification records inside
// the store's transaction, where no hook may run. Its decision therefore asks
// factorHooks whether each record was approved. A record whose before hooks
// have not run is queued and the run ends with errFactorUnapproved: the store
// rolls back, the hooks run outside, and the call runs again bound to what
// they saw. A run that needs no new approval commits on its first try.
var (
	errFactorUnapproved   = errors.New("auth: two-factor records await their verification hooks")
	errFactorSendDeclined = errors.New("auth: a verification hook declined the delivered code")
)

type factorRole uint8

const (
	roleDelivery  factorRole = iota // a guess judged against a delivered code: delete before
	roleChallenge                   // a guess judged against a sign-in challenge: delete before
	roleSpend                       // a sign-in spends a remembered browser's grant: delete before
	roleGrant                       // a new remembered browser: create before
	roleIssue                       // a new sign-in challenge: create before
	roleSend                        // a new delivered code: create before
)

type factorVerdict uint8

const (
	factorApproved factorVerdict = iota
	factorDeclined
	factorPending
)

type factorWant struct {
	role factorRole
	rec  VerificationRecord
}

type factorAnswer struct {
	rec VerificationRecord
	ok  bool
}

// factorHooks follows the verification records of one two-factor call; it is
// nil when no verification hook is set.
type factorHooks struct {
	a *Auth
	// delivery and challenge follow the guess, as for an email or phone code:
	// the record their delete before hooks approved, kept across runs.
	delivery, challenge codeGuess
	// asked holds what the other roles' before hooks said, kept across runs.
	asked map[factorRole]factorAnswer
	// want and marked belong to the current run: the records it waits on,
	// and the approved records it would write.
	want   []factorWant
	marked map[factorRole]VerificationRecord
	// state and change are what the last run saw and returned; once the
	// store call returns nil, they are what it committed.
	state  FactorState
	change FactorChange
}

func (a *Auth) newFactorHooks() *factorHooks {
	if !a.dbHooks.verification.set() {
		return nil
	}
	return &factorHooks{a: a, asked: map[factorRole]factorAnswer{}, marked: map[factorRole]VerificationRecord{}}
}

// factorRecord is a two-factor row as a verification record: a sign-in
// challenge with its attempt counter ("2fa"), a delivered code ("2fa-otp")
// or a remembered browser ("trust-device"). A second factor proves an
// account, so each names its owner, and none carries a key, code or count.
func factorRecord(kind, id, userID string, expiresAt time.Time) VerificationRecord {
	return VerificationRecord{ID: id, Identifier: kind, UserID: userID, ExpiresAt: expiresAt.UTC().Truncate(time.Millisecond)}
}

func (h *factorHooks) chain(role factorRole) operationChain[VerificationRecord] {
	if role == roleSpend {
		return h.a.dbHooks.verification.delete
	}
	return h.a.dbHooks.verification.create
}

// follow wraps decide so that each run starts with nothing queued or marked,
// and records what it saw and returned.
func (h *factorHooks) follow(decide func(FactorState) (FactorChange, error)) func(FactorState) (FactorChange, error) {
	if h == nil {
		return decide
	}
	return func(st FactorState) (FactorChange, error) {
		h.want, h.marked = nil, map[factorRole]VerificationRecord{}
		ch, err := decide(st)
		h.state, h.change = st, ch
		return ch, err
	}
}

// approval reports what the before hooks of rec's create or spend said, for
// a record this run would write in role. A record they have not seen, or
// another than the one they answered for, is queued and reported pending.
// With no before hook of that kind, rec is approved at once. An approved
// record is marked for the after hooks.
func (h *factorHooks) approval(role factorRole, rec VerificationRecord) factorVerdict {
	if h == nil || !h.chain(role).set() {
		return factorApproved
	}
	if len(h.chain(role).before) > 0 {
		answer, asked := h.asked[role]
		if !asked || answer.rec != rec {
			h.want = append(h.want, factorWant{role, rec})
			return factorPending
		}
		if !answer.ok {
			return factorDeclined
		}
	}
	h.marked[role] = rec
	return factorApproved
}

// allows reports whether this run may write role's record: no hooks follow
// it, or this run marked it approved.
func (h *factorHooks) allows(role factorRole) bool {
	if h == nil || !h.chain(role).set() {
		return true
	}
	_, ok := h.marked[role]
	return ok
}

// guess reports whether a guess may be judged against rec, the live record g
// follows: its delete before hooks approved rec, or none is set. A record they
// have not seen is queued (pending); one they approved another record for in
// its place has changed, which the guess refuses.
func (h *factorHooks) guess(g *codeGuess, role factorRole, rec VerificationRecord) (pending, changed bool) {
	if h == nil || !h.a.watchesCodes() {
		return false, false
	}
	if len(h.a.dbHooks.verification.delete.before) == 0 {
		g.rec = &rec
		return false, false
	}
	if g.rec == nil {
		h.want = append(h.want, factorWant{role, rec})
		return true, false
	}
	return false, *g.rec != rec
}

// approve runs, outside the store's transaction, the before hooks of the
// records the last run queued, in order. A declined guess ends the call with
// its refusal, and a declined delivered code with errFactorSendDeclined;
// other answers are kept for the next run, which acts on them. A new grant is
// not asked about once the spend of the grant it replaces was declined.
func (h *factorHooks) approve(ctx context.Context) error {
	if h == nil {
		return nil
	}
	want := h.want
	h.want = nil
	for _, w := range want {
		switch w.role {
		case roleDelivery:
			if err := h.a.beforeCodeGuess(ctx, &h.delivery, w.rec, otpExpired()); err != nil {
				return err
			}
			continue
		case roleChallenge:
			if err := h.a.beforeCodeGuess(ctx, &h.challenge, w.rec, factorCookieError()); err != nil {
				return err
			}
			continue
		case roleGrant:
			if spend, ok := h.asked[roleSpend]; ok && !spend.ok {
				continue
			}
		}
		err := h.a.beforeVerification(ctx, h.chain(w.role), w.rec)
		if err != nil && !errors.Is(err, ErrSkipWrite) {
			return err
		}
		h.asked[w.role] = factorAnswer{w.rec, err == nil}
		if w.role == roleSend && err != nil {
			return errFactorSendDeclined
		}
	}
	return nil
}

// after runs, once the store call returned nil, the after hooks of what its
// last run committed to the records their before hooks saw, before the
// session's: the guessed delivered code, then the challenge, then a spent
// remembered browser, a new challenge, a new remembered browser and a new
// delivered code. A record no before hook saw runs none.
func (h *factorHooks) after(ctx context.Context) error {
	if h == nil {
		return nil
	}
	st, ch, v := h.state, h.change, h.a.dbHooks.verification
	h.delivery.decision = PhoneKeepProof
	if d := st.Delivery; h.delivery.rec != nil && d != nil && d.ID == h.delivery.rec.ID {
		switch {
		case ch.RemoveDelivery || ch.ConsumeChallenge: // ConsumeChallenge removes the challenge's codes too
			h.delivery.decision = PhoneRemoveProof
		case ch.SaveDelivery != nil && ch.SaveDelivery.ID == d.ID && ch.SaveDelivery.Attempts > d.Attempts:
			h.delivery.decision = PhoneCountAttempt
		}
	}
	h.challenge.decision = PhoneKeepProof
	if h.challenge.rec != nil && st.ChallengeID == h.challenge.rec.ID {
		switch {
		case ch.ConsumeChallenge:
			h.challenge.decision = PhoneRemoveProof
		case ch.IncrementAttempts:
			h.challenge.decision = PhoneCountAttempt
		}
	}
	for _, g := range []*codeGuess{&h.delivery, &h.challenge} {
		if err := h.a.afterCodeGuess(ctx, g); err != nil {
			return err
		}
	}
	if rec, ok := h.marked[roleSpend]; ok && ch.CreateTrustedGrant != "" && st.TrustedGrantID == rec.ID {
		if err := runAfter(ctx, h.a, v.delete, rec); err != nil {
			return err
		}
	}
	if rec, ok := h.marked[roleIssue]; ok && ch.CreateChallenge != "" && ch.ChallengeID == rec.ID {
		if err := runAfter(ctx, h.a, v.create, rec); err != nil {
			return err
		}
	}
	if rec, ok := h.marked[roleGrant]; ok && ch.CreateTrustedGrant != "" && ch.TrustedGrantID == rec.ID {
		if err := runAfter(ctx, h.a, v.create, rec); err != nil {
			return err
		}
	}
	if rec, ok := h.marked[roleSend]; ok && ch.SaveDelivery != nil && ch.SaveDelivery.Pending && ch.SaveDelivery.ID == rec.ID {
		return runAfter(ctx, h.a, v.create, rec)
	}
	return nil
}

// runFactor runs call, a two-factor store call, again each time it ends with
// errFactorUnapproved, after the before hooks it queued ran outside the
// store's transaction. With retime, sub's time is taken again after them, so
// the store judges expiry at the time it writes. Each record's before hooks
// run at most once per request, so four runs cover any outcome.
func (a *Auth) runFactor(ctx context.Context, h *factorHooks, sub *FactorSubject, retime bool, call func(context.Context) error) error {
	for range 4 {
		err := call(ctx)
		if !errors.Is(err, errFactorUnapproved) {
			return err
		}
		if err := h.approve(ctx); err != nil {
			return err
		}
		if retime {
			sub.Now = a.now().UTC()
		}
	}
	return errors.New("auth: the two-factor call kept changing while its hooks ran")
}
