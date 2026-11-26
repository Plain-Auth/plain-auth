package plainauth

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

// factorHookTest is an Auth whose verification hooks record each event, and
// whose before hooks skip the events in skip.
func factorHookTest(t *testing.T, skip map[string]bool) (*Auth, *[]string) {
	t.Helper()
	var events []string
	note := func(event string, r VerificationRecord) error {
		events = append(events, event+":"+r.Identifier)
		if skip[event+":"+r.Identifier] {
			return ErrSkipWrite
		}
		return nil
	}
	var o Options
	v := &o.DatabaseHooks.Verification
	v.Create.Before = func(_ context.Context, r *VerificationRecord, _ *HookContext) error {
		return note("v-create-before", *r)
	}
	v.Create.After = func(_ context.Context, r VerificationRecord, _ *HookContext) error { return note("v-create-after", r) }
	v.Update.After = func(_ context.Context, r VerificationRecord, _ *HookContext) error { return note("v-update-after", r) }
	v.Delete.Before = func(_ context.Context, r *VerificationRecord, _ *HookContext) error {
		return note("v-delete-before", *r)
	}
	v.Delete.After = func(_ context.Context, r VerificationRecord, _ *HookContext) error { return note("v-delete-after", r) }
	return &Auth{opts: o, dbHooks: composeDatabaseHooks(o)}, &events
}

// After a two-factor store call commits, the hooks run the after hooks of
// the records its last run wrote, as the records their before hooks saw: a
// code removed with its challenge counts as removed, and a record no before
// hook saw runs none.
func TestFactorHooksFollowCommittedChanges(t *testing.T) {
	at := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	challenge := factorRecord("2fa", "challenge-row", "owner", at)
	code := factorRecord("2fa-otp", "code-row", "owner", at)
	oldGrant := factorRecord("trust-device", "old-grant", "owner", at)
	newGrant := factorRecord("trust-device", "new-grant", "owner", at)
	delivery := &FactorDelivery{ID: "code-row", Attempts: 1, ExpiresAt: at}
	counted := *delivery
	counted.Attempts++
	sent := FactorDelivery{ID: "code-row", ExpiresAt: at}
	for _, tc := range []struct {
		name               string
		state              FactorState
		change             FactorChange
		marked             map[factorRole]VerificationRecord
		gateCode, gateChal bool
		want               []string
	}{
		{name: "challenge created", change: FactorChange{CreateChallenge: "2fa-key", ChallengeID: "challenge-row"}, marked: map[factorRole]VerificationRecord{roleIssue: challenge}, want: []string{"v-create-after:2fa"}},
		{name: "declined challenge", marked: map[factorRole]VerificationRecord{}},
		{name: "wrong guess", state: FactorState{ChallengeID: "challenge-row"}, change: FactorChange{IncrementAttempts: true}, gateChal: true, want: []string{"v-update-after:2fa"}},
		{name: "fifth wrong guess", state: FactorState{ChallengeID: "challenge-row"}, change: FactorChange{IncrementAttempts: true, ConsumeChallenge: true}, gateChal: true, want: []string{"v-delete-after:2fa"}},
		{name: "correct code under a challenge", state: FactorState{ChallengeID: "challenge-row", Delivery: delivery}, change: FactorChange{RemoveDelivery: true, ConsumeChallenge: true}, gateCode: true, gateChal: true, want: []string{"v-delete-after:2fa-otp", "v-delete-after:2fa"}},
		{name: "fifth wrong code", state: FactorState{ChallengeID: "challenge-row", Delivery: delivery}, change: FactorChange{SaveDelivery: &counted, IncrementAttempts: true, ConsumeChallenge: true}, gateCode: true, gateChal: true, want: []string{"v-delete-after:2fa-otp", "v-delete-after:2fa"}},
		{name: "counted code", state: FactorState{ChallengeID: "challenge-row", Delivery: delivery}, change: FactorChange{SaveDelivery: &counted, IncrementAttempts: true}, gateCode: true, gateChal: true, want: []string{"v-update-after:2fa-otp", "v-update-after:2fa"}},
		{name: "signed-in correct code", state: FactorState{Delivery: delivery}, change: FactorChange{RemoveDelivery: true}, gateCode: true, want: []string{"v-delete-after:2fa-otp"}},
		{name: "exhausted code", state: FactorState{ChallengeID: "challenge-row", Delivery: delivery}, change: FactorChange{RemoveDelivery: true}, gateCode: true, gateChal: true, want: []string{"v-delete-after:2fa-otp"}},
		{name: "another code", state: FactorState{ChallengeID: "challenge-row", Delivery: &FactorDelivery{ID: "resent-row"}}, change: FactorChange{RemoveDelivery: true}, gateCode: true, gateChal: true},
		{name: "new code", change: FactorChange{SaveDelivery: &sent}, marked: map[factorRole]VerificationRecord{roleSend: code}, want: []string{"v-create-after:2fa-otp"}},
		{name: "remembered rotation", state: FactorState{TrustedGrant: "trust-device-old", TrustedGrantID: "old-grant"}, change: FactorChange{CreateTrustedGrant: "trust-device-new", TrustedGrantID: "new-grant"},
			marked: map[factorRole]VerificationRecord{roleSpend: oldGrant, roleGrant: newGrant}, want: []string{"v-delete-after:trust-device", "v-create-after:trust-device"}},
		{name: "a proof's grant", state: FactorState{ChallengeID: "challenge-row"}, change: FactorChange{ConsumeChallenge: true, CreateTrustedGrant: "trust-device-new", TrustedGrantID: "new-grant"},
			marked: map[factorRole]VerificationRecord{roleGrant: newGrant}, gateChal: true, want: []string{"v-delete-after:2fa", "v-create-after:trust-device"}},
		{name: "a spend whose replacement was not stored", state: FactorState{TrustedGrant: "trust-device-old", TrustedGrantID: "old-grant"}, marked: map[factorRole]VerificationRecord{roleSpend: oldGrant}},
		{name: "disableSession", state: FactorState{ChallengeID: "challenge-row"}, change: FactorChange{ConsumeChallenge: true}, gateChal: true, want: []string{"v-delete-after:2fa"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, events := factorHookTest(t, nil)
			h := a.newFactorHooks()
			h.state, h.change, h.marked = tc.state, tc.change, tc.marked
			if tc.gateCode {
				h.delivery.rec = &code
			}
			if tc.gateChal {
				h.challenge.rec = &challenge
			}
			if err := h.after(t.Context()); err != nil {
				t.Fatal(err)
			}
			if len(*events)+len(tc.want) > 0 && !reflect.DeepEqual(*events, tc.want) {
				t.Fatalf("ran %q, want %q", *events, tc.want)
			}
		})
	}
	var none *factorHooks
	if none.after(t.Context()) != nil || none.approve(t.Context()) != nil || none.approval(roleIssue, challenge) != factorApproved || !none.allows(roleGrant) {
		t.Fatal("nil hooks did something")
	}
	if p, c := none.guess(&codeGuess{}, roleChallenge, challenge); p || c {
		t.Fatal("nil hooks held a guess")
	}

	// A record is pending until its before hooks answered for that record.
	a, events := factorHookTest(t, map[string]bool{"v-create-before:2fa": true})
	h := a.newFactorHooks()
	if h.approval(roleIssue, challenge) != factorPending || len(h.want) != 1 {
		t.Fatal("an unseen record was not queued")
	}
	if err := h.approve(t.Context()); err != nil || h.approval(roleIssue, challenge) != factorDeclined || h.allows(roleIssue) {
		t.Fatal("a declined record was not recorded:", err)
	}
	other := challenge
	other.ID = "another-row"
	if h.approval(roleIssue, other) != factorPending {
		t.Fatal("another record took the first one's answer")
	}
	h.want = nil
	if h.approval(roleGrant, newGrant) != factorPending || h.approve(t.Context()) != nil || h.approval(roleGrant, newGrant) != factorApproved || !h.allows(roleGrant) {
		t.Fatal("an approved record was not marked")
	}
	same := func(want ...string) {
		t.Helper()
		if !reflect.DeepEqual(*events, want) {
			t.Fatalf("ran %q, want %q", *events, want)
		}
		*events = nil
	}
	same("v-create-before:2fa", "v-create-before:trust-device")

	// A guess waits for its record's delete before hooks, and is refused when
	// the record changed after they ran.
	if p, _ := h.guess(&h.challenge, roleChallenge, challenge); !p {
		t.Fatal("an unseen guess was not held")
	}
	if err := h.approve(t.Context()); err != nil {
		t.Fatal(err)
	}
	if p, c := h.guess(&h.challenge, roleChallenge, challenge); p || c {
		t.Fatal("an approved guess was held")
	}
	if _, c := h.guess(&h.challenge, roleChallenge, other); !c {
		t.Fatal("a changed record was judged")
	}
	same("v-delete-before:2fa")

	// Declines end the call with their answers.
	a, events = factorHookTest(t, map[string]bool{"v-delete-before:2fa-otp": true, "v-delete-before:2fa": true, "v-create-before:2fa-otp": true, "v-delete-before:trust-device": true})
	for _, tc := range []struct {
		queue func(*factorHooks)
		want  error
	}{
		{func(h *factorHooks) { h.guess(&h.delivery, roleDelivery, code) }, otpExpired()},
		{func(h *factorHooks) { h.guess(&h.challenge, roleChallenge, challenge) }, factorCookieError()},
		{func(h *factorHooks) { h.approval(roleSend, code) }, errFactorSendDeclined},
	} {
		h := a.newFactorHooks()
		tc.queue(h)
		var api *APIError
		err := h.approve(t.Context())
		if errors.As(tc.want, &api) {
			var got *APIError
			if !errors.As(err, &got) || *got != *api {
				t.Fatal("a decline answered", err, "want", tc.want)
			}
		} else if !errors.Is(err, tc.want) {
			t.Fatal("a decline answered", err, "want", tc.want)
		}
	}
	same("v-delete-before:2fa-otp", "v-delete-before:2fa", "v-create-before:2fa-otp")
	// A declined spend means its replacement is never asked.
	h = a.newFactorHooks()
	h.approval(roleSpend, oldGrant)
	h.approval(roleGrant, newGrant)
	if err := h.approve(t.Context()); err != nil || h.approval(roleSpend, oldGrant) != factorDeclined {
		t.Fatal("a declined spend was not recorded:", err)
	}
	same("v-delete-before:trust-device")
}
