package sqlstore

import (
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/memory"
)

// codeStore is what the email code contract tests call directly.
type codeStore interface {
	auth.Store
	auth.EmailOTPStore
	auth.EmailOTPFinder
	auth.EmailOTPRegistrationStore
}

// The email code stores honour ProofID, CurrentProofID, Decided and
// CurrentDecided: a call judges only the bound code, refuses any other
// untouched, and reports Count for a counted wrong guess, Remove for a code
// it spent or removed, including by a refusal that spends it, and Keep for a
// successful check, a refusal that writes nothing, and every rolled-back
// write. FindEmailOTP reads a live or expired code without spending it.
func TestEmailCodeDecisions(t *testing.T) {
	for _, dialect := range []string{"memory", "sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			var s codeStore = memory.New()
			if dialect != "memory" {
				sqlStore, err := Open(ctx, dialect, organizationTestDSN(t, dialect))
				if err != nil {
					t.Fatal(err)
				}
				defer sqlStore.Close()
				s = sqlStore
			}
			now := time.Now().UTC().Truncate(time.Millisecond)
			session := func(id, user string) auth.StoredSession {
				return auth.StoredSession{Session: auth.Session{ID: id, UserID: user, Token: "token-" + id, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}}
			}
			ada := auth.User{ID: "ada", Email: "ada@decisions.example", EmailVerified: true, CreatedAt: now, UpdatedAt: now}
			first := session("ada-1", ada.ID)
			if err := s.CreateUser(ctx, ada, "", &first); err != nil {
				t.Fatal(err)
			}
			request := func(email string, purpose auth.EmailOTPPurpose) auth.EmailOTPRequest {
				return auth.EmailOTPRequest{Email: email, Purpose: purpose, Now: now}
			}
			save := func(req auth.EmailOTPRequest, id, code string, expires time.Time) {
				t.Helper()
				req.ProofID = id
				raw, err := s.SaveEmailOTP(ctx, req, true, expires, func(*auth.EmailOTPRecord) (string, string, int, error) { return code, code, 0, nil })
				if err != nil || raw != code {
					t.Fatal("saving", id, "answered", raw, err)
				}
			}
			matches := func(code string) func(string) (bool, error) {
				return func(stored string) (bool, error) { return stored == code, nil }
			}
			// use judges code under act and returns what the store reported.
			use := func(act auth.EmailOTPAction, code string) (auth.PhoneOTPDecision, error) {
				t.Helper()
				d := auth.PhoneOTPDecision(99)
				act.Decided = &d
				if act.MaxAttempts == 0 {
					act.MaxAttempts = 3
				}
				if act.Now.IsZero() {
					act.Now = now
				}
				_, err := s.UseEmailOTP(ctx, act, matches(code))
				return d, err
			}
			decided := func(got, want auth.PhoneOTPDecision, err error, code string) {
				t.Helper()
				var api *auth.APIError
				if got != want || code == "" && err != nil || code != "" && (!errors.As(err, &api) || api.Code != code) {
					t.Fatalf("the store reported %d with %v, want %d with %q", got, err, want, code)
				}
			}
			attempts := func(req auth.EmailOTPRequest) int {
				t.Helper()
				rec, err := s.ReadEmailOTP(ctx, req)
				if err != nil {
					t.Fatal(err)
				}
				if rec == nil {
					return -1
				}
				return rec.Attempts
			}
			signIn := request(ada.Email, auth.OTPSignIn)

			// SaveEmailOTP stores the code under ProofID, and FindEmailOTP reads it.
			save(signIn, "proof-1", "111111", now.Add(time.Minute))
			id, expires, err := s.FindEmailOTP(ctx, signIn)
			if err != nil || id != "proof-1" || !expires.Equal(now.Add(time.Minute)) {
				t.Fatal("FindEmailOTP answered", id, expires, err)
			}
			if _, _, err := s.FindEmailOTP(ctx, request("nobody@decisions.example", auth.OTPSignIn)); !errors.Is(err, auth.ErrNotFound) {
				t.Fatal("FindEmailOTP of no code answered", err)
			}

			// A binding to another code refuses the guess untouched.
			act := auth.EmailOTPAction{EmailOTPRequest: signIn, CheckOnly: true}
			act.ProofID = "proof-0"
			got, err := use(act, "111111")
			decided(got, auth.PhoneKeepProof, err, "INVALID_OTP")
			// A right check keeps the code; a wrong guess is counted.
			act.ProofID = "proof-1"
			got, err = use(act, "111111")
			decided(got, auth.PhoneKeepProof, err, "")
			got, err = use(act, "999999")
			decided(got, auth.PhoneCountAttempt, err, "INVALID_OTP")
			if n := attempts(signIn); n != 1 {
				t.Fatal("the wrong guess was counted", n, "times")
			}
			// A matcher's error and a rolled-back session insert keep the code.
			broken := act
			broken.Decided, broken.MaxAttempts = new(auth.PhoneOTPDecision), 3
			if _, err := s.UseEmailOTP(ctx, broken, func(string) (bool, error) { return false, errors.New("transform") }); err == nil || *broken.Decided != auth.PhoneKeepProof {
				t.Fatal("a matcher's error reported", *broken.Decided, err)
			}
			spend := auth.EmailOTPAction{EmailOTPRequest: signIn, AllowSignUp: true, Session: first}
			spend.ProofID = "proof-1"
			got, err = use(spend, "111111")
			if got != auth.PhoneKeepProof || err == nil {
				t.Fatal("a duplicate session token reported", got, err)
			}
			if n := attempts(signIn); n != 1 {
				t.Fatal("a rolled-back sign-in changed the code:", n)
			}
			// A spend removes the code.
			spend.Session = session("ada-2", "")
			got, err = use(spend, "111111")
			decided(got, auth.PhoneRemoveProof, err, "")
			if _, _, err := s.FindEmailOTP(ctx, signIn); !errors.Is(err, auth.ErrNotFound) {
				t.Fatal("the spent code was found:", err)
			}

			// An expired code, and one out of attempts, are removed.
			save(signIn, "proof-2", "222222", now.Add(-time.Second))
			if id, _, err := s.FindEmailOTP(ctx, signIn); err != nil || id != "proof-2" {
				t.Fatal("FindEmailOTP of an expired code answered", id, err)
			}
			spend.ProofID = "proof-2"
			got, err = use(spend, "222222")
			decided(got, auth.PhoneRemoveProof, err, "OTP_EXPIRED")
			save(signIn, "proof-3", "333333", now.Add(time.Minute))
			spend.ProofID = "proof-3"
			for range 3 {
				got, err = use(spend, "999999")
				decided(got, auth.PhoneCountAttempt, err, "INVALID_OTP")
			}
			got, err = use(spend, "333333")
			decided(got, auth.PhoneRemoveProof, err, "TOO_MANY_ATTEMPTS")

			// Refusals that spend the code: an unknown account's verification,
			// closed sign-up and invalid registration fields.
			ghost := request("ghost@decisions.example", auth.OTPVerifyEmail)
			save(ghost, "ghost-1", "444444", now.Add(time.Minute))
			check := auth.EmailOTPAction{EmailOTPRequest: ghost, CheckOnly: true}
			check.ProofID = "ghost-1"
			got, err = use(check, "444444")
			decided(got, auth.PhoneKeepProof, err, "USER_NOT_FOUND")
			verify := auth.EmailOTPAction{EmailOTPRequest: ghost}
			verify.ProofID = "ghost-1"
			got, err = use(verify, "444444")
			decided(got, auth.PhoneRemoveProof, err, "USER_NOT_FOUND")
			closed := request("closed@decisions.example", auth.OTPSignIn)
			save(closed, "closed-1", "555555", now.Add(time.Minute))
			shut := auth.EmailOTPAction{EmailOTPRequest: closed, Session: session("closed", "")}
			shut.ProofID = "closed-1"
			got, err = use(shut, "555555")
			decided(got, auth.PhoneRemoveProof, err, "INVALID_OTP")
			save(closed, "closed-2", "666666", now.Add(time.Minute))
			register := auth.EmailOTPAction{EmailOTPRequest: closed, AllowSignUp: true, Session: session("register", ""), NewUser: auth.User{ID: "new-user"}, MaxAttempts: 3}
			register.ProofID, register.Decided = "closed-2", new(auth.PhoneOTPDecision)
			if _, err := s.UseEmailOTPRegistration(ctx, register, matches("666666"), func() (auth.UserFieldValues, error) {
				return auth.UserFieldValues{}, &auth.APIError{Status: 400, Code: "FIELD_REQUIRED", Message: "locale is required"}
			}); err == nil || *register.Decided != auth.PhoneRemoveProof {
				t.Fatal("invalid registration fields reported", *register.Decided, err)
			}

			// Email changes: a bad session writes nothing, a taken address spends the code.
			source := &auth.EmailOTPSource{UserID: ada.ID, Email: ada.Email, SessionToken: first.Token}
			change := request("next@decisions.example", auth.OTPChangeEmail)
			change.Source = source
			save(change, "change-1", "777777", now.Add(time.Minute))
			if id, _, err := s.FindEmailOTP(ctx, change); err != nil || id != "change-1" {
				t.Fatal("FindEmailOTP of a change code answered", id, err)
			}
			unscoped := change
			unscoped.Source = nil
			if _, _, err := s.FindEmailOTP(ctx, unscoped); !errors.Is(err, auth.ErrNotFound) {
				t.Fatal("FindEmailOTP found a change code without its account:", err)
			}
			// An address too long for the identifier column is stored under its digest.
			long := request(strings.Repeat("a", 290)+"@decisions.example", auth.OTPSignIn)
			save(long, "long-1", "121212", now.Add(time.Minute))
			if id, _, err := s.FindEmailOTP(ctx, long); err != nil || id != "long-1" {
				t.Fatal("FindEmailOTP of a long address answered", id, err)
			}
			moved := auth.EmailOTPAction{EmailOTPRequest: change}
			moved.ProofID = "change-1"
			lost := *source
			lost.SessionToken = "token-gone"
			moved.Source = &lost
			got, err = use(moved, "777777")
			decided(got, auth.PhoneKeepProof, err, "UNAUTHORIZED")
			bo := auth.User{ID: "bo", Email: "next@decisions.example", CreatedAt: now, UpdatedAt: now}
			if err := s.CreateUser(ctx, bo, "", nil); err != nil {
				t.Fatal(err)
			}
			moved.Source = source
			got, err = use(moved, "777777")
			if got != auth.PhoneRemoveProof || err == nil || !strings.Contains(err.Error(), "Email already in use") {
				t.Fatal("a taken address reported", got, err)
			}

			// A change request judges the current address's code under CurrentProofID.
			current := request(ada.Email, auth.OTPVerifyEmail)
			save(current, "current-1", "888888", now.Add(time.Minute))
			ask := func(newEmail, currentID, code string) (string, auth.PhoneOTPDecision, error) {
				t.Helper()
				req := request(newEmail, auth.OTPChangeEmail)
				req.Source, req.ProofID, req.CurrentProofID, req.MaxAttempts = source, "change-"+newEmail, currentID, 3
				req.CurrentMatches = matches(code)
				d := auth.PhoneOTPDecision(99)
				req.CurrentDecided = &d
				raw, err := s.SaveEmailOTP(ctx, req, true, now.Add(time.Minute), func(*auth.EmailOTPRecord) (string, string, int, error) { return "new", "new", 0, nil })
				return raw, d, err
			}
			_, got, err = ask("other@decisions.example", "current-0", "888888")
			decided(got, auth.PhoneKeepProof, err, "INVALID_OTP")
			_, got, err = ask("other@decisions.example", "current-1", "000000")
			decided(got, auth.PhoneCountAttempt, err, "INVALID_OTP")
			raw, got, err := ask("next@decisions.example", "current-1", "888888")
			if raw != "" || got != auth.PhoneRemoveProof || err != nil {
				t.Fatal("a change to a held address answered", raw, got, err)
			}
			if n := attempts(current); n != -1 {
				t.Fatal("the current code survived the change request:", n)
			}
		})
	}
}

// codeTransaction reports a commit after a denial and none after an error,
// whose writes roll back.
func TestCodeTransactionCommits(t *testing.T) {
	ctx := t.Context()
	store, err := Open(ctx, "sqlite", organizationTestDSN(t, "sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	key := newEmailOTPKey(auth.EmailOTPRequest{Email: "tx@decisions.example", Purpose: auth.OTPSignIn})
	denied := errors.New("denied")
	committed, err := store.codeTransaction(ctx, key, func(*sql.Tx) (error, error) { return denied, nil })
	if !committed || !errors.Is(err, denied) {
		t.Fatal("a denial reported", committed, err)
	}
	broken := errors.New("broken")
	now := time.Now()
	committed, err = store.codeTransaction(ctx, key, func(tx *sql.Tx) (error, error) {
		if _, err := tx.ExecContext(ctx, store.bind(`INSERT INTO "verification" ("id","identifier","value","expiresAt","createdAt","updatedAt") VALUES (?,?,?,?,?,?)`),
			"rolled-back", key.identifier, "x:0", store.date(now.Add(time.Minute)), store.date(now), store.date(now)); err != nil {
			return nil, err
		}
		return nil, broken
	})
	if committed || !errors.Is(err, broken) {
		t.Fatal("an error reported", committed, err)
	}
	if _, _, err := store.FindEmailOTP(ctx, auth.EmailOTPRequest{Email: "tx@decisions.example", Purpose: auth.OTPSignIn}); !errors.Is(err, auth.ErrNotFound) {
		t.Fatal("a rolled-back write stayed:", err)
	}
}

// The phone code stores report through PhoneOTPUse.Decided what they
// committed: Count for a counted wrong guess, Remove for a spent, expired or
// exhausted code and for a refusal after a spend, and Keep for a code
// another use bound, a missing code and every rolled-back write.
func TestPhoneCodeDecisions(t *testing.T) {
	for _, dialect := range []string{"memory", "sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			opened, _ := phoneStores(t, dialect)
			if _, ok := opened.(auth.PhoneOTPReporter); !ok {
				t.Fatal("the store does not report phone code decisions")
			}
			s := opened.(interface {
				auth.Store
				auth.PhoneAccountStore
			})
			now := time.Now().UTC().Truncate(time.Millisecond)
			save := func(number, id, code string, purpose auth.PhoneOTPPurpose, expires time.Time) {
				t.Helper()
				r := auth.PhoneOTPRecord{ID: id, PhoneNumber: number, Code: code, Purpose: purpose, CreatedAt: now, ExpiresAt: expires}
				var err error
				if purpose == auth.PhonePasswordReset {
					_, err = s.SavePhoneReset(ctx, r, false)
				} else {
					err = s.SavePhoneOTP(ctx, r)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			use := func(number, code, proof string) auth.PhoneOTPUse {
				return auth.PhoneOTPUse{PhoneNumber: number, Code: code, Purpose: auth.PhoneVerify, AllowedAttempts: 3, Now: now, ProviderProof: proof, ProviderAccepted: proof != "" && code == "right"}
			}
			consume := func(u auth.PhoneOTPUse) (auth.PhoneOTPDecision, error) {
				d := auth.PhoneOTPDecision(99)
				u.Decided = &d
				err := s.ConsumePhoneOTP(ctx, u)
				return d, err
			}
			apply := func(act auth.PhoneAccountAction) (auth.PhoneOTPDecision, error) {
				d := auth.PhoneOTPDecision(99)
				act.Use.Decided = &d
				_, err := s.ApplyPhoneOTP(ctx, act)
				return d, err
			}
			decided := func(got, want auth.PhoneOTPDecision, err error, code string) {
				t.Helper()
				var api *auth.APIError
				if got != want || code == "" && err != nil || code != "" && (!errors.As(err, &api) || api.Code != code) {
					t.Fatalf("the store reported %d with %v, want %d with %q", got, err, want, code)
				}
			}
			session := func(id string) *auth.StoredSession {
				return &auth.StoredSession{Session: auth.Session{ID: id, Token: "token-" + id, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}}
			}

			// Guesses: a code another use bound and a missing code are kept,
			// a wrong guess counted, a spend removes the code.
			save("+15551000001", "p1", "right", auth.PhoneVerify, now.Add(time.Minute))
			got, err := consume(use("+15551000001", "right", "p0"))
			decided(got, auth.PhoneKeepProof, err, "INVALID_OTP")
			got, err = consume(use("+15551000001", "wrong", ""))
			decided(got, auth.PhoneCountAttempt, err, "INVALID_OTP")
			got, err = consume(use("+15551000001", "right", "p1"))
			decided(got, auth.PhoneRemoveProof, err, "")
			got, err = consume(use("+15551000001", "right", "p1"))
			decided(got, auth.PhoneKeepProof, err, "OTP_NOT_FOUND")
			// Expired and exhausted codes are removed.
			save("+15551000001", "p2", "right", auth.PhoneVerify, now.Add(-time.Second))
			got, err = consume(use("+15551000001", "right", "p2"))
			decided(got, auth.PhoneRemoveProof, err, "OTP_EXPIRED")
			save("+15551000001", "p3", "right", auth.PhoneVerify, now.Add(time.Minute))
			for range 3 {
				got, err = consume(use("+15551000001", "wrong", "p3"))
				decided(got, auth.PhoneCountAttempt, err, "INVALID_OTP")
			}
			got, err = consume(use("+15551000001", "right", "p3"))
			decided(got, auth.PhoneRemoveProof, err, "TOO_MANY_ATTEMPTS")

			// A sign-up spends the code.
			save("+15551000002", "p4", "right", auth.PhoneVerify, now.Add(time.Minute))
			first := session("first")
			got, err = apply(auth.PhoneAccountAction{Use: use("+15551000002", "right", "p4"), Create: &auth.User{ID: "u2", Email: "two@phone.example", CreatedAt: now, UpdatedAt: now}, Session: first})
			decided(got, auth.PhoneRemoveProof, err, "")
			// A taken email and a duplicate session token roll back and keep the code.
			save("+15551000003", "p5", "right", auth.PhoneVerify, now.Add(time.Minute))
			got, err = apply(auth.PhoneAccountAction{Use: use("+15551000003", "right", "p5"), Create: &auth.User{ID: "u3", Email: "two@phone.example", CreatedAt: now, UpdatedAt: now}, Session: session("third")})
			if got != auth.PhoneKeepProof || !errors.Is(err, auth.ErrEmailTaken) {
				t.Fatal("a taken email reported", got, err)
			}
			got, err = apply(auth.PhoneAccountAction{Use: use("+15551000003", "right", "p5"), Create: &auth.User{ID: "u4", Email: "four@phone.example", CreatedAt: now, UpdatedAt: now}, Session: first})
			if got != auth.PhoneKeepProof || err == nil {
				t.Fatal("a duplicate session token reported", got, err)
			}
			if r, err := s.ReadPhoneOTP(ctx, "+15551000003", auth.PhoneVerify); err != nil || r == nil || r.ID != "p5" {
				t.Fatal("a rolled-back sign-up spent the code", r, err)
			}

			// Refusals after the spend: a held number, a link without a session,
			// and a reset of a number no one holds.
			linker := auth.User{ID: "u5", Email: "five@phone.example", CreatedAt: now, UpdatedAt: now}
			linked := session("linker")
			linked.UserID = linker.ID
			if err := s.CreateUser(ctx, linker, "", linked); err != nil {
				t.Fatal(err)
			}
			save("+15551000002", "p6", "right", auth.PhoneVerify, now.Add(time.Minute))
			got, err = apply(auth.PhoneAccountAction{Use: use("+15551000002", "right", "p6"), SourceID: linker.ID, SourceToken: linked.Token})
			decided(got, auth.PhoneRemoveProof, err, "PHONE_NUMBER_EXIST")
			save("+15551000006", "p7", "right", auth.PhoneVerify, now.Add(time.Minute))
			got, err = apply(auth.PhoneAccountAction{Use: use("+15551000006", "right", "p7"), SourceID: linker.ID, SourceToken: "token-gone"})
			decided(got, auth.PhoneRemoveProof, err, "USER_NOT_FOUND")
			save("+15551000007", "p8", "right", auth.PhonePasswordReset, now.Add(time.Minute))
			reset := use("+15551000007", "right", "p8")
			reset.Purpose = auth.PhonePasswordReset
			got, err = apply(auth.PhoneAccountAction{Use: reset, PasswordHash: "hash"})
			decided(got, auth.PhoneRemoveProof, err, "UNEXPECTED_ERROR")
		})
	}
}
