package sqlstore

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/Stonewrit/stonewrit-auth"
	"github.com/Stonewrit/stonewrit-auth/schema"
)

func TestEmailVerificationObserverBoundaries(t *testing.T) {
	for _, dialect := range []string{"memory", "sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			store, peer := phoneStores(t, dialect)
			ctx := t.Context()
			off, on := false, true
			var link auth.MailLink
			var code string
			var before, after auth.EmailVerificationHook
			plugin, err := auth.NewEmailOTP(auth.EmailOTPOptions{AutoSignInAfterVerification: true, ChangeEmail: auth.EmailOTPChangeOptions{Enabled: true}, Send: func(_ context.Context, m auth.EmailOTPMessage) error { code = m.OTP; return nil }})
			if err != nil {
				t.Fatal(err)
			}
			opts := auth.Options{Store: store, BaseURL: "https://auth.example.test", Secret: strings.Repeat("v", 40), EmailAndPassword: true, RateLimit: &off,
				AutoSignInAfterVerification: true, SendVerificationOnSignUp: &on, RequireEmailVerification: true, Plugins: []auth.Plugin{plugin},
				SendVerificationEmail:   func(_ context.Context, m auth.MailLink) error { link = m; return nil },
				BeforeEmailVerification: func(ctx context.Context, u auth.User, r *http.Request) error { return before(ctx, u, r) },
				AfterEmailVerification:  func(ctx context.Context, u auth.User, r *http.Request) error { return after(ctx, u, r) },
			}
			a, err := auth.New(opts)
			if err != nil {
				t.Fatal(err)
			}
			opts.Store = peer
			b, err := auth.New(opts)
			if err != nil {
				t.Fatal(err)
			}
			signup := func(email string) auth.User {
				t.Helper()
				res, err := a.SignUpEmail(ctx, auth.SignUpInput{Name: "Mailbox owner", Email: email, Password: "verification callback password"}, auth.RequestMeta{})
				if err != nil || res.Token != "" || link.User.ID != res.User.ID {
					t.Fatal("gated signup", err)
				}
				return res.User
			}
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			noHook := func(context.Context, auth.User, *http.Request) error { return nil }
			denied := errors.New("private fixture callback failure")
			for _, mode := range []string{"link", "otp"} {
				for _, phase := range []string{"before", "after"} {
					email := fmt.Sprintf("%s-%s@example.test", mode, phase)
					u := signup(email)
					token := link.Token
					if mode == "otp" {
						must(a.SendEmailOTP(ctx, email, auth.OTPVerifyEmail))
					}
					var calls []string
					observer := func(stage string) auth.EmailVerificationHook {
						return func(ctx context.Context, snapshot auth.User, r *http.Request) error {
							if r != nil || snapshot.ID != u.ID || snapshot.Email != email || snapshot.EmailVerified != (stage == "after") {
								t.Fatal("incorrect native snapshot or request", stage, r != nil)
							}
							persisted, _, err := peer.Credential(ctx, email)
							must(err)
							if persisted.EmailVerified != snapshot.EmailVerified {
								t.Fatal("callback did not see committed profile", stage)
							}
							sessions, err := peer.ListSessions(ctx, u.ID)
							must(err)
							if len(sessions) != 0 {
								t.Fatal("session was published before callback completed")
							}
							calls = append(calls, stage)
							if stage == phase {
								return denied
							}
							return nil
						}
					}
					before, after = observer("before"), observer("after")
					run := func() error {
						if mode == "link" {
							return b.VerifyEmail(ctx, token)
						}
						_, err := b.CompleteEmailVerificationOTP(ctx, email, code, auth.RequestMeta{})
						return err
					}
					if err := run(); !errors.Is(err, denied) {
						t.Fatalf("%s %s: %v", mode, phase, err)
					}
					wantCalls := "before"
					if phase == "after" {
						wantCalls = "before,after"
					}
					if strings.Join(calls, ",") != wantCalls {
						t.Fatal("hook order", calls)
					}
					persisted, _, err := peer.Credential(ctx, email)
					must(err)
					if persisted.EmailVerified != (phase == "after") {
						t.Fatal("failed hook moved verification to the wrong side of the transaction")
					}
					sessions, err := peer.ListSessions(ctx, u.ID)
					must(err)
					if len(sessions) != 0 {
						t.Fatal("failed callback left a session")
					}
					if db, ok := peer.(*Store); ok {
						var pending int
						err := db.db.QueryRowContext(ctx, db.bind(`SELECT COUNT(*) FROM "verification" WHERE "identifier" IN (?,?)`), "mail-observer-code:"+u.ID, "mail-observer-session:"+u.ID).Scan(&pending)
						must(err)
						if pending != 0 {
							t.Fatal("callback rejection left an active handoff", pending)
						}
					}
					before, after = noHook, noHook
					err = run()
					if mode == "link" {
						must(err)
					} else if err == nil {
						t.Fatal("consumed OTP replayed after callback failure")
					}
				}
			}
			t.Run("changed-mailbox", func(t *testing.T) {
				u := signup("resume@example.test")
				must(a.SendEmailOTP(ctx, u.Email, auth.OTPVerifyEmail))
				changes := peer.(interface {
					ChangeAccountEmail(context.Context, string, string, string, bool, time.Time) (auth.User, error)
				})
				before = func(ctx context.Context, snapshot auth.User, _ *http.Request) error {
					_, err := changes.ChangeAccountEmail(ctx, snapshot.ID, snapshot.Email, "résumé@example.test", false, time.Now())
					return err
				}
				after = func(context.Context, auth.User, *http.Request) error {
					t.Fatal("after ran for reassigned mailbox")
					return nil
				}
				_, err := a.VerifyEmailOTP(ctx, u.Email, code)
				if err == nil {
					t.Fatal("old proof verified the replacement mailbox")
				}
				changed, _, err := peer.Credential(ctx, "résumé@example.test")
				must(err)
				if changed.EmailVerified {
					t.Fatal("replacement verified")
				}
			})
			t.Run("hook-revokes-existing-session", func(t *testing.T) {
				u := signup("old-session@example.test")
				actor := signup("actor@example.test")
				actorProof := link.Token
				before, after = noHook, noHook
				must(a.VerifyEmail(ctx, actorProof))
				login, err := a.SignInEmail(ctx, auth.SignInInput{Email: actor.Email, Password: "verification callback password"}, auth.RequestMeta{})
				must(err)
				must(a.SendVerificationEmail(ctx, nil, u.Email, "/"))
				proof := link.Token
				after = func(ctx context.Context, subject auth.User, r *http.Request) error {
					if r == nil || r.URL.Path != "/api/auth/verify-email" || r.Header.Get("X-Probe") != "yes" || r.Body != http.NoBody || r.GetBody != nil || r.URL.Query().Has("token") || strings.Contains(r.RequestURI, proof) || !subject.EmailVerified {
						t.Fatal("HTTP observer request or profile")
					}
					return peer.DeleteSession(ctx, login.Token)
				}
				h := http.Header{"X-Probe": {"yes"}, "Cookie": {a.SessionCookie(login.Token, true).String()}}
				w := verificationRequest(b, proof, h)
				if w.Code != 200 || len(w.Result().Cookies()) != 0 {
					t.Fatal("revoked caller received a session", w.Code, w.Body)
				}
				list, err := peer.ListSessions(ctx, u.ID)
				must(err)
				if len(list) != 0 {
					t.Fatal("revoked caller left a session")
				}
			})
			t.Run("concurrent-first-use", func(t *testing.T) {
				u := signup("concurrent@example.test")
				token := link.Token
				ready := make(chan struct{}, 2)
				release := make(chan struct{})
				var wins atomic.Int32
				before = func(context.Context, auth.User, *http.Request) error {
					ready <- struct{}{}
					select {
					case <-release:
						return nil
					case <-time.After(10 * time.Second):
						return errors.New("before hook held account lock")
					}
				}
				after = func(context.Context, auth.User, *http.Request) error { wins.Add(1); return nil }
				done := make(chan int, 2)
				for _, node := range []*auth.Auth{a, b} {
					go func() { done <- verificationRequest(node, token, nil).Code }()
				}
				for range 2 {
					select {
					case <-ready:
					case <-time.After(12 * time.Second):
						t.Fatal("independent callbacks could not enter")
					}
				}
				close(release)
				if <-done != 200 || <-done != 200 || wins.Load() != 1 {
					t.Fatal("expected a single committed after callback")
				}
				list, err := peer.ListSessions(ctx, u.ID)
				must(err)
				if len(list) != 1 {
					t.Fatal("concurrent hooks issued more than one session", len(list))
				}
			})
			t.Run("otp-change-rechecks-actor", func(t *testing.T) {
				u := signup("change-source@example.test")
				before, after = noHook, noHook
				must(a.VerifyEmail(ctx, link.Token))
				res, err := a.SignInEmail(ctx, auth.SignInInput{Email: u.Email, Password: "verification callback password"}, auth.RequestMeta{})
				must(err)
				h := http.Header{"Cookie": {a.SessionCookie(res.Token, true).String()}}
				next := "change-target@example.test"
				must(a.RequestEmailChangeOTP(ctx, h, next, ""))
				before = func(ctx context.Context, subject auth.User, r *http.Request) error {
					if r != nil || subject.Email != u.Email || !subject.EmailVerified {
						t.Fatal("before change snapshot")
					}
					return peer.DeleteSession(ctx, res.Token)
				}
				after = func(context.Context, auth.User, *http.Request) error {
					t.Fatal("revoked session changed address")
					return nil
				}
				if err := a.ChangeEmailOTP(ctx, h, next, code); err == nil {
					t.Fatal("changed mailbox after source session removal")
				}
				current, _, err := peer.Credential(ctx, u.Email)
				must(err)
				if current.ID != u.ID {
					t.Fatal("lost original mailbox")
				}
			})
		})
	}
}

func TestVerificationCallbackStoreRequirements(t *testing.T) {
	type coreOnly struct{ auth.Store }
	type linkOnly struct {
		auth.Store
		auth.EmailOTPStore
		auth.EmailVerificationObserverStore
	}
	store, _ := phoneStores(t, "memory")
	opts := auth.Options{Store: coreOnly{store}, BaseURL: "https://auth.example.test", Secret: strings.Repeat("q", 40)}
	if _, err := auth.New(opts); err != nil {
		t.Fatal("disabled observers required additional methods", err)
	}
	opts.AfterEmailVerification = func(context.Context, auth.User, *http.Request) error { return nil }
	if _, err := auth.New(opts); err == nil || !strings.Contains(err.Error(), "EmailVerificationObserverStore") {
		t.Fatal("missing observer store", err)
	}
	opts.Store = linkOnly{store, store.(auth.EmailOTPStore), store.(auth.EmailVerificationObserverStore)}
	if _, err := auth.New(opts); err != nil {
		t.Fatal("link-only verification should not require code storage", err)
	}
	plugin, err := auth.NewEmailOTP(auth.EmailOTPOptions{Send: func(context.Context, auth.EmailOTPMessage) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	opts.Plugins = []auth.Plugin{plugin}
	if _, err := auth.New(opts); err == nil || !strings.Contains(err.Error(), "EmailOTPVerificationObserverStore") {
		t.Fatal("missing code observer store", err)
	}
}

func TestVerificationObserverHandoffsAreSingleUse(t *testing.T) {
	for _, dialect := range []string{"memory", "sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			store, peer := phoneStores(t, dialect)
			ctx := t.Context()
			proofs := store.(auth.EmailVerificationObserverStore)
			remote := peer.(auth.EmailVerificationObserverStore)
			if err := remote.DiscardEmailVerificationReceipt(ctx, auth.EmailVerificationReceipt{Identifier: "unrelated-credential", Value: "secret"}); !errors.Is(err, auth.ErrNotFound) {
				t.Fatal("cleanup accepted an unrelated verification namespace", err)
			}
			codeProofs := store.(auth.EmailOTPVerificationObserverStore)
			remoteCode := peer.(auth.EmailOTPVerificationObserverStore)
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			o := auth.Options{Store: store, BaseURL: "https://auth.example.test", Secret: strings.Repeat("v", 40), EmailAndPassword: true, DisableAutoSignIn: true}
			plugin, err := auth.NewEmailOTP(auth.EmailOTPOptions{Send: func(context.Context, auth.EmailOTPMessage) error { return nil }})
			must(err)
			o.Plugins = []auth.Plugin{plugin}
			a, err := auth.New(o)
			must(err)
			for _, method := range []string{"link", "code"} {
				res, err := a.SignUpEmail(ctx, auth.SignUpInput{Name: "Handoff", Email: method + "@handoff.example.test", Password: "local receipt pass"}, auth.RequestMeta{})
				must(err)
				owner := res.User
				now := time.Now().UTC().Truncate(time.Millisecond)
				row := auth.StoredSession{Session: auth.Session{ID: "row-" + method, Token: "token-" + method, UserID: owner.ID, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}}
				rev := owner.UpdatedAt.UnixMilli()
				v := auth.EmailVerificationAttempt{ProfileUpdatedAtMillis: &rev, OwnerID: owner.ID, Email: owner.Email, ProofID: "proof-" + method, IssuedAt: owner.CreatedAt, Now: now, ExpiresAt: now.Add(time.Hour), NewSession: &row}
				if method == "link" {
					winner, err := proofs.CompleteObservedEmailVerification(ctx, v)
					must(err)
					if !winner.SessionEligible || winner.User.ID != owner.ID {
						t.Fatal("expected an eligible handoff")
					}
					owner = winner.User
				} else {
					code, err := a.CreateEmailOTP(ctx, owner.Email, auth.OTPVerifyEmail)
					must(err)
					req := auth.EmailOTPRequest{Purpose: auth.OTPVerifyEmail, Email: owner.Email, Now: now, MaxAttempts: 3, Observation: &auth.EmailOTPObservation{ID: v.ProofID, ExpiresAt: v.ExpiresAt, NewSession: &row}}
					before, err := codeProofs.ConsumeObservedEmailOTP(ctx, req, func(stored string) (bool, error) { return stored == code, nil })
					must(err)
					forged := req
					copy := *req.Observation
					copy.ID = "other-grant"
					forged.Observation = &copy
					if _, err := remoteCode.FinishObservedEmailOTP(ctx, forged, before); err == nil {
						t.Fatal("unissued OTP continuation changed a mailbox")
					}
					owner, err = remoteCode.FinishObservedEmailOTP(ctx, req, before)
					must(err)
					if _, err := codeProofs.FinishObservedEmailOTP(ctx, req, before); err == nil {
						t.Fatal("a consumed OTP continuation was reused")
					}
					v = req.ObservationAttempt(owner)
				}
				replacement := *v.NewSession
				replacement.Token = "substitute-" + method
				foreign := v
				foreign.NewSession = &replacement
				if got, err := remote.FinishObservedEmailSession(ctx, foreign, owner); err != nil || got != "" {
					t.Fatal("substitute session redeemed a continuation", err)
				}
				winners := make(chan string, 2)
				errs := make(chan error, 2)
				for _, node := range []auth.EmailVerificationObserverStore{proofs, remote} {
					go func() { tok, err := node.FinishObservedEmailSession(ctx, v, owner); winners <- tok; errs <- err }()
				}
				win := 0
				for range 2 {
					tok := <-winners
					must(<-errs)
					if tok == row.Token {
						win++
					} else if tok != "" {
						t.Fatal("unexpected token")
					}
				}
				if win != 1 {
					t.Fatal("session continuation was accepted multiple times", win)
				}
				got, err := remote.FinishObservedEmailSession(ctx, v, owner)
				must(err)
				if got != "" {
					t.Fatal("a spent verification handoff issued a second session")
				}
			}
		})
	}
}

func TestVerificationObserverPolicyAfterHostChanges(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			dsn := organizationTestDSN(t, dialect)
			ddl, err := schema.Generate(dialect, []string{"admin", "two-factor"})
			if err != nil {
				t.Fatal(err)
			}
			open := func() *Store {
				t.Helper()
				s, err := OpenWithSchema(ctx, dialect, dsn, ddl)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { s.Close() })
				return s
			}
			store, peer := open(), open()
			var proof string
			off := false
			var after auth.EmailVerificationHook
			plugin, err := auth.NewEmailOTP(auth.EmailOTPOptions{AutoSignInAfterVerification: true, Send: func(context.Context, auth.EmailOTPMessage) error { return nil }})
			if err != nil {
				t.Fatal(err)
			}
			var beforeCount int
			a, err := auth.New(auth.Options{Store: store, BaseURL: "https://auth.example.test", Secret: strings.Repeat("f", 40), EmailAndPassword: true, RequireEmailVerification: true, AutoSignInAfterVerification: true, RateLimit: &off, Plugins: []auth.Plugin{plugin},
				SendVerificationEmail:   func(_ context.Context, m auth.MailLink) error { proof = m.Token; return nil },
				BeforeEmailVerification: func(context.Context, auth.User, *http.Request) error { beforeCount++; return nil },
				AfterEmailVerification:  func(ctx context.Context, u auth.User, r *http.Request) error { return after(ctx, u, r) }})
			if err != nil {
				t.Fatal(err)
			}
			// Imported records can retain the original display case. The signed
			// owner ID selects the record even on case-sensitive databases.
			imported, err := a.SignUpEmail(ctx, auth.SignUpInput{Name: "Imported", Email: "mixed@domain.example.test", Password: "observer policy password"}, auth.RequestMeta{})
			if err != nil {
				t.Fatal(err)
			}
			original := "MixEd@Domain.Example.Test"
			if _, err := peer.db.ExecContext(ctx, peer.bind(`UPDATE "user" SET "email"=? WHERE "id"=?`), original, imported.User.ID); err != nil {
				t.Fatal(err)
			}
			after = func(_ context.Context, u auth.User, _ *http.Request) error {
				if u.Email != original || !u.EmailVerified {
					t.Fatal("lost stored mailbox casing")
				}
				return nil
			}
			if w := verificationRequest(a, proof, nil); w.Code != 200 || len(w.Result().Cookies()) == 0 {
				t.Fatal("bound mixed-case imported mailbox could not verify", w.Code, w.Body)
			}
			for _, method := range []string{"link", "code"} {
				for _, column := range []string{"banned", "twoFactorEnabled"} {
					u, err := a.SignUpEmail(ctx, auth.SignUpInput{Name: "Owner", Email: method + "-" + strings.ToLower(column) + "@policies.example.test", Password: "observer policy password"}, auth.RequestMeta{})
					if err != nil {
						t.Fatal(err)
					}
					after = func(ctx context.Context, snapshot auth.User, _ *http.Request) error {
						_, err := peer.db.ExecContext(ctx, peer.bind(`UPDATE "user" SET "`+column+`"=? WHERE "id"=?`), true, snapshot.ID)
						return err
					}
					if method == "link" {
						w := verificationRequest(a, proof, nil)
						if w.Code != 200 || len(w.Result().Cookies()) != 0 {
							t.Fatal("after hook changed the physical session policy", w.Code, w.Body)
						}
						_, err = peer.db.ExecContext(ctx, peer.bind(`UPDATE "user" SET "emailVerified"=? WHERE "id"=?`), false, u.User.ID)
						if err != nil {
							t.Fatal(err)
						}
						n := beforeCount
						w = verificationRequest(a, proof, nil)
						if w.Code != 401 || beforeCount != n {
							t.Fatal("known spent proof invoked another before hook", w.Code)
						}
					} else {
						otp, err := a.CreateEmailOTP(ctx, u.User.Email, auth.OTPVerifyEmail)
						if err != nil {
							t.Fatal(err)
						}
						result, err := a.CompleteEmailVerificationOTP(ctx, u.User.Email, otp, auth.RequestMeta{})
						if err != nil || result.Token != "" || !result.User.EmailVerified {
							t.Fatal("code granted a session despite the new policy", err)
						}
					}
					rows, err := peer.ListSessions(ctx, u.User.ID)
					if err != nil || len(rows) != 0 {
						t.Fatal("restricted owner obtained a session", len(rows), err)
					}
				}
			}
		})
	}
}
