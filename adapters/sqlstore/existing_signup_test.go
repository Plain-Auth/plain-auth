package sqlstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/memory"
	"github.com/Plain-Org/plain-auth/schema"
)

type signupContextKey struct{}

func TestProtectedDuplicateSignUpObserver(t *testing.T) {
	for _, dialect := range []string{"memory", "sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := context.WithValue(t.Context(), signupContextKey{}, "preserved")
			var stores [2]auth.Store
			var sql *Store
			if dialect == "memory" {
				stores[0] = memory.New()
				stores[1] = stores[0]
			} else {
				dsn := organizationTestDSN(t, dialect)
				for i := range stores {
					s, err := Open(ctx, dialect, dsn)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { s.Close() })
					stores[i] = s
				}
				sql = stores[0].(*Store)
			}
			var calls atomic.Int32
			var logs bytes.Buffer
			asset := "https://images.example.test/owner"
			federated := testUser("identity")
			federated.EmailVerified = true
			federated.Image = &asset
			if sql != nil {
				if _, created, err := sql.CompleteOAuth(ctx, "fixture", "provider-subject", auth.OAuthTokens{}, federated, testSession(federated, "provider-session"), auth.OAuthLoginOptions{}); err != nil || !created {
					t.Fatalf("create provider-only account: %v", err)
				}
			} else if err := stores[0].CreateUser(ctx, federated, "", nil); err != nil {
				t.Fatal(err)
			}
			if _, _, err := stores[1].Credential(ctx, federated.Email); !errors.Is(err, auth.ErrNotFound) {
				t.Fatal("fixture unexpectedly has a credential")
			}
			const submitted = "submitted-password-private"
			const alternate = "Submitted private name"
			secretErr := "private host callback detail"
			obs := func(callCtx context.Context, u auth.User, r *http.Request) error {
				n := calls.Add(1)
				if callCtx.Value(signupContextKey{}) != "preserved" || u.ID != federated.ID || u.Email != federated.Email || !u.EmailVerified || u.Name != federated.Name || u.Image == nil || *u.Image != asset || !u.CreatedAt.Equal(federated.CreatedAt) {
					t.Fatalf("callback did not see the durable provider-only owner, independent of the submitted profile")
				}
				// Reenter another live store while the callback runs, including for the memory store.
				saved, err := stores[1].(auth.AccountStore).FindAccountUser(callCtx, u.Email)
				if err != nil || saved.ID != u.ID {
					t.Fatalf("winner was unavailable outside the insertion transaction: %v", err)
				}
				switch n {
				case 1:
					if r != nil {
						t.Fatal("a direct Go call received an HTTP request")
					}
					return errors.New(secretErr)
				case 2:
					if r == nil || r.Method != "POST" || r.URL.Path != "/identity/sign-up/email" || r.Header.Get("X-Trace-Id") != "request-marker" || r.Body != http.NoBody || r.GetBody != nil || r.Context().Value(signupContextKey{}) != "preserved" {
						t.Fatal("mounted hook did not preserve isolated request metadata")
					}
					r.Header.Set("X-Trace-Id", "changed by hook")
					panic(secretErr)
				default:
					return nil
				}
			}
			off := false
			opts := auth.Options{Store: stores[0], BaseURL: "https://auth.test", BasePath: "/identity", Secret: strings.Repeat("x", 40), RateLimit: &off,
				EmailAndPassword: true, RequireEmailVerification: true, SendVerificationOnSignUp: &off, OnExistingUserSignUp: obs,
				Logger: slog.New(slog.NewJSONHandler(&logs, nil))}
			open := func(opts auth.Options) *auth.Auth {
				t.Helper()
				a, err := auth.New(opts)
				if err != nil {
					t.Fatal(err)
				}
				return a
			}
			api := open(opts)
			attempt := auth.SignUpInput{Name: alternate, Email: strings.ToUpper(federated.Email), Password: submitted}
			out, err := api.SignUpEmail(ctx, attempt, auth.RequestMeta{})
			if err != nil || out.Token != "" || out.User.ID == federated.ID || out.User.Name != alternate || out.User.EmailVerified || out.User.Image != nil || calls.Load() != 1 {
				t.Fatalf("native replay exposed callback or owner state: %v", err)
			}
			raw, _ := json.Marshal(map[string]string{"name": alternate, "email": attempt.Email, "password": submitted})
			req := httptest.NewRequest("POST", "https://auth.test/identity/sign-up/email", bytes.NewReader(raw)).WithContext(ctx)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Trace-Id", "request-marker")
			rec := httptest.NewRecorder()
			api.ServeHTTP(rec, req)
			var wire struct {
				Token any
				User  auth.User
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &wire); err != nil || rec.Code != 200 || wire.Token != nil || wire.User.ID == out.User.ID || wire.User.ID == federated.ID || wire.User.Name != alternate || len(rec.Result().Cookies()) != 0 ||
				req.Header.Get("X-Trace-Id") != "request-marker" || calls.Load() != 2 {
				t.Fatalf("mounted replay exposed callback failure, owner, or session: %v, HTTP %d", err, rec.Code)
			}
			for _, value := range []string{submitted, alternate, federated.Email, secretErr, federated.ID} {
				if strings.Contains(logs.String(), value) {
					t.Fatal("observer diagnostics contained private data")
				}
			}
			if count := strings.Count(logs.String(), "Existing-user sign-up observer failed"); count != 2 {
				t.Fatalf("missing redacted hook diagnostics: %d", count)
			}
			if _, _, err = stores[1].Credential(ctx, federated.Email); !errors.Is(err, auth.ErrNotFound) {
				t.Fatal("a duplicate sign-up added credentials to a provider-only account")
			}

			// Normal sign-up and its explicit 422 duplicate mode never emit this observer.
			opts.RequireEmailVerification = false
			ordinary := open(opts)
			_, err = ordinary.SignUpEmail(ctx, attempt, auth.RequestMeta{})
			var ae *auth.APIError
			if !errors.As(err, &ae) || ae.Status != 422 || ae.Code != "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL" || calls.Load() != 2 {
				t.Fatal("ordinary sign-up called the observer")
			}
			invalid := attempt
			invalid.Password = "x"
			if _, err = api.SignUpEmail(ctx, invalid, auth.RequestMeta{}); err == nil || calls.Load() != 2 {
				t.Fatal("invalid attempts reached the observer")
			}

			// Multiple independent instances attempt a new email concurrently; the observer sees the committed winner.
			const n = 6
			email := "concurrent@example.test"
			type outcome struct {
				user auth.User
				err  error
			}
			events := make(chan auth.User, n)
			finished := make(chan outcome, n)
			start := make(chan struct{})
			var wg sync.WaitGroup
			opts.DisableAutoSignIn = true
			opts.OnExistingUserSignUp = func(ctx context.Context, u auth.User, r *http.Request) error { events <- u; return nil }
			nodes := [2]*auth.Auth{}
			for i := range nodes {
				opts.Store = stores[i]
				nodes[i] = open(opts)
			}
			for i := range n {
				wg.Go(func() {
					<-start
					res, e := nodes[i%2].SignUpEmail(ctx, auth.SignUpInput{Name: fmt.Sprintf("Candidate %d", i), Email: email, Password: submitted}, auth.RequestMeta{})
					if res.Token != "" {
						e = errors.New("private registration issued a session")
					}
					finished <- outcome{res.User, e}
				})
			}
			close(start)
			wg.Wait()
			close(events)
			close(finished)
			winner, e := stores[0].(auth.AccountStore).FindAccountUser(ctx, email)
			if e != nil {
				t.Fatal(e)
			}
			ids := map[string]bool{}
			for reply := range finished {
				if reply.err != nil || reply.user.ID == "" || ids[reply.user.ID] {
					t.Fatalf("opaque concurrent sign-up: %v", reply.err)
				}
				ids[reply.user.ID] = true
			}
			if len(events) != n-1 || !ids[winner.ID] {
				t.Fatalf("expected one durable account and %d duplicate observations, got %d", n-1, len(events))
			}
			for u := range events {
				if u.ID != winner.ID || u.Name != winner.Name || u.Email != winner.Email {
					t.Fatal("concurrent observer received a synthetic or unrelated account")
				}
			}
			if rows, e := stores[0].ListSessions(ctx, winner.ID); e != nil || len(rows) != 0 {
				t.Fatal("private concurrent sign-up created a session")
			}

			if dialect == "mysql" {
				// A legacy imported accent can collide under MySQL's default collation without owning the requested address.
				imported := testUser("legacy")
				imported.Email = "résumé@example.test"
				if err := stores[0].CreateUser(ctx, imported, "fixture", nil); err != nil {
					t.Fatal(err)
				}
				var wrong atomic.Bool
				opts.OnExistingUserSignUp = func(context.Context, auth.User, *http.Request) error { wrong.Store(true); return nil }
				_, e := open(opts).SignUpEmail(ctx, auth.SignUpInput{Name: "Other", Email: "resume@example.test", Password: submitted}, auth.RequestMeta{})
				if e != nil || wrong.Load() {
					t.Fatal("collation-equivalent imported email received another address's notification")
				}
			}
		})
	}
}

func TestProtectedSignUpPluginFields(t *testing.T) {
	for _, dialect := range []string{"memory", "sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			var store auth.Store
			if dialect == "memory" {
				store = memory.New()
			} else {
				ddl, err := schema.Generate(dialect, []string{"phone-number", "anonymous"})
				if err != nil {
					t.Fatal(err)
				}
				s, err := OpenWithSchema(ctx, dialect, organizationTestDSN(t, dialect), ddl)
				if err != nil {
					t.Fatal(err)
				}
				defer s.Close()
				store = s
			}
			anon, err := auth.NewAnonymous(auth.AnonymousOptions{})
			if err != nil {
				t.Fatal(err)
			}
			phone, err := auth.NewPhoneNumber(auth.PhoneNumberOptions{})
			if err != nil {
				t.Fatal(err)
			}
			a, err := auth.New(auth.Options{Store: store, BaseURL: "http://example.test", Secret: strings.Repeat("s", 40), EmailAndPassword: true, DisableAutoSignIn: true, Plugins: []auth.Plugin{anon, phone}})
			if err != nil {
				t.Fatal(err)
			}
			var fresh map[string]any
			for i := range 2 {
				req := httptest.NewRequest("POST", "http://example.test/api/auth/sign-up/email", strings.NewReader(`{"name":"Person","email":"person@example.test","password":"test-password"}`))
				req.Header.Set("Content-Type", "application/json")
				w := httptest.NewRecorder()
				a.ServeHTTP(w, req)
				var response struct{ User map[string]any }
				if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || w.Code != 200 {
					t.Fatalf("HTTP %d: %s", w.Code, w.Body.String())
				}
				for _, key := range []string{"id", "createdAt", "updatedAt"} {
					delete(response.User, key)
				}
				if i == 0 {
					fresh = response.User
					continue
				}
				if !reflect.DeepEqual(fresh, response.User) || fresh["isAnonymous"] != false {
					t.Fatal("protected HTTP sign-up had different public plugin fields for fresh and duplicate registrations")
				}
				for _, key := range []string{"phoneNumber", "phoneNumberVerified"} {
					if v, ok := fresh[key]; !ok || v != nil {
						t.Fatal("missing public phone field in default sign-up")
					}
				}
			}
		})
	}
}
