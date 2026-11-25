package sqlstore

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	pk "github.com/Plain-Org/plain-auth/plugins/passkey"
	"github.com/Plain-Org/plain-auth/schema"
)

// Passkey challenges run the verification hooks on SQLite, PostgreSQL and
// MySQL, outside the store's transactions and with the stored row's ID: the
// create hooks when options are generated, and the delete hooks when a
// verification spends the challenge, before the credential is checked and
// before the session hooks.
func TestVerificationHooksAroundPasskeyChallenges(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			dsn := organizationTestDSN(t, dialect)
			const origin = "https://login.example.test"
			const rp = "example.test"
			ddl, err := schema.Generate(dialect, []string{"passkey"})
			if err != nil {
				t.Fatal(err)
			}
			s, err := OpenWithSchema(ctx, dialect, dsn, ddl)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			s2, err := OpenWithSchema(ctx, dialect, dsn, ddl)
			if err != nil {
				t.Fatal(err)
			}
			defer s2.Close()

			var mu sync.Mutex
			var events []string
			var records []auth.VerificationRecord
			rows := map[string]int{} // event → rows the hook saw under the record's ID
			decline, failing := map[string]bool{}, map[string]bool{}
			note := func(ctx context.Context, event string, rec *auth.VerificationRecord) error {
				// Each store reads on its one SQLite connection, which a hook run
				// inside that store's transaction would hold.
				read, cancel := context.WithTimeout(ctx, 5*time.Second)
				defer cancel()
				n := -1
				for _, st := range []*Store{s, s2} {
					id := ""
					if rec != nil {
						id = rec.ID
					}
					if err := st.db.QueryRowContext(read, st.bind(`SELECT COUNT(*) FROM "verification" WHERE "id"=?`), id).Scan(&n); err != nil {
						t.Error("a store was locked during", event, err)
					}
				}
				mu.Lock()
				defer mu.Unlock()
				events = append(events, event)
				if rec != nil {
					records = append(records, *rec)
					rows[event] = n
				}
				if decline[event] {
					return auth.ErrSkipWrite
				}
				if failing[event] {
					return errors.New("hook failed")
				}
				return nil
			}
			drain := func() ([]string, []auth.VerificationRecord) {
				mu.Lock()
				defer mu.Unlock()
				e, r := events, records
				events, records = nil, nil
				return e, r
			}
			same := func(got []string, want ...string) {
				t.Helper()
				if len(got)+len(want) > 0 && !reflect.DeepEqual(got, want) {
					t.Fatalf("hooks ran as %q, want %q", got, want)
				}
			}
			toggle := func(m map[string]bool, event string, on bool) {
				mu.Lock()
				defer mu.Unlock()
				m[event] = on
			}
			hooks := auth.DatabaseHooks{
				Verification: auth.ModelHooks[auth.VerificationRecord]{
					Create: auth.OperationHooks[auth.VerificationRecord]{
						Before: func(ctx context.Context, r *auth.VerificationRecord, _ *auth.HookContext) error {
							return note(ctx, "v-create-before:"+r.Identifier, r)
						},
						After: func(ctx context.Context, r auth.VerificationRecord, _ *auth.HookContext) error {
							return note(ctx, "v-create-after:"+r.Identifier, &r)
						},
					},
					Delete: auth.OperationHooks[auth.VerificationRecord]{
						Before: func(ctx context.Context, r *auth.VerificationRecord, _ *auth.HookContext) error {
							return note(ctx, "v-delete-before:"+r.Identifier, r)
						},
						After: func(ctx context.Context, r auth.VerificationRecord, _ *auth.HookContext) error {
							return note(ctx, "v-delete-after:"+r.Identifier, &r)
						},
					},
				},
				Session: auth.ModelHooks[auth.SessionRecord]{Create: auth.OperationHooks[auth.SessionRecord]{
					Before: func(ctx context.Context, _ *auth.SessionRecord, _ *auth.HookContext) error {
						return note(ctx, "session-before", nil)
					},
					After: func(ctx context.Context, _ auth.SessionRecord, _ *auth.HookContext) error {
						return note(ctx, "session-after", nil)
					},
				}},
			}
			instance := func(store *Store, registration pk.RegistrationOptions) *auth.Auth {
				t.Helper()
				plug, err := pk.New(pk.Options{RPID: rp, RPName: "Test", Origins: []string{origin}, RequireUserVerification: true, Registration: registration})
				if err != nil {
					t.Fatal(err)
				}
				off := false
				a, err := auth.New(auth.Options{Store: store, Secret: "test-only-passkey-0123456789-abcdefgh", BaseURL: origin, EmailAndPassword: true,
					Plugins: []auth.Plugin{plug}, RateLimit: &off, DatabaseHooks: hooks})
				if err != nil {
					t.Fatal(err)
				}
				return a
			}
			a, b := instance(s, pk.RegistrationOptions{}), instance(s2, pk.RegistrationOptions{})
			request := func(server *auth.Auth, path string, payload any, status int, cookies ...*http.Cookie) (map[string]any, *http.Cookie) {
				t.Helper()
				var body bytes.Buffer
				method := "GET"
				if payload != nil {
					method = "POST"
					if err := json.NewEncoder(&body).Encode(payload); err != nil {
						t.Fatal(err)
					}
				}
				r := httptest.NewRequest(method, origin+"/api/auth/passkey/"+path, &body)
				r.Header.Set("Origin", origin)
				if payload != nil {
					r.Header.Set("Content-Type", "application/json")
				}
				for _, cookie := range cookies {
					r.AddCookie(cookie)
				}
				w := httptest.NewRecorder()
				server.ServeHTTP(w, r)
				if w.Code != status {
					t.Fatalf("%s: got %d want %d: %s", path, w.Code, status, w.Body.String())
				}
				var out map[string]any
				if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
					t.Fatal(err)
				}
				var challenge *http.Cookie
				for _, c := range w.Result().Cookies() {
					if strings.HasSuffix(c.Name, "passkey_challenge") {
						challenge = c
					}
				}
				return out, challenge
			}
			// stored reads the row a challenge cookie names.
			stored := func(cookie *http.Cookie) (key, id string, expires time.Time) {
				t.Helper()
				sum := sha256.Sum256([]byte(a.VerifySignedSessionToken(cookie.Value)))
				key = hex.EncodeToString(sum[:])
				err := s.db.QueryRowContext(ctx, s.bind(`SELECT "id","expiresAt" FROM "verification" WHERE "identifier"=?`), "passkey:"+key).Scan(&id, &expires)
				if errors.Is(err, sql.ErrNoRows) {
					return key, "", time.Time{}
				}
				if err != nil {
					t.Fatal(err)
				}
				return key, id, expires
			}
			challenges := func() int {
				t.Helper()
				var n int
				if err := s.db.QueryRowContext(ctx, s.bind(`SELECT COUNT(*) FROM "verification" WHERE "identifier" LIKE 'passkey:%'`)).Scan(&n); err != nil {
					t.Fatal(err)
				}
				return n
			}
			// like checks that every record hook since the last drain saw want,
			// and none carried a secret of the challenge cookie names.
			like := func(got []auth.VerificationRecord, want auth.VerificationRecord, cookie *http.Cookie, secrets ...string) {
				t.Helper()
				if len(got) == 0 {
					t.Fatal("no record hook ran")
				}
				sum := sha256.Sum256([]byte(a.VerifySignedSessionToken(cookie.Value)))
				for _, r := range got {
					if r.ID != want.ID || r.Identifier != want.Identifier || r.UserID != want.UserID || !r.ExpiresAt.Equal(want.ExpiresAt) || r.ExpiresAt.Location() != time.UTC {
						t.Fatalf("a hook saw %+v, want %+v", r, want)
					}
					for _, secret := range append(secrets, cookie.Value, a.VerifySignedSessionToken(cookie.Value), hex.EncodeToString(sum[:])) {
						if secret != "" && strings.Contains(fmt.Sprint(r), secret) {
							t.Fatal("a record carried a secret:", r)
						}
					}
				}
			}
			// saw checks that every record hook since the last drain saw the
			// challenge cookie names, and returns that record.
			saw := func(got []auth.VerificationRecord, cookie *http.Cookie, kind, owner string, secrets ...string) auth.VerificationRecord {
				t.Helper()
				key, id, expires := stored(cookie)
				if id == "" {
					t.Fatal("the challenge was not stored")
				}
				if id != pk.ChallengeRecordID(key) {
					t.Fatal("the row ID", id, "is not derived from the key")
				}
				want := auth.VerificationRecord{ID: id, Identifier: kind, UserID: owner, ExpiresAt: expires}
				like(got, want, cookie, secrets...)
				return want
			}

			res, err := a.SignUpEmail(ctx, auth.SignUpInput{Email: "owner@example.test", Name: "owner", Password: "local sample passphrase"}, auth.RequestMeta{})
			if err != nil {
				t.Fatal(err)
			}
			owner, session := res.User, a.SessionCookie(res.Token, true)
			drain()

			// A signed-in registration's challenge names the user it is for.
			key := newSoftwareKey(t)
			options, cookie := request(a, "generate-register-options", nil, 200, session)
			got, recs := drain()
			same(got, "v-create-before:passkey-registration", "v-create-after:passkey-registration")
			created := saw(recs, cookie, "passkey-registration", owner.ID, options["challenge"].(string))
			key.handle = options["user"].(map[string]any)["id"].(string)
			// The challenge's hooks run before the session's.
			request(b, "verify-registration", map[string]any{"response": key.response(t, options["challenge"].(string), origin, rp, 0, true), "name": "Primary", "createSession": true}, 200, cookie, session)
			got, recs = drain()
			same(got, "v-delete-before:passkey-registration", "v-delete-after:passkey-registration", "session-before", "session-after")
			like(recs, created, cookie, options["challenge"].(string))
			if rows["v-delete-before:passkey-registration"] != 1 || rows["v-delete-after:passkey-registration"] != 0 {
				t.Fatal("the delete hooks saw", rows, "rows")
			}

			// A declined challenge returns options that redeem nothing.
			before := challenges()
			toggle(decline, "v-create-before:passkey-registration", true)
			declined, expired := request(a, "generate-register-options", nil, 200, session)
			toggle(decline, "v-create-before:passkey-registration", false)
			if declined["challenge"] == nil || expired == nil || expired.MaxAge >= 0 || challenges() != before {
				t.Fatal("a declined challenge was stored or kept its cookie:", expired, challenges(), before)
			}
			got, _ = drain()
			same(got, "v-create-before:passkey-registration")
			second := newSoftwareKey(t)
			second.handle = declined["user"].(map[string]any)["id"].(string)
			request(b, "verify-registration", map[string]any{"response": second.response(t, declined["challenge"].(string), origin, rp, 0, true)}, 400, session)
			got, _ = drain()
			same(got)

			// A declined spend keeps the challenge for a retry.
			options, cookie = request(a, "generate-register-options", nil, 200, session)
			drain()
			second.handle = options["user"].(map[string]any)["id"].(string)
			attempt := map[string]any{"response": second.response(t, options["challenge"].(string), origin, rp, 0, true), "name": "Second"}
			toggle(decline, "v-delete-before:passkey-registration", true)
			if body, cleared := request(b, "verify-registration", attempt, 400, cookie, session); body["code"] != "CHALLENGE_NOT_FOUND" || cleared != nil {
				t.Fatal("a declined spend answered", body, "and set", cleared)
			}
			toggle(decline, "v-delete-before:passkey-registration", false)
			if _, id, _ := stored(cookie); id == "" {
				t.Fatal("a declined spend removed the challenge")
			}
			got, _ = drain()
			same(got, "v-delete-before:passkey-registration")
			if _, cleared := request(b, "verify-registration", attempt, 200, cookie, session); cleared == nil || cleared.MaxAge >= 0 {
				t.Fatal("a spent challenge kept its cookie")
			}
			got, _ = drain()
			same(got, "v-delete-before:passkey-registration", "v-delete-after:passkey-registration")
			// The challenge is spent before the attestation is verified.
			options, cookie = request(a, "generate-register-options", nil, 200, session)
			drain()
			third := newSoftwareKey(t)
			third.handle = options["user"].(map[string]any)["id"].(string)
			if body, _ := request(b, "verify-registration", map[string]any{"response": third.response(t, options["challenge"].(string), "https://untrusted.example.test", rp, 0, true)}, 400, cookie, session); body["code"] != "FAILED_TO_VERIFY_REGISTRATION" {
				t.Fatal("a bad attestation answered", body)
			}
			got, _ = drain()
			same(got, "v-delete-before:passkey-registration", "v-delete-after:passkey-registration")
			if _, id, _ := stored(cookie); id != "" {
				t.Fatal("a bad attestation kept its challenge")
			}

			// A signed-out sign-in's challenge names no owner.
			counter := uint32(0)
			login := func(server *auth.Auth, origin string, status int) {
				t.Helper()
				options, cookie := request(a, "generate-authenticate-options", nil, 200)
				got, recs := drain()
				same(got, "v-create-before:passkey-authentication", "v-create-after:passkey-authentication")
				saw(recs, cookie, "passkey-authentication", "", options["challenge"].(string))
				counter++
				request(server, "verify-authentication", map[string]any{"response": key.response(t, options["challenge"].(string), origin, rp, counter, false)}, status, cookie)
			}
			// A sign-in spends its challenge before the session hooks run.
			login(b, origin, 200)
			got, recs = drain()
			same(got, "v-delete-before:passkey-authentication", "v-delete-after:passkey-authentication", "session-before", "session-after")
			for _, r := range recs {
				if r.Identifier != "passkey-authentication" || r.UserID != "" {
					t.Fatal("a signed-out sign-in's spend saw", r)
				}
			}
			// A failed assertion still spends the challenge.
			login(b, "https://untrusted.example.test", 401)
			got, _ = drain()
			same(got, "v-delete-before:passkey-authentication", "v-delete-after:passkey-authentication")

			// A first-use registration's challenge names no owner either.
			resolver := instance(s, pk.RegistrationOptions{AllowWithoutSession: true, ResolveUser: func(auth.EndpointContext, *string) (pk.RegistrationUser, error) {
				return pk.RegistrationUser{ID: "pending-owner", Name: "pending@example.test"}, nil
			}})
			_, cookie = request(resolver, "generate-register-options", nil, 200)
			got, recs = drain()
			same(got, "v-create-before:passkey-registration", "v-create-after:passkey-registration")
			saw(recs, cookie, "passkey-registration", "")

			// A cookie for the other ceremony is refused before the store.
			options, cookie = request(a, "generate-authenticate-options", nil, 200)
			drain()
			request(b, "verify-registration", attempt, 400, cookie, session)
			got, _ = drain()
			same(got)
			if _, id, _ := stored(cookie); id == "" {
				t.Fatal("a cookie for the other ceremony spent its challenge")
			}

			// Concurrent verifications of one passkey challenge run one delete after hook.
			counter++
			payload := map[string]any{"response": key.response(t, options["challenge"].(string), origin, rp, counter, false)}
			var wg sync.WaitGroup
			statuses := make(chan int, 6)
			for i := range 6 {
				wg.Go(func() {
					var body bytes.Buffer
					json.NewEncoder(&body).Encode(payload)
					r := httptest.NewRequest("POST", origin+"/api/auth/passkey/verify-authentication", &body)
					r.Header.Set("Origin", origin)
					r.Header.Set("Content-Type", "application/json")
					r.AddCookie(cookie)
					w := httptest.NewRecorder()
					[]*auth.Auth{a, b}[i%2].ServeHTTP(w, r)
					statuses <- w.Code
				})
			}
			wg.Wait()
			close(statuses)
			signedIn := 0
			for status := range statuses {
				if status == 200 {
					signedIn++
				} else if status != 400 {
					t.Fatal("a concurrent verification answered", status)
				}
			}
			spends, sessions := 0, 0
			got, _ = drain()
			for _, e := range got {
				switch e {
				case "v-delete-after:passkey-authentication":
					spends++
				case "session-after":
					sessions++
				}
			}
			if signedIn != 1 || spends != 1 || sessions != 1 {
				t.Fatal("six concurrent verifications signed in", signedIn, "times with", spends, "spends and", sessions, "sessions")
			}

			// A failed delete after hook is returned with the challenge spent and
			// before any session.
			options, cookie = request(a, "generate-authenticate-options", nil, 200)
			drain()
			toggle(failing, "v-delete-after:passkey-authentication", true)
			counter++
			request(b, "verify-authentication", map[string]any{"response": key.response(t, options["challenge"].(string), origin, rp, counter, false)}, 500, cookie)
			toggle(failing, "v-delete-after:passkey-authentication", false)
			got, _ = drain()
			same(got, "v-delete-before:passkey-authentication", "v-delete-after:passkey-authentication")
			if _, id, _ := stored(cookie); id != "" {
				t.Fatal("a failed after hook kept the challenge")
			}

			// An expired challenge is refused without hooks.
			options, cookie = request(a, "generate-authenticate-options", nil, 200)
			drain()
			if _, err := s.db.ExecContext(ctx, s.bind(`UPDATE "verification" SET "expiresAt"=? WHERE "identifier" LIKE 'passkey:%'`), s.date(time.Now().Add(-time.Hour))); err != nil {
				t.Fatal(err)
			}
			counter++
			request(b, "verify-authentication", map[string]any{"response": key.response(t, options["challenge"].(string), origin, rp, counter, false)}, 400, cookie)
			got, _ = drain()
			same(got)

			// FindPasskeyChallenge reads the challenge the take spends, with its
			// stored ID, and nothing once it is spent, expired or unknown.
			now := time.Now().UTC().Truncate(time.Millisecond)
			if err := s.SavePasskeyChallenge(ctx, "contract", []byte(`{"Kind":"authentication"}`), now, now.Add(time.Minute)); err != nil {
				t.Fatal(err)
			}
			id, body, expires, err := s2.FindPasskeyChallenge(ctx, "contract", now)
			if err != nil || id != pk.ChallengeRecordID("contract") || string(body) != `{"Kind":"authentication"}` || !expires.Equal(now.Add(time.Minute)) {
				t.Fatal("the finder read", id, string(body), expires, err)
			}
			if _, err := s2.TakePasskeyChallenge(ctx, "contract", now); err != nil {
				t.Fatal("the finder kept the challenge from its take:", err)
			}
			for _, k := range []string{"contract", "unknown"} {
				if _, _, _, err := s2.FindPasskeyChallenge(ctx, k, now); !errors.Is(err, auth.ErrNotFound) {
					t.Fatal("the finder read a challenge it should not:", k, err)
				}
			}
			if err := s.SavePasskeyChallenge(ctx, "short", []byte(`{}`), now, now.Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, _, _, err := s2.FindPasskeyChallenge(ctx, "short", now.Add(2*time.Second)); !errors.Is(err, auth.ErrNotFound) {
				t.Fatal("the finder read an expired challenge:", err)
			}
			// A challenge stored before row IDs were derived keeps its own.
			legacy := rand.Text()
			if _, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO "verification" ("id","identifier","value","expiresAt","createdAt","updatedAt") VALUES(?,?,?,?,?,?)`),
				legacy, "passkey:legacy", "{}", s.date(now.Add(time.Minute)), s.date(now), s.date(now)); err != nil {
				t.Fatal(err)
			}
			if id, _, _, err := s2.FindPasskeyChallenge(ctx, "legacy", now); err != nil || id != legacy {
				t.Fatal("the finder reported", id, "for the stored", legacy, err)
			}
		})
	}
}
