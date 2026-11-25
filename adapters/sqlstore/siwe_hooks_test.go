package sqlstore

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/siwe"
	"github.com/Plain-Org/plain-auth/schema"
)

// Wallet sign-in nonces run the verification hooks on SQLite, PostgreSQL and
// MySQL, outside the store's transactions and with the stored row's ID: the
// create hooks when a nonce is issued, and the delete hooks when a
// verification spends it, before the message and signature are checked and
// before the session hooks.
func TestVerificationHooksAroundWalletNonces(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			dsn := organizationTestDSN(t, dialect)
			ddl, err := schema.Generate(dialect, []string{"siwe"})
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
			const domain = "wallet.example.test"

			var mu sync.Mutex
			var events []string
			var records []auth.VerificationRecord
			decline := map[string]bool{}
			note := func(ctx context.Context, event string, rec *auth.VerificationRecord) error {
				// Each store reads on its one SQLite connection, which a hook run
				// inside that store's transaction would hold.
				read, cancel := context.WithTimeout(ctx, 5*time.Second)
				defer cancel()
				for _, st := range []*Store{s, s2} {
					var n int
					if err := st.db.QueryRowContext(read, st.bind(`SELECT COUNT(*) FROM "verification" WHERE "identifier" LIKE 'siwe:%'`)).Scan(&n); err != nil {
						t.Error("a store was locked during", event, err)
					}
				}
				mu.Lock()
				defer mu.Unlock()
				events = append(events, event)
				if rec != nil {
					records = append(records, *rec)
				}
				if decline[event] {
					return auth.ErrSkipWrite
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
			toggle := func(event string, on bool) {
				mu.Lock()
				defer mu.Unlock()
				decline[event] = on
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
			instance := func(store *Store, o siwe.Options) *auth.Auth {
				t.Helper()
				o.Domain = domain
				plug, err := siwe.New(o)
				if err != nil {
					t.Fatal(err)
				}
				off := false
				a, err := auth.New(auth.Options{Store: store, BaseURL: returnOrigin + returnMount, Secret: strings.Repeat("s", 32), RateLimit: &off,
					Plugins: []auth.Plugin{plug}, DatabaseHooks: hooks})
				if err != nil {
					t.Fatal(err)
				}
				return a
			}
			a, b := instance(s, siwe.Options{}), instance(s2, siwe.Options{})
			call := func(a *auth.Auth, path string, body any, status int) map[string]any {
				t.Helper()
				raw, err := json.Marshal(body)
				if err != nil {
					t.Fatal(err)
				}
				r := httptest.NewRequest("POST", returnOrigin+returnMount+path, strings.NewReader(string(raw)))
				r.Header.Set("Origin", returnOrigin)
				r.Header.Set("Content-Type", "application/json")
				w := httptest.NewRecorder()
				a.ServeHTTP(w, r)
				if w.Code != status {
					t.Fatalf("%s answered %d %s, want %d", path, w.Code, w.Body.String(), status)
				}
				var out map[string]any
				if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
					t.Fatal(err)
				}
				return out
			}
			issue := func(a *auth.Auth) string {
				t.Helper()
				return call(a, "/siwe/nonce", map[string]any{}, 200)["nonce"].(string)
			}
			signed := func(w walletSigner, nonce string, extra map[string]any) map[string]any {
				msg := walletMessage(w.address, domain, nonce, 1)
				body := map[string]any{"message": msg, "signature": w.sign(msg)}
				for k, v := range extra {
					body[k] = v
				}
				return body
			}
			stored := func(nonce string) []string {
				t.Helper()
				rows, err := s.db.QueryContext(ctx, s.bind(`SELECT "id" FROM "verification" WHERE "identifier"=?`), "siwe:"+nonce)
				if err != nil {
					t.Fatal(err)
				}
				defer rows.Close()
				var ids []string
				for rows.Next() {
					var id string
					if err := rows.Scan(&id); err != nil {
						t.Fatal(err)
					}
					ids = append(ids, id)
				}
				return ids
			}
			// saw checks that every record hook since the last drain saw the
			// nonce's row, and none carried the nonce.
			saw := func(got []auth.VerificationRecord, nonce, id string, expires time.Time) {
				t.Helper()
				if len(got) == 0 {
					t.Fatal("no record hook ran")
				}
				for _, r := range got {
					if r.ID != id || r.Identifier != "siwe" || r.UserID != "" || !r.ExpiresAt.Equal(expires) || r.ExpiresAt.Location() != time.UTC || strings.Contains(fmt.Sprint(r), nonce) {
						t.Fatalf("a hook saw %+v for the row %s expiring %v", r, id, expires)
					}
				}
			}
			wallet := freshWallet(t)

			// The nonce's record names its row and no owner.
			n := issue(a)
			got, recs := drain()
			same(got, "v-create-before:siwe", "v-create-after:siwe")
			var id string
			var expires time.Time
			if err := s.db.QueryRowContext(ctx, s.bind(`SELECT "id","expiresAt" FROM "verification" WHERE "identifier"=?`), "siwe:"+n).Scan(&id, &expires); err != nil {
				t.Fatal(err)
			}
			if id != siwe.NonceRecordID(n) || id != walletLock("nonce", n).digest[:36] {
				t.Fatal("the row ID", id, "is not the nonce's record ID")
			}
			saw(recs, n, id, expires)
			// The nonce's hooks run before the session's.
			call(b, "/siwe/verify", signed(wallet, n, nil), 200)
			got, recs = drain()
			same(got, "v-delete-before:siwe", "v-delete-after:siwe", "session-before", "session-after")
			saw(recs, n, id, expires)
			// A bad signature still spends the nonce.
			n = issue(a)
			drain()
			bad := signed(wallet, n, nil)
			bad["signature"] = freshWallet(t).sign(bad["message"].(string))
			call(b, "/siwe/verify", bad, 401)
			got, _ = drain()
			same(got, "v-delete-before:siwe", "v-delete-after:siwe")
			if len(stored(n)) != 0 {
				t.Fatal("a refused signature kept its nonce")
			}

			// A declined nonce is returned but redeems nothing.
			toggle("v-create-before:siwe", true)
			n = issue(a)
			toggle("v-create-before:siwe", false)
			if len(stored(n)) != 0 {
				t.Fatal("a declined nonce was stored")
			}
			got, _ = drain()
			same(got, "v-create-before:siwe")
			if out := call(b, "/siwe/verify", signed(wallet, n, nil), 401); out["code"] != "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE" {
				t.Fatal("a declined nonce answered", out)
			}
			got, _ = drain()
			same(got)

			// A declined spend keeps the nonce for a retry.
			n = issue(a)
			drain()
			toggle("v-delete-before:siwe", true)
			if out := call(b, "/siwe/verify", signed(wallet, n, nil), 401); out["code"] != "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE" || len(stored(n)) != 1 {
				t.Fatal("a declined spend answered", out, "and left", stored(n))
			}
			toggle("v-delete-before:siwe", false)
			got, _ = drain()
			same(got, "v-delete-before:siwe")
			call(b, "/siwe/verify", signed(wallet, n, nil), 200)
			got, _ = drain()
			same(got, "v-delete-before:siwe", "v-delete-after:siwe", "session-before", "session-after")

			// A host verifier spends the nonce with its deadline, through the
			// same hooks.
			verifier := instance(s2, siwe.Options{VerifyMessage: func(_ context.Context, v siwe.VerifyMessageArgs) (bool, error) { return v.SignedBy(v.Address), nil }})
			n = issue(a)
			drain()
			call(verifier, "/siwe/verify", signed(wallet, n, nil), 200)
			got, _ = drain()
			same(got, "v-delete-before:siwe", "v-delete-after:siwe", "session-before", "session-after")
			// A contact email's reservation runs no hooks.
			contacts := instance(s2, siwe.Options{RequireEmail: true})
			n = issue(a)
			drain()
			call(contacts, "/siwe/verify", signed(freshWallet(t), n, map[string]any{"email": "wallet-owner@example.test"}), 200)
			got, _ = drain()
			same(got, "v-delete-before:siwe", "v-delete-after:siwe", "session-before", "session-after")

			// A declined custom nonce still enters the history.
			var fixed string
			custom := instance(s, siwe.Options{GetNonce: func(context.Context) (string, error) {
				mu.Lock()
				defer mu.Unlock()
				return fixed, nil
			}})
			setFixed := func(v string) {
				mu.Lock()
				defer mu.Unlock()
				fixed = v
			}
			setFixed("Declined" + rand.Text())
			toggle("v-create-before:siwe", true)
			call(custom, "/siwe/nonce", map[string]any{}, 200)
			got, _ = drain()
			same(got, "v-create-before:siwe")
			if len(stored(fixed)) != 0 {
				t.Fatal("a declined custom nonce was stored")
			}
			digest := sha256.Sum256([]byte(fixed))
			var kept int
			if err := s.db.QueryRowContext(ctx, s.bind(`SELECT COUNT(*) FROM "plainauth_siwe_nonce_digest" WHERE "digest"=?`), digest[:]).Scan(&kept); err != nil || kept != 1 {
				t.Fatal("a declined custom nonce left the history:", kept, err)
			}
			for _, declined := range []bool{true, false} {
				toggle("v-create-before:siwe", declined)
				if out := call(custom, "/siwe/nonce", map[string]any{}, 500); out["code"] != "SIWE_INVALID_NONCE" {
					t.Fatal("a repeated custom nonce answered", out)
				}
				got, _ = drain()
				same(got, "v-create-before:siwe")
			}
			toggle("v-create-before:siwe", false)
			// An issued custom nonce runs the same hooks.
			setFixed("Issued" + rand.Text())
			call(custom, "/siwe/nonce", map[string]any{}, 200)
			call(custom, "/siwe/verify", signed(wallet, fixed, nil), 200)
			got, _ = drain()
			same(got, "v-create-before:siwe", "v-create-after:siwe", "v-delete-before:siwe", "v-delete-after:siwe", "session-before", "session-after")

			// An expired nonce is refused without hooks.
			n = issue(a)
			drain()
			if _, err := s.db.ExecContext(ctx, s.bind(`UPDATE "verification" SET "expiresAt"=? WHERE "identifier"=?`), s.date(time.Now().Add(-time.Hour)), "siwe:"+n); err != nil {
				t.Fatal(err)
			}
			call(b, "/siwe/verify", signed(wallet, n, nil), 401)
			got, _ = drain()
			same(got)

			// A nonce another runtime stored twice is removed and refused without hooks.
			n = issue(a)
			drain()
			now := time.Now().UTC()
			if _, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO "verification" ("id","identifier","value","expiresAt","createdAt","updatedAt") VALUES(?,?,?,?,?,?)`),
				rand.Text(), "siwe:"+n, n, s.date(now.Add(time.Minute)), s.date(now), s.date(now)); err != nil {
				t.Fatal(err)
			}
			if _, _, err := s2.FindWalletNonce(ctx, n, now); !errors.Is(err, auth.ErrNotFound) {
				t.Fatal("the finder read a duplicated nonce:", err)
			}
			call(b, "/siwe/verify", signed(wallet, n, nil), 401)
			got, _ = drain()
			same(got)
			if len(stored(n)) != 0 {
				t.Fatal("a duplicated nonce was kept")
			}
			if _, _, err := s2.FindWalletNonce(ctx, "unknown", now); !errors.Is(err, auth.ErrNotFound) {
				t.Fatal("the finder read an unknown nonce:", err)
			}

			// Concurrent verifications of one wallet nonce run one delete after hook.
			n = issue(a)
			drain()
			body := signed(wallet, n, nil)
			var wg sync.WaitGroup
			statuses := make(chan int, 6)
			for i := range 6 {
				wg.Go(func() {
					raw, _ := json.Marshal(body)
					r := httptest.NewRequest("POST", returnOrigin+returnMount+"/siwe/verify", strings.NewReader(string(raw)))
					r.Header.Set("Origin", returnOrigin)
					r.Header.Set("Content-Type", "application/json")
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
				} else if status != 401 {
					t.Fatal("a concurrent verification answered", status)
				}
			}
			spends, sessions := 0, 0
			got, _ = drain()
			for _, e := range got {
				switch e {
				case "v-delete-after:siwe":
					spends++
				case "session-after":
					sessions++
				}
			}
			if signedIn != 1 || spends != 1 || sessions != 1 {
				t.Fatal("six concurrent verifications signed in", signedIn, "times with", spends, "spends and", sessions, "sessions")
			}
		})
	}
}
