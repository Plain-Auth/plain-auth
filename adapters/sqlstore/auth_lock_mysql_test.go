package sqlstore

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/schema"
)

type mysqlAuthLockTest struct {
	fixture      *mysqlPoolConnector
	observer     *Store
	primary      *Store
	before       int64
	lockOwnerSQL string
	args         []any
}

func mysqlAuthLockFixture(t *testing.T) (driver.Connector, *Store) {
	t.Helper()
	real := mysqlTestConnector(t)
	db := sql.OpenDB(real)
	t.Cleanup(func() { db.Close() })
	observer := &Store{db: db, dialect: "mysql", adminSchema: new(atomic.Bool), apiKeyLedgerReady: new(atomic.Bool)}
	ddl, err := schema.Generate("mysql", []string{"jwt"})
	if err != nil {
		t.Fatal(err)
	}
	if err = observer.migrate(t.Context(), ddl); err != nil {
		t.Fatal(err)
	}
	return real, observer
}

func startMySQLAuthLock(t *testing.T, real driver.Connector, observer *Store, fault, nameSQL string, args ...any) *mysqlAuthLockTest {
	t.Helper()
	fixture := &mysqlPoolConnector{
		Connector: real, fault: fault,
		rollbackEntered: make(chan struct{}), resumeRollback: make(chan struct{}),
	}
	db := sql.OpenDB(fixture)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	t.Cleanup(func() { db.Close() })
	primary := *observer
	primary.db = db
	return &mysqlAuthLockTest{
		fixture: fixture, observer: observer, primary: &primary,
		before: mysqlPhysicalID(t, db), lockOwnerSQL: "SELECT IS_USED_LOCK(" + nameSQL + ")", args: args,
	}
}

func (p *mysqlAuthLockTest) owner(t *testing.T) sql.NullInt64 {
	t.Helper()
	var owner sql.NullInt64
	if err := p.observer.db.QueryRowContext(t.Context(), p.lockOwnerSQL, p.args...).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	return owner
}

func (p *mysqlAuthLockTest) assertHeld(t *testing.T) {
	t.Helper()
	if owner := p.owner(t); !owner.Valid || owner.Int64 != p.before {
		t.Fatalf("callback saw lock owner %v; want connection %d", owner, p.before)
	}
}

// Wait until database/sql has started the physical rollback so the caller
// cannot mistake its own deferred Rollback's ErrTxDone for a confirmed end.
func (p *mysqlAuthLockTest) callbackError(t *testing.T, cancel context.CancelFunc) error {
	t.Helper()
	switch p.fixture.fault {
	case "abort", "rollback":
		return errAuthLockAbort
	case "cancel":
		cancel()
		select {
		case <-p.fixture.rollbackEntered:
			defer close(p.fixture.resumeRollback)
			p.assertHeld(t)
		case <-time.After(3 * time.Second):
			t.Fatal("driver did not begin rollback after request cancellation")
		}
		return context.Canceled
	}
	return nil
}

func (p *mysqlAuthLockTest) assertReleased(t *testing.T, reuse bool) {
	t.Helper()
	after := mysqlPhysicalID(t, p.primary.db)
	if same := after == p.before; same != reuse {
		t.Errorf("physical connection reuse = %v; want %v (%d -> %d)", same, reuse, p.before, after)
	}
	deadline := time.Now().Add(3 * time.Second)
	for owner := p.owner(t); owner.Valid; owner = p.owner(t) {
		if time.Now().After(deadline) {
			t.Fatalf("lock still owned by physical connection %d", owner.Int64)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

var authLockCases = []struct {
	fault                      string
	reached, committed, reused bool
}{
	{"success", true, true, true},
	{"abort", true, false, true},
	{"acquire", false, false, false},
	{"acquire-zero", false, false, true},
	{"acquire-null", false, false, true},
	{"begin", false, false, false},
	{"commit", true, false, false},
	{"rollback", true, false, false},
	{"commit-reply", true, true, false},
	{"cancel", true, false, false},
	{"release", true, true, false},
	{"release-zero", true, true, false},
	{"release-null", true, true, false},
}

var errAuthLockAbort = errors.New("callback stopped the transaction")

func assertMySQLAuthLockError(t *testing.T, fault string, err error, busy string) {
	t.Helper()
	switch fault {
	case "abort", "rollback":
		if !errors.Is(err, errAuthLockAbort) {
			t.Fatalf("lost callback error: %v", err)
		}
	case "cancel":
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("lost cancellation: %v", err)
		}
	case "begin", "commit", "commit-reply", "acquire":
		if !errors.Is(err, errMySQLPoolFixture) {
			t.Fatalf("lost driver error: %v", err)
		}
	case "acquire-zero", "acquire-null":
		if err == nil || err.Error() != busy {
			t.Fatalf("unexpected busy error: %v", err)
		}
	default:
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestMySQLJWTLockOutcomes(t *testing.T) {
	real, observer := mysqlAuthLockFixture(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	for _, tc := range authLockCases {
		t.Run(tc.fault, func(t *testing.T) {
			ctx := t.Context()
			probe := startMySQLAuthLock(t, real, observer, tc.fault, "CONCAT('authn/jwks/', MD5(DATABASE()))")
			generated := false
			id := "key-" + tc.fault
			request, cancel := context.WithCancel(ctx)
			defer cancel()
			key, err := probe.primary.ActiveJWTKey(request, "EdDSA", now, func() (auth.StoredJWTKey, error) {
				generated = true
				probe.assertHeld(t)
				if failure := probe.callbackError(t, cancel); failure != nil {
					return auth.StoredJWTKey{}, failure
				}
				return auth.StoredJWTKey{
					PublicJWTKey:        auth.PublicJWTKey{ID: id, Algorithm: "EdDSA", Curve: "Ed25519", PublicKey: "fixture public JWK", CreatedAt: now},
					EncryptedPrivateKey: "fixture encrypted key",
				}, nil
			})
			assertMySQLAuthLockError(t, tc.fault, err, "jwt: signing key lock unavailable")
			if generated != tc.reached {
				t.Fatalf("generated = %v; want %v", generated, tc.reached)
			}
			probe.assertReleased(t, tc.reused)
			stored, err := observer.JWTKeyByID(ctx, id)
			if !tc.committed {
				if !errors.Is(err, sql.ErrNoRows) {
					t.Fatalf("uncommitted key visible: %v", err)
				}
				return
			}
			if err != nil || stored.ID != key.ID || key.ID != id {
				t.Fatalf("published key differs from committed key: %v", err)
			}
			// Existing live keys are served without entering the named lock.
			cached, err := probe.primary.ActiveJWTKey(ctx, "EdDSA", now, func() (auth.StoredJWTKey, error) {
				t.Fatal("generated a second live key")
				return auth.StoredJWTKey{}, nil
			})
			if err != nil || cached.ID != id {
				t.Fatalf("lost committed signing key: %v", err)
			}
			if _, err := observer.db.ExecContext(ctx, "DELETE FROM jwks WHERE id=?", id); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestMySQLEmailOTPLockOutcomes(t *testing.T) {
	real, observer := mysqlAuthLockFixture(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	for _, tc := range authLockCases {
		t.Run(tc.fault, func(t *testing.T) {
			ctx := t.Context()
			id := "otp-" + tc.fault
			req := auth.EmailOTPRequest{Email: id + "@example.test", Purpose: auth.OTPVerifyEmail, Now: now}
			user := auth.User{ID: id, Name: id, Email: req.Email, CreatedAt: now, UpdatedAt: now}
			if err := observer.CreateUser(ctx, user, "fixture credential", nil); err != nil {
				t.Fatal(err)
			}
			if _, err := observer.SaveEmailOTP(ctx, req, false, now.Add(time.Minute), func(*auth.EmailOTPRecord) (string, string, int, error) {
				return "fixture", "fixture", 0, nil
			}); err != nil {
				t.Fatal(err)
			}
			key := newEmailOTPKey(req)
			probe := startMySQLAuthLock(t, real, observer, tc.fault, "SHA2(CONCAT(DATABASE(), '/auth/email-otp/', ?), 256)", key.digest)
			action := auth.EmailOTPAction{EmailOTPRequest: req, MaxAttempts: 3}
			called := false
			request, cancel := context.WithCancel(ctx)
			defer cancel()
			_, err := probe.primary.UseEmailOTP(request, action, func(stored string) (bool, error) {
				called = true
				probe.assertHeld(t)
				if failure := probe.callbackError(t, cancel); failure != nil {
					return false, failure
				}
				return stored == "fixture", nil
			})
			assertMySQLAuthLockError(t, tc.fault, err, "email OTP mailbox lock unavailable")
			if called != tc.reached {
				t.Fatalf("checked proof = %v; want %v", called, tc.reached)
			}
			probe.assertReleased(t, tc.reused)
			var verified bool
			if err := observer.db.QueryRowContext(ctx, "SELECT emailVerified FROM user WHERE id=?", id).Scan(&verified); err != nil {
				t.Fatal(err)
			}
			record, err := observer.ReadEmailOTP(ctx, req)
			if err != nil || verified != tc.committed || (record == nil) != tc.committed {
				t.Fatalf("incomplete OTP transaction: verified=%v record=%v error=%v", verified, record, err)
			}
			if tc.committed {
				_, err = observer.UseEmailOTP(ctx, action, func(string) (bool, error) {
					t.Fatal("replayed consumed code")
					return true, nil
				})
				var apiErr *auth.APIError
				if !errors.As(err, &apiErr) || apiErr.Code != "INVALID_OTP" {
					t.Fatalf("unexpected replay result: %v", err)
				}
			}
		})
	}
	t.Run("bad proof commits its attempt despite uncertain release", func(t *testing.T) {
		ctx := t.Context()
		req := auth.EmailOTPRequest{Email: "denied@example.test", Purpose: auth.OTPSignIn, Now: now}
		_, err := observer.SaveEmailOTP(ctx, req, true, now.Add(time.Minute), func(*auth.EmailOTPRecord) (string, string, int, error) { return "fixture", "fixture", 0, nil })
		if err != nil {
			t.Fatal(err)
		}
		key := newEmailOTPKey(req)
		probe := startMySQLAuthLock(t, real, observer, "release", "SHA2(CONCAT(DATABASE(), '/auth/email-otp/', ?), 256)", key.digest)
		_, err = probe.primary.UseEmailOTP(ctx, auth.EmailOTPAction{EmailOTPRequest: req, MaxAttempts: 3}, func(string) (bool, error) { return false, nil })
		var apiErr *auth.APIError
		if !errors.As(err, &apiErr) || apiErr.Code != "INVALID_OTP" {
			t.Fatalf("lost denial: %v", err)
		}
		probe.assertReleased(t, false)
		record, err := observer.ReadEmailOTP(ctx, req)
		if err != nil || record == nil || record.Attempts != 1 {
			t.Fatalf("attempt count lost: %+v %v", record, err)
		}
	})
}
