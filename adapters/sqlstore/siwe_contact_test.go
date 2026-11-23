package sqlstore

import (
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/client"
	"github.com/Plain-Org/plain-auth/plugins/siwe"
	"github.com/Plain-Org/plain-auth/schema"
)

type coreWalletStorage interface{ auth.Store }
type walletStorage interface{ siwe.Store }
type basicWalletStorage struct {
	coreWalletStorage
	walletStorage
}

func TestSIWEContactOwnership(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			dsn := organizationTestDSN(t, dialect)
			ddl, err := schema.Generate(dialect, []string{"siwe"})
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
			first, second := open(), open()
			for _, required := range []bool{false, true} {
				plugin, err := siwe.New(siwe.Options{Domain: "wallet.example.test", RequireEmail: required})
				if err != nil {
					t.Fatal(err)
				}
				err = plugin.ValidateStore(basicWalletStorage{first, first})
				if (err != nil) != required {
					t.Fatal("base adapter capability check", required, err)
				}
			}
			const domain = "wallet.example.test"
			opt := siwe.Options{Domain: domain, RequireEmail: true}
			a, b := walletCallbackClient(t, first, opt), walletCallbackClient(t, second, opt)
			alice, bob := freshWallet(t), freshWallet(t)
			message := func(c *client.Client, w walletSigner, chain int64) string {
				t.Helper()
				n, err := c.SIWENonce(ctx)
				if err != nil {
					t.Fatal(err)
				}
				return walletMessage(w.address, domain, n, chain)
			}
			proof := func(c *client.Client, w walletSigner, chain int64, contact string) *siwe.Result {
				t.Helper()
				m := message(c, w, chain)
				res, err := c.VerifySIWEWithEmail(ctx, m, w.sign(m), contact)
				if err != nil {
					t.Fatal(err)
				}
				return res
			}
			user := func(c *client.Client, want string) auth.User {
				t.Helper()
				s, err := c.GetSession(ctx)
				if err != nil || s == nil || s.User.Email != want || s.User.EmailVerified {
					t.Fatal("unexpected wallet contact", s, err)
				}
				return s.User
			}
			placeholder := func(w walletSigner) string { return w.address + "@siwe.placeholder.invalid" }
			m := message(a, alice, 1)
			sig := alice.sign(m)
			for _, v := range []any{nil, "", "bad.mailbox", "K@example.test", 42} {
				err := a.Do(ctx, http.MethodPost, "/siwe/verify", map[string]any{"email": v, "signature": sig, "message": m}, nil)
				var api *auth.APIError
				if !errors.As(err, &api) || api.Status != 400 {
					t.Fatalf("invalid contact %#v: %v", v, err)
				}
			}
			_, err = a.VerifySIWE(ctx, m, sig)
			var api *auth.APIError
			if !errors.As(err, &api) || api.Status != 400 {
				t.Fatal("missing contact", err)
			}
			const email = "shared-contact@example.test"
			res, err := a.VerifySIWEWithEmail(ctx, m, sig, strings.ToUpper(email))
			if err != nil {
				t.Fatal("contact validation spent the challenge", err)
			}
			owner := user(a, email)
			if res.User.ID != owner.ID {
				t.Fatal("session mismatch")
			}
			if again := proof(b, alice, 137, "new@example.test"); again.User.ID != owner.ID {
				t.Fatal("returning wallet lost its owner")
			}
			user(b, email)
			if peer := proof(b, bob, 1, email); peer.User.ID == owner.ID {
				t.Fatal("unproven contact linked two wallet identities")
			}
			user(b, placeholder(bob))
			occupied := freshWallet(t)
			proof(b, occupied, 1, placeholder(freshWallet(t)))
			user(b, placeholder(occupied))
			now := time.Now().UTC()
			victim := auth.User{ID: rand.Text(), Name: "Existing credential owner", Email: "credential@example.test", EmailVerified: true, CreatedAt: now, UpdatedAt: now}
			if err := first.CreateUser(ctx, victim, "existing-password-hash", nil); err != nil {
				t.Fatal(err)
			}
			if _, err := first.db.ExecContext(ctx, first.bind(`UPDATE "user" SET "email"=? WHERE "id"=?`), strings.ToUpper(victim.Email), victim.ID); err != nil {
				t.Fatal(err)
			}
			newcomer := freshWallet(t)
			if other := proof(b, newcomer, 1, victim.Email); other.User.ID == victim.ID {
				t.Fatal("registered email selected a foreign account")
			}
			user(b, placeholder(newcomer))

			// One caller holds the claim over a host lookup. An independent node
			// must immediately issue a different wallet identity for the loser.
			const raceEmail = "simultaneous@example.test"
			held, release := make(chan struct{}), make(chan struct{})
			block := opt
			block.ENSLookup = func(ctx context.Context, _ siwe.ENSLookupArgs) (siwe.ENSLookupResult, error) {
				close(held)
				select {
				case <-release:
				case <-ctx.Done():
					return siwe.ENSLookupResult{}, ctx.Err()
				}
				return siwe.ENSLookupResult{}, nil
			}
			c := walletCallbackClient(t, first, block)
			winner, loser := freshWallet(t), freshWallet(t)
			challenge := message(c, winner, 1)
			done := make(chan error, 1)
			finished := false
			defer func() {
				if !finished {
					close(release)
				}
			}()
			go func() {
				_, err := c.VerifySIWEWithEmail(ctx, challenge, winner.sign(challenge), raceEmail)
				done <- err
			}()
			select {
			case <-held:
			case <-time.After(10 * time.Second):
				t.Fatal("contact lookup did not start")
			}
			proof(b, loser, 1, raceEmail)
			user(b, placeholder(loser))
			close(release)
			finished = true
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			user(c, raceEmail)

			// A separate registration can complete after the reservation.
			const late = "late-registration@example.test"
			lateWallet := freshWallet(t)
			during := opt
			during.ENSLookup = func(ctx context.Context, _ siwe.ENSLookupArgs) (siwe.ENSLookupResult, error) {
				u := auth.User{ID: rand.Text(), Name: "Mail owner", Email: late, EmailVerified: true, CreatedAt: now, UpdatedAt: now}
				return siwe.ENSLookupResult{}, second.CreateUser(ctx, u, "credential", nil)
			}
			d := walletCallbackClient(t, first, during)
			proof(d, lateWallet, 1, late)
			user(d, placeholder(lateWallet))

			// Cancelled profile registration releases only its claimed receipt.
			const failed = "after-error@example.test"
			bad := opt
			bad.ENSLookup = func(context.Context, siwe.ENSLookupArgs) (siwe.ENSLookupResult, error) {
				return siwe.ENSLookupResult{}, errors.New("fixture lookup failure")
			}
			e := walletCallbackClient(t, first, bad)
			failedWallet := freshWallet(t)
			m = message(e, failedWallet, 1)
			if _, err := e.VerifySIWEWithEmail(ctx, m, failedWallet.sign(m), failed); err == nil {
				t.Fatal("failed callback created a wallet")
			}
			proof(b, failedWallet, 1, failed)
			user(b, failed)

			// An expired, forged or transferred store receipt never claims an email.
			const fenced = "fenced@example.test"
			lease, err := first.ReserveWalletContact(ctx, fenced, bob.address)
			if err != nil || lease == nil {
				t.Fatal("missing claim", err)
			}
			if _, err := first.db.ExecContext(ctx, first.bind(`UPDATE "verification" SET "expiresAt"=? WHERE "id"=?`), first.date(now.Add(-time.Minute)), lease.ID); err != nil {
				t.Fatal(err)
			}
			replacement, err := second.ReserveWalletContact(ctx, fenced, alice.address)
			if err != nil || replacement == nil {
				t.Fatal("expired claim prevented new reservation", err)
			}
			if err := first.ReleaseWalletContact(ctx, *lease); err != nil {
				t.Fatal(err)
			}
			impostor := *replacement
			impostor.Address = bob.address
			if err := first.ReleaseWalletContact(ctx, impostor); err != nil {
				t.Fatal(err)
			}
			if next, err := first.ReserveWalletContact(ctx, fenced, bob.address); err != nil || next != nil {
				t.Fatal("stale cleanup released the new owner's claim", next, err)
			}
			// A different signer cannot use a current claim, even through the trusted
			// storage interface. The original signer can still finish with it.
			direct := func(address string, c siwe.ContactClaim) auth.User {
				t.Helper()
				id := rand.Text()
				in := siwe.Login{Address: address, CandidateID: id, Email: strings.ToLower(address) + "@siwe.placeholder.invalid", ChainID: 1, AllowSignUp: true}
				ss := auth.StoredSession{Session: auth.Session{ID: rand.Text(), UserID: id, Token: rand.Text(), CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}}
				u, err := first.FinishWalletContactLogin(ctx, in, ss, c)
				if err != nil {
					t.Fatal(err)
				}
				return u
			}
			stranger := freshWallet(t)
			if u := direct(stranger.address, *replacement); u.Email != placeholder(stranger) {
				t.Fatal("foreign receipt claimed contact")
			}
			unrelated := freshWallet(t)
			newClaim, err := second.ReserveWalletContact(ctx, "native@example.test", unrelated.address)
			if err != nil || newClaim == nil {
				t.Fatal(err)
			}
			if u := direct(unrelated.address, *newClaim); u.Email != "native@example.test" || u.EmailVerified {
				t.Fatal("live owner receipt lost at commit")
			}
			// An externally expired lease must also fall back when finishing.
			lateSigner := freshWallet(t)
			expired, err := first.ReserveWalletContact(ctx, "expired@example.test", lateSigner.address)
			if err != nil || expired == nil {
				t.Fatal(err)
			}
			expired.ExpiresAt = now.Add(-time.Minute)
			if _, err := first.db.ExecContext(ctx, first.bind(`UPDATE "verification" SET "expiresAt"=? WHERE "id"=?`), first.date(expired.ExpiresAt), expired.ID); err != nil {
				t.Fatal(err)
			}
			if u := direct(lateSigner.address, *expired); u.Email != placeholder(lateSigner) {
				t.Fatal("expired claim authorized a contact")
			}
			if err := first.ReleaseWalletContact(ctx, *expired); err != nil {
				t.Fatal(err)
			}
			if err := second.ReleaseWalletContact(ctx, *replacement); err != nil {
				t.Fatal(err)
			}
			var leases int
			if err := first.db.QueryRowContext(ctx, first.bind(`SELECT COUNT(*) FROM "verification" WHERE "identifier" LIKE 'siwe-email-claim-%'`)).Scan(&leases); err != nil || leases != 0 {
				t.Fatal("contact reservation survived registration", leases, err)
			}

			// The mailbox proof supersedes every pre-proof wallet session and chain.
			key := rand.Text()
			if err := second.SaveMagicLink(ctx, auth.MagicLinkChallenge{Key: key, Email: email, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
				t.Fatal(err)
			}
			session := auth.StoredSession{Session: auth.Session{ID: rand.Text(), Token: rand.Text(), CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}}
			verified, created, err := second.CompleteMagicLink(ctx, key, rand.Text(), session, true)
			if err != nil || !verified.EmailVerified || verified.ID != owner.ID || created {
				t.Fatal("mailbox sign-in failed to promote owner", verified, created, err)
			}
			if stale, err := a.GetSession(ctx); err != nil || stale != nil {
				t.Fatal("wallet session survived mailbox reclaim", stale, err)
			}
			if replacement := proof(b, alice, 10, email); replacement.User.ID == verified.ID {
				t.Fatal("another chain restored access to the proven mailbox")
			}
			user(b, placeholder(alice))
			// Email sign-in codes, like magic links, independently prove mailbox
			// ownership. A purposeful verify-email operation preserves the wallet.
			codeSigner := freshWallet(t)
			const codeEmail = "contact-code@example.test"
			original := proof(b, codeSigner, 1, codeEmail)
			req := auth.EmailOTPRequest{Email: codeEmail, Purpose: auth.OTPSignIn, Now: now}
			code, err := second.SaveEmailOTP(ctx, req, true, now.Add(time.Hour), func(*auth.EmailOTPRecord) (string, string, int, error) { return "034579", "034579", 0, nil })
			if err != nil || code == "" {
				t.Fatal(err)
			}
			session.ID, session.Token = rand.Text(), rand.Text()
			mailbox, err := second.UseEmailOTP(ctx, auth.EmailOTPAction{EmailOTPRequest: req, MaxAttempts: 3, Session: session}, func(stored string) (bool, error) { return stored == code, nil })
			if err != nil || mailbox.ID != original.User.ID || !mailbox.EmailVerified {
				t.Fatal("email code failed to reclaim contact", err)
			}
			if other := proof(b, codeSigner, 137, codeEmail); other.User.ID == mailbox.ID {
				t.Fatal("email code retained old wallet access")
			}
			consenting := freshWallet(t)
			const confirmedEmail = "consented@example.test"
			confirmed := proof(a, consenting, 1, confirmedEmail)
			if err := second.VerifyAccountEmail(ctx, confirmed.User.ID, confirmedEmail, now); err != nil {
				t.Fatal(err)
			}
			returning := proof(b, consenting, 137, "unused@example.test")
			live, err := b.GetSession(ctx)
			if err != nil || live == nil || returning.User.ID != confirmed.User.ID || !live.User.EmailVerified || live.User.Email != confirmedEmail {
				t.Fatal("explicit address verification lost wallet ownership", live, err)
			}

		})
	}
}
