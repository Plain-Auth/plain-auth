package sqlstore

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/client"
	"github.com/Plain-Auth/plain-auth/plugins/siwe"
	"github.com/Plain-Auth/plain-auth/schema"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"
)

type walletSigner struct {
	private *secp.PrivateKey
	address string
}

func freshWallet(t *testing.T) walletSigner {
	t.Helper()
	key, err := secp.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	h := sha3.NewLegacyKeccak256()
	h.Write(key.PubKey().SerializeUncompressed()[1:])
	return walletSigner{key, "0x" + hex.EncodeToString(h.Sum(nil)[12:])}
}

func (w walletSigner) sign(text string) string {
	h := sha3.NewLegacyKeccak256()
	fmt.Fprintf(h, "\x19Ethereum Signed Message:\n%d%s", len(text), text)
	sig := ecdsa.SignCompact(w.private, h.Sum(nil), false)
	return "0x" + hex.EncodeToString(append(sig[1:], sig[0]))
}

func walletMessage(address, domain, nonce string, chain int64) string {
	return domain + " wants you to sign in with your Ethereum account:\n" + address + "\n\nSign in.\n\nURI: https://" + domain + "/welcome\nVersion: 1\nChain ID: " + strconv.FormatInt(chain, 10) + "\nNonce: " + nonce + "\nIssued At: " + time.Now().UTC().Format(time.RFC3339Nano)
}

func TestSIWEWalletIdentity(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			dsn := organizationTestDSN(t, dialect)
			ddl, err := schema.Generate(dialect, []string{"siwe", "admin"})
			if err != nil {
				t.Fatal(err)
			}
			var store *Store
			node := func(allow bool, emailDomain string) *client.Client {
				s, err := OpenWithSchema(ctx, dialect, dsn, ddl)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { s.Close() })
				if store == nil {
					store = s
				}
				p, err := siwe.New(siwe.Options{Domain: "wallet.example.test", EmailDomainName: emailDomain, Chains: []int64{1, 137}})
				if err != nil {
					t.Fatal(err)
				}
				off := false
				server, err := auth.New(auth.Options{Store: s, BaseURL: returnOrigin + returnMount, Secret: strings.Repeat("s", 32), EmailAndPassword: true, DisableSignUp: !allow, RateLimit: &off, Plugins: []auth.Plugin{p}})
				if err != nil {
					t.Fatal(err)
				}
				c, err := client.New(returnOrigin+returnMount, &http.Client{Transport: localBillingTransport(func(r *http.Request) (*http.Response, error) {
					out := httptest.NewRecorder()
					server.ServeHTTP(out, r)
					return out.Result(), nil
				})})
				if err != nil {
					t.Fatal(err)
				}
				return c
			}
			a, b, restricted := node(true, ""), node(true, ""), node(false, "")
			w := freshWallet(t)
			challenge := func(c *client.Client) string {
				t.Helper()
				n, err := c.SIWENonce(ctx)
				if err != nil {
					t.Fatal(err)
				}
				return n
			}
			verify := func(c *client.Client, chain int64) (*siwe.Result, error) {
				n := challenge(c)
				s := walletMessage(w.address, "wallet.example.test", n, chain)
				return c.VerifySIWE(ctx, s, w.sign(s))
			}
			denied := func(err error, status int) {
				t.Helper()
				var api *auth.APIError
				if !errors.As(err, &api) || api.Status != status {
					t.Fatalf("wanted status %d, got %v", status, err)
				}
			}
			_, err = verify(restricted, 1)
			denied(err, 403)

			for _, mutate := range []func(string) string{
				func(s string) string { return strings.ReplaceAll(s, "wallet.example.test", "other.example.test") },
				func(s string) string {
					return strings.Replace(s, "URI: https://wallet.example.test", "URI: https://other.example.test", 1)
				},
				func(s string) string { return strings.Replace(s, "Chain ID: 1", "Chain ID: 10", 1) },
				func(s string) string {
					return s + "\nExpiration Time: " + time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
				},
				func(s string) string {
					return s + "\nNot Before: " + time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
				},
				func(s string) string { return s + "\nExpiration Time: invalid" },
			} {
				n := challenge(a)
				original := walletMessage(w.address, "wallet.example.test", n, 1)
				modified := mutate(original)
				_, err := b.VerifySIWE(ctx, modified, w.sign(modified))
				denied(err, 401)
				_, err = a.VerifySIWE(ctx, original, w.sign(original))
				denied(err, 401)
			}
			n := challenge(a)
			if _, err = store.db.ExecContext(ctx, store.bind(`UPDATE "verification" SET "expiresAt"=? WHERE "identifier"=?`), store.date(time.Now().Add(-time.Second)), "siwe:"+n); err != nil {
				t.Fatal(err)
			}
			stale := walletMessage(w.address, "wallet.example.test", n, 1)
			_, err = b.VerifySIWE(ctx, stale, w.sign(stale))
			denied(err, 401)
			_ = challenge(a)
			var expired int
			if err := store.db.QueryRowContext(ctx, store.bind(`SELECT COUNT(*) FROM "verification" WHERE "identifier"=?`), "siwe:"+n).Scan(&expired); err != nil || expired != 0 {
				t.Fatal("expired wallet challenges were not removed", err)
			}

			type result struct {
				value *siwe.Result
				err   error
			}
			replies := make(chan result, 2)
			n = challenge(a)
			same := walletMessage(w.address, "wallet.example.test", n, 1)
			signature := w.sign(same)
			for _, node := range []*client.Client{a, b} {
				go func() { v, err := node.VerifySIWE(ctx, same, signature); replies <- result{v, err} }()
			}
			var user string
			var successes int
			for range 2 {
				r := <-replies
				if r.err == nil {
					successes++
					user = r.value.User.ID
					if !strings.EqualFold(r.value.User.WalletAddress, w.address) {
						t.Fatal("incorrect recovered address")
					}
				} else {
					denied(r.err, 401)
				}
			}
			if successes != 1 {
				t.Fatal("a signed wallet nonce must issue exactly one session", successes)
			}
			res, err := verify(restricted, 137)
			if err != nil || res.User.ID != user || res.User.ChainID != 137 {
				t.Fatal("second chain changed the wallet owner", res, err)
			}
			session, err := restricted.GetSession(ctx)
			if err != nil || session == nil || session.User.ID != user || session.User.EmailVerified || session.User.Email != w.address+"@siwe.placeholder.invalid" {
				t.Fatal("wallet cookie or placeholder identity", session, err)
			}

			count := func(table string) int {
				t.Helper()
				var n int
				if err := store.db.QueryRowContext(ctx, store.bind(`SELECT COUNT(*) FROM "`+table+`" WHERE "userId"=?`), user).Scan(&n); err != nil {
					t.Fatal(err)
				}
				return n
			}
			if count("walletAddress") != 2 || count("account") != 2 {
				t.Fatal("cross-chain sign-in duplicated wallets or accounts")
			}
			// An imported provider subject may lack a uniqueness constraint.
			// Refuse duplicates even if the first row names the expected owner.
			exec := func(query string, args ...any) {
				t.Helper()
				if _, err := store.db.ExecContext(ctx, store.bind(query), args...); err != nil {
					t.Fatal(err)
				}
			}
			subject := res.User.WalletAddress + ":1"
			now := store.date(time.Now())
			exec(`INSERT INTO "account" ("id","accountId","providerId","userId","createdAt","updatedAt") VALUES ('duplicate-wallet',?,'siwe',?,?,?)`, subject, user, now, now)
			sessions := count("session")
			_, err = verify(b, 1)
			if err == nil || count("session") != sessions {
				t.Fatal("ambiguous imported wallet accounts issued a session")
			}
			exec(`DELETE FROM "account" WHERE "id"='duplicate-wallet'`)

			if _, err = store.db.ExecContext(ctx, store.bind(`UPDATE "user" SET "banned"=? WHERE "id"=?`), true, user); err != nil {
				t.Fatal(err)
			}
			before := count("session")
			_, err = verify(b, 1)
			denied(err, 403)
			if count("session") != before {
				t.Fatal("banned wallet created a session")
			}
			if _, err = store.db.ExecContext(ctx, store.bind(`UPDATE "user" SET "banned"=? WHERE "id"=?`), false, user); err != nil {
				t.Fatal(err)
			}
			accounts, err := store.ListUserAccounts(ctx, user)
			if err != nil {
				t.Fatal(err)
			}
			for _, account := range accounts {
				if account.AccountID == subject {
					err = store.UnlinkAccount(ctx, user, account.ID, false)
				}
			}
			if err != nil || count("walletAddress") != 1 {
				t.Fatal("unlink did not remove the wallet credential", err)
			}
			var primary bool
			if err := store.db.QueryRowContext(ctx, store.bind(`SELECT "isPrimary" FROM "walletAddress" WHERE "userId"=?`), user).Scan(&primary); err != nil || !primary {
				t.Fatal("remaining wallet lost its primary status", err)
			}
			if err = store.DeleteFixtureUser(ctx, user); err != nil {
				t.Fatal(err)
			}
			if count("walletAddress") != 0 || count("session") != 0 || count("account") != 0 {
				t.Fatal("deletion retained wallet identity or sessions")
			}

			first := freshWallet(t)
			for _, node := range []*client.Client{a, b} {
				nonce := challenge(node)
				s := walletMessage(first.address, "wallet.example.test", nonce, 1)
				sig := first.sign(s)
				go func() { v, e := node.VerifySIWE(ctx, s, sig); replies <- result{v, e} }()
			}
			left, right := <-replies, <-replies
			if left.err != nil || right.err != nil || left.value.User.ID != right.value.User.ID {
				t.Fatalf("concurrent first use created conflicting owners: %+v %+v", left, right)
			}
			user = left.value.User.ID
			if count("walletAddress") != 1 || count("account") != 1 {
				t.Fatal("duplicate first-use credentials")
			}
			preexisting := freshWallet(t)
			exec(`INSERT INTO "user" ("id","name","email","emailVerified","createdAt","updatedAt") VALUES ('email-owner','Existing',?,?,?,?)`, preexisting.address+"@siwe.placeholder.invalid", true, now, now)
			contested := walletMessage(preexisting.address, "wallet.example.test", challenge(a), 1)
			_, err = a.VerifySIWE(ctx, contested, preexisting.sign(contested))
			denied(err, 409)
			user = "email-owner"
			if count("session") != 0 || count("walletAddress") != 0 || count("account") != 0 {
				t.Fatal("wallet registration attached to an existing email owner")
			}
			custom := node(true, "wallet.invalid")
			key := freshWallet(t)
			text := walletMessage(key.address, "wallet.example.test", challenge(custom), 1)
			if _, err := custom.VerifySIWE(ctx, text, key.sign(text)); err != nil {
				t.Fatal(err)
			}
			observed, err := custom.GetSession(ctx)
			if err != nil || observed == nil || observed.User.Email != key.address+"@wallet.invalid" || observed.User.EmailVerified {
				t.Fatal("custom wallet email domain was not applied", observed, err)
			}

		})
	}
}
