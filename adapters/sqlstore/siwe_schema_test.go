package sqlstore

import (
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/client"
	"github.com/Plain-Auth/plain-auth/plugins/siwe"
	"github.com/Plain-Auth/plain-auth/schema"
)

func TestMappedWalletOwnership(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			dsn := organizationTestDSN(t, dialect)
			layout := schema.WalletSchema{Table: "wallet_address", UserID: "user_id", Address: "wallet_address", ChainID: "chain_id", IsPrimary: "is_primary", CreatedAt: "created_at"}
			opts := schema.Options{Wallet: layout, AdditionalFields: schema.AdditionalFields{Session: map[string]schema.SessionField{"region": {Type: auth.FieldString}}}}
			open := func() *Store {
				t.Helper()
				s, err := OpenWithOptions(ctx, dialect, dsn, []string{"siwe"}, opts)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { s.Close() })
				return s
			}
			first := open()
			const domain = "wallet.example.test"
			opt := siwe.Options{Domain: domain, RequireEmail: true, Schema: layout}
			a := walletCallbackClient(t, first, opt)
			if err := first.CheckWalletMapping(ctx, siwe.Schema{}); err == nil {
				t.Fatal("wallet plugin accepted another layout")
			}
			alice := freshWallet(t)
			const email = "profile@mapped.test"
			proof := func(c *client.Client, w walletSigner, chain int64) (*siwe.Result, error) {
				t.Helper()
				nonce, err := c.SIWENonce(ctx)
				if err != nil {
					return nil, err
				}
				m := walletMessage(w.address, domain, nonce, chain)
				return c.VerifySIWEWithEmail(ctx, m, w.sign(m), email)
			}
			res, err := proof(a, alice, 1)
			if err != nil {
				t.Fatal(err)
			}
			owner := res.User.ID
			peer := open()
			b := walletCallbackClient(t, peer, opt)
			res, err = proof(b, alice, 137)
			if err != nil || res.User.ID != owner {
				t.Fatal("repeated migration split wallet ownership", res, err)
			}
			findings, err := CheckSchemaWithOptions(ctx, dialect, dsn, []string{"siwe"}, opts)
			if err != nil || len(findings) != 0 {
				t.Fatal("mapped schema check", findings, err)
			}
			var n int
			count := func(want int) {
				t.Helper()
				if err := peer.db.QueryRowContext(ctx, peer.bind(`SELECT COUNT(*) FROM "wallet_address" WHERE "user_id"=?`), owner).Scan(&n); err != nil || n != want {
					t.Fatal("mapped wallet row count", n, err)
				}
			}
			count(2)
			wrong := layout
			wrong.Table = "unrelated_wallet"
			if s, err := OpenWithOptions(ctx, dialect, dsn, []string{"siwe"}, schema.Options{Wallet: wrong}); err == nil {
				s.Close()
				t.Fatal("migration silently selected a new table for existing wallet accounts")
			}
			seen, err := first.walletTableExists(ctx, first.db, wrong.Table)
			if err != nil || seen {
				t.Fatal("rejected new mapping created a table", seen, err)
			}
			wrong = layout
			wrong.UserID = "other_owner"
			if s, err := OpenWithOptions(ctx, dialect, dsn, []string{"siwe"}, schema.Options{Wallet: wrong}); err == nil {
				s.Close()
				t.Fatal("migration added competing ownership columns")
			}
			for _, column := range []string{"id", "user", "account"} {
				bad := layout
				if column == "id" {
					bad.Address = column
				} else {
					bad.Table = column
				}
				if _, err := schema.GenerateWithOptions(dialect, []string{"siwe"}, schema.Options{Wallet: bad}); err == nil {
					t.Fatal("accepted reserved wallet mapping", column)
				}
			}
			items, err := first.ListUserAccounts(ctx, owner)
			if err != nil {
				t.Fatal(err)
			}
			var oldest string
			for _, it := range items {
				if strings.HasSuffix(it.AccountID, ":1") {
					oldest = it.ID
				}
			}
			if oldest == "" {
				t.Fatal("missing first chain")
			}
			// Another application may have installed a different wallet table on
			// this same database. A node configured for it may not split identities.
			ddl, err := schema.Generate(dialect, []string{"siwe"})
			if err != nil {
				t.Fatal(err)
			}
			other, err := OpenWithSchema(ctx, dialect, dsn, ddl)
			if err != nil {
				t.Fatal(err)
			}
			defer other.Close()
			c := walletCallbackClient(t, other, siwe.Options{Domain: domain, RequireEmail: true})
			if _, err := proof(c, alice, 10); err == nil {
				t.Fatal("wrong wallet mapping adopted a new chain")
			}
			if err := other.UnlinkAccount(ctx, owner, oldest, false); err == nil {
				t.Fatal("unpartitioned node removed a mapped credential")
			}
			if err := other.DeleteFixtureUser(ctx, owner); err == nil {
				t.Fatal("unpartitioned node removed a mapped wallet user")
			}
			count(2)
			if err := peer.UnlinkAccount(ctx, owner, oldest, false); err != nil {
				t.Fatal(err)
			}
			count(1)
			var primary bool
			if err := first.db.QueryRowContext(ctx, first.bind(`SELECT "is_primary" FROM "wallet_address" WHERE "user_id"=? AND "chain_id"=137`), owner).Scan(&primary); err != nil || !primary {
				t.Fatal("unlink lost the remaining primary", primary, err)
			}
			now := time.Now().UTC()
			key := rand.Text()
			if err := other.SaveMagicLink(ctx, auth.MagicLinkChallenge{Key: key, Email: email, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
				t.Fatal(err)
			}
			session := auth.StoredSession{Session: auth.Session{ID: rand.Text(), Token: rand.Text(), CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}}
			if _, _, err := other.CompleteMagicLink(ctx, key, rand.Text(), session, true); err == nil {
				t.Fatal("wrong layout consumed a mailbox proof without reclaiming the wallet")
			}
			count(1)
			reclaimed, created, err := peer.CompleteMagicLink(ctx, key, rand.Text(), session, true)
			if err != nil || created || reclaimed.ID != owner || !reclaimed.EmailVerified {
				t.Fatal("mapped mailbox promotion failed", reclaimed, err)
			}
			count(0)
			if _, _, err := first.Session(ctx, res.Token); !errors.Is(err, auth.ErrNotFound) {
				t.Fatal("reclaimed wallet session remained valid", err)
			}
			again, err := proof(a, alice, 10)
			if err != nil || again.User.ID == owner {
				t.Fatal("reclaimed address restored the old owner", again, err)
			}
			// An older writer may have already removed an account while leaving its
			// renamed wallet row. The row alone must never establish another chain.
			if _, err := peer.db.ExecContext(ctx, peer.bind(`UPDATE "account" SET "providerId"='fixture-removed-wallet' WHERE "providerId"='siwe' AND "userId"=?`), again.User.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := proof(a, alice, 42161); err == nil {
				t.Fatal("orphaned mapped wallet authenticated on another chain")
			}
			if _, err := peer.db.ExecContext(ctx, peer.bind(`UPDATE "account" SET "providerId"='siwe' WHERE "providerId"='fixture-removed-wallet' AND "userId"=?`), again.User.ID); err != nil {
				t.Fatal(err)
			}
			if err := peer.DeleteFixtureUser(ctx, again.User.ID); err != nil {
				t.Fatal(err)
			}
			if got, err := first.WalletOwner(ctx, alice.address); err != nil || got != "" {
				t.Fatal("mapped wallet deletion retained a binding", got, err)
			}
		})
	}
}
