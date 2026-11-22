package sqlstore

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/client"
	"github.com/Plain-Auth/plain-auth/plugins/siwe"
	"github.com/Plain-Auth/plain-auth/schema"
)

func walletCallbackClient(t *testing.T, store *Store, o siwe.Options) *client.Client {
	t.Helper()
	plugin, err := siwe.New(o)
	if err != nil {
		t.Fatal(err)
	}
	off := false
	app, err := auth.New(auth.Options{Store: store, Plugins: []auth.Plugin{plugin}, Secret: strings.Repeat("s", 32), BaseURL: returnOrigin + returnMount, RateLimit: &off})
	if err != nil {
		t.Fatal(err)
	}
	c, err := client.New(returnOrigin+returnMount, &http.Client{Transport: localBillingTransport(func(r *http.Request) (*http.Response, error) {
		w := httptest.NewRecorder()
		app.ServeHTTP(w, r)
		return w.Result(), nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestSIWECallbacks(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			dsn := organizationTestDSN(t, dialect)
			ddl, err := schema.Generate(dialect, []string{"siwe"})
			if err != nil {
				t.Fatal(err)
			}
			open := func() *Store {
				s, err := OpenWithSchema(ctx, dialect, dsn, ddl)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { s.Close() })
				return s
			}
			first, second := open(), open()
			domain := "wallet.example.test"
			contract, ethereum, polygon := freshWallet(t), freshWallet(t), freshWallet(t)
			// caseMode describes faults in the host, never input from the HTTP request.
			var caseMode, selection, pauseUntil atomic.Value
			caseMode.Store("")
			selection.Store("")
			var verifications, lookups atomic.Int32
			type cancelKey struct{}
			options := siwe.Options{Domain: domain, Chains: []int64{1, 137}}
			options.GetNonce = func(ctx context.Context) (string, error) {
				switch caseMode.Load().(string) {
				case "nonce error":
					return "", errors.New("private host token")
				case "nonce panic":
					panic("private host token")
				}
				if n := selection.Load().(string); n != "" {
					return n, nil
				}
				return "Host" + rand.Text(), nil
			}
			options.VerifyMessage = func(ctx context.Context, v siwe.VerifyMessageArgs) (bool, error) {
				verifications.Add(1)
				if v.Cacao.Header.Type != "caip122" || v.Cacao.Payload.Domain != domain || v.Cacao.Payload.Audience != domain || v.Cacao.Payload.Issuer != domain || v.Cacao.Payload.Version != "1" || v.Cacao.Signature.Type != "eip191" || v.Cacao.Signature.Value != v.Signature || !strings.Contains(v.Message, "Nonce: "+v.Cacao.Payload.Nonce+"\n") {
					return false, errors.New("unexpected verification context")
				}
				switch caseMode.Load().(string) {
				case "reject":
					return false, nil
				case "verify error":
					return false, errors.New("private host token")
				case "verify panic":
					panic("private host token")
				case "cancel":
					cancel := ctx.Value(cancelKey{}).(context.CancelFunc)
					cancel()
					return true, nil
				case "deadline":
					time.Sleep(time.Until(pauseUntil.Load().(time.Time)))
				case "late":
					time.Sleep(300 * time.Millisecond)
				}
				if v.SignedBy(v.Address) {
					return true, nil
				}
				if !strings.EqualFold(v.Address, contract.address) {
					return false, nil
				}
				switch v.ChainID {
				case 1:
					return v.SignedBy(ethereum.address), nil
				case 137:
					return v.SignedBy(polygon.address), nil
				}
				return false, nil
			}
			options.ENSLookup = func(ctx context.Context, a siwe.ENSLookupArgs) (siwe.ENSLookupResult, error) {
				lookups.Add(1)
				switch caseMode.Load().(string) {
				case "lookup error":
					return siwe.ENSLookupResult{}, errors.New("private host token")
				case "lookup panic":
					panic("private host token")
				case "invalid avatar":
					return siwe.ENSLookupResult{Avatar: "javascript:alert(1)"}, nil
				}
				return siwe.ENSLookupResult{Name: fmt.Sprintf("wallet-%d.eth", a.ChainID), Avatar: "ipfs://fixture/portrait"}, nil
			}
			plainBeforeUpgrade := walletCallbackClient(t, first, siwe.Options{Domain: domain})
			inherited, err := plainBeforeUpgrade.SIWENonce(ctx)
			if err != nil {
				t.Fatal(err)
			}
			a, b := walletCallbackClient(t, first, options), walletCallbackClient(t, second, options)
			nonce := func(c *client.Client) string {
				t.Helper()
				v, err := c.SIWENonce(ctx)
				if err != nil {
					t.Fatal(err)
				}
				return v
			}
			proof := func(c *client.Client, chain int64, signer walletSigner) (*siwe.Result, error) {
				text := walletMessage(contract.address, domain, nonce(c), chain)
				return c.VerifySIWE(ctx, text, signer.sign(text))
			}
			denied := func(err error, status int) {
				t.Helper()
				var api *auth.APIError
				if !errors.As(err, &api) || api.Status != status || strings.Contains(err.Error(), "private host token") {
					t.Fatalf("expected sanitized HTTP %d, got %v", status, err)
				}
			}
			msgBefore := walletMessage(contract.address, domain, inherited, 1)
			if _, err := a.VerifySIWE(ctx, msgBefore, polygon.sign(msgBefore)); err == nil {
				t.Fatal("invalid migrated proof accepted")
			}
			selection.Store(inherited)
			_, err = a.SIWENonce(ctx)
			denied(err, 500)
			later := nonce(plainBeforeUpgrade)
			if taken, err := second.TakeWalletNonce(ctx, later, time.Now()); err != nil || !taken {
				t.Fatal("default nonce did not survive the upgrade", err)
			}
			selection.Store(later)
			_, err = a.SIWENonce(ctx)
			denied(err, 500)
			selection.Store("")
			for _, mode := range []string{"nonce panic", "nonce error"} {
				caseMode.Store(mode)
				_, err := a.SIWENonce(ctx)
				denied(err, 500)
			}
			caseMode.Store("")
			for _, value := range []string{"bad", "bad:nonce", "Verylong" + strings.Repeat("Z", 245)} {
				selection.Store(value)
				_, err := a.SIWENonce(ctx)
				denied(err, 500)
			}
			selection.Store("UniqueCustomNonceForTest")
			type outcome struct {
				nonce string
				err   error
			}
			issued := make(chan outcome, 2)
			for _, c := range []*client.Client{a, b} {
				go func() { v, err := c.SIWENonce(ctx); issued <- outcome{v, err} }()
			}
			var success int
			for range 2 {
				r := <-issued
				if r.err != nil {
					denied(r.err, 500)
				} else if r.nonce == "UniqueCustomNonceForTest" {
					success++
				}
			}
			if success != 1 {
				t.Fatal("concurrent generators issued a repeated nonce", success)
			}
			text := walletMessage(contract.address, domain, "UniqueCustomNonceForTest", 1)
			_, err = b.VerifySIWE(ctx, text, polygon.sign(text))
			denied(err, 401)
			_, err = a.VerifySIWE(ctx, text, ethereum.sign(text))
			denied(err, 401)
			restarted := walletCallbackClient(t, open(), options)
			_, err = restarted.SIWENonce(ctx)
			denied(err, 500)
			selection.Store("")
			for _, alter := range []func(string) string{
				func(s string) string { return strings.ReplaceAll(s, domain, "foreign.test") },
				func(s string) string { return strings.Replace(s, "Chain ID: 1", "Chain ID: 10", 1) },
				func(s string) string {
					return s + "\nExpiration Time: " + time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)
				},
			} {
				before := verifications.Load()
				msg := alter(walletMessage(contract.address, domain, nonce(a), 1))
				_, err := a.VerifySIWE(ctx, msg, ethereum.sign(msg))
				denied(err, 401)
				if before != verifications.Load() {
					t.Fatal("invalid relying party, chain or expiry reached the host verifier")
				}
			}
			for _, mode := range []string{"verify panic", "verify error", "lookup panic", "lookup error", "invalid avatar"} {
				caseMode.Store(mode)
				msg := walletMessage(contract.address, domain, nonce(a), 1)
				_, err := a.VerifySIWE(ctx, msg, ethereum.sign(msg))
				denied(err, 401)
				_, err = a.VerifySIWE(ctx, msg, ethereum.sign(msg))
				denied(err, 401)
			}
			caseMode.Store("cancel")
			reqCtx, cancel := context.WithCancel(ctx)
			reqCtx = context.WithValue(reqCtx, cancelKey{}, cancel)
			msg := walletMessage(contract.address, domain, nonce(a), 1)
			_, err = a.VerifySIWE(reqCtx, msg, ethereum.sign(msg))
			cancel()
			if err == nil {
				t.Fatal("cancelled callback issued a session")
			}
			caseMode.Store("late")
			beforeDeadline := verifications.Load()
			msg = walletMessage(contract.address, domain, nonce(a), 1) + "\nExpiration Time: " + time.Now().Add(200*time.Millisecond).UTC().Format(time.RFC3339Nano)
			_, err = a.VerifySIWE(ctx, msg, ethereum.sign(msg))
			denied(err, 401)
			// A real stored challenge can expire while the host is computing
			// its verdict, even when the signed message omits an expiration.
			caseMode.Store("deadline")
			end := time.Now().Truncate(time.Second).Add(2 * time.Second)
			pauseUntil.Store(end.Add(20 * time.Millisecond))
			n := "ShortLivedNonce" + rand.Text()
			if err := first.SaveCustomWalletNonce(ctx, n, time.Now(), end); err != nil {
				t.Fatal(err)
			}
			msg = walletMessage(contract.address, domain, n, 1)
			_, err = a.VerifySIWE(ctx, msg, ethereum.sign(msg))
			denied(err, 401)
			if verifications.Load() != beforeDeadline+2 {
				t.Fatal("expiry must be rechecked after a slow host verdict")
			}
			caseMode.Store("reject")
			_, err = proof(a, 1, contract)
			denied(err, 401)
			var users int
			if err := first.db.QueryRowContext(ctx, first.bind(`SELECT COUNT(*) FROM "user"`)).Scan(&users); err != nil || users != 0 {
				t.Fatal("failed callbacks persisted an account", users, err)
			}
			caseMode.Store("")
			start := lookups.Load()
			one, err := proof(a, 1, ethereum)
			if err != nil {
				t.Fatal(err)
			}
			again, err := proof(b, 1, ethereum)
			if err != nil || one.User.ID != again.User.ID || lookups.Load() != start+1 {
				t.Fatal("returning contract owner reran ENS", again, err)
			}
			firstSession, err := a.GetSession(ctx)
			if err != nil || firstSession.User.Name != "wallet-1.eth" || firstSession.User.Image == nil || *firstSession.User.Image != "ipfs://fixture/portrait" {
				t.Fatal("ENS profile was not persisted", firstSession, err)
			}
			_, err = proof(a, 137, ethereum)
			denied(err, 401)
			two, err := proof(b, 137, polygon)
			if err != nil || one.User.ID == two.User.ID {
				t.Fatal("contracts at the same address on different chains shared an owner", two, err)
			}
			three, err := proof(a, 1, contract)
			if err != nil || three.User.ID == one.User.ID || three.User.ID == two.User.ID {
				t.Fatal("EOA recovery adopted a chain-bound contract", three, err)
			}
			plain := walletCallbackClient(t, open(), siwe.Options{Domain: domain})
			_, err = proof(plain, 1, ethereum)
			denied(err, 401)
			plainResult, err := proof(plain, 137, contract)
			if err != nil || plainResult.User.ID != three.User.ID {
				t.Fatal("callback-free node adopted the wrong identity", plainResult, err)
			}
		})
	}
}
