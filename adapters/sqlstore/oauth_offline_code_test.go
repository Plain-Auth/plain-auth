package sqlstore

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	op "github.com/Plain-Org/plain-auth/plugins/oauthprovider"
)

func testOfflineCodeTransactions(t *testing.T, store, peer *Store, verifier string, now time.Time) {
	ctx := t.Context()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	write := func(q string, args ...any) {
		t.Helper()
		_, err := peer.db.ExecContext(ctx, peer.bind(q), args...)
		must(err)
	}
	digest := func(s string) string {
		sum := sha256.Sum256([]byte(s))
		return base64.RawURLEncoding.EncodeToString(sum[:])
	}
	setScopes := func(scopes string) { write(`UPDATE "oauthClient" SET "scopes"=? WHERE "clientId"='client'`, scopes) }
	const scopes = `["reports","offline_access"]`
	setScopes(scopes)
	proofTime := now.Add(-3 * time.Hour)
	seedCode := func(code string, created time.Time, authTime *time.Time) {
		fields := map[string]any{
			"type": "authorization_code", "userId": "u", "sessionId": "sid", "referenceId": "tenant",
			"query": map[string]any{"client_id": "client", "scope": "reports offline_access", "code_challenge_method": "S256", "code_challenge": digest(verifier),
				"claims": `{"userinfo":{"email_verified":null,"ignored":null,"name":{"essential":true}}}`},
		}
		if authTime != nil {
			fields["authTime"] = authTime.UnixMilli()
		}
		value, err := json.Marshal(fields)
		must(err)
		write(`INSERT INTO "verification" ("id","identifier","value","createdAt","updatedAt","expiresAt") VALUES (?,?,?,?,?,?)`, rand.Text(), digest(code), string(value), store.date(created), store.date(created), store.date(now.Add(time.Hour)))
	}
	seed := func(code string, created time.Time) { seedCode(code, created, &proofTime) }
	var duringEncoding func(context.Context) error
	var forceAccessCollision bool
	var forceRefreshCollision bool
	p, err := op.New(op.Options{UserInfo: op.UserInfoOptions{SupportedClaims: []string{"name", "email_verified"}}, Tokens: op.TokenOptions{
		RefreshLifetime: 47 * time.Minute, RefreshPrefix: "rt.", ScopeLifetimes: map[string]time.Duration{"reports": time.Minute},
		GenerateOpaqueToken: func(context.Context) (string, error) {
			if forceAccessCollision {
				return "offline-conflict", nil
			}
			return rand.Text(), nil
		},
		GenerateRefreshToken: func(context.Context) (string, error) {
			if forceRefreshCollision {
				return "duplicate", nil
			}
			return "custom-" + rand.Text(), nil
		},
		HashRefreshToken: func(_ context.Context, raw string) (string, error) { return digest("refresh/" + raw), nil },
		EncodeRefreshToken: func(ctx context.Context, raw, sid string) (string, error) {
			if duringEncoding != nil {
				if err := duringEncoding(ctx); err != nil {
					return "", err
				}
			}
			return sid + "." + raw, nil
		},
		DecodeRefreshToken: func(_ context.Context, wire string) (string, error) {
			raw, ok := strings.CutPrefix(wire, "sid.")
			if !ok {
				return "", op.ErrInvalidRefreshToken
			}
			return raw, nil
		},
	}})
	must(err)
	off := false
	h, err := auth.New(auth.Options{BaseURL: "https://issuer.example.test", Secret: strings.Repeat("a", 40), Store: store, Plugins: []auth.Plugin{p}, RateLimit: &off})
	must(err)
	call := func(code string) *httptest.ResponseRecorder {
		form := url.Values{"client_id": {"client"}, "grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier}}
		r := httptest.NewRequest("POST", "https://issuer.example.test/api/auth/oauth2/token", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		out := httptest.NewRecorder()
		h.ServeHTTP(out, r)
		return out
	}
	expect := func(code string, status int, wireError string) op.DelegatedToken {
		t.Helper()
		res := call(code)
		var body struct {
			op.DelegatedToken
			Error string
		}
		must(json.Unmarshal(res.Body.Bytes(), &body))
		if res.Code != status || (wireError != "" && body.Error != wireError) || status != 200 && (body.AccessToken != "" || body.RefreshToken != "") {
			t.Fatalf("unexpected exchange (%s): HTTP %d, error %s", code, res.Code, body.Error)
		}
		return body.DelegatedToken
	}
	count := func(table, code string) int {
		t.Helper()
		var n int
		must(peer.db.QueryRowContext(ctx, peer.bind(`SELECT COUNT(*) FROM "`+table+`" WHERE "authorizationCodeId"=?`), digest(code)).Scan(&n))
		return n
	}
	seed("retry-offline", now)
	duringEncoding = func(context.Context) error { return errors.New("private formatter failure") }
	expect("retry-offline", 500, "")
	duringEncoding = func(context.Context) error { setScopes(`["reports"]`); return nil }
	expect("retry-offline", 400, "invalid_scope")
	duringEncoding = nil
	setScopes(scopes)
	// Force a collision on the access insert, after the refresh insert.
	write(`INSERT INTO "oauthAccessToken" ("id","clientId","token","createdAt","expiresAt","scopes") VALUES ('offline-conflict','client',?,?,?,?)`, digest("offline-conflict"), store.date(now), store.date(now.Add(time.Hour)), scopes)
	forceAccessCollision = true
	expect("retry-offline", 500, "")
	if count("oauthRefreshToken", "retry-offline") != 0 || count("oauthAccessToken", "retry-offline") != 0 {
		t.Fatal("failed exchange persisted part of the pair")
	}
	forceAccessCollision = false
	token := expect("retry-offline", 200, "")
	raw, ok := strings.CutPrefix(token.RefreshToken, "rt.sid.custom-")
	if !ok || raw == "" || token.ExpiresIn != 60 {
		t.Fatal("unexpected refresh format or access lifetime")
	}
	var accessTime, refreshTime, expires, authTime time.Time
	var reference, refreshDigest, owner, sid string
	var accessClaims, refreshClaims []byte
	q := `SELECT a."createdAt",r."createdAt",r."expiresAt",r."authTime",r."referenceId",r."token",r."userId",r."sessionId",a."requestedUserInfoClaims",r."requestedUserInfoClaims"
	FROM "oauthAccessToken" a JOIN "oauthRefreshToken" r ON a."refreshId"=r."id" WHERE a."token"=? AND a."authorizationCodeId"=r."authorizationCodeId"`
	must(peer.db.QueryRowContext(ctx, peer.bind(q), digest(token.AccessToken)).Scan(&accessTime, &refreshTime, &expires, &authTime, &reference, &refreshDigest, &owner, &sid, &accessClaims, &refreshClaims))
	if !accessTime.Equal(refreshTime) || expires.Sub(refreshTime) != 47*time.Minute || !authTime.Equal(proofTime) || reference != "tenant" || owner != "u" || sid != "sid" || refreshDigest != digest("refresh/custom-"+raw) {
		t.Fatal("offline grant bindings or lifetime were lost")
	}
	for _, b := range [][]byte{accessClaims, refreshClaims} {
		var names []string
		must(json.Unmarshal(b, &names))
		if !slices.Equal(names, []string{"email_verified", "name"}) {
			t.Fatal("changed authorized UserInfo claims", names)
		}
	}
	seedCode("session-time", now, nil)
	expect("session-time", 200, "")
	must(peer.db.QueryRowContext(ctx, peer.bind(`SELECT "authTime" FROM "oauthRefreshToken" WHERE "authorizationCodeId"=?`), digest("session-time")).Scan(&authTime))
	if !authTime.Equal(now) {
		t.Fatal("missing authentication time did not fall back to session creation")
	}
	seed("replaced-offline", now)
	duringEncoding = func(context.Context) error { seed("replaced-offline", now.Add(time.Second)); return nil }
	expect("replaced-offline", 400, "invalid_grant")
	duringEncoding = nil
	forceRefreshCollision = true
	expect("replaced-offline", 200, "")
	seed("duplicate-refresh", now)
	expect("duplicate-refresh", 500, "")
	forceRefreshCollision = false
	expect("duplicate-refresh", 200, "")
	seed("race-offline", now)
	// Both requests validate the same code before either can commit.
	ready := make(chan struct{}, 2)
	resume := make(chan struct{})
	results := make(chan int, 2)
	duringEncoding = func(ctx context.Context) error {
		ready <- struct{}{}
		select {
		case <-resume:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	for range 2 {
		go func() { results <- call("race-offline").Code }()
	}
	for range 2 {
		select {
		case <-ready:
		case <-time.After(10 * time.Second):
			close(resume)
			t.Fatal("refresh callbacks ran under database locks")
		}
	}
	close(resume)
	statuses := []int{<-results, <-results}
	slices.Sort(statuses)
	if !slices.Equal(statuses, []int{200, 400}) || count("oauthRefreshToken", "race-offline") != 0 || count("oauthAccessToken", "race-offline") != 0 {
		t.Fatal("concurrent redemption left a usable descendant", statuses)
	}
	if count("oauthRefreshToken", "retry-offline") != 1 || count("oauthAccessToken", "retry-offline") != 1 {
		t.Fatal("another code lost its token pair")
	}
}
