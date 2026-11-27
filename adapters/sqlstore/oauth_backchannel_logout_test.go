package sqlstore

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/client"
	op "github.com/Plain-Org/plain-auth/plugins/oauthprovider"
	"github.com/Plain-Org/plain-auth/schema"
)

// syncLog collects log output written from several goroutines.
type syncLog struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *syncLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *syncLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// logoutReceiver records logout token deliveries and answers each host
// with its configured status.
type logoutReceiver struct {
	mu         sync.Mutex
	status     map[string]int
	deliveries []logoutDelivery
}

type logoutDelivery struct {
	host, method, contentType, accept, token string
	deadline                                 time.Duration
}

func (r *logoutReceiver) RoundTrip(req *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	form, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, err
	}
	d := logoutDelivery{host: req.URL.Host, method: req.Method, contentType: req.Header.Get("Content-Type"), accept: req.Header.Get("Accept"), token: form.Get("logout_token")}
	if deadline, ok := req.Context().Deadline(); ok {
		d.deadline = time.Until(deadline)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.deliveries = append(r.deliveries, d)
	code := r.status[req.URL.Host]
	if code == 0 {
		code = http.StatusOK
	}
	header := http.Header{}
	if code == http.StatusTemporaryRedirect {
		header.Set("Location", "https://elsewhere.example.test/logout")
	}
	return &http.Response{StatusCode: code, Status: http.StatusText(code), Header: header, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
}

func (r *logoutReceiver) take() []logoutDelivery {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.deliveries
	r.deliveries = nil
	slices.SortFunc(out, func(a, b logoutDelivery) int { return strings.Compare(a.host, b.host) })
	return out
}

// Ending a session sends one logout token to each enabled client with a
// back-channel logout URI that held tokens on it: signed by the jwt plugin
// with the session's sid and the client's subject, posted as a form with a
// deadline, never followed through a redirect. Disabled clients, clients
// without a URI and clients whose pairwise subject cannot be resolved get
// none; a refused delivery is only logged; a background runner sends after
// the response; and without the jwt plugin discovery advertises no support.
func TestBackchannelLogout(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			const origin = "https://logout.example.test"
			pairwise := strings.Repeat("p", 32)
			receiver := &logoutReceiver{status: map[string]int{"refusing.example.test": 500, "moving.example.test": http.StatusTemporaryRedirect}}
			opts := op.Options{Scopes: []string{"openid", "offline_access"}, PairwiseSecret: pairwise, BackchannelTransport: receiver}
			off := false
			host := func(s *Store, logs io.Writer, background func(func()), jwt bool) *auth.Auth {
				t.Helper()
				p, err := op.New(opts)
				must(err)
				plugins := []auth.Plugin{p}
				if jwt {
					signing, err := auth.NewJWT(auth.JWTOptions{})
					must(err)
					plugins = append(plugins, signing)
				}
				h, err := auth.New(auth.Options{BaseURL: origin, Secret: strings.Repeat("l", 40), Store: s, EmailAndPassword: true, PasswordHash: testPasswordHash, PasswordVerify: testPasswordVerify, Plugins: plugins, RateLimit: &off,
					Logger: slog.New(slog.NewTextHandler(logs, nil)), BackgroundTasks: background})
				must(err)
				return h
			}
			open := func() *Store {
				t.Helper()
				s, err := OpenWithOptions(ctx, dialect, organizationTestDSN(t, dialect), []string{"oauth-provider", "jwt"}, schema.Options{})
				must(err)
				t.Cleanup(func() { s.Close() })
				return s
			}
			// signIn creates an account and returns its client, user ID and
			// session ID, with access tokens on that session for the clients.
			signIn := func(s *Store, h *auth.Auth, email string, clients ...string) (*client.Client, string, string) {
				t.Helper()
				c, err := client.New(origin, &http.Client{Transport: guestTransport{h}})
				must(err)
				signed, err := c.SignUpEmail(ctx, client.SignUpRequest{Name: "Owner", Email: email, Password: "local logout test password"})
				must(err)
				var sid string
				must(s.db.QueryRowContext(ctx, s.bind(`SELECT "id" FROM "session" WHERE "userId"=?`), signed.User.ID).Scan(&sid))
				now := time.Now().UTC()
				for _, id := range clients {
					_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO "oauthAccessToken" ("id","token","clientId","sessionId","userId","scopes","createdAt","expiresAt") VALUES (?,?,?,?,?,?,?,?)`),
						rand.Text(), rand.Text(), id, sid, signed.User.ID, `["openid"]`, s.date(now), s.date(now.Add(time.Hour)))
					must(err)
				}
				return c, signed.User.ID, sid
			}
			addClient := func(s *Store, id, logoutHost string, disabled bool, subjectType string, redirects string) {
				t.Helper()
				var uri any
				if logoutHost != "" {
					uri = "https://" + logoutHost + "/logout"
				}
				var subject any
				if subjectType != "" {
					subject = subjectType
				}
				_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO "oauthClient" ("id","clientId","redirectUris","backchannelLogoutUri","disabled","subjectType") VALUES (?,?,?,?,?,?)`),
					id, id, redirects, uri, disabled, subject)
				must(err)
			}
			s := open()
			logs := &syncLog{}
			h := host(s, logs, nil, true)
			for _, c := range []struct {
				id, host    string
				disabled    bool
				subject     string
				redirectURI string
			}{
				{"plain", "plain.example.test", false, "", "https://rp.example.test/cb"},
				{"silent", "", false, "", "https://rp.example.test/cb"},
				{"off", "off.example.test", true, "", "https://rp.example.test/cb"},
				{"paired", "paired.example.test", false, "pairwise", "https://sector.example.test/cb"},
				{"broken", "broken.example.test", false, "pairwise", "not a url"},
				{"refusing", "refusing.example.test", false, "", "https://rp.example.test/cb"},
				{"moving", "moving.example.test", false, "", "https://rp.example.test/cb"},
			} {
				addClient(s, c.id, c.host, c.disabled, c.subject, `["`+c.redirectURI+`"]`)
			}
			doc, err := op.GetOpenIDConfig(h)
			must(err)
			if !doc.BackchannelLogoutSupported || !doc.BackchannelLogoutSessionSupported {
				t.Fatal("discovery did not advertise back-channel logout", doc.BackchannelLogoutSupported, doc.BackchannelLogoutSessionSupported)
			}
			c, user, sid := signIn(s, h, "owner@logout.test", "plain", "silent", "off", "paired", "broken", "refusing", "moving")
			must(c.SignOut(ctx))
			got := receiver.take()
			hosts := make([]string, len(got))
			for i, d := range got {
				hosts[i] = d.host
			}
			if !slices.Equal(hosts, []string{"moving.example.test", "paired.example.test", "plain.example.test", "refusing.example.test"}) {
				t.Fatal("logout tokens did not reach exactly the eligible clients", hosts)
			}
			published := h.OAuthIssuer()
			mac := hmac.New(sha256.New, []byte(pairwise))
			mac.Write([]byte("sector.example.test." + user))
			subjects := map[string]string{"plain": user, "paired": base64.StdEncoding.EncodeToString(mac.Sum(nil)), "refusing": user, "moving": user}
			for _, d := range got {
				id := strings.TrimSuffix(d.host, ".example.test")
				if d.method != http.MethodPost || d.contentType != "application/x-www-form-urlencoded" || d.accept != "application/json" || d.deadline <= 0 || d.deadline > 5*time.Second {
					t.Fatal("the logout token was not posted as a form with a deadline", d)
				}
				claims, err := h.VerifyJWT(ctx, d.token, auth.JWTVerifyOptions{Issuer: published, Audience: id, Subject: subjects[id]})
				must(err)
				header, err := base64.RawURLEncoding.DecodeString(strings.Split(d.token, ".")[0])
				must(err)
				var typ struct {
					Type string `json:"typ"`
				}
				must(json.Unmarshal(header, &typ))
				events, _ := claims["events"].(map[string]any)
				event, ok := events["http://schemas.openid.net/event/backchannel-logout"].(map[string]any)
				jti, _ := claims["jti"].(string)
				iat, _ := claims["iat"].(float64)
				exp, _ := claims["exp"].(float64)
				if typ.Type != "logout+jwt" || claims["sid"] != sid || len(jti) != 32 || !ok || len(event) != 0 || len(events) != 1 || exp-iat != 120 || claims["nonce"] != nil {
					t.Fatal("the logout token's header or claims were wrong", typ.Type, claims)
				}
			}
			if out := logs.String(); !strings.Contains(out, "Back-channel logout failed") || !strings.Contains(out, "client=refusing") || !strings.Contains(out, "client=moving") ||
				!strings.Contains(out, "Back-channel logout could not resolve the subject") || !strings.Contains(out, "client=broken") {
				t.Fatal("a refused delivery or an unresolved subject was not logged", out)
			}
			// Revoking every session reports each one.
			c, _, first := signIn(s, h, "second@logout.test", "plain")
			_, err = c.SignInEmail(ctx, client.SignInRequest{Email: "second@logout.test", Password: "local logout test password"})
			must(err)
			var second string
			must(s.db.QueryRowContext(ctx, s.bind(`SELECT s."id" FROM "session" s JOIN "user" u ON u."id"=s."userId" WHERE u."email"=? AND s."id"<>?`), "second@logout.test", first).Scan(&second))
			_, err = s.db.ExecContext(ctx, s.bind(`INSERT INTO "oauthAccessToken" ("id","token","clientId","sessionId","scopes","createdAt","expiresAt") VALUES ('other','other','plain',?,'[]',?,?)`), second, s.date(time.Now()), s.date(time.Now().Add(time.Hour)))
			must(err)
			must(c.RevokeSessions(ctx))
			if got := receiver.take(); len(got) != 2 {
				t.Fatal("revoking every session did not notify for each session", len(got))
			}
			// A background runner sends after the response.
			s2 := open()
			var mu sync.Mutex
			var tasks []func()
			hb := host(s2, io.Discard, func(task func()) {
				mu.Lock()
				defer mu.Unlock()
				tasks = append(tasks, task)
			}, true)
			addClient(s2, "plain", "plain.example.test", false, "", `["https://rp.example.test/cb"]`)
			cb, _, _ := signIn(s2, hb, "background@logout.test", "plain")
			must(cb.SignOut(ctx))
			mu.Lock()
			pending := tasks
			tasks = nil
			mu.Unlock()
			if len(receiver.take()) != 0 || len(pending) == 0 {
				t.Fatal("the logout token was sent before the background runner ran", len(pending))
			}
			for _, task := range pending {
				task()
			}
			if got := receiver.take(); len(got) != 1 || got[0].host != "plain.example.test" {
				t.Fatal("the background runner did not send the logout token", got)
			}
			// Without the jwt plugin no logout token can be signed.
			plain := host(open(), io.Discard, nil, false)
			server, err := op.GetAuthorizationServerConfig(plain)
			must(err)
			if server.BackchannelLogoutSupported || server.BackchannelLogoutSessionSupported {
				t.Fatal("discovery advertised back-channel logout without the jwt plugin")
			}
		})
	}
}
