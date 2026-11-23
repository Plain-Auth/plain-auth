package sqlstore

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	plainauth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/client"
	ak "github.com/Plain-Auth/plain-auth/plugins/apikey"
	org "github.com/Plain-Auth/plain-auth/plugins/organization"
	"github.com/Plain-Auth/plain-auth/plugins/twofactor"
	"github.com/Plain-Auth/plain-auth/schema"
	"github.com/pquerna/otp/totp"
)

func TestOrgAPIKeyAndEphemeralSession(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(e error) {
				t.Helper()
				if e != nil {
					t.Fatal(e)
				}
			}
			code := func(e error, want string) {
				t.Helper()
				var api *plainauth.APIError
				if !errors.As(e, &api) || api.Code != want {
					t.Fatalf("expected %s, got %v", want, e)
				}
			}
			dsn := organizationTestDSN(t, dialect)
			ddl, e := schema.Generate(dialect, []string{"api-key", "organization", "admin", "two-factor"})
			must(e)
			db, e := OpenWithSchema(ctx, dialect, dsn, ddl)
			must(e)
			defer db.Close()
			users, e := ak.New(ak.Options{Store: db, EnableSession: true, DisableRateLimit: true})
			must(e)
			orgs, e := ak.New(ak.Options{Store: db, ConfigID: "teams", Organization: &ak.OrganizationOptions{Roles: map[string][]string{"auditor": {"read"}, "writer": {"create", "update", "delete", "read"}}}, EnableSession: true, Headers: []string{"X-Team-Key"}, DisableRateLimit: true})
			must(e)
			automation, e := ak.New(ak.Options{Store: db, ConfigID: "automation", EnableSession: true})
			must(e)
			plugin, e := ak.NewPlugin(users, orgs, automation)
			must(e)
			var prepared []org.InvitationCreationEvent
			var delivered []org.InvitationDelivery
			organization, e := org.New(org.Options{Store: db, BeforeCreateInvitation: func(_ context.Context, event org.InvitationCreationEvent) (*org.InvitationChanges, error) {
				prepared = append(prepared, event)
				return nil, nil
			}, SendInvitationEmail: func(ctx context.Context, message org.InvitationDelivery) error {
				var status string
				err := db.db.QueryRowContext(ctx, db.bind(`SELECT "status" FROM "invitation" WHERE "id"=?`), message.Invitation.ID).Scan(&status)
				if err != nil || status != "pending" {
					t.Errorf("mail callback could not read its committed invitation: %v", err)
				}
				delivered = append(delivered, message)
				return nil
			}})
			must(e)
			const origin = "https://keys.example"
			off := false
			var afterVerification func() error
			scopeChange := plainauth.Plugin{ID: "scope-change", OnRequest: func(plainauth.RequestContext) error {
				if afterVerification != nil {
					change := afterVerification
					afterVerification = nil
					return change()
				}
				return nil
			}}
			host, e := plainauth.New(plainauth.Options{Store: db, EmailAndPassword: true, Secret: strings.Repeat("k", 32), BaseURL: origin, RateLimit: &off, Plugins: []plainauth.Plugin{plugin, organization, twofactor.New(twofactor.Options{}), scopeChange}})
			must(e)
			otherDatabase, e := Open(ctx, "sqlite", ":memory:")
			must(e)
			if err := plugin.ValidateStore(otherDatabase); err == nil {
				t.Fatal("a foreign credential store could authenticate local accounts")
			}
			must(otherDatabase.Close())
			const pw = "test account password"
			browser := func(email string) (*client.Client, *client.EmailResult) {
				t.Helper()
				c, e := client.New(origin, &http.Client{Transport: guestTransport{host}})
				must(e)
				user, e := c.SignUpEmail(ctx, client.SignUpRequest{Name: "Member", Email: email, Password: pw})
				must(e)
				return c, user
			}
			owner, ownerUser := browser("owner@example.test")
			visitor, visitorUser := browser("visitor@example.test")
			reader, readerUser := browser("reader@example.test")
			var group org.Organization
			must(owner.Do(ctx, "POST", "/organization/create", map[string]any{"name": "Engineering", "slug": "engineering"}, &group))
			insertMember := func(user, id, role string) {
				_, e = db.db.ExecContext(ctx, db.bind(`INSERT INTO "member" ("id","organizationId","userId","role","createdAt") VALUES (?,?,?,?,?)`), id, group.ID, user, role, db.date(time.Now()))
				must(e)
			}
			insertMember(readerUser.User.ID, "reader", "member,auditor")
			teamKey, e := owner.CreateAPIKey(ctx, client.CreateAPIKeyRequest{Name: "CI", ConfigID: "teams", OrganizationID: group.ID})
			must(e)
			if teamKey.ReferenceID != group.ID {
				t.Fatal("organization key owner was not the group")
			}
			_, e = visitor.GetAPIKey(ctx, teamKey.ID, "teams")
			code(e, "USER_NOT_MEMBER_OF_ORGANIZATION")
			_, e = reader.GetAPIKey(ctx, teamKey.ID, "teams")
			must(e)
			_, e = reader.CreateAPIKey(ctx, client.CreateAPIKeyRequest{ConfigID: "teams", OrganizationID: group.ID})
			code(e, "INSUFFICIENT_API_KEY_PERMISSIONS")
			code(reader.DeleteAPIKey(ctx, teamKey.ID, "teams"), "INSUFFICIENT_API_KEY_PERMISSIONS")
			_, e = owner.GetAPIKey(ctx, teamKey.ID, "default")
			code(e, "KEY_NOT_FOUND")
			page, e := reader.ListAPIKeys(ctx, "", ak.PageOptions{OrganizationID: group.ID})
			must(e)
			if page.Total != 1 || page.Keys[0].ID != teamKey.ID {
				t.Fatal("aggregated organization page lost key")
			}
			page, e = reader.ListAPIKeys(ctx, "", ak.PageOptions{})
			must(e)
			if page.Total != 0 {
				t.Fatal("organization key appeared in personal listing")
			}
			_, e = db.db.ExecContext(ctx, db.bind(`UPDATE "member" SET "role"=? WHERE "id"=?`), "member", "reader")
			must(e)
			_, e = reader.GetAPIKey(ctx, teamKey.ID, "teams")
			code(e, "INSUFFICIENT_API_KEY_PERMISSIONS")
			_, e = db.db.ExecContext(ctx, db.bind(`UPDATE "member" SET "role"=? WHERE "id"=?`), "writer", "reader")
			must(e)
			written, e := reader.CreateAPIKey(ctx, client.CreateAPIKeyRequest{ConfigID: "teams", OrganizationID: group.ID})
			must(e)
			revised := "Revised"
			_, e = reader.UpdateAPIKey(ctx, client.UpdateAPIKeyRequest{ConfigID: "teams", KeyID: written.ID, Name: &revised})
			must(e)
			must(reader.DeleteAPIKey(ctx, written.ID, "teams"))
			verified, e := orgs.Verify(ctx, teamKey.Secret, nil)
			must(e)
			if !verified.Valid || verified.Key.ReferenceID != group.ID {
				t.Fatal("organization key did not verify as the organization")
			}
			req := func(path, key, header string, body map[string]string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
				method := "GET"
				var payload string
				if body != nil {
					method = "POST"
					b, e := json.Marshal(body)
					must(e)
					payload = string(b)
				}
				r := httptest.NewRequest(method, origin+"/api/auth/"+path, strings.NewReader(payload))
				r.Header.Set("Origin", origin)
				if body != nil {
					r.Header.Set("Content-Type", "application/json")
				}
				r.Header.Set(header, key)
				for _, c := range cookies {
					r.AddCookie(c)
				}
				w := httptest.NewRecorder()
				host.ServeHTTP(w, r)
				return w
			}
			expectHTTP := func(w *httptest.ResponseRecorder, status int, reason string) {
				t.Helper()
				if w.Code != status || !strings.Contains(w.Body.String(), reason) {
					t.Fatalf("expected %d %s: %d %s", status, reason, w.Code, w.Body.String())
				}
			}
			expectHTTP(req("get-session", teamKey.Secret, "X-Team-Key", nil), 401, "INVALID_REFERENCE_ID_FROM_API_KEY")
			priv, e := users.Create(ctx, ownerUser.User.ID, ak.CreateInput{Policy: ak.Policy{Permissions: ak.Permissions{"invitation": {"create"}, "twoFactor": {"enable"}}}})
			must(e)
			limited, e := users.Create(ctx, ownerUser.User.ID, ak.CreateInput{Policy: ak.Policy{Permissions: ak.Permissions{"reports": {"read"}}}})
			must(e)
			headers := http.Header{"X-Api-Key": {priv.Secret}}
			worker, e := automation.Create(ctx, visitorUser.User.ID, ak.CreateInput{})
			must(e)
			replaced, e := users.Create(ctx, ownerUser.User.ID, ak.CreateInput{})
			must(e)
			_, e = db.db.ExecContext(ctx, db.bind(`UPDATE "apikey" SET "key"=? WHERE "id"=?`), ak.Digest(worker.Secret), replaced.ID)
			must(e)
			expectHTTP(req("get-session", worker.Secret, "X-Api-Key", nil), 401, "INVALID_API_KEY")
			must(users.Delete(ctx, ownerUser.User.ID, replaced.ID))
			expectHTTP(req("get-session", worker.Secret, "X-Api-Key", nil), 200, visitorUser.User.ID)
			ss, e := host.GetSession(ctx, headers)
			must(e)
			if ss == nil || ss.User.ID != ownerUser.User.ID || ss.Session.ID != priv.ID || !ss.Session.IsApplicationCredential() {
				t.Fatal("native session did not identify the verified key owner")
			}
			defaultPolicy, e := ak.New(ak.Options{Store: db})
			must(e)
			unconfigured, e := plainauth.New(plainauth.Options{Store: db, Secret: strings.Repeat("k", 32), BaseURL: origin, Plugins: []plainauth.Plugin{defaultPolicy.Plugin()}})
			must(e)
			disabled, e := unconfigured.GetSession(ctx, headers)
			must(e)
			if disabled != nil {
				t.Fatal("a key authenticated a session without opt-in")
			}
			w := req("get-session", priv.Secret, "X-Api-Key", nil)
			expectHTTP(w, 200, ownerUser.User.ID)
			var wire plainauth.SessionResult
			must(json.Unmarshal(w.Body.Bytes(), &wire))
			if !wire.Session.IsApplicationCredential() || wire.Session.RequireOwner() == nil {
				t.Fatal("decoded key session lost its credential type")
			}
			forged, e := host.GetSession(ctx, http.Header{"Cookie": {host.SessionCookie(priv.Secret, true).String()}})
			must(e)
			if forged != nil {
				t.Fatal("raw application key authenticated through browser session lookup")
			}
			if len(w.Result().Cookies()) != 0 {
				t.Fatal("ephemeral session returned browser cookies")
			}
			var n int
			must(db.db.QueryRowContext(ctx, db.bind(`SELECT COUNT(*) FROM "session" WHERE "token"=?`), priv.Secret).Scan(&n))
			if n != 0 {
				t.Fatal("API key was inserted into browser sessions")
			}
			expectHTTP(req("get-session", priv.Secret, "X-Api-Key", nil, host.SessionCookie(*visitorUser.Token, true)), 400, "AMBIGUOUS_CREDENTIALS")
			expectHTTP(req("list-sessions", priv.Secret, "X-Api-Key", nil), 403, "OWNER_SESSION_REQUIRED")
			expectHTTP(req("api-key/create", priv.Secret, "X-Api-Key", map[string]string{}), 403, "OWNER_SESSION_REQUIRED")
			expectHTTP(req("organization/list", limited.Secret, "X-Api-Key", nil), 403, "INSUFFICIENT_API_KEY_PERMISSIONS")
			profile, e := users.Create(ctx, ownerUser.User.ID, ak.CreateInput{Policy: ak.Policy{Permissions: ak.Permissions{"user": {"update"}, "organization": {"read"}, "invitation": {"create"}}}})
			must(e)
			name := "Renamed by owner key"
			must(host.UpdateUser(ctx, http.Header{"X-Api-Key": {profile.Secret}}, plainauth.ProfileUpdate{Name: &name}))
			expectHTTP(req("get-session", profile.Secret, "X-Api-Key", nil), 200, name)
			expectHTTP(req("organization/list", profile.Secret, "X-Api-Key", nil), 200, group.ID)
			expectHTTP(req("update-user", limited.Secret, "X-Api-Key", map[string]string{"name": "Forbidden"}), 403, "OWNER_SESSION_REQUIRED")
			inv := map[string]string{"organizationId": group.ID, "email": "invitee@example.test", "role": "member"}
			restrict := func() error {
				_, err := users.Update(ctx, ownerUser.User.ID, profile.ID, ak.UpdateInput{Policy: ak.Policy{Permissions: ak.Permissions{"reports": {"read"}}}})
				return err
			}
			afterVerification = restrict
			expectHTTP(req("organization/invite-member", profile.Secret, "X-Api-Key", inv), 403, "INSUFFICIENT_API_KEY_PERMISSIONS")
			must(db.db.QueryRowContext(ctx, db.bind(`SELECT COUNT(*) FROM "invitation" WHERE "email"=?`), inv["email"]).Scan(&n))
			if n != 0 {
				t.Fatal("scope downgrade during request still created an invitation")
			}
			expectHTTP(req("organization/invite-member", limited.Secret, "X-Api-Key", inv), 403, "INSUFFICIENT_API_KEY_PERMISSIONS")
			expectHTTP(req("organization/invite-member", priv.Secret, "X-Api-Key", inv), 200, inv["email"])
			if len(prepared) != 1 || prepared[0].Inviter.ID != ownerUser.User.ID || prepared[0].Invitation.Email != inv["email"] {
				t.Fatal("creation hook received an unauthorized or unrelated application credential")
			}
			if len(delivered) != 1 || delivered[0].Inviter.User.ID != ownerUser.User.ID || delivered[0].Inviter.User.Name != name || delivered[0].Organization.ID != group.ID || delivered[0].Email != inv["email"] {
				t.Fatal("application credential delivered an incorrect sender or destination")
			}
			count := int64(1)
			single, e := users.Create(ctx, ownerUser.User.ID, ak.CreateInput{Policy: ak.Policy{Remaining: &count}})
			must(e)
			expectHTTP(req("get-session", single.Secret, "X-Api-Key", nil), 200, ownerUser.User.ID)
			expectHTTP(req("get-session", single.Secret, "X-Api-Key", nil), 429, "USAGE_EXCEEDED")
			expectHTTP(req("two-factor/enable", limited.Secret, "X-Api-Key", map[string]string{"password": pw}), 403, "OWNER_SESSION_REQUIRED")
			expectHTTP(req("two-factor/enable", priv.Secret, "X-Api-Key", map[string]string{"password": "incorrect password"}), 400, "INVALID_PASSWORD")
			w = req("two-factor/enable", priv.Secret, "X-Api-Key", map[string]string{"password": pw})
			expectHTTP(w, 200, "totpURI")
			var enroll client.TOTPEnrollment
			must(json.Unmarshal(w.Body.Bytes(), &enroll))
			uri, e := url.Parse(enroll.URI)
			must(e)
			otp, e := totp.GenerateCode(uri.Query().Get("secret"), time.Now())
			must(e)
			otherKey, e := users.Create(ctx, ownerUser.User.ID, ak.CreateInput{})
			must(e)
			expectHTTP(req("two-factor/verify-totp", otherKey.Secret, "X-Api-Key", map[string]string{"code": otp}), 401, "UNAUTHORIZED")
			w = req("two-factor/verify-totp", priv.Secret, "X-Api-Key", map[string]string{"code": otp})
			expectHTTP(w, 200, ownerUser.User.ID)
			if len(w.Result().Cookies()) != 0 {
				t.Fatal("MFA enrollment upgraded the key to a browser session")
			}
			enabled, e := db.FactorEnabled(ctx, ownerUser.User.ID)
			must(e)
			if !enabled {
				t.Fatal("password-confirmed enrollment did not activate")
			}
			enabled, e = db.FactorEnabled(ctx, visitorUser.User.ID)
			must(e)
			if enabled {
				t.Fatal("MFA enrollment changed another user")
			}
			must(users.Delete(ctx, ownerUser.User.ID, priv.ID))
			expectHTTP(req("get-session", priv.Secret, "X-Api-Key", nil), 401, "INVALID_API_KEY")
			personal, e := users.Create(ctx, readerUser.User.ID, ak.CreateInput{})
			must(e)
			visitorSS, e := visitor.GetSession(ctx)
			must(e)
			when := time.Now().UTC()
			overlap := org.Organization{ID: readerUser.User.ID, Name: "Same ID, separate owner", Slug: "overlap", CreatedAt: when}
			must(db.CreateOrganization(ctx, overlap, org.Member{ID: "overlap-member", OrganizationID: overlap.ID, UserID: visitorUser.User.ID, Role: "owner", CreatedAt: when}, visitorSS.Session.ID, true))
			teamOverlap, e := visitor.CreateAPIKey(ctx, client.CreateAPIKeyRequest{ConfigID: "teams", OrganizationID: overlap.ID})
			must(e)
			must(db.DeleteAccount(ctx, readerUser.User.ID, *readerUser.Token, "", "", when))
			deleted, e := users.Verify(ctx, personal.Secret, nil)
			must(e)
			if deleted.Valid {
				t.Fatal("deleted user key survived an overlapping organization ID")
			}
			retained, e := orgs.Verify(ctx, teamOverlap.Secret, nil)
			must(e)
			if !retained.Valid {
				t.Fatal("deleting a user revoked an organization key with the same reference ID")
			}
			_, e = db.db.ExecContext(ctx, db.bind(`DELETE FROM "organization" WHERE "id"=?`), overlap.ID)
			must(e)
			dead, e := orgs.Verify(ctx, teamOverlap.Secret, nil)
			must(e)
			if dead.Valid {
				t.Fatal("deleted organization still authenticated")
			}
			_, e = ak.New(ak.Options{Store: db, ConfigID: "teams"})
			if e == nil {
				t.Fatal("organization namespace was reinterpreted as user credentials")
			}
			imported, e := users.Create(ctx, visitorUser.User.ID, ak.CreateInput{})
			must(e)
			_, e = db.db.ExecContext(ctx, db.bind(`UPDATE "apikey" SET "configId"=? WHERE "id"=?`), "imported", imported.ID)
			must(e)
			if _, err := ak.New(ak.Options{Store: db, ConfigID: "imported", Organization: &ak.OrganizationOptions{}}); err == nil {
				t.Fatal("existing user key was adopted into an organization namespace")
			}
		})
	}
}

func TestAPIKeySchemaRejectsMissingColumns(t *testing.T) {
	dsn := organizationTestDSN(t, "sqlite")
	s, e := Open(t.Context(), "sqlite", dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if _, e = s.db.ExecContext(t.Context(), `CREATE TABLE apikey (id TEXT PRIMARY KEY)`); e != nil {
		t.Fatal(e)
	}
	if e = s.CheckAPIKeySchema(t.Context()); e == nil {
		t.Fatal("SQLite accepted a key schema missing the digest and policy columns")
	}
}
