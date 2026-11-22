package sqlstore

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/adapters/memory"
	"github.com/Plain-Auth/plain-auth/client"
	"github.com/Plain-Auth/plain-auth/schema"
)

func TestPhoneRegistrationUserFields(t *testing.T) {
	for _, dialect := range []string{"memory", "sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			fields := userFieldFixture()
			fields["code"] = auth.UserField{Type: auth.FieldString, Column: "profile_code"}
			fields["disableSession"] = auth.UserField{Type: auth.FieldBoolean, Column: "profile_quiet"}
			fields["updatePhoneNumber"] = auth.UserField{Type: auth.FieldBoolean, Column: "profile_replace"}
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			var store, peer auth.Store
			if dialect == "memory" {
				store = memory.New()
				peer = store
			} else {
				dsn := organizationTestDSN(t, dialect)
				open := func() *Store {
					s, err := OpenWithAdditionalFields(ctx, dialect, dsn, []string{"phone-number"}, schema.AdditionalFields{User: fields})
					must(err)
					t.Cleanup(func() { s.Close() })
					return s
				}
				store, peer = open(), open()
			}

			sms := make(chan string, 1)
			resolved := atomic.Int32{}
			options := auth.PhoneNumberOptions{
				SendOTP: func(_ context.Context, m auth.PhoneOTPMessage) error { sms <- m.Code; return nil },
				SignUpOnVerification: &auth.PhoneSignUpOptions{
					GetTempName:  func(n string) string { return "Holder " + n },
					GetTempEmail: func(n string) string { resolved.Add(1); return n + "@phone.test" },
				},
			}
			plugin, err := auth.NewPhoneNumber(options)
			must(err)
			server := httptest.NewUnstartedServer(nil)
			off := false
			opts := auth.Options{Store: store, BaseURL: "http://" + server.Listener.Addr().String(), Secret: strings.Repeat("s", 40), RateLimit: &off, Plugins: []auth.Plugin{plugin}, UserAdditionalFields: fields}
			node, err := auth.New(opts)
			must(err)
			server.Config.Handler = node
			server.Start()
			defer server.Close()
			c, err := client.New(server.URL, nil)
			must(err)
			opts.Store = peer
			other, err := auth.New(opts)
			must(err)
			send := func(n string) string { t.Helper(); must(c.SendPhoneNumberOTP(ctx, n)); return <-sms }
			n := "+14155550111"
			proof := send(n)
			req := auth.PhoneVerificationInput{PhoneNumber: n, Code: "incorrect"}
			_, err = c.VerifyPhoneNumber(ctx, req)
			checkUserFieldError(t, err, "INVALID_OTP")
			req.Code = proof
			_, err = c.VerifyPhoneNumber(ctx, req)
			checkUserFieldError(t, err, "MISSING_FIELD")
			_, err = c.VerifyPhoneNumber(ctx, req)
			checkUserFieldError(t, err, "OTP_NOT_FOUND")
			if resolved.Load() != 0 {
				t.Fatal("invoked identity resolver before a valid registration")
			}
			if _, err := store.(auth.AccountStore).FindAccountUser(ctx, n+"@phone.test"); !errors.Is(err, auth.ErrNotFound) {
				t.Fatal("invalid profile created an account", err)
			}
			// A caller cannot mark the new number verified through generic profile input.
			asserted := send(n)
			err = c.Do(ctx, "POST", "/phone-number/verify", map[string]any{"phoneNumber": n, "code": asserted, "locale": "fr", "phoneNumberVerified": true}, nil)
			checkUserFieldError(t, err, "FIELD_NOT_ALLOWED")
			req.Code = asserted
			_, err = c.VerifyPhoneNumber(ctx, req)
			checkUserFieldError(t, err, "OTP_NOT_FOUND")
			req.Code = send(n)
			req.DisableSession = true
			req.AdditionalFields = map[string]any{"locale": "fr", "score": 0, "activeFlag": false, "secretNote": "private", "accountClass": "supplied", "privateRank": 999}
			first, err := c.VerifyPhoneNumber(ctx, req)
			must(err)
			if !first.Status || first.Token != nil || first.User.Name != "Holder "+n || first.User.Email != n+"@phone.test" || first.User.EmailVerified || first.User.PhoneNumberVerified == nil || !*first.User.PhoneNumberVerified {
				t.Fatal("incorrect phone registration")
			}
			checkUserField(t, first.User, "locale", "fr")
			checkUserField(t, first.User, "accountClass", "basic")
			checkUserField(t, first.User, "score", int64(0))
			checkUserField(t, first.User, "activeFlag", false)
			for _, field := range []string{"code", "disableSession", "updatePhoneNumber"} {
				checkUserField(t, first.User, field, nil)
			}
			for _, field := range []string{"secretNote", "privateRank", "preferred_locale"} {
				if _, ok := first.User.AdditionalField(field); ok {
					t.Fatal("private field returned", field)
				}
			}
			view, err := c.GetSession(ctx)
			must(err)
			if view != nil {
				t.Fatal("quiet signup issued a session")
			}
			must(other.UpdateTrustedUserFields(ctx, first.User.ID, map[string]any{"accountClass": "operator"}))
			req.AdditionalFields = map[string]any{"locale": false, "score": "bad", "secretNote": "replacement", "accountClass": "public"}
			req.DisableSession = false
			req.Code = send(n)
			login, err := c.VerifyPhoneNumber(ctx, req)
			must(err)
			if login.Token == nil || login.User.ID != first.User.ID {
				t.Fatal("existing owner not signed in")
			}
			checkUserField(t, login.User, "accountClass", "operator")
			checkUserField(t, login.User, "locale", "fr")
			view, err = c.GetSession(ctx)
			must(err)
			checkUserField(t, view.User, "locale", "fr")
			replacement := "+14155550112"
			req.PhoneNumber, req.Code, req.UpdatePhoneNumber = replacement, send(replacement), true
			linked, err := c.VerifyPhoneNumber(ctx, req)
			must(err)
			if linked.Token == nil || *linked.Token != *login.Token || *linked.User.PhoneNumber != replacement || resolved.Load() != 1 {
				t.Fatal("returning verification or phone replacement re-ran registration")
			}
			checkUserField(t, linked.User, "locale", "fr")
			if s, ok := peer.(*Store); ok {
				var note string
				var rank int
				var code *string
				var quiet, replace *bool
				err := s.db.QueryRowContext(ctx, s.bind(`SELECT "secretNote","privateRank","profile_code","profile_quiet","profile_replace" FROM "user" WHERE "id"=?`), first.User.ID).Scan(&note, &rank, &code, &quiet, &replace)
				if err != nil || note != "private" || rank != 9 || code != nil || quiet != nil || replace != nil {
					t.Fatal("persisted phone profile or transport protection", err)
				}
			}
			// Both nodes see the same proof. Only the winning transaction can publish a profile.
			raceNumber := "+14155550113"
			proof = send(raceNumber)
			type outcome struct {
				locale string
				result auth.PhoneVerificationResult
				err    error
			}
			start := make(chan struct{})
			results := make(chan outcome, 2)
			for locale, instance := range map[string]*auth.Auth{"en": node, "de": other} {
				go func() {
					<-start
					r, e := instance.VerifyPhoneNumber(ctx, nil, auth.PhoneVerificationInput{PhoneNumber: raceNumber, Code: proof, AdditionalFields: map[string]any{"locale": locale}}, auth.RequestMeta{})
					results <- outcome{locale, r, e}
				}()
			}
			close(start)
			wins := 0
			for range 2 {
				out := <-results
				if out.err != nil {
					checkUserFieldError(t, out.err, "OTP_NOT_FOUND")
					continue
				}
				wins++
				checkUserField(t, out.result.User, "locale", out.locale)
			}
			if wins != 1 {
				t.Fatal("phone registration proof issued multiple profiles", wins)
			}

			// A resolver may consult the same store outside its transaction. Replacing
			// the code before registration commits must leave the new generation usable.
			reissued := false
			options.SignUpOnVerification = &auth.PhoneSignUpOptions{GetTempEmail: func(number string) string {
				if !reissued {
					reissued = true
					must(other.SendPhoneNumberOTP(ctx, number))
				}
				return number + "@phone.test"
			}}
			rotating, err := auth.NewPhoneNumber(options)
			must(err)
			opts.Plugins = []auth.Plugin{rotating}
			rotationNode, err := auth.New(opts)
			must(err)
			anotherNumber := "+14155550114"
			rotation := auth.PhoneVerificationInput{PhoneNumber: anotherNumber, Code: send(anotherNumber), AdditionalFields: map[string]any{"locale": "reissued"}}
			_, err = rotationNode.VerifyPhoneNumber(ctx, nil, rotation, auth.RequestMeta{})
			checkUserFieldError(t, err, "INVALID_OTP")
			if _, err := store.(auth.AccountStore).FindAccountUser(ctx, anotherNumber+"@phone.test"); !errors.Is(err, auth.ErrNotFound) {
				t.Fatal("superseded phone proof published a profile", err)
			}
			rotation.Code = <-sms
			accepted, err := rotationNode.VerifyPhoneNumber(ctx, nil, rotation, auth.RequestMeta{})
			must(err)
			if accepted.User.Name != anotherNumber {
				t.Fatal("default phone display name")
			}
			checkUserField(t, accepted.User, "locale", "reissued")

		})
	}
}

type legacyPhoneFieldsStore struct {
	auth.Store
	auth.UserFieldStore
	auth.PhoneAccountStore
}

func TestPhoneRegistrationFieldStoreContract(t *testing.T) {
	mem := memory.New()
	legacy := legacyPhoneFieldsStore{mem, mem, mem}
	plugin, err := auth.NewPhoneNumber(auth.PhoneNumberOptions{SignUpOnVerification: &auth.PhoneSignUpOptions{GetTempEmail: func(n string) string { return n + "@phone.test" }}})
	if err != nil {
		t.Fatal(err)
	}
	opts := auth.Options{Store: legacy, BaseURL: "http://phone.localhost", Secret: strings.Repeat("s", 40), Plugins: []auth.Plugin{plugin}, UserAdditionalFields: userFieldFixture()}
	if _, err := auth.New(opts); err == nil || !strings.Contains(err.Error(), "PhoneRegistrationStore") {
		t.Fatal("legacy store accepted configured phone registration", err)
	}
	opts.DisableSignUp = true
	if _, err := auth.New(opts); err != nil {
		t.Fatal("closed registration required an unused extension", err)
	}
	opts.DisableSignUp = false
	opts.UserAdditionalFields = nil
	if _, err := auth.New(opts); err != nil {
		t.Fatal("unconfigured legacy registration changed", err)
	}
}

func TestPhoneRegistrationProfileRollsBackWithSession(t *testing.T) {
	for _, dialect := range []string{"memory", "sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			fields := userFieldFixture()
			sessions := map[string]auth.SessionField{"browserFamily": {Type: auth.FieldString, Required: true}}
			var store auth.Store
			if dialect == "memory" {
				store = memory.New()
			} else {
				s, err := OpenWithAdditionalFields(ctx, dialect, organizationTestDSN(t, dialect), []string{"phone-number"}, schema.AdditionalFields{User: fields, Session: sessions})
				if err != nil {
					t.Fatal(err)
				}
				defer s.Close()
				store = s
			}
			var code string
			plugin, err := auth.NewPhoneNumber(auth.PhoneNumberOptions{
				SignUpOnVerification: &auth.PhoneSignUpOptions{GetTempEmail: func(n string) string { return n + "@phone.test" }},
				SendOTP:              func(_ context.Context, m auth.PhoneOTPMessage) error { code = m.Code; return nil },
			})
			if err != nil {
				t.Fatal(err)
			}
			opts := auth.Options{Store: store, BaseURL: "http://fields.localhost", Secret: strings.Repeat("s", 40), Plugins: []auth.Plugin{plugin}, UserAdditionalFields: fields, SessionAdditionalFields: sessions}
			node, err := auth.New(opts)
			if err != nil {
				t.Fatal(err)
			}
			n := "+14155550115"
			if err := node.SendPhoneNumberOTP(ctx, n); err != nil {
				t.Fatal(err)
			}
			in := auth.PhoneVerificationInput{PhoneNumber: n, Code: code, AdditionalFields: map[string]any{"locale": "rollback"}}
			if _, err := node.VerifyPhoneNumber(ctx, nil, in, auth.RequestMeta{}); err == nil {
				t.Fatal("registration committed without its required session field")
			}
			if _, err := store.(auth.AccountStore).FindAccountUser(ctx, n+"@phone.test"); !errors.Is(err, auth.ErrNotFound) {
				t.Fatal("failed phone session left an account", err)
			}
			opts.SessionAdditionalFields = map[string]auth.SessionField{"browserFamily": {Type: auth.FieldString, Required: true, Default: "go"}}
			fixed, err := auth.New(opts)
			if err != nil {
				t.Fatal(err)
			}
			result, err := fixed.VerifyPhoneNumber(ctx, nil, in, auth.RequestMeta{})
			if err != nil || result.Token == nil {
				t.Fatal("failed session lost the proof", err)
			}
			checkUserField(t, result.User, "locale", "rollback")
		})
	}
}

type unavailablePhoneProfile struct {
	*memory.Store
	unavailable bool
}

func (s *unavailablePhoneProfile) ReadUserFields(ctx context.Context, id string, fields map[string]auth.UserField) (map[string]any, error) {
	if s.unavailable {
		return nil, errors.New("profile unavailable")
	}
	return s.Store.ReadUserFields(ctx, id, fields)
}

func TestPhoneRegistrationDiscardsUnpublishedSession(t *testing.T) {
	ctx := t.Context()
	store := &unavailablePhoneProfile{Store: memory.New()}
	var code string
	o := auth.PhoneNumberOptions{
		SignUpOnVerification: &auth.PhoneSignUpOptions{GetTempEmail: func(n string) string { return n + "@phone.test" }},
		SendOTP:              func(_ context.Context, m auth.PhoneOTPMessage) error { code = m.Code; return nil },
	}
	p, err := auth.NewPhoneNumber(o)
	if err != nil {
		t.Fatal(err)
	}
	node, err := auth.New(auth.Options{Store: store, Plugins: []auth.Plugin{p}, UserAdditionalFields: userFieldFixture(), BaseURL: "http://phone.localhost", Secret: strings.Repeat("s", 40)})
	if err != nil {
		t.Fatal(err)
	}
	n := "+14155550116"
	signin := func() (auth.PhoneVerificationResult, error) {
		t.Helper()
		if err := node.SendPhoneNumberOTP(ctx, n); err != nil {
			t.Fatal(err)
		}
		return node.VerifyPhoneNumber(ctx, nil, auth.PhoneVerificationInput{PhoneNumber: n, Code: code, AdditionalFields: map[string]any{"locale": "fr"}}, auth.RequestMeta{})
	}
	first, err := signin()
	if err != nil || first.Token == nil {
		t.Fatal("first login", err)
	}
	store.unavailable = true
	result, err := signin()
	if err == nil || result.Token != nil || result.Status {
		t.Fatal("published inaccessible phone profile")
	}
	sessions, err := store.ListSessions(ctx, first.User.ID)
	if err != nil || len(sessions) != 1 || sessions[0].Token != *first.Token {
		t.Fatal("projection failure leaked a session or revoked the owner's earlier login", err)
	}
}
