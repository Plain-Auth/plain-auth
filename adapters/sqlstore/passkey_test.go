package sqlstore

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	pk "github.com/Plain-Org/plain-auth/plugins/passkey"
	"github.com/Plain-Org/plain-auth/schema"
	"github.com/fxamacker/cbor/v2"
)

type softwareKey struct {
	key    *ecdsa.PrivateKey
	id     []byte
	handle string
}

func newSoftwareKey(t *testing.T) *softwareKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 32)
	rand.Read(id)
	return &softwareKey{key: key, id: id}
}
func (k *softwareKey) response(t *testing.T, challenge, origin, rp string, count uint32, register bool) map[string]any {
	t.Helper()
	kind := "webauthn.get"
	flags := byte(0x05)
	if register {
		kind = "webauthn.create"
		flags |= 0x40
	}
	client, err := json.Marshal(map[string]string{"type": kind, "origin": origin, "challenge": challenge})
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte(rp))
	data := append(bytes.Clone(hash[:]), flags)
	data = binary.BigEndian.AppendUint32(data, count)
	b64 := base64.RawURLEncoding.EncodeToString
	output := map[string]any{"clientDataJSON": b64(client)}
	if register {
		key, err := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: k.key.X.FillBytes(make([]byte, 32)), -3: k.key.Y.FillBytes(make([]byte, 32))})
		if err != nil {
			t.Fatal(err)
		}
		data = append(data, make([]byte, 16)...)
		data = binary.BigEndian.AppendUint16(data, uint16(len(k.id)))
		data = append(data, k.id...)
		data = append(data, key...)
		obj, err := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": data})
		if err != nil {
			t.Fatal(err)
		}
		output["attestationObject"] = b64(obj)
		output["transports"] = []string{"internal"}
	} else {
		h := sha256.Sum256(client)
		toSign := sha256.Sum256(append(bytes.Clone(data), h[:]...))
		signature, err := ecdsa.SignASN1(rand.Reader, k.key, toSign[:])
		if err != nil {
			t.Fatal(err)
		}
		output["signature"] = b64(signature)
		output["authenticatorData"] = b64(data)
		output["userHandle"] = k.handle
	}
	return map[string]any{"id": b64(k.id), "rawId": b64(k.id), "type": "public-key", "response": output, "clientExtensionResults": map[string]any{}}
}

func TestPasskeySoftwareAuthenticator(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			dsn := organizationTestDSN(t, dialect)
			const origin = "https://login.example.test"
			const rp = "example.test"
			ddl, err := schema.Generate(dialect, []string{"anonymous", "passkey"})
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
			plug, err := pk.New(pk.Options{RPID: rp, RPName: "Test", Origins: []string{origin}, RequireUserVerification: true})
			if err != nil {
				t.Fatal(err)
			}
			guestPlugin, err := auth.NewAnonymous(auth.AnonymousOptions{})
			if err != nil {
				t.Fatal(err)
			}
			off := false
			opts := auth.Options{Store: s, Secret: "test-only-passkey-0123456789-abcdefgh", BaseURL: origin, EmailAndPassword: true, Plugins: []auth.Plugin{plug, guestPlugin}, RateLimit: &off}
			first, err := auth.New(opts)
			if err != nil {
				t.Fatal(err)
			}
			opts.Store = s2
			second, err := auth.New(opts)
			if err != nil {
				t.Fatal(err)
			}
			signup := func(name string) (auth.AuthResult, *http.Cookie) {
				t.Helper()
				res, err := first.SignUpEmail(ctx, auth.SignUpInput{Email: name + "@example.test", Name: name, Password: "local sample passphrase"}, auth.RequestMeta{})
				if err != nil {
					t.Fatal(err)
				}
				return res, first.SessionCookie(res.Token, true)
			}
			owner, session := signup("owner")
			_, foreign := signup("foreign")
			request := func(server *auth.Auth, path string, payload any, status int, cookies ...*http.Cookie) (map[string]any, []*http.Cookie) {
				t.Helper()
				var body bytes.Buffer
				method := "GET"
				if payload != nil {
					method = "POST"
					if err := json.NewEncoder(&body).Encode(payload); err != nil {
						t.Fatal(err)
					}
				}
				r := httptest.NewRequest(method, origin+"/api/auth/passkey/"+path, &body)
				r.Header.Set("Origin", origin)
				if payload != nil {
					r.Header.Set("Content-Type", "application/json")
				}
				for _, cookie := range cookies {
					r.AddCookie(cookie)
				}
				w := httptest.NewRecorder()
				server.ServeHTTP(w, r)
				if w.Code != status {
					t.Fatalf("%s: got %d want %d: %s", path, w.Code, status, w.Body.String())
				}
				var raw any
				if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
					t.Fatal(err)
				}
				if items, ok := raw.([]any); ok {
					return map[string]any{"items": items}, w.Result().Cookies()
				}
				return raw.(map[string]any), w.Result().Cookies()
			}
			key := newSoftwareKey(t)
			register := func(switchUser, duplicate bool) map[string]any {
				t.Helper()
				options, cs := request(first, "generate-register-options", nil, 200, session)
				if len(cs) != 1 || !cs[0].Secure || !cs[0].HttpOnly || cs[0].MaxAge != 300 {
					t.Fatal("registration challenge cookie has incorrect attributes")
				}
				key.handle = options["user"].(map[string]any)["id"].(string)
				resp := map[string]any{"response": key.response(t, options["challenge"].(string), origin, rp, 0, true), "name": "Primary"}
				if switchUser {
					request(second, "verify-registration", resp, 401, cs[0], foreign)
					return nil
				}
				if duplicate {
					request(second, "verify-registration", resp, 400, cs[0], session)
					return nil
				}
				row, _ := request(second, "verify-registration", resp, 200, cs[0], session)
				request(first, "verify-registration", resp, 400, cs[0], session)
				return row
			}
			request(first, "generate-register-options", nil, 401)
			register(true, false)
			row := register(false, false)
			if row["credentialID"] != base64.RawURLEncoding.EncodeToString(key.id) || row["userId"] != owner.User.ID || row["id"] == row["credentialID"] {
				t.Fatal("stored credential identity mismatch")
			}
			again, _ := request(first, "generate-register-options", nil, 200, session)
			excluded, _ := again["excludeCredentials"].([]any)
			if len(excluded) != 1 || !reflect.DeepEqual(excluded[0], map[string]any{"type": "public-key", "id": row["credentialID"], "transports": []any{"internal"}}) {
				t.Fatalf("registration options did not exclude the enrolled credential: %v", excluded)
			}
			register(false, true)
			gr := httptest.NewRequest("POST", origin+"/api/auth/sign-in/anonymous", strings.NewReader("{}"))
			gr.Header.Set("Content-Type", "application/json")
			gr.Header.Set("Origin", origin)
			gw := httptest.NewRecorder()
			first.ServeHTTP(gw, gr)
			var visitor auth.AuthResult
			if gw.Code != 200 || json.Unmarshal(gw.Body.Bytes(), &visitor) != nil || visitor.User.IsAnonymous == nil {
				t.Fatal("could not start guest passkey browser")
			}
			var guestCookie = first.SessionCookie(visitor.Token, true)
			login := func(count uint32, reportedOrigin string, expected int) {
				t.Helper()
				options, cs := request(first, "generate-authenticate-options", nil, 200)
				if len(cs) != 1 || options["rpId"] != rp {
					t.Fatal("missing RP or challenge")
				}
				payload := map[string]any{"response": key.response(t, options["challenge"].(string), reportedOrigin, rp, count, false)}
				request(second, "verify-authentication", payload, 400)
				cookies := []*http.Cookie{cs[0]}
				if guestCookie != nil {
					cookies = append(cookies, guestCookie)
				}
				result, newCookies := request(second, "verify-authentication", payload, expected, cookies...)
				if expected == 200 {
					if guestCookie != nil {
						if _, err := s.IsAnonymous(ctx, visitor.User.ID); err != auth.ErrNotFound {
							t.Fatal("passkey did not retire the guest after verified assertion")
						}
						guestCookie = nil
					}
					if result["user"].(map[string]any)["id"] != owner.User.ID {
						t.Fatal("assertion issued a session for the wrong owner")
					}
					var h = http.Header{}
					for _, c := range newCookies {
						if c.MaxAge > 0 {
							h.Set("Cookie", c.Name+"="+c.Value)
						}
					}
					live, err := first.GetSession(ctx, h)
					if err != nil || live == nil || live.User.ID != owner.User.ID {
						t.Fatal("assertion session missing on second instance")
					}
				}
				request(first, "verify-authentication", payload, 400, cs[0])
			}
			login(0, origin, 200)
			login(0, origin, 200)
			login(1, origin, 200)
			login(1, origin, 401)
			login(2, "https://untrusted.example.test", 401)
			login(2, origin, 200)
			optsAuth, cs := request(first, "generate-authenticate-options", nil, 200)
			_, err = s.db.ExecContext(ctx, s.bind(`UPDATE "verification" SET "expiresAt"=? WHERE "identifier" LIKE 'passkey:%'`), s.date(time.Now().Add(-time.Hour)))
			if err != nil {
				t.Fatal(err)
			}
			request(second, "verify-authentication", map[string]any{"response": key.response(t, optsAuth["challenge"].(string), origin, rp, 3, false)}, 400, cs[0])
			items, _ := request(first, "list-user-passkeys", nil, 200, foreign)
			if len(items["items"].([]any)) != 0 {
				t.Fatal("foreign passkeys listed")
			}
			mutation := map[string]any{"id": row["id"], "name": "Renamed"}
			request(first, "update-passkey", mutation, 401, foreign)
			request(first, "delete-passkey", mutation, 401, foreign)
			updated, _ := request(first, "update-passkey", mutation, 200, session)
			if updated["passkey"].(map[string]any)["name"] != "Renamed" {
				t.Fatal("rename failed")
			}
			owned, _ := request(first, "list-user-passkeys", nil, 200, session)
			if owned["items"].([]any)[0].(map[string]any)["counter"] != float64(2) {
				t.Fatal("counter not persisted")
			}
			primary := key
			key = newSoftwareKey(t)
			secondKey := register(false, false)
			if secondKey["id"] == row["id"] || secondKey["credentialID"] == row["credentialID"] {
				t.Fatal("separate authenticator credential IDs collided")
			}
			key = primary
			bound, cc := request(first, "generate-authenticate-options", nil, 200, session)
			if len(bound["allowCredentials"].([]any)) != 2 {
				t.Fatal("account challenge omitted an enrolled credential")
			}
			request(second, "verify-authentication", map[string]any{"response": key.response(t, bound["challenge"].(string), origin, rp, 3, false)}, 200, cc[0])
			request(second, "delete-passkey", mutation, 200, session)
			login(3, origin, 401)
			register(false, false)
			_, err = s.db.ExecContext(ctx, s.bind(`UPDATE "session" SET "createdAt"=? WHERE "token"=?`), s.date(time.Now().Add(-48*time.Hour)), owner.Token)
			if err != nil {
				t.Fatal(err)
			}
			request(second, "generate-register-options", nil, 403, session)
			if err := s.DeleteAccount(ctx, owner.User.ID, owner.Token, "", "", time.Now()); err != nil {
				t.Fatal(err)
			}
			var remaining int
			if err := s.db.QueryRowContext(ctx, s.bind(`SELECT COUNT(*) FROM "passkey" WHERE "userId"=?`), owner.User.ID).Scan(&remaining); err != nil || remaining != 0 {
				t.Fatal("account deletion left a passkey", err)
			}
		})
	}
}
