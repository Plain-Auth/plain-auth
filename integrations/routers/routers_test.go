// The integration module keeps framework dependencies out of the library.
package routers_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/go-chi/chi/v5"
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/adaptor"
	"github.com/gorilla/mux"
	authn "github.com/FineStack/finestack-auth"
	"github.com/FineStack/finestack-auth/adapters/sqlite"
)

type runner func(*http.Request) (*http.Response, error)

func httpRunner(handler http.Handler) runner {
	return func(req *http.Request) (*http.Response, error) {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w.Result(), nil
	}
}

func TestFrameworkMounts(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tc := range []struct {
		name  string
		mount func(http.Handler) runner
	}{
		{"ServeMux", func(h http.Handler) runner { r := http.NewServeMux(); r.Handle("/api/auth/", h); return httpRunner(r) }},
		{"chi", func(h http.Handler) runner { r := chi.NewRouter(); r.Handle("/api/auth/*", h); return httpRunner(r) }},
		{"Gorilla", func(h http.Handler) runner {
			r := mux.NewRouter()
			r.PathPrefix("/api/auth/").Handler(h)
			return httpRunner(r)
		}},
		{"Gin", func(h http.Handler) runner {
			r := gin.New()
			r.Any("/api/auth/*path", gin.WrapH(h))
			return httpRunner(r)
		}},
		{"Fiber", func(h http.Handler) runner {
			r := fiber.New()
			r.All("/api/auth/*", adaptor.HTTPHandler(h))
			return func(req *http.Request) (*http.Response, error) { return r.Test(req) }
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := sqlite.Open(":memory:")
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			const origin = "http://localhost"
			auth, err := authn.New(authn.Options{BaseURL: origin, Secret: strings.Repeat("r", 32), Store: s, EmailAndPassword: true})
			if err != nil {
				t.Fatal(err)
			}
			run := tc.mount(auth)
			send := func(method, path, body string, cookies []*http.Cookie, expect int) (*http.Response, string) {
				t.Helper()
				req, err := http.NewRequest(method, origin+path, strings.NewReader(body))
				if err != nil {
					t.Fatal(err)
				}
				if method == http.MethodPost {
					req.Header.Set("Content-Type", "application/json")
					req.Header.Set("Origin", origin)
				}
				for _, c := range cookies {
					req.AddCookie(c)
				}
				res, err := run(req)
				if err != nil {
					t.Fatal(err)
				}
				defer res.Body.Close()
				b, err := io.ReadAll(res.Body)
				if err != nil {
					t.Fatal(err)
				}
				if res.StatusCode != expect {
					t.Fatalf("%s %s: got %d: %s", method, path, res.StatusCode, b)
				}
				return res, strings.TrimSpace(string(b))
			}
			send("GET", "/app-owned", "", nil, 404)
			res, _ := send("POST", "/api/auth/sign-up/email", `{"name":"Ada","email":"ada@example.com","password":"example-password"}`, nil, 200)
			cookies := res.Cookies()
			if len(cookies) == 0 {
				t.Fatal("registration returned no session cookie")
			}
			_, session := send("GET", "/api/auth/get-session", "", cookies, 200)
			var result authn.SessionResult
			if json.Unmarshal([]byte(session), &result) != nil || result.User.Email != "ada@example.com" {
				t.Fatalf("unexpected session: %s", session)
			}
			res, _ = send("POST", "/api/auth/sign-out", "{}", cookies, 200)
			if len(res.Cookies()) < 2 {
				t.Fatal("adapter lost multiple Set-Cookie headers")
			}
			_, session = send("GET", "/api/auth/get-session", "", cookies, 200)
			if session != "null" {
				t.Fatal("revoked session accepted")
			}
		})
	}
}
