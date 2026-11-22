// The integration module keeps framework dependencies out of the library.
package routers_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	authn "github.com/Stonewrit/stonewrit-auth"
	"github.com/Stonewrit/stonewrit-auth/adapters/sqlite"
	"github.com/gin-gonic/gin"
	"github.com/go-chi/chi/v5"
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/adaptor"
	"github.com/gorilla/mux"
	"github.com/labstack/echo/v5"
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
		mount func(http.Handler, http.HandlerFunc) runner
	}{
		{"ServeMux", func(h http.Handler, me http.HandlerFunc) runner {
			r := http.NewServeMux()
			r.Handle("/api/auth/", h)
			r.HandleFunc("GET /me", me)
			return httpRunner(r)
		}},
		{"chi", func(h http.Handler, me http.HandlerFunc) runner {
			r := chi.NewRouter()
			r.Handle("/api/auth/*", h)
			r.Get("/me", me)
			return httpRunner(r)
		}},
		{"Gorilla", func(h http.Handler, me http.HandlerFunc) runner {
			r := mux.NewRouter()
			r.PathPrefix("/api/auth/").Handler(h)
			r.HandleFunc("/me", me).Methods("GET")
			return httpRunner(r)
		}},
		{"Gin", func(h http.Handler, me http.HandlerFunc) runner {
			r := gin.New()
			r.Any("/api/auth/*path", gin.WrapH(h))
			r.GET("/me", gin.WrapH(me))
			return httpRunner(r)
		}},
		{"Echo", func(h http.Handler, me http.HandlerFunc) runner {
			r := echo.New()
			r.Any("/api/auth/*", echo.WrapHandler(h))
			r.GET("/me", echo.WrapHandler(me))
			return httpRunner(r)
		}},
		{"Fiber", func(h http.Handler, me http.HandlerFunc) runner {
			r := fiber.New()
			r.All("/api/auth/*", adaptor.HTTPHandler(h))
			r.Get("/me", adaptor.HTTPHandler(me))
			return func(req *http.Request) (*http.Response, error) {
				// Real password hashing under -race can exceed Fiber's one-second test default.
				return r.Test(req, fiber.TestConfig{Timeout: 15 * time.Second, FailOnTimeout: true})
			}
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
			run := tc.mount(auth, func(w http.ResponseWriter, r *http.Request) {
				session, err := auth.GetSession(r.Context(), r.Header)
				if err != nil {
					http.Error(w, "session lookup failed", http.StatusInternalServerError)
					return
				}
				if session == nil {
					http.Error(w, "sign in first", http.StatusUnauthorized)
					return
				}
				w.Header().Set("Content-Type", "text/plain")
				_, _ = io.WriteString(w, session.User.Email)
			})
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
					t.Fatalf("%s %s: %v", method, path, err)
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
			send("GET", "/me", "", nil, http.StatusUnauthorized)
			res, _ := send("POST", "/api/auth/sign-up/email", `{"name":"Ada","email":"ada@example.com","password":"example-password"}`, nil, 200)
			cookies := res.Cookies()
			if len(cookies) == 0 {
				t.Fatal("registration returned no session cookie")
			}
			if _, email := send("GET", "/me", "", cookies, http.StatusOK); email != "ada@example.com" {
				t.Fatalf("application route received incorrect account %q", email)
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
			send("GET", "/me", "", cookies, http.StatusUnauthorized)
		})
	}
}
