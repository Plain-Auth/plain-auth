package captcha_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	authn "github.com/nabuhadba/go-better-auth"
	"github.com/nabuhadba/go-better-auth/adapters/memory"
	"github.com/nabuhadba/go-better-auth/plugins/captcha"
)

type transport func(*http.Request) (*http.Response, error)

func (f transport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func instance(t *testing.T, o captcha.Options, ip authn.ClientIPOptions) *authn.Auth {
	t.Helper()
	p, err := captcha.New(o)
	if err != nil {
		t.Fatal(err)
	}
	h, err := authn.New(authn.Options{
		Store: memory.New(), Secret: strings.Repeat("s", 32), BaseURL: "http://app.example.org/mount", Plugins: []authn.Plugin{p}, EmailAndPassword: true, ClientIP: ip,
	})
	if err != nil {
		t.Fatal(err)
	}
	return h
}
func request(h *authn.Auth, method, path, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://app.example.org"+path, nil)
	r.Header.Set("X-Forwarded-For", "203.0.113.4")
	if token != "" {
		r.Header.Set("X-Captcha-Response", token)
	}
	r.RemoteAddr = "127.0.0.1:9210"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestProviderContracts(t *testing.T) {
	data, err := os.ReadFile("testdata/reference.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []struct {
		Name, Override    string
		Provider          captcha.Provider
		Missing, NoSecret bool
		MinScore          *float64
		Status            int
		Reply             json.RawMessage
		Sent              *struct {
			URL, Method, Type string
			Fields            map[string]string
		}
		Expected struct {
			Status        int
			Code, Message string
		}
	}
	if err = json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	for _, f := range fixtures {
		t.Run(f.Name, func(t *testing.T) {
			sent := false
			o := captcha.Options{Provider: f.Provider, SecretKey: "fixture-secret", SiteKey: "site-key", Endpoints: []string{"/ok"}, MinScore: f.MinScore, ExpectedAction: "login", AllowedHostnames: []string{"app.example.org"}, SiteVerifyURLOverride: f.Override}
			if f.NoSecret {
				o.SecretKey = ""
			}
			o.Transport = transport(func(req *http.Request) (*http.Response, error) {
				if f.Sent == nil {
					t.Fatal("unexpected remote request")
				}
				sent = true
				if req.URL.String() != f.Sent.URL || req.Method != f.Sent.Method || req.Header.Get("Content-Type") != f.Sent.Type {
					t.Fatalf("unexpected provider request %s %s %s", req.Method, req.URL, req.Header.Get("Content-Type"))
				}
				deadline, ok := req.Context().Deadline()
				if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > 10*time.Second {
					t.Fatal("verification request missing ten-second deadline")
				}
				fields := map[string]string{}
				if f.Sent.Type == "application/json" {
					if e := json.NewDecoder(req.Body).Decode(&fields); e != nil {
						t.Fatal(e)
					}
				} else {
					if e := req.ParseForm(); e != nil {
						t.Fatal(e)
					}
					for k, v := range req.PostForm {
						if len(v) != 1 {
							t.Fatal("duplicate verification parameter")
						}
						fields[k] = v[0]
					}
				}
				if !reflect.DeepEqual(fields, f.Sent.Fields) {
					t.Fatalf("verification fields %#v, want %#v", fields, f.Sent.Fields)
				}
				status := f.Status
				if status == 0 {
					status = 200
				}
				return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewReader(f.Reply)), Header: http.Header{"Content-Type": {"application/json"}}}, nil
			})
			h := instance(t, o, authn.ClientIPOptions{TrustedProxies: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}})
			tok := "fixture-token"
			if f.Missing {
				tok = ""
			}
			w := request(h, "GET", "/mount/ok", tok)
			if sent != (f.Sent != nil) || w.Code != f.Expected.Status {
				t.Fatalf("status=%d, provider called=%v: %s", w.Code, sent, w.Body)
			}
			if w.Code != 200 {
				var response struct{ Code, Message string }
				if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || response.Code != f.Expected.Code || response.Message != f.Expected.Message {
					t.Fatalf("error body %s", w.Body)
				}
			}
		})
	}
}

func TestPathsAndNativeMethods(t *testing.T) {
	for _, tc := range []struct {
		path     string
		patterns []string
		want     int
	}{
		{"/mount/sign-up/email", nil, 400}, {"/mount/sign-in/email", nil, 400}, {"/mount/request-password-reset", nil, 400},
		{"/mount/sign-in/email/", nil, 400}, {"/mount/sign-in//email", nil, 400},
		{"/mount/sign-in/email-otp", nil, 404}, {"/mount/sign-in/email/deep", nil, 404}, {"/mounted/sign-in/email", nil, 404},
		{"/mount/sign-in/email", []string{"/sign-in/*"}, 400}, {"/mount/sign-in/level/nested", []string{"/sign-in/*"}, 404},
		{"/mount/sign-in/level/nested", []string{"/sign-in/**"}, 400},
		{"/mount/sign-in/social", []string{"/sign-in/*"}, 400},
	} {
		t.Run(tc.path, func(t *testing.T) {
			h := instance(t, captcha.Options{Provider: captcha.GoogleRecaptcha, SecretKey: "key", Endpoints: tc.patterns}, authn.ClientIPOptions{})
			w := request(h, "POST", tc.path, "")
			if w.Code != tc.want {
				t.Fatalf("%d %s", w.Code, w.Body)
			}
		})
	}
	h := instance(t, captcha.Options{Provider: captcha.HCaptcha, SecretKey: "key"}, authn.ClientIPOptions{})
	user, err := h.SignUpEmail(context.Background(), authn.SignUpInput{Name: "User", Email: "fixture@example.org", Password: "user-password"}, authn.RequestMeta{})
	if err != nil || user.User.Email != "fixture@example.org" {
		t.Fatalf("direct signup %v", err)
	}
}

func TestPeerPrivacyAndServiceErrors(t *testing.T) {
	for _, tc := range []struct {
		name, reply, wantIP string
		disable             bool
		want                int
	}{
		{"direct peer", `{"success":true}`, "127.0.0.1", false, 200},
		{"tracking disabled", `{"success":true}`, "", true, 200},
		{"malformed JSON", "invalid", "127.0.0.1", false, 500},
		{"redirect", "", "127.0.0.1", false, 500},
		{"response exceeds bound", strings.Repeat(" ", 65537), "127.0.0.1", false, 500},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			h := instance(t, captcha.Options{Provider: captcha.HCaptcha, SecretKey: "secret", Endpoints: []string{"/ok"}, Transport: transport(func(r *http.Request) (*http.Response, error) {
				calls++
				if err := r.ParseForm(); err != nil {
					t.Fatal(err)
				}
				if r.PostForm.Get("remoteip") != tc.wantIP || r.PostForm.Has("remoteip") != (tc.wantIP != "") {
					t.Fatalf("unexpected IP information: %v", r.PostForm)
				}
				code := 200
				header := http.Header{}
				if tc.name == "redirect" {
					code = 307
					header.Set("Location", "https://other.example.org/secret")
				}
				return &http.Response{StatusCode: code, Header: header, Body: io.NopCloser(strings.NewReader(tc.reply))}, nil
			})}, authn.ClientIPOptions{DisableTracking: tc.disable})
			w := request(h, "GET", "/mount/ok", "fixture-token")
			if w.Code != tc.want || calls != 1 {
				t.Fatalf("%d %s, calls %d", w.Code, w.Body, calls)
			}
		})
	}
}

func TestBotID(t *testing.T) {
	for _, tc := range []struct {
		name           string
		verdict        captcha.BotIDVerdict
		failed, custom bool
		want           int
	}{
		{"human", captcha.BotIDVerdict{}, false, false, 200},
		{"bot", captcha.BotIDVerdict{IsBot: true}, false, false, 403},
		{"allow verified bot", captcha.BotIDVerdict{IsBot: true, IsVerifiedBot: true, VerifiedBotName: "indexer"}, false, true, 200},
		{"custom deny human", captcha.BotIDVerdict{}, false, true, 403},
		{"provider failure", captcha.BotIDVerdict{}, true, false, 500},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := captcha.Options{Provider: captcha.VercelBotID, Endpoints: []string{"/ok"}, CheckBotID: func(r *http.Request) (captcha.BotIDVerdict, error) {
				if _, ok := r.Context().Deadline(); !ok {
					t.Error("missing verdict deadline")
				}
				if tc.failed {
					return captcha.BotIDVerdict{}, errors.New("private diagnostic")
				}
				return tc.verdict, nil
			}}
			if tc.custom {
				o.ValidateRequest = func(r *http.Request, v captcha.BotIDVerdict) (bool, error) {
					return v.IsVerifiedBot && v.VerifiedBotName == "indexer" && r.URL.Path == "/mount/ok", nil
				}
			}
			h := instance(t, o, authn.ClientIPOptions{})
			w := request(h, "GET", "/mount/ok", "")
			if w.Code != tc.want || strings.Contains(w.Body.String(), "private diagnostic") {
				t.Fatalf("%d %s", w.Code, w.Body)
			}
		})
	}
}
func TestBotIDReturnsWhenCallerCancels(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	h := instance(t, captcha.Options{Provider: captcha.VercelBotID, Endpoints: []string{"/ok"}, CheckBotID: func(*http.Request) (captcha.BotIDVerdict, error) { <-release; return captcha.BotIDVerdict{}, nil }}, authn.ClientIPOptions{})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	req := httptest.NewRequestWithContext(ctx, "GET", "http://app.example.org/mount/ok", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 500 {
		t.Fatalf("pending BotID: %d %s", w.Code, w.Body)
	}
}

func TestProviderVerificationCancellation(t *testing.T) {
	h := instance(t, captcha.Options{Provider: captcha.GoogleRecaptcha, SecretKey: "fixture-secret", Endpoints: []string{"/ok"}, Transport: transport(func(r *http.Request) (*http.Response, error) {
		<-r.Context().Done()
		return nil, r.Context().Err()
	})}, authn.ClientIPOptions{})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	r := httptest.NewRequestWithContext(ctx, http.MethodGet, "http://app.example.org/mount/ok", nil)
	r.Header.Set("X-Captcha-Response", "fixture-token")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 500 || !strings.Contains(w.Body.String(), "UNKNOWN_ERROR") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}
