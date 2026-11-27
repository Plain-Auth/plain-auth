package polar

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/memory"
	polargo "github.com/polarsource/polar-go"
	"github.com/polarsource/polar-go/models/components"
)

// A verified sign-up creates the account's Polar customer with its ID,
// email and name and the host's parameters, from HTTP and direct Go calls;
// an unverified sign-up creates none; and a failing callback or provider,
// a panic or a slow provider never fails the sign-up.
func TestSignUpCustomer(t *testing.T) {
	const merchant = "11111111-1111-4111-8111-111111111111"
	var mu sync.Mutex
	var created []map[string]any
	var versions []string
	status := 201
	external := ""
	block := make(chan struct{})
	slow, panics := false, false
	client := polargo.New(polargo.WithSecurity("fixture"), polargo.WithClient(transport(func(r *http.Request) (*http.Response, error) {
		if r.Method != "POST" || r.URL.Path != "/v1/customers/" {
			return nil, errors.New("unexpected Polar call " + r.Method + " " + r.URL.Path)
		}
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		json.Unmarshal(raw, &body)
		mu.Lock()
		created, versions = append(created, body), append(versions, r.Header.Get("Polar-Version"))
		code, id, wait, explodes := status, external, slow, panics
		mu.Unlock()
		if explodes {
			panic("transport panic detail")
		}
		if wait {
			select {
			case <-block:
			case <-r.Context().Done():
				return nil, r.Context().Err()
			}
		}
		if id == "" {
			id, _ = body["external_id"].(string)
		}
		if code == 422 {
			return &http.Response{StatusCode: 422, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"detail":[{"loc":["body","email"],"msg":"provider detail","type":"value_error"}]}`)), Request: r}, nil
		}
		if code != 201 {
			return &http.Response{StatusCode: code, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"detail":"provider detail"}`)), Request: r}, nil
		}
		reply, _ := json.Marshal(map[string]any{"id": "44444444-4444-4444-8444-444444444444", "created_at": time.Now(), "modified_at": nil, "metadata": map[string]any{}, "external_id": id,
			"email": body["email"], "email_verified": true, "type": "individual", "name": body["name"], "billing_address": nil, "tax_id": nil, "organization_id": merchant, "deleted_at": nil, "avatar_url": "https://avatars.example.test/a"})
		return &http.Response{StatusCode: 201, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(reply)), Request: r}, nil
	})))
	var requests []*http.Request
	var paramsErr error
	explode := false
	var logs bytes.Buffer
	var logMu sync.Mutex
	logger := slog.New(slog.NewTextHandler(lockedLog{&logMu, &logs}, nil))
	plugin, err := New(Options{Client: client, OrganizationID: merchant, SignUpCustomer: &SignUpCustomerOptions{Logger: logger, Params: func(_ context.Context, u auth.User, r *http.Request) (CustomerParams, error) {
		mu.Lock()
		defer mu.Unlock()
		requests = append(requests, r)
		if explode {
			panic("host panic detail")
		}
		return CustomerParams{Metadata: map[string]components.CustomerIndividualCreateMetadata{"plan": components.CreateCustomerIndividualCreateMetadataStr("trial")}}, paramsErr
	}}})
	if err != nil {
		t.Fatal(err)
	}
	a, err := auth.New(auth.Options{BaseURL: host, Secret: strings.Repeat("c", 40), Store: memory.New(), EmailAndPassword: true,
		// Accounts named "verified ..." sign up with a verified email.
		DatabaseHooks: auth.DatabaseHooks{User: auth.ModelHooks[auth.UserRecord]{Create: auth.OperationHooks[auth.UserRecord]{
			Before: func(_ context.Context, row *auth.UserRecord, _ *auth.HookContext) error {
				row.EmailVerified = strings.HasPrefix(row.Name, "verified")
				return nil
			}}}},
		Plugins: []auth.Plugin{plugin}})
	if err != nil {
		t.Fatal(err)
	}
	users := 0
	signUp := func(name string) auth.User {
		t.Helper()
		users++
		hit, err := a.SignUpEmail(t.Context(), auth.SignUpInput{Name: name, Email: strings.ReplaceAll(name, " ", ".") + "@example.test", Password: "local fixture password"}, auth.RequestMeta{})
		if err != nil {
			t.Fatal("the sign-up failed", name, err)
		}
		return hit.User
	}
	calls := func() int {
		mu.Lock()
		defer mu.Unlock()
		return len(created)
	}

	// A verified Go sign-up creates the customer from the account, with the
	// host's metadata and no request.
	user := signUp("verified buyer")
	mu.Lock()
	body, version, request := created[0], versions[0], requests[0]
	mu.Unlock()
	if body["external_id"] != user.ID || body["email"] != user.Email || body["name"] != "verified buyer" || body["type"] != "individual" || body["metadata"].(map[string]any)["plan"] != "trial" || body["organization_id"] != nil || version != apiVersion || request != nil {
		t.Fatal("the customer was not created from the account", body, version, request)
	}
	// An HTTP sign-up passes its request to the callback.
	raw, _ := json.Marshal(map[string]string{"name": "verified http", "email": "verified.http@example.test", "password": "local fixture password"})
	r := httptest.NewRequest("POST", host+"/api/auth/sign-up/email", bytes.NewReader(raw))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", host)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	mu.Lock()
	httpRequest := requests[len(requests)-1]
	mu.Unlock()
	if w.Code != 200 || calls() != 2 || httpRequest == nil || !strings.HasSuffix(httpRequest.URL.Path, "/sign-up/email") {
		t.Fatal("an HTTP sign-up did not create the customer with its request", w.Code, calls())
	}
	// An unverified sign-up creates none.
	signUp("new buyer")
	if calls() != 2 {
		t.Fatal("an unverified sign-up created a customer")
	}
	// A failing or panicking callback creates none and keeps the sign-up.
	mu.Lock()
	paramsErr = errors.New("host detail")
	mu.Unlock()
	signUp("verified failing")
	mu.Lock()
	paramsErr, explode = nil, true
	mu.Unlock()
	signUp("verified panicking")
	mu.Lock()
	explode = false
	mu.Unlock()
	if calls() != 2 {
		t.Fatal("a failing callback created a customer", calls())
	}
	// A provider failure, an unexpected customer and a slow provider keep
	// the sign-up, and nothing logs provider or host text.
	mu.Lock()
	status = 500
	mu.Unlock()
	signUp("verified outage")
	mu.Lock()
	status = 422
	mu.Unlock()
	signUp("verified taken")
	mu.Lock()
	status, panics = 201, true
	mu.Unlock()
	signUp("verified panicking transport")
	mu.Lock()
	panics = false
	status, external = 201, "someone-else"
	mu.Unlock()
	signUp("verified mismatch")
	mu.Lock()
	external, slow = "", true
	mu.Unlock()
	saved := signUpCustomerTimeout
	signUpCustomerTimeout = 50 * time.Millisecond
	started := time.Now()
	signUp("verified slow")
	signUpCustomerTimeout = saved
	close(block)
	if time.Since(started) > 5*time.Second {
		t.Fatal("a slow provider held the sign-up")
	}
	logMu.Lock()
	out := logs.String()
	logMu.Unlock()
	for _, want := range []string{"SignUpCustomer.Params failed", "could not create the customer", "unexpected customer", "refused the customer", "customer hook for a new account panicked"} {
		if !strings.Contains(out, want) {
			t.Error("a failure was not logged", want)
		}
	}
	if strings.Contains(out, "provider detail") || strings.Contains(out, "host detail") || strings.Contains(out, "panic detail") || strings.Contains(out, "@example.test") {
		t.Fatal("a log line carried provider, host or account text", out)
	}
}

// lockedLog serializes log writes.
type lockedLog struct {
	mu *sync.Mutex
	w  *bytes.Buffer
}

func (l lockedLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}
