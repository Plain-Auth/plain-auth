// Device authorization lets an input-constrained device obtain a first-party session.

package plainauth

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

const DeviceGrantType = "urn:ietf:params:oauth:grant-type:device_code"
const deviceUserAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

type DeviceAuthorizationOptions struct {
	ExpiresIn, Interval                  time.Duration
	DeviceCodeLength, UserCodeLength     int
	VerificationURI                      string
	GenerateDeviceCode, GenerateUserCode func(context.Context) (string, error)
	ValidateClient                       func(context.Context, string) (bool, error)
	OnDeviceAuthRequest                  func(ctx context.Context, clientID, scope string) error
}

// DeviceGrant is persisted in the device-authorization schema profile.
type DeviceGrant struct {
	ID, DeviceCode, UserCode, UserID, ClientID, Scope, Status string
	ExpiresAt                                                 time.Time
	Interval                                                  time.Duration
}

// DeviceReview identifies an optional live browser session and a decision.
// Action is one of review, approve or deny.
type DeviceReview struct {
	Code, NormalizedCode, UserID, SessionToken, Action string
	Now                                                time.Time
}

type DeviceAuthorizationStore interface {
	CheckDeviceSchema(context.Context) error
	CreateDeviceGrant(context.Context, DeviceGrant) (created bool, err error)
	ReviewDeviceGrant(context.Context, DeviceReview) (grant DeviceGrant, outcome string, err error)
	// PollDeviceGrant binds the session to the approving owner and consumes an
	// approved grant in the same transaction. Pending polls update lastPolledAt.
	PollDeviceGrant(ctx context.Context, code, clientID string, session StoredSession) (scope, outcome string, err error)
}

func deviceError(code, desc string) error { return &OAuthError{400, code, desc} }
func deviceOutcome(outcome string) error {
	switch outcome {
	case "":
		return nil
	case "invalid_user_code":
		return deviceError("invalid_request", "Invalid user code")
	case "unclaimed":
		return deviceError("invalid_request", "Device code has not been claimed by a verifying session; call `GET /device` with the `user_code` while signed in before approving or denying")
	case "processed":
		return deviceError("invalid_request", "Device code already processed")
	case "expired_user_code":
		return deviceError("expired_token", "User code has expired")
	case "expired_token":
		return deviceError(outcome, "Device code has expired")
	case "slow_down":
		return deviceError(outcome, "Polling too frequently")
	case "authorization_pending":
		return deviceError(outcome, "Authorization pending")
	case "access_denied":
		return deviceError(outcome, "Access denied")
	case "invalid_grant":
		return deviceError(outcome, "Invalid device code")
	case "external_grant":
		return deviceError("invalid_grant", "This grant belongs to the OAuth authorization server")
	case "different_client":
		return deviceError("invalid_grant", "Client ID mismatch")
	case "unauthorized":
		return &OAuthError{401, outcome, "Authentication required"}
	case "forbidden":
		return &OAuthError{403, "access_denied", "You are not authorized to decide this device authorization"}
	default:
		return &OAuthError{500, "server_error", "Device authorization is unavailable"}
	}
}

func NewDeviceAuthorization(o DeviceAuthorizationOptions) (Plugin, error) {
	if o.ExpiresIn == 0 {
		o.ExpiresIn = 30 * time.Minute
	}
	if o.Interval == 0 {
		o.Interval = 5 * time.Second
	}
	if o.DeviceCodeLength == 0 {
		o.DeviceCodeLength = 40
	}
	if o.UserCodeLength == 0 {
		o.UserCodeLength = 8
	}
	if o.ExpiresIn < time.Second || o.Interval < time.Second || o.Interval.Milliseconds() > 1<<31-1 || o.DeviceCodeLength < 1 || o.DeviceCodeLength > 191 || o.UserCodeLength < 1 || o.UserCodeLength > 191 {
		return Plugin{}, errors.New("authn: invalid device grant duration or code length")
	}
	if o.VerificationURI == "" {
		o.VerificationURI = "/device"
	}
	uri, err := url.Parse(o.VerificationURI)
	if err != nil || uri.User != nil || uri.Opaque != "" || uri.Host != "" && !uri.IsAbs() || uri.IsAbs() && (uri.Host == "" || uri.Scheme != "https" && uri.Scheme != "http") {
		return Plugin{}, errors.New("authn: invalid device verification URI")
	}
	return Plugin{ID: "device-authorization", ValidateStore: func(s Store) error {
		db, ok := s.(DeviceAuthorizationStore)
		if !ok {
			return errors.New("authn: device authorization needs a device grant store")
		}
		return db.CheckDeviceSchema(context.Background())
	}, Endpoints: []Endpoint{
		{Method: "POST", Path: "/device/code", RawBody: true, Handler: o.createCode},
		{Method: "POST", Path: "/device/token", RawBody: true, Handler: o.token},
		{Method: "GET", Path: "/device", RateLimit: &RateLimitRule{Window: o.ExpiresIn, Max: 5}, Handler: reviewDevice("review")},
		{Method: "POST", Path: "/device/approve", Handler: reviewDevice("approve")},
		{Method: "POST", Path: "/device/deny", Handler: reviewDevice("deny")},
	}}, nil
}

func deviceFields(r *http.Request, keys ...string) (map[string]string, error) {
	mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	fields := make(map[string]string)
	switch mt {
	case "application/json":
		var obj map[string]json.RawMessage
		dec := json.NewDecoder(r.Body)
		if dec.Decode(&obj) != nil || obj == nil || dec.Decode(new(any)) != io.EOF {
			return nil, deviceError("invalid_request", "Invalid JSON object")
		}
		for _, k := range keys {
			if v, ok := obj[k]; ok {
				var value *string
				if json.Unmarshal(v, &value) != nil || value == nil {
					return nil, deviceError("invalid_request", k+" must be a string")
				}
				fields[k] = *value
			}
		}
	case "application/x-www-form-urlencoded":
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, deviceError("invalid_request", "Invalid form body")
		}
		params, err := url.ParseQuery(string(body))
		if err != nil {
			return nil, deviceError("invalid_request", "Invalid form body")
		}
		for _, k := range keys {
			for _, v := range params[k] {
				if v != "" {
					if fields[k] != "" {
						return nil, deviceError("invalid_request", k+" must not be repeated")
					}
					fields[k] = v
				}
			}
		}
	default:
		return nil, &OAuthError{415, "invalid_request", "Expected JSON or form data"}
	}
	return fields, nil
}

func deviceRandomCode(ctx context.Context, generator func(context.Context) (string, error), length int, alphabet string) (string, error) {
	if generator != nil {
		code, err := generator(ctx)
		if err != nil {
			return "", err
		}
		if code == "" || !utf8.ValidString(code) || utf8.RuneCountInString(code) > 191 {
			return "", deviceError("invalid_request", "Generated code must contain 1 to 191 characters")
		}
		return code, nil
	}
	code := make([]byte, length)
	limit := big.NewInt(int64(len(alphabet)))
	for i := range code {
		n, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return "", err
		}
		code[i] = alphabet[n.Int64()]
	}
	return string(code), nil
}

func (o DeviceAuthorizationOptions) checkClient(ctx context.Context, id string) error {
	if id == "" {
		return deviceError("invalid_request", "client_id is required")
	}
	if o.ValidateClient != nil {
		valid, err := o.ValidateClient(ctx, id)
		if err != nil {
			return err
		}
		if !valid {
			return deviceError("invalid_client", "Invalid client ID")
		}
	}
	return nil
}

func (o DeviceAuthorizationOptions) createCode(c EndpointContext) (any, error) {
	c.ResponseHeader.Set("Pragma", "no-cache")
	f, err := deviceFields(c.Request, "client_id", "user_id", "scope")
	if err != nil {
		return nil, err
	}
	ctx := c.Request.Context()
	if err = o.checkClient(ctx, f["client_id"]); err != nil {
		return nil, err
	}
	if o.OnDeviceAuthRequest != nil {
		if err := o.OnDeviceAuthRequest(ctx, f["client_id"], f["scope"]); err != nil {
			return nil, err
		}
	}
	verification, err := url.Parse(c.Auth.opts.BaseURL)
	if err != nil {
		return nil, err
	}
	verification, err = verification.Parse(o.VerificationURI)
	if err != nil {
		return nil, err
	}
	store := c.Store().(DeviceAuthorizationStore)
	for range 3 {
		device, err := deviceRandomCode(ctx, o.GenerateDeviceCode, o.DeviceCodeLength, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
		if err != nil {
			return nil, err
		}
		user, err := deviceRandomCode(ctx, o.GenerateUserCode, o.UserCodeLength, deviceUserAlphabet)
		if err != nil {
			return nil, err
		}
		grant := DeviceGrant{ID: randomID(), DeviceCode: device, UserCode: user, UserID: f["user_id"], ClientID: f["client_id"], Scope: f["scope"], Status: "pending", ExpiresAt: c.Auth.now().Add(o.ExpiresIn), Interval: o.Interval}
		created, err := store.CreateDeviceGrant(ctx, grant)
		if err != nil {
			return nil, err
		}
		if !created {
			continue
		}
		complete := *verification
		q := complete.Query()
		q.Set("user_code", user)
		complete.RawQuery = q.Encode()
		return map[string]any{"device_code": device, "user_code": user, "verification_uri": verification.String(), "verification_uri_complete": complete.String(), "expires_in": int64(o.ExpiresIn / time.Second), "interval": int64(o.Interval / time.Second)}, nil
	}
	return nil, &OAuthError{500, "server_error", "Failed to generate a unique device code"}
}

func (o DeviceAuthorizationOptions) token(c EndpointContext) (any, error) {
	c.ResponseHeader.Set("Pragma", "no-cache")
	fields, err := deviceFields(c.Request, "client_id", "grant_type", "device_code")
	if err != nil {
		return nil, err
	}
	ctx := c.Request.Context()
	if fields["grant_type"] != DeviceGrantType || fields["device_code"] == "" {
		return nil, deviceError("invalid_request", "A device code and device grant type are required")
	}
	if err := o.checkClient(ctx, fields["client_id"]); err != nil {
		return nil, err
	}
	ss, _ := c.Auth.newSession("", RequestMeta{IPAddress: c.Auth.clientIP(c.Request), UserAgent: c.Request.UserAgent()})
	scope, outcome, err := c.Store().(DeviceAuthorizationStore).PollDeviceGrant(ctx, fields["device_code"], fields["client_id"], ss)
	if err != nil {
		return nil, err
	}
	if err = deviceOutcome(outcome); err != nil {
		return nil, err
	}
	return map[string]any{"access_token": ss.Token, "token_type": "Bearer", "expires_in": int64(ss.ExpiresAt.Sub(ss.CreatedAt) / time.Second), "scope": scope}, nil
}

// Normalize only codes from the default alphabet. Exact custom codes are tried first.
func normalizeDeviceUserCode(code string) string {
	var b strings.Builder
	for i := 0; i < len(code); i++ {
		c := code[i]
		if c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		if c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			if !strings.ContainsRune(deviceUserAlphabet, rune(c)) {
				return ""
			}
			b.WriteByte(c)
		}
	}
	return b.String()
}

func reviewDevice(action string) func(EndpointContext) (any, error) {
	return func(c EndpointContext) (any, error) {
		code := c.Request.URL.Query().Get("user_code")
		if action != "review" {
			code, _ = c.Body["userCode"].(string)
		}
		if code == "" {
			return nil, deviceOutcome("invalid_user_code")
		}
		ctx := c.Request.Context()
		session, err := c.Auth.GetSession(ctx, c.Request.Header)
		if err != nil {
			return nil, err
		}
		in := DeviceReview{Code: code, NormalizedCode: normalizeDeviceUserCode(code), Action: action, Now: c.Auth.now()}
		if session != nil {
			if action != "review" {
				if err := session.Session.RequireOwner(); err != nil {
					return nil, err
				}
			}
			in.UserID = session.User.ID
			in.SessionToken = session.Session.Token
		} else if action != "review" {
			return nil, deviceOutcome("unauthorized")
		}
		grant, outcome, err := c.Store().(DeviceAuthorizationStore).ReviewDeviceGrant(ctx, in)
		if err != nil {
			return nil, err
		}
		if err = deviceOutcome(outcome); err != nil {
			return nil, err
		}
		if action != "review" {
			return map[string]bool{"success": true}, nil
		}
		result := map[string]string{"user_code": code, "status": grant.Status}
		if in.UserID != "" && in.UserID == grant.UserID {
			result["client_id"] = grant.ClientID
			if grant.Scope != "" {
				result["scope"] = grant.Scope
			}
		}
		return result, nil
	}
}
