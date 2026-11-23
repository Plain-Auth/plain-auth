package authtest

import (
	"context"
	"sync"

	auth "github.com/Plain-Org/plain-auth"
)

// OTPRecorder keeps the last issued proof for each mailbox or phone number.
// Use a separate recorder per test server. Its zero value is ready for use.
type OTPRecorder struct {
	mu    sync.RWMutex
	codes map[string]string
}

// Get returns the most recently observed code for a delivery address.
func (r *OTPRecorder) Get(address string) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	code, ok := r.codes[address]
	return code, ok
}

// Clear forgets all captured codes. It does not change their validity at the server.
func (r *OTPRecorder) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	clear(r.codes)
}

func (r *OTPRecorder) record(address, code string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.codes == nil {
		r.codes = make(map[string]string)
	}
	r.codes[address] = code
}

// Email records each issued code before calling the configured sender, if present.
func (r *OTPRecorder) Email(send func(context.Context, auth.EmailOTPMessage) error) func(context.Context, auth.EmailOTPMessage) error {
	return func(ctx context.Context, message auth.EmailOTPMessage) error {
		r.record(message.Email, message.OTP)
		if send == nil {
			return nil
		}
		return send(ctx, message)
	}
}

// Phone records verification or recovery codes before forwarding the original message.
func (r *OTPRecorder) Phone(send func(context.Context, auth.PhoneOTPMessage) error) func(context.Context, auth.PhoneOTPMessage) error {
	return func(ctx context.Context, message auth.PhoneOTPMessage) error {
		r.record(message.PhoneNumber, message.Code)
		if send == nil {
			return nil
		}
		return send(ctx, message)
	}
}
