package stripe

import (
	"context"
	"net/http"
)

// TrialTransition identifies the committed local subscription and the mounted
// webhook that observed a conversion or expiry.
type TrialTransition struct {
	Subscription Subscription
	Request      *http.Request
}

func trialHook(plan Plan, status string) func(context.Context, TrialTransition) error {
	if plan.FreeTrial == nil {
		return nil
	}
	switch status {
	case "active":
		return plan.FreeTrial.OnTrialEnd
	case "incomplete_expired":
		return plan.FreeTrial.OnTrialExpired
	default:
		return nil
	}
}

func webhookRequest(r *http.Request) *http.Request {
	request := r.Clone(r.Context())
	request.Body = http.NoBody
	request.GetBody = nil
	return request
}
