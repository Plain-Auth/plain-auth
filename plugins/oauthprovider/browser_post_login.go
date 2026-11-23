package oauthprovider

import (
	"context"
	"net/http"
	"slices"

	auth "github.com/Plain-Auth/plain-auth"
)

// PostLoginContext describes the live account, headers and requested scopes.
// IsContinuation means the browser submitted the post-login form. The policy
// must still check that the account has made a valid selection.
type PostLoginContext struct {
	RegistrationAccess
	Scopes         []string
	IsContinuation bool
}

// PostLoginOptions lets the host require a step between signup and consent,
// such as choosing the organization that will own a delegated grant.
type PostLoginOptions struct {
	Page           string
	ShouldRedirect func(context.Context, PostLoginContext) (bool, error)
}

type accountPage struct{ page, marker string }

func (o BrowserAuthorizationOptions) requiredAccountStep(c auth.EndpointContext, session auth.SessionResult, scopes []string, continuation, cleared bool) (*accountPage, error) {
	if check := o.CheckSignup; check != nil {
		step, err := check(c.Request.Context(), RegistrationAccess{session, c.Request.Header.Clone()}, slices.Clone(scopes))
		if err != nil {
			return nil, err
		}
		if step != nil {
			page := step.Page
			if page == "" {
				page = o.SignupPage
			}
			if page == "" {
				page = o.LoginPage
			}
			return &accountPage{page, "pa_signup"}, nil
		}
	}
	if o.PostLogin != nil && !cleared {
		access := PostLoginContext{RegistrationAccess: RegistrationAccess{session, c.Request.Header.Clone()}, Scopes: slices.Clone(scopes), IsContinuation: continuation}
		required, err := o.PostLogin.ShouldRedirect(c.Request.Context(), access)
		if err != nil {
			return nil, err
		}
		if required {
			return &accountPage{o.PostLogin.Page, "pa_post"}, nil
		}
	}
	return nil, nil
}

// Organization actions can return the next URL directly when their successful
// mutation reissues the browser cookie. Explicit /continue sets IsContinuation.
func (o Options) prepareSelection(c auth.EndpointContext, raw string) (auth.OAuthLoginContinuation, error) {
	if _, err := signedAccountPage(c, raw, "pa_post"); err != nil {
		return nil, err
	}
	session, err := requireBrowserOwner(c)
	if err != nil {
		return nil, err
	}
	return func(issued auth.Session) (*http.Request, error) {
		if session.Session.ID != issued.ID {
			return nil, registrationProblem(400, "invalid_request", "selection session changed")
		}
		q, err := signedAccountPage(c, raw, "pa_post")
		if err != nil {
			return nil, err
		}
		return accountAuthorizationRequest(c, q, false), nil
	}, nil
}
