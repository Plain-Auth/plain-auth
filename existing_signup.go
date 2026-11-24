package plainauth

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

// signUpUserFinder reads the mailbox owner independently of any password account.
type signUpUserFinder interface {
	FindAccountUser(ctx context.Context, email string) (User, error)
}

// CreateUser has already released its transaction. An observer may safely query
// the winner from another connection. Its outcome cannot change the caller's
// response, and with BackgroundTasks it runs after the response.
func (a *Auth) notifyExistingSignUp(ctx context.Context, email string, request *http.Request) {
	request = accountObserverRequest(ctx, request)
	a.runInBackgroundOrAwait(ctx, "Existing-user sign-up observer failed", func(ctx context.Context) error {
		if request != nil {
			request = request.WithContext(ctx)
		}
		a.observeExistingSignUp(ctx, email, request)
		return nil
	})
}

func (a *Auth) observeExistingSignUp(ctx context.Context, email string, request *http.Request) {
	defer func() {
		if recover() != nil {
			a.Logger().ErrorContext(ctx, "Existing-user sign-up observer failed")
		}
	}()
	user, err := a.opts.Store.(signUpUserFinder).FindAccountUser(ctx, email)
	if errors.Is(err, ErrNotFound) {
		return // The account may have been removed between the duplicate and the lookup.
	}
	if err != nil || user.ID == "" {
		a.Logger().ErrorContext(ctx, "Existing-user sign-up owner lookup failed")
		return
	}
	// Some SQL collations also equate distinct accented addresses.
	if strings.ToLower(user.Email) != email {
		return
	}
	if err := a.opts.OnExistingUserSignUp(ctx, user, request); err != nil {
		// Callback errors may contain a credential or data from a mail transport.
		a.Logger().ErrorContext(ctx, "Existing-user sign-up observer failed")
	}
}
