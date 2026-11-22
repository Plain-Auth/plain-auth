# Manage authorized applications

Use the consent endpoints to build an account page that shows which applications a user has authorized. The user can inspect a grant, replace its scopes or remove it. Each operation uses the signed-in account owner's session and works with any router that serves the Plain Auth handler.

## Set up the server

Enable the `oauth-provider` database profile and install the consent plugin when constructing the auth handler. Configure `AUTH_SECRET` and `AUTH_URL` for the public auth origin. SQLite, PostgreSQL and MySQL support these operations. [Database profiles and CLI migrations](schema.md#oauth-authorization-server-tables) · [Environment settings](environment.md)

```go
import (
    "context"

    auth "github.com/Plain-Auth/plain-auth"
    "github.com/Plain-Auth/plain-auth/adapters/sqlstore"
    "github.com/Plain-Auth/plain-auth/plugins/oauthprovider"
    "github.com/Plain-Auth/plain-auth/schema"
)

func openAuth(ctx context.Context, dialect, dsn string) (*auth.Auth, *sqlstore.Store, error) {
    store, err := sqlstore.OpenWithOptions(ctx, dialect, dsn, []string{"oauth-provider"}, schema.Options{})
    if err != nil {
        return nil, nil, err
    }
    api, err := auth.New(auth.Options{
        Store: store,
        EmailAndPassword: true,
        Plugins: []auth.Plugin{
            oauthprovider.ConsentManagement(oauthprovider.ConsentOptions{
                Scopes: []string{"openid", "profile", "email", "offline_access", "reports:read"},
            }),
        },
    })
    if err != nil {
        store.Close()
        return nil, nil, err
    }
    return api, store, nil
}
```

Mount `api` under the configured auth path and close the store at application shutdown. An alternative adapter implements `oauthprovider.ConsentStore` alongside the core identity store. [Router examples](routers.md)

## Build the account page

Paths below are relative to the auth mount, which defaults to `/api/auth`. The signed-in user is identified by their session cookie. URL-encode the grant ID for the read request.

| Operation | Request | Result |
| --- | --- | --- |
| List grants | `GET /oauth2/get-consents` | An array of the user's consents, including an empty array for a new account |
| Inspect one | `GET /oauth2/get-consent?id=…` | The grant and its registered client ID, scopes, resources, requested UserInfo claims and timestamps |
| Replace scopes | `POST /oauth2/update-consent` with `{"id":"…","update":{"scopes":["reports:read"]}}` | The saved grant and its new update time |
| Remove the grant | `POST /oauth2/delete-consent` with `{"id":"…"}` | HTTP 200 with an empty body |

A client registration's scope list limits updates. An explicit empty list permits clearing the consent to `[]` only. If the registration omits its scope list, the provider's configured scopes apply. The default provider scopes are `openid`, `profile`, `email` and `offline_access`. An update replaces the entire granted scope list, keeping the requested order and the grant's remaining fields. A disallowed scope rejects the entire change.

A missing or revoked session receives 401. Using another user's grant ID also receives 401. A missing grant receives 404. Impersonation sessions and application credentials receive 403 under the account-owner policy. Removing a grant deletes the consent record. Access-token revocation is a separate operation.

These endpoints operate on stored consent records. Interactive authorization, consent collection and client metadata discovery have separate checklist entries. Scope updates currently support locally registered OAuth clients. A registration requiring a discovery provider receives `client not found` until that provider is supported. [OAuth feature checklist](parity/plugins/oauth-provider.md)

## Call it from Go

The Go client maintains a separate cookie jar for each user. Use the signed-in client to show all grants or update the selected record.

```go
import (
    "context"

    "github.com/Plain-Auth/plain-auth/client"
    "github.com/Plain-Auth/plain-auth/plugins/oauthprovider"
)

func updateGrant(ctx context.Context, signedIn *client.Client, grantID string) (oauthprovider.Consent, error) {
    return signedIn.UpdateOAuthConsent(ctx, grantID, []string{"reports:read"})
}
```

Use `signedIn.OAuthConsents(ctx)` to list grants, `signedIn.OAuthConsent(ctx, grantID)` for the selected grant and `signedIn.DeleteOAuthConsent(ctx, grantID)` when the user confirms removal. Pass an empty slice to clear only the scopes and retain the consent record. [Go client and database tests](../adapters/sqlstore/oauth_consent_test.go) · [HTTP comparison tests](../conformance/oauth-consent.mjs)
