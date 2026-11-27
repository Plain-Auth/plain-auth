# OAuth logout

A client can ask the OAuth provider to end the user's session, and when a session ends, the provider tells the clients that hold tokens for it.

## RP-initiated logout

To let a client end the user's session, give it `EnableEndSession` from server code. `/oauth2/end-session` then implements [RP-Initiated Logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout) for it, and discovery publishes it as `end_session_endpoint`:

```go
end := true
created, err := manager.CreateClient(ctx, r.Header, oauthprovider.ClientCreation{
    RegistrationMetadata: oauthprovider.RegistrationMetadata{
        RedirectURIs:           []string{"https://app.example.com/callback"},
        PostLogoutRedirectURIs: []string{"https://app.example.com/logout"},
    },
    EnableEndSession: &end,
})
```

`ClientManager.UpdateClient` changes the setting later. Owners cannot set it through `/oauth2/register`, `/oauth2/create-client` or `/oauth2/update-client`.

- **Requests** use `GET` query parameters or a `POST` body as a form or JSON, with `id_token_hint`, `client_id`, `post_logout_redirect_uri` and `state`; body fields win over query fields. A repeated query field, a non-string JSON field or a JSON array answers 400 `invalid_request`; in a form, the last of a repeated field wins, as in another runtime. The Go client sends one with `client.EndOAuthSession`.
- **The browser's session** is the stored session its signed session cookie names, even one that has expired, whatever other credentials the request carries.
- **A valid hint** ends the session it names: the browser's own session, or the hinted one when the browser's cookie names no stored session. The hint must be an ID token this issuer signed for the client, with `sid` and `sub`; an expired one is accepted. The client comes from `client_id`, or else from the hint's `aud` or `azp`; at most one client is looked up before the signature is checked. With `DisableJWTPlugin`, the hint is checked with the client's secret, read back from its encrypted storage.
- **Confirmation** is needed without a hint, with a hint for another session than the browser's, or, from a browser with a session, with a hint that fails. A browser gets a "Confirm logout" page whose form posts `action=confirm` to `/oauth2/end-session/confirm`, with a signed cookie named after the session cookie plus `.oauth_logout_confirmation`, `HttpOnly`, `SameSite=Lax`, scoped to that path and valid for five minutes. Other callers get 400 `invalid_request`: "User confirmation is required to complete logout", or "No active session is available for logout". Confirming ends the browser's current session; a missing, tampered or expired cookie, or one bound to another session, answers 400 "The logout confirmation is invalid or expired", and the core origin check refuses a cross-origin form.
- **Redirects** go only to a `post_logout_redirect_uri` that exactly matches one of the client's registered URIs, with `state` added. A browser is redirected with 302; a fetch or JSON caller gets `{"redirect":true,"url":...}`. Without a match, a browser sees a "Logged out." page, noting an unregistered redirect when one was asked for, and other callers get JSON `null`. After confirmation, the redirect is checked again: the client must still be enabled, allowed to end sessions and list the URI, and the URI must still pass the HTTPS rule. A URI that fails the HTTPS rule, as at authorize, answers 400 `invalid_request` before anything else.
- **Refusals:** a missing client answers 400 `invalid_client` "The logout client does not exist", a disabled one 400 "The logout client is disabled", and one without `EnableEndSession` 401 "The client is not allowed to initiate logout", before the hint is checked; a hint that fails answers 401 `invalid_token`. A browser gets these as an error page. Pages are sent with `Content-Security-Policy: default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'`, and every answer with `Cache-Control: no-store` and `Pragma: no-cache`.
- **Ending the session** runs the session delete hooks, as sign-out does, and so sends back-channel logout tokens. A failure answers 500 `server_error` and keeps the session.

The store must implement `oauthprovider.EndSessionStore`, as the SQL adapter does, to read the session a hint names; without it, the endpoint answers 501 and discovery leaves `end_session_endpoint` out, where another runtime always lists it.

[Three-database tests](../adapters/sqlstore/oauth_end_session_test.go) · [Cross-runtime test](../conformance/oauth-end-session.mjs)

## Back-channel logout

Register a `backchannel_logout_uri` for a client to receive a signed [Logout Token](https://openid.net/specs/openid-connect-backchannel-1_0.html#LogoutToken) when a session it holds tokens for ends. The session can end in any way: sign-out, revoking sessions, a password change or reset, an administrator's revocation or ban, account deletion, SCIM deactivation or SAML logout.

```go
logoutURI, sessionRequired := "https://app.example.com/logout/backchannel", true
created, err := manager.CreateClient(ctx, r.Header, oauthprovider.ClientCreation{
    RegistrationMetadata: oauthprovider.RegistrationMetadata{
        RedirectURIs:                     []string{"https://app.example.com/callback"},
        BackchannelLogoutURI:             &logoutURI,
        BackchannelLogoutSessionRequired: &sessionRequired,
    },
})
```

The field works the same through `/oauth2/register`, `/oauth2/create-client` and `/oauth2/update-client`.

- **Recipients** are the enabled clients with a URI that hold opaque access tokens or refresh tokens on the session, revoked or not. A client that holds only a signed access token for it, such as one issued for a `resource` without `offline_access`, is not notified, because signed tokens are not stored.
- **The token** has the header `typ: logout+jwt` and the claims `iss`, `aud` (the client ID), `sub`, `sid`, `iat`, `exp`, `jti` and `events`, and no `nonce`. It lives for 120 seconds. `sub` is the subject the client's ID tokens carry, so a pairwise client gets its pairwise subject; a client whose pairwise subject cannot be computed is skipped with a warning. The jwt plugin signs it, so a client verifies it with the issuer's key set.
- **Delivery** is one `POST` of the form field `logout_token`, with `Accept: application/json`, a 5-second timeout and no redirects. A response other than 200 or 204, or any failure, is logged as a warning and never fails the sign-out. Clients are notified concurrently, and none is retried.
- **Tokens** of the session are revoked as it ends: its access tokens and its refresh tokens without `offline_access`. Introspection and UserInfo then refuse those access tokens; a resource server that verifies signed access tokens itself accepts them until they expire. Refresh tokens with `offline_access` survive, as [section 2.7](https://openid.net/specs/openid-connect-backchannel-1_0.html#BCActions) allows.
- **Timing:** delivery runs through `Options.BackgroundTasks` when it is set, so a slow client cannot delay sign-out. Without it, delivery finishes before the response returns, and goes on if the caller disconnects.

Discovery advertises `backchannel_logout_supported` and `backchannel_logout_session_supported`, always present, true when logout tokens can be sent. Back-channel logout needs the jwt plugin: without it, including with `DisableJWTPlugin`, registering a `backchannel_logout_uri` answers 400 `invalid_client_metadata` and both flags are false. It also needs a store that reports ended sessions (`plainauth.SessionEndReporter`), as the SQL adapter does; with another store the flags are false and no token is sent.

`backchannel_logout_uri` must be an absolute `https` URL with no credentials or fragment, and loopback, private and metadata hosts are refused with `invalid_client_metadata`. Where another runtime then posts to whatever address the name resolves to, the default transport here resolves the name at delivery and dials only public addresses, so a public name that points at a private network gets no token. Set `Options.BackchannelTransport` to send through your own transport, such as an egress proxy.

Another runtime finds recipients through its session delete hooks. Here the store reports every session it ends after the transaction commits, so sessions ended inside a store's own transaction, such as a password reset or a SCIM deactivation, notify clients too; see [observe ended sessions](hooks.md#observe-ended-sessions). One store reports to the Auth created last on it.

[Three-database tests](../adapters/sqlstore/oauth_backchannel_logout_test.go) · [Cross-runtime test](../conformance/oauth-backchannel-logout.mjs) · [Token revocation tests](../adapters/sqlstore/session_deletion_test.go) · [Feature checklist](parity/plugins/oauth-provider.md)
