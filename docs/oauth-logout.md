# OAuth logout

When a user's session ends, the OAuth provider tells the clients that hold tokens for it.

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
- **Timing:** delivery runs through `Options.BackgroundTasks` when it is set, so a slow client cannot delay sign-out. Without it, delivery finishes before the response returns.

Discovery advertises `backchannel_logout_supported` and `backchannel_logout_session_supported`, always present, true when logout tokens can be sent. Back-channel logout needs the jwt plugin: without it, including with `DisableJWTPlugin`, registering a `backchannel_logout_uri` answers 400 `invalid_client_metadata` and both flags are false. It also needs a store that reports ended sessions (`plainauth.SessionEndReporter`), as the SQL adapter does; with another store the flags are false and no token is sent.

`backchannel_logout_uri` must be an absolute `https` URL with no credentials or fragment, and loopback, private and metadata hosts are refused with `invalid_client_metadata`. Where another runtime then posts to whatever address the name resolves to, the default transport here resolves the name at delivery and dials only public addresses, so a public name that points at a private network gets no token. Set `Options.BackchannelTransport` to send through your own transport, such as an egress proxy.

Another runtime finds recipients through its session delete hooks. Here the store reports every session it ends after the transaction commits, so sessions ended inside a store's own transaction, such as a password reset or a SCIM deactivation, notify clients too; see [observe ended sessions](hooks.md#observe-ended-sessions). One store reports to the Auth created last on it.

[Three-database tests](../adapters/sqlstore/oauth_backchannel_logout_test.go) · [Cross-runtime test](../conformance/oauth-backchannel-logout.mjs) · [Token revocation tests](../adapters/sqlstore/session_deletion_test.go) · [Feature checklist](parity/plugins/oauth-provider.md)
