# Enterprise OpenID Connect

Signed-in users can register a confidential OpenID Connect client and read the providers they administer. Adding the `sso` schema profile creates the provider catalog. Add `organization` or `organization-teams` when providers belong to organizations.

```go
ddl, err := schema.Generate("postgres", []string{"sso"})
if err != nil { return err }
store, err := sqlstore.OpenWithSchema(ctx, "postgres", databaseDSN, ddl)
if err != nil { return err }
defer store.Close()

providers, err := sso.New(sso.Options{})
if err != nil { return err }
host, err := stonewrit.New(stonewrit.Options{
    BaseURL: "https://accounts.example.org",
    Secret: authSecret, Store: store,
    TrustedOrigins: []string{"https://identity.example.org"},
    Plugins: []stonewrit.Plugin{providers},
})
if err != nil { return err }
mux.Handle("/api/auth/", host)
```

The host imports the root `github.com/Stonewrit/stonewrit-auth` module and its `plugins/sso`, `schema` and `adapters/sqlstore` packages. Serve these routes from an existing auth deployment that lets administrators sign in.

| Route under the auth mount | Access and behavior |
| --- | --- |
| `POST /sso/register` | Registers a provider with the account owner's direct session. An organization administrator can supply an organization ID. |
| `GET /sso/providers` | Lists the caller's personal registrations and the organization providers they currently administer. |
| `GET /sso/get-provider?providerId=company` | Returns sanitized management metadata for a single registration. |

```json
{
  "providerId": "company",
  "issuer": "https://identity.example.org/tenant",
  "domain": "example.org,subsidiary.example.org",
  "oidcConfig": {
    "clientId": "company-application",
    "clientSecret": "<confidential client secret>"
  }
}
```

Registration fetches the issuer's discovery document and stores the configured issuer, authorization, token and signing-key endpoints. Give the discovery origin its own exact entry in `TrustedOrigins`, or use the auth server's own origin. Browser wildcard grants apply only to browser requests and callbacks. The discovery request has a ten-second deadline and a one-megabyte response limit. Redirects and mismatched issuers fail registration. You can set `skipDiscovery: true` inside `oidcConfig` and provide `authorizationEndpoint`, `tokenEndpoint` and `jwksEndpoint` directly. Both `client_secret_basic` and `client_secret_post` are supported for persisted configuration. [Discovery tests](../plugins/sso/discovery_test.go)

Treat the registration response and the provider table as confidential. The successful registration response includes the submitted OIDC configuration and its client secret, with `Cache-Control: no-store`. The database stores that configuration as JSON in `ssoProvider.oidcConfig`. List and read responses expose only the masked client ID, the selected endpoints and public configuration. Domain names are normalized to ASCII and lowercase, with duplicate entries removed. Recording a domain supplies routing metadata. Management reads currently cover OIDC-only registrations on the default `sso` profile and return `domainVerified: false`. Imported SAML-only and dual-protocol rows still count toward the creator quota. DNS proof-state import has a separate checklist entry.

The default quota is ten provider records per creator across their personal and organization registrations. Set `Options.ProvidersLimit` to a pointer to a different maximum, or to zero to disable registration. The live organization membership controls access on every node that shares the database, including nodes that serve only the SSO routes. Only owners and administrators can register or inspect the organization's providers. Membership and session authority are checked again before the new provider commits. An impersonated administrator cannot register a provider. Personal registrations disappear when their creator's account is deleted, and previously linked account provider IDs stay reserved. [Ownership, cleanup and concurrency tests](../adapters/sqlstore/sso_test.go)

The native Go client exposes `RegisterOIDCProvider`, `ListSSOProviders` and `GetSSOProvider`. The registration result supplies the callback URI for IdP setup. [Compatibility tests](../conformance/sso-providers.mjs) · [SSO checklist](parity/plugins/sso.md)

## Enterprise browser sign-in

Post a trusted `callbackURL` and a `providerId`, `organizationSlug`, `domain` or `email` to `/sign-in/sso`. The response contains the authorization URL and `redirect: true`. Open that URL in the browser that started the request. A registered domain also matches its subdomains. When multiple entries match, the most specific DNS suffix wins. Equally specific registrations require the caller to identify the provider. Optional request fields include `newUserCallbackURL`, `errorCallbackURL`, `requestSignUp`, `scopes`, `loginHint` and `additionalParams`.

The default redirect URI ends in `/sso/callback/{providerId}`. Set `sso.Options.SharedCallback` to register `/sso/callback` for all providers. Both routes use the host's configured auth mount. Each attempt stores its return destinations, nonce and PKCE verifier in a ten-minute database record bound to the initiating browser, session and callback path. The callback consumes the record once. Two Go nodes with the same configuration and database can handle opposite ends of a sign-in. [Cross-instance tests](../adapters/sqlstore/sso_browser_test.go)

Token exchange supports confidential clients using `client_secret_basic` and `client_secret_post`. The callback validates the ID token's signature against the provider’s JWKS, issuer, audience, authorized party, nonce and validity window. If configured, UserInfo supplies profile data using the provider-issued access token. When both sources are available they must name the same subject. Profile resolution supports the standard claims and configured email, name and image claim names. The provider ID and subject identify the linked account. Email addresses start unverified, and an existing user with the same email requires an existing account link. `DisableImplicitSignUp` requires `requestSignUp` before account creation. The host's global signup policy and administrator bans also apply. [Released client round trips](../conformance/sso-browser.mjs)

Provider endpoints use HTTPS. Explicitly trusted loopback HTTP origins are supported for local tests. For public tenant endpoints, the token, UserInfo and key requests connect directly to a validated public IP and preserve TLS hostname verification. Host-provided transports apply only to exact trusted origins. Each outbound response is limited to one megabyte. Redirects fail the exchange. [Network policy tests](../plugins/sso/identity_test.go)

The SQL adapter rechecks the provider's immutable record ID and configuration before token exchange and inside the transaction that writes the account and session. A changed issuer, tenant, endpoint or client ID cancels an in-flight authorization. Rotating only the confidential client secret preserves the provider reference. Account token storage follows the host's `EncryptOAuthTokens` setting.

An organization-bound provider adds the authenticated user as a member of the bound tenant in the session transaction. Existing roles and live invitations are preserved. A full or deleted organization cannot leave a partial identity or session. These checks also apply on sign-in nodes that share the organization database and serve only the SSO routes. Set `DisableOrganizationProvisioning` to manage membership separately. [Membership and concurrent removal tests](../adapters/sqlstore/sso_browser_test.go)

The native client starts the flow with `SignInSSO`. A Go flow must finish on a Go instance. Completed enterprise accounts can sign in on either tested implementation using the shared canonical database. Arbitrary callback aliases, stateless IdP-initiated entry, private-key client authentication, custom resolver/provisioning hooks, profile replacement on subsequent sign-in, provider update/deletion, DNS ownership verification and SAML remain open.
