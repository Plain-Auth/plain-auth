# Enterprise single sign-on

Signed-in users can register an OpenID Connect client or a SAML identity provider and read the providers they administer. Adding the `sso` schema profile creates the provider catalog. Add `organization` or `organization-teams` when providers belong to organizations.

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
| `POST /sso/delete-provider` | Deletes a managed registration and its attributed account links. |

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

Treat the registration response and the provider table as confidential. The successful registration response includes the submitted OIDC configuration and its client secret, with `Cache-Control: no-store`. The database stores that configuration as JSON in `ssoProvider.oidcConfig`. List and read responses expose only the masked client ID, the selected endpoints and public configuration. Domain names are normalized to ASCII and lowercase, with duplicate entries removed. Recording a domain supplies routing metadata. Management reads cover single-protocol OIDC and supported SAML registrations and report whether the current registration holds a bound DNS proof. All records count toward the creator quota.

The default quota is ten provider records per creator across their personal and organization registrations. Set `Options.ProvidersLimit` to a pointer to a different maximum, or to zero to disable registration. The live organization membership controls access on every node that shares the database, including nodes that serve only the SSO routes. Only owners and administrators can register or inspect the organization's providers. Membership and session authority are checked again before the new provider commits. An impersonated administrator cannot register a provider. Personal registrations disappear when their creator's account is deleted, and previously linked account provider IDs stay reserved. [Ownership, cleanup and concurrency tests](../adapters/sqlstore/sso_test.go)

The native Go client exposes `RegisterOIDCProvider`, `ListSSOProviders`, `GetSSOProvider` and `DeleteSSOProvider`. The registration result supplies the callback URI for IdP setup. [Compatibility tests](../conformance/sso-providers.mjs) · [SSO checklist](parity/plugins/sso.md)

## Enterprise browser sign-in

Post a trusted `callbackURL` and a `providerId`, `organizationSlug`, `domain` or `email` to `/sign-in/sso`. The response contains the authorization URL and `redirect: true`. Open that URL in the browser that started the request. A registered domain also matches its subdomains. Discovery selects eligible verified registrations first, then the most specific matching DNS suffix. A pending registration cannot shadow a proved domain. Equally specific registrations require the caller to identify the provider. Optional request fields include `newUserCallbackURL`, `errorCallbackURL`, `requestSignUp`, `scopes`, `loginHint` and `additionalParams`.

The default redirect URI ends in `/sso/callback/{providerId}`. Set `sso.Options.SharedCallback` to register `/sso/callback` for all providers. Both routes use the host's configured auth mount. Each attempt stores its return destinations, nonce and PKCE verifier in a ten-minute database record bound to the initiating browser, session and callback path. The callback consumes the record once. Two Go nodes with the same configuration and database can handle opposite ends of a sign-in. [Cross-instance tests](../adapters/sqlstore/sso_browser_test.go)

Token exchange supports confidential clients using `client_secret_basic` and `client_secret_post`. The callback validates the ID token's signature against the provider’s JWKS, issuer, audience, authorized party, nonce and validity window. If configured, UserInfo supplies profile data using the provider-issued access token. When both sources are available they must name the same subject. Profile resolution supports the standard claims and configured email, name and image claim names. The provider ID and subject select a canonical account row. StoneWrit also checks the row’s recorded authority before issuing a session. Email addresses start unverified. A returning user needs a matching account link or the verified-domain linking conditions below. `DisableImplicitSignUp` requires `requestSignUp` before account creation. The host's global signup policy and administrator bans also apply. [Released client round trips](../conformance/sso-browser.mjs)

Provider endpoints use HTTPS. Explicitly trusted loopback HTTP origins are supported for local tests. For public tenant endpoints, the token, UserInfo and key requests connect directly to a validated public IP and preserve TLS hostname verification. Host-provided transports apply only to exact trusted origins. Each outbound response is limited to one megabyte. Redirects fail the exchange. [Network policy tests](../plugins/sso/identity_test.go)

The SQL adapter rechecks the provider's immutable record ID and configuration before token exchange and inside the transaction that writes the account and session. A changed issuer, tenant, endpoint or client ID cancels an in-flight authorization. Rotating only the confidential client secret preserves the provider reference. Account token storage follows the host's `EncryptOAuthTokens` setting.

An organization-bound provider adds the authenticated user as a member of the bound tenant in the session transaction. Existing roles and live invitations are preserved. A full or deleted organization cannot leave a partial identity or session. These checks also apply on sign-in nodes that share the organization database and serve only the SSO routes. Set `DisableOrganizationProvisioning` to manage membership separately. [Membership and concurrent removal tests](../adapters/sqlstore/sso_browser_test.go)

The native client starts the flow with `SignInSSO`. A Go flow must finish on a Go instance. The released client can use Go-created enterprise accounts on both tested implementations. Imported links require an explicit source classification before the Go runtime can use them. Arbitrary callback aliases, stateless IdP-initiated entry, private-key client authentication, custom resolver/provisioning hooks, profile replacement on subsequent sign-in, provider updates, and automatic organization assignment on ordinary signup remain open.

## Verify directory domains with DNS

Migrate with the `sso-domain-verification` schema profile, which includes the provider catalog and adds its nullable `domainVerified` column. Enable verification on each SSO sign-in and management instance. Existing registrations can request a challenge after migration.

```go
providers, err := sso.New(sso.Options{
    DomainVerification: &sso.DomainVerificationOptions{},
})
```

1. Register the provider. The response includes `domainVerified: false` and a 24-character `domainVerificationToken`. For an existing registration, send `{"providerId":"company"}` to `POST /sso/request-domain-verification`. A 201 response returns the current token. A challenge lasts seven days. Requesting an expired challenge generates a new token.
2. Publish a TXT record at `_stonewrit-auth-token-company` under **each** registered domain. For example, publish at `_stonewrit-auth-token-company.example.org.` and `_stonewrit-auth-token-company.subsidiary.example.org.` for the registration above. Its value can be the token alone or `_stonewrit-auth-token-company=<token>`. Set `TokenPrefix` to customize the part after the underscore and before the provider ID. Use a provider ID containing letters, digits, underscores or hyphens for DNS verification. The complete label must fit within 63 characters, and each full TXT name within 253. Dotted IDs can still be managed as ordinary OIDC registrations. You can supply a private DNS resolver through `Resolver`.
3. Send the same provider ID to `POST /sso/verify-domain`. A successful response is HTTP 204 with an empty body. A missing or incorrect TXT answer returns 502. An expired or absent challenge returns 404. Repeating either operation after verification returns 409. The native client exposes `RequestSSODomainVerification` and `VerifySSODomain`. [Released client and local DNS tests](../conformance/sso-domains.mjs)

Both operations require the creator's direct session for a personal directory, or a current organization owner or administrator for an organization directory. The SQL adapter rechecks that authority and the active token after DNS lookup. It binds the proof to the registration ID, provider ID, domain list, issuer, creator, organization and OIDC configuration. Rotating just the client secret preserves the proof. Changing the client ID, key source, claim mapping or UserInfo endpoint requires a new challenge. Back up the related verification records with the provider catalog. A deployment importing a standalone verification flag or an externally generated challenge must request and complete a fresh challenge. Existing deployments should switch every public sign-in node to the new policy before accepting enterprise logins. [Three-engine migration and authorization tests](../adapters/sqlstore/sso_domain_test.go)

A verified domain authorizes its exact name and subdomains. Enterprise sign-in checks ownership at initiation, before contacting the identity provider on callback, and inside the transaction that creates the session. The provider can link an existing **verified local account** when the email from the authenticated identity provider is within a proved domain. An email entered into the browser cannot grant that authority. New users retain the ordinary unverified email status. Removing a TXT record after verification does not automatically revoke the stored proof. [Identity and concurrency tests](../adapters/sqlstore/sso_domain_test.go)

## Delete a provider

Send `{"providerId":"company"}` to `POST /sso/delete-provider` with a direct owner session. A personal registration belongs to its creator. Organization owners and administrators can delete registrations bound to their organization. Access follows current membership on every node. A successful response is `{"success":true}`. A repeated delete returns HTTP 404. [Client compatibility tests](../conformance/sso-providers.mjs)

The SQL adapter locks the exact registration and removes only the links whose recorded source belongs to that registration. A same-name static OAuth link is preserved. An unclassified link in the provider namespace returns HTTP 409 with `SSO_ACCOUNT_ORIGIN_REQUIRED` before anything is removed. Existing users, active sessions, organization memberships and links to other providers survive. A replacement registration receives a new internal ID. An authorization started against its predecessor cannot issue a new session through the replacement. Users whose old link was removed must establish a new authorized link before they can reuse their existing account with that provider. [Browser replacement test](../conformance/sso-browser.mjs)

Set `sso.Options.GuardProviderMutation` to apply an application deletion policy. The callback receives the locked registration ID, provider ID, organization ID, configuration fingerprint and linked-account count. Returning an error rolls back the operation with HTTP 409 and code `SSO_PROVIDER_MUTATION_REJECTED`. Keep the callback brief and free of side effects because database conflicts can retry the transaction. Custom adapters can implement `sso.DeletionStore` to supply the same transactional boundary. [SQL authorization and rollback tests](../adapters/sqlstore/sso_delete_test.go)

## Existing OAuth accounts and shared databases

A canonical account row carries a public provider ID and a subject. Two identity services can choose the same values. The SQL adapter records each new link’s source atomically with its creation, binding the canonical account ID, owner ID, subject and creation time. A managed link also belongs to one immutable registration, issuer and organization scope. Static OAuth sign-in, token access, refresh, profile lookup and provider logout require a static link. Enterprise sign-in requires the matching managed registration. A known static link and a managed link can share a public provider name when their subjects differ. Use distinct provider IDs if the issuers can produce the same subjects. [Mixed-node login and credential tests](../adapters/sqlstore/sso_browser_test.go)

Before adding an SSO schema profile to an existing deployment, inventory the OAuth accounts and confirm their original authority from the host’s provider configuration, provisioning records or identity provider. Existing static-only databases without a directory catalog can continue to use their historical static links. Mark confirmed static rows before deploying the schema to keep them available through the upgrade. When the directory catalog is present, unclassified historical links require this explicit step even if the old registration has since disappeared. [Schema upgrade test](../adapters/sqlstore/oauth_origin_test.go)

Call the trusted server-side operation for each independently verified link. Restrict access to the operator performing the migration. For a static provider supply the exact `AccountID`, `UserID`, `ProviderID` and `Subject`. For an enterprise link also supply the immutable `EnterpriseRecordID` and exact `EnterpriseIssuer`, plus `EnterpriseOrganizationID` for organization-bound registrations. Repeating the same classification is safe. Changing an established source is rejected. A newly created browser authorization or a matching email alone cannot establish the origin of an old row.

```go
err := store.ReconcileOAuthAccount(ctx, sqlstore.OAuthAccountAttribution{
    AccountID: rowID, UserID: ownerID, ProviderID: providerName, Subject: subject,
    EnterpriseRecordID: registrationID, EnterpriseIssuer: issuer,
    EnterpriseOrganizationID: organizationID,
})
```

Source records use the existing verification table and contain no provider tokens. Include them when backing up and restoring account rows. The Go SQL adapter maintains these records when linking, unlinking and deleting accounts. External writers and earlier library versions can write canonical links without recording their source and may delete all links under a shared name. Assign separate names to those writers or route link management through a source-aware deployment. [Deletion and reconciliation tests](../adapters/sqlstore/sso_delete_test.go)

## SP-initiated SAML sign-in

Enable SAML on each instance handling enterprise sign-in. Use the public HTTPS auth URL and the same SQL provider catalog, signing secret, cookie prefix and auth mount across those instances. The default SSO configuration enables OIDC. SAML uses the same `sso` schema profile. Add `sso-domain-verification` and enable DNS verification when a directory should link existing verified accounts by email.

```go
directory, err := sso.New(sso.Options{
    SAML:               &sso.SAMLOptions{},
    DomainVerification: &sso.DomainVerificationOptions{},
})
```

With an authorized administrator's cookie, send an identity provider registration to `POST /sso/register`. The native client exposes `RegisterSAMLProvider`. The top-level `issuer` is a URL and supplies the default service provider entity ID. Use `spMetadata.entityID` to give the application its own identifier. Set `idpMetadata.entityID` to the exact issuer in the IdP's signed assertions, and supply its trusted RSA signing certificate. The app accepts a PEM certificate or an array of up to eight certificates for planned overlap. A certificate list in `idpMetadata.cert` takes precedence over `samlConfig.cert`.

```json
{
  "providerId": "company",
  "issuer": "https://idp.example.org/metadata",
  "domain": "staff.example.org",
  "samlConfig": {
    "entryPoint": "https://idp.example.org/login",
    "idpMetadata": { "entityID": "https://idp.example.org/metadata" },
    "spMetadata": { "entityID": "https://accounts.example.org/saml" },
    "cert": "<PEM-encoded IdP signing certificate>",
    "wantAssertionsSigned": true
  }
}
```

The registration response retains the catalog’s OIDC-style `redirectURI` field. Use the ACS advertised by SAML metadata when configuring your identity provider. Give the IdP the public `GET /sso/saml2/sp/metadata?providerId=company` URL under the auth mount. It publishes the entity ID and exact HTTP-POST assertion consumer service (ACS) URL. To sign outgoing HTTP-Redirect requests with RSA-SHA256, set `SAMLOptions.RequestSigner` and `RequestCertificate` to the host-managed matching RSA key and certificate, then register the provider with `authnRequestsSigned: true`. Signing and verification require RSA keys of at least 2048 bits. The SQL catalog holds public IdP configuration.

Start with `POST /sign-in/sso` or the native `SignInSSO` method. Supply `providerId`, `providerType: "saml"` and a trusted `callbackURL`. Open the returned URL in the initiating browser. The IdP sends a URL-encoded POST containing `SAMLResponse` and `RelayState` to `/sso/saml2/sp/acs/company`. The browser must return the ten-minute `Secure; HttpOnly; SameSite=None` state cookie. When the IdP sends an Origin header, it must match the entry point's origin. The ACS accepts forms up to 1 MiB. It validates the signed assertion, issuer, audience, response destination, bearer recipient, request correlation and validity times. A valid form redirects both new and returning users to `callbackURL` and issues the configured application session. A second browser cannot continue the first browser's request.

`NameID` identifies the external account. Use `identifierFormat` to request a persistent NameID when your IdP offers one. Default attributes are `email`, `givenName`, `surname` and `displayName`; set `mapping` to select other single-valued attribute names. An email-shaped NameID supplies a missing email. To accept the IdP's verification claim, set both `SAMLOptions.TrustEmailVerified` and `mapping.emailVerified`. Existing verified mailboxes still require a live matching DNS domain proof for automatic linking. Current provider configuration, organization binding and domain proof are checked in the SQL transaction that claims the assertion and creates the account or session. A SHA-256 fingerprint identifies each accepted issuer and assertion ID for replay prevention. The receipt lasts 24 hours. Avoid recording assertion forms and state cookies in proxy or request logs.

This profile supports plaintext, directly signed assertions over HTTP-POST. IdP-initiated sign-in, a GET or JSON ACS, encrypted assertions, XML metadata import, SAML single logout and registration-time private keys remain open. Configure an IdP to use the posted HTTPS ACS and a modern SHA-256-or-stronger signature. The `additionalParams` OAuth option is unavailable for this protocol. Imported SAML links without recorded identity authority are rejected; the historical account reconciliation interface currently supports OIDC and static social identities.
