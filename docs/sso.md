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
host, err := plainauth.New(plainauth.Options{
    BaseURL: "https://accounts.example.org",
    Secret: authSecret, Store: store,
    TrustedOrigins: []string{"https://identity.example.org"},
    Plugins: []plainauth.Plugin{providers},
})
if err != nil { return err }
mux.Handle("/api/auth/", host)
```

The host imports the root `github.com/Plain-Org/plain-auth` module and its `plugins/sso`, `schema` and `adapters/sqlstore` packages. Serve these routes from an existing auth deployment that lets administrators sign in.

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

Registration fetches the issuer's discovery document and stores the configured issuer, authorization, token and signing-key endpoints, and the UserInfo endpoint when the document advertises one. An endpoint set in `oidcConfig` takes precedence. Give the discovery origin its own exact entry in `TrustedOrigins`, or use the auth server's own origin. Browser wildcard grants apply only to browser requests and callbacks. The discovery request has a ten-second deadline and a one-megabyte response limit. Redirects and mismatched issuers fail registration, and so does a discovered endpoint outside an exact `TrustedOrigins` entry, so a document cannot send the client secret to another origin; another runtime also honours wildcard patterns there. A failed registration answers with a `code`: `discovery_not_found` (400) for a 404, `discovery_invalid_url` (400) for a malformed or non-HTTP issuer, discovery or endpoint URL, `discovery_timeout` (502) after ten seconds or a 408, `discovery_unexpected_error` (502) for any other HTTP status or network failure, and `issuer_mismatch`, `discovery_incomplete`, `discovery_invalid_json`, `discovery_untrusted_origin`, `discovery_private_host` or `oidc_endpoint_redirect` (400) for an unusable document or endpoint. Plain Auth also refuses URLs with credentials, a fragment or a backslash, and checks the issuer before contacting the provider. You can set `skipDiscovery: true` inside `oidcConfig` and provide `authorizationEndpoint`, `tokenEndpoint` and `jwksEndpoint` directly. Both `client_secret_basic` and `client_secret_post` are supported for persisted configuration. [Discovery tests](../plugins/sso/discovery_test.go)

Treat the registration response and the provider table as confidential. The successful registration response includes the submitted OIDC configuration and its client secret, with `Cache-Control: no-store`. The database stores that configuration as JSON in `ssoProvider.oidcConfig`. List and read responses expose only the masked client ID, the selected endpoints and public configuration. Domain names are normalized to ASCII and lowercase, with duplicate entries removed. Recording a domain supplies routing metadata. Management reads cover single-protocol OIDC and supported SAML registrations and report whether the current registration holds a bound DNS proof. All records count toward the creator quota.

The default quota is ten provider records per creator across their personal and organization registrations. Set `Options.ProvidersLimit` to a pointer to a different maximum, or to zero to disable registration. The live organization membership controls access on every node that shares the database, including nodes that serve only the SSO routes. Only owners and administrators can register or inspect the organization's providers. Membership and session authority are checked again before the new provider commits. An impersonated administrator cannot register a provider. Personal registrations disappear when their creator's account is deleted, and previously linked account provider IDs stay reserved. [Ownership, cleanup and concurrency tests](../adapters/sqlstore/sso_test.go)

The native Go client exposes `RegisterOIDCProvider`, `ListSSOProviders`, `GetSSOProvider` and `DeleteSSOProvider`. The registration result supplies the callback URI for IdP setup. [Compatibility tests](../conformance/sso-providers.mjs) · [SSO checklist](parity/plugins/sso.md)

## Enterprise browser sign-in

Post a trusted `callbackURL` and a `providerId`, `organizationSlug`, `domain` or `email` to `/sign-in/sso`. The response contains the authorization URL and `redirect: true`. Open that URL in the browser that started the request. A registered domain also matches its subdomains. Discovery selects eligible verified registrations first, then the most specific matching DNS suffix. A pending registration cannot shadow a proved domain. Equally specific registrations require the caller to identify the provider. Optional request fields include `newUserCallbackURL`, `errorCallbackURL`, `requestSignUp`, `scopes`, `loginHint` and `additionalParams`.

The default redirect URI ends in `/sso/callback/{providerId}`. Set `sso.Options.SharedCallback` to register `/sso/callback` for all providers. Both routes use the host's configured auth mount. Each attempt keeps its return destinations, nonce and PKCE verifier for ten minutes, bound to the initiating browser, session and callback path. By default they are a database record that the callback consumes once. With [`OAuthStateStrategy`](social.md#keep-oauth-state-in-a-cookie) set to `OAuthStateCookie` they are sealed in the `sso_state` cookie, or the SameSite=None `saml_state` cookie for a SAML form post, and a captured copy stays valid until it expires; the identity provider's single-use code or the assertion receipt then stops a replay. Two Go nodes with the same configuration and database can handle opposite ends of a sign-in. An OIDC callback whose state cannot be used redirects to the error page with the same `state_not_found`, `state_mismatch` or `state_invalid` codes as a [social sign-in](social.md), while a provider that changed during the sign-in still sends `invalid_state` to `errorCallbackURL`. A SAML response with unusable state answers 400. [Verification hooks](hooks.md#verification-hooks) run when this record is stored and spent; a declined spend answers as unusable state and keeps the record. [Cross-instance tests](../adapters/sqlstore/sso_browser_test.go)

When Plain Auth also issues OAuth codes, your login page can pass its verified signed query as `oauth_query` on `POST /sign-in/sso`. A successful OIDC callback continues the original authorization with the new session. Your application supplies any organization picker, team picker or consent screen. Ordinary OIDC sign-in uses `newUserCallbackURL` for a new account when configured and `callbackURL` for a returning account. An identity provider denial can return to `errorCallbackURL`. SAML uses the application's `callbackURL` after a successful assertion. [Enterprise issuer login example](oauth-authorization-code.md#sign-in-through-an-enterprise-directory) · [Organization and team selection over HTTP](organizations.md#switch-organizations-and-teams-from-any-client)

Token exchange supports confidential clients using `client_secret_basic` and `client_secret_post`. The callback validates the ID token's signature against the provider’s JWKS, issuer, audience, authorized party, nonce and validity window. If configured, UserInfo supplies profile data using the provider-issued access token. When both sources are available they must name the same subject. Profile resolution supports the standard claims and configured email, name and image claim names. The provider ID and subject select a canonical account row. Plain Auth also checks the row’s recorded authority before issuing a session. Email addresses start unverified. A returning user needs a matching account link or the verified-domain linking conditions below. `DisableImplicitSignUp` requires `requestSignUp` before account creation. The host's global signup policy and administrator bans also apply. [Released client round trips](../conformance/sso-browser.mjs)

Provider endpoints use HTTPS. Explicitly trusted loopback HTTP origins are supported for local tests. For public tenant endpoints, the token, UserInfo and key requests connect directly to a validated public IP and preserve TLS hostname verification. Host-provided transports apply only to exact trusted origins. Each outbound response is limited to one megabyte. Redirects fail the exchange. [Network policy tests](../plugins/sso/identity_test.go)

The SQL adapter rechecks the provider's immutable record ID and configuration before token exchange and inside the transaction that writes the account and session. A changed issuer, tenant, endpoint or client ID cancels an in-flight authorization. Rotating only the confidential client secret preserves the provider reference. Account token storage follows the host's `EncryptOAuthTokens` setting.

An organization-bound provider adds the authenticated user as a member of the bound tenant in the session transaction. Existing roles and live invitations are preserved. A full or deleted organization cannot leave a partial identity or session. These checks also apply on sign-in nodes that share the organization database and serve only the SSO routes. Set `DisableOrganizationProvisioning` to manage membership separately. [Membership and concurrent removal tests](../adapters/sqlstore/sso_browser_test.go)

The native client starts the flow with `SignInSSO`. A Go flow must finish on a Go instance. The released client can use Go-created enterprise accounts on both tested implementations. Imported links require an explicit source classification before the Go runtime can use them. Arbitrary OIDC callback aliases, stateless OIDC IdP-initiated entry, private-key client authentication, custom resolver/provisioning hooks, profile replacement on subsequent sign-in, general provider updates, and automatic organization assignment on ordinary signup remain open.

## Verify directory domains with DNS

Migrate with the `sso-domain-verification` schema profile, which includes the provider catalog and adds its nullable `domainVerified` column. Enable verification on each SSO sign-in and management instance. Existing registrations can request a challenge after migration.

```go
providers, err := sso.New(sso.Options{
    DomainVerification: &sso.DomainVerificationOptions{},
})
```

1. Register the provider. The response includes `domainVerified: false` and a 24-character `domainVerificationToken`. For an existing registration, send `{"providerId":"company"}` to `POST /sso/request-domain-verification`. A 201 response returns the current token. A challenge lasts seven days. Requesting an expired challenge generates a new token. Issuing a token runs its [verification create hooks](hooks.md#verification-hooks); a declined token is returned but cannot be verified until a new one is requested.
2. Publish a TXT record at `_plain-auth-token-company` under **each** registered domain. For example, publish at `_plain-auth-token-company.example.org.` and `_plain-auth-token-company.subsidiary.example.org.` for the registration above. Its value can be the token alone or `_plain-auth-token-company=<token>`. Set `TokenPrefix` to customize the part after the underscore and before the provider ID. Use a provider ID containing letters, digits, underscores or hyphens for DNS verification. The complete label must fit within 63 characters, and each full TXT name within 253. Dotted IDs can still be managed as ordinary OIDC registrations. You can supply a private DNS resolver through `Resolver`.
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

With an authorized administrator's cookie, send an identity provider registration to `POST /sso/register`. The native client exposes `RegisterSAMLProvider`. The top-level `issuer` is a URL and supplies the default service provider entity ID and expected assertion audience. Registration accepts `samlConfig.signatureAlgorithm` and `digestAlgorithm` as URIs or short forms such as `rsa-sha256` and `sha256`, checks them against `SAMLOptions.Algorithms` and returns them with the provider. A deprecated value fails with 400 `SAML_DEPRECATED_CONFIG_ALGORITHM`, an unrecognized one with `SAML_UNKNOWN_ALGORITHM`, and one outside an allow-list with `SAML_ALGORITHM_NOT_ALLOWED`. The values are recorded only: requests are signed with RSA-SHA256, and update-provider replaces only IdP metadata, so it never rechecks them. Upgrade every instance before registering providers with these fields; earlier releases cannot read them. Use `spMetadata.entityID` to give the application its own identifier. Set `idpMetadata.entityID` to the exact issuer in the IdP's signed assertions, and supply its trusted RSA signing certificate. The app accepts a PEM certificate or an array of up to eight certificates for planned overlap. A certificate list in `idpMetadata.cert` takes precedence over `samlConfig.cert`.

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

Start with `POST /sign-in/sso` or the native `SignInSSO` method. Supply `providerId`, `providerType: "saml"` and a trusted `callbackURL`. Open the returned URL in the initiating browser. The IdP sends a URL-encoded POST containing `SAMLResponse` and `RelayState` to `/sso/saml2/sp/acs/company`. The browser must return the ten-minute `Secure; HttpOnly; SameSite=None` state cookie. When the IdP sends an Origin header, it must match the entry point's origin. The ACS reads up to 1 MiB of form data and accepts a SAMLResponse of up to 256 KiB. Set `SAMLOptions.MaxResponseSize` in bytes for another limit up to 1 MiB. A larger response redirects to the sign-in's error callback with `error=saml_error` and an `error_description` that states the limit, like the other ACS failures, where another runtime uses the directory's fallback landing page. The limit applies after the request-body cap, so set a lower cap at the reverse proxy to refuse oversized bodies before they reach the application. It validates the signed assertion, issuer, audience, response destination, bearer recipient, request correlation and validity times. Set `SAMLOptions.ClockSkew` to narrow the tolerance for assertion times; zero selects three minutes, which is also the maximum because the SAML library applies a three-minute tolerance process-wide, where another runtime defaults to five. An assertion outside its validity window redirects with `error=saml_error` and `error_description` `SAML assertion has expired` or `SAML assertion is not yet valid`. An assertion whose Conditions has neither NotBefore nor NotOnOrAfter is accepted and a warning is written to `auth.Options.Logger`, unless `SAMLOptions.RequireTimestamps` is set; then it redirects with `SAML assertion missing required timestamp conditions`. The subject confirmation's NotOnOrAfter and the issue time still bound such an assertion, and one without a Conditions element is always refused, because the SAML library requires one. Set `SAMLOptions.Algorithms.AllowedSignatureAlgorithms` or `AllowedDigestAlgorithms` to accept only the listed URIs; list full URIs using the exported `SignatureAlgorithm` and `DigestAlgorithm` constants, since short forms such as `rsa-sha256` are accepted only in a directory's `samlConfig`. By default the ACS accepts RSA signatures with SHA-256, SHA-384 or SHA-512, and the same digests. A refused algorithm redirects with `error` set to `saml_deprecated_algorithm`, `saml_algorithm_not_allowed` or `saml_unknown_algorithm` and a description that names the algorithm only when it is one of the exported URIs. There is no warn or allow mode: SHA-1 signatures and digests, RSA 1.5 and Triple DES are always refused, and the allow-lists cannot include them. Digest rules also apply to each response signature's DigestMethod, where another runtime checks only the configured digest. ECDSA-signed responses are not accepted: directory certificates must be RSA, because the Go XML signature library checks ECDSA values in a form identity providers do not produce. The `SignatureAlgorithm`, `DigestAlgorithm`, `KeyEncryptionAlgorithm` and `DataEncryptionAlgorithm` constants hold the algorithm URIs. The response must carry exactly one assertion, plain or encrypted: none redirects with `error=saml_no_assertion` and a second or nested one with `error=saml_multiple_assertions`. A valid form redirects both new and returning users to `callbackURL` and issues the configured application session. A second browser cannot continue the first browser's request.

`NameID` identifies the external account. Use `identifierFormat` to request a persistent NameID when your IdP offers one. It sets the NameIDPolicy of each AuthnRequest and the NameIDFormat in the SP metadata. Default attributes are `email`, `givenName`, `surname` and `displayName`; set `mapping` to select other single-valued attribute names. The name joins the first and last names, falls back to `displayName` and then to the NameID. Several values for an identity attribute refuse the response, so an ambiguous email cannot pick a mailbox; another runtime takes the first value. An email-shaped NameID supplies a missing email. To accept the IdP's verification claim, set both `SAMLOptions.TrustEmailVerified` and `mapping.emailVerified`. Existing verified mailboxes still require a live matching DNS domain proof for automatic linking. Current provider configuration, organization binding and domain proof are checked in the SQL transaction that claims the assertion and creates the account or session. A SHA-256 fingerprint identifies each accepted issuer and assertion ID for replay prevention. The receipt lasts 24 hours. Avoid recording assertion forms and state cookies in proxy or request logs.

The default profile accepts a directly signed plaintext assertion over HTTP-POST. A GET or JSON ACS, SP metadata XML import and registration-time private keys remain open. Configure an IdP to use the posted HTTPS ACS and a modern SHA-256-or-stronger signature. The `additionalParams` OAuth option is unavailable for this protocol. Imported SAML links require a recorded identity authority. The historical account reconciliation interface currently supports OIDC and static social identities.

### Start single logout from the application

Set `SAMLOptions.EnableSingleLogout` on the instances serving the provider. Supply the host’s matching RSA `RequestSigner` and `RequestCertificate`. An IdP directory can specify a HTTP-Redirect logout service in its imported metadata XML or register it explicitly.

```json
{
  "singleLogoutService": [
    {
      "Binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
      "Location": "https://identity.example.org/logout"
    }
  ]
}
```

Put this object’s `singleLogoutService` field under `samlConfig.idpMetadata`. The supported IdP logout endpoint uses HTTPS, shares the configured sign-in origin, and has no preset query or fragment. The SP metadata publishes the service’s Redirect SLO URL and the request-signing certificate for eligible directories. Enabling logout alone leaves the existing AuthnRequest signing policy in effect.

After logging in with SAML, send `POST /sso/saml2/logout/{providerId}` with the active browser cookie and an optional trusted `callbackURL`. The native SDK’s `StartSAMLLogout(ctx, providerID, callbackURL)` returns a URL for the same browser to open. The signed IdP assertion must have supplied exactly one authentication statement with a nonempty SessionIndex. The Go service requires a record from that login and the same directory configuration. A password session or a SAML login predating this setting can use ordinary application sign-out.

The start transaction revokes the selected local session and records a single-use return before issuing its HTTP 302. Other logins for the same user stay active. The IdP receives the original NameID, qualifiers and SessionIndex in a signed Redirect LogoutRequest. Its successful HTTP-Redirect response must include the original request ID, the exact issuer and HTTPS destination, the opaque RelayState and a query signature using RSA-SHA256, RSA-SHA384 or RSA-SHA512. The browser returns a dedicated Secure, HttpOnly, SameSite=Lax cookie. Set `SAMLOptions.LogoutRequestTTL` to a positive whole number of seconds to change the five-minute default.

The auth host consumes the pending response once and redirects to the previously stored callback. A timeout or failed IdP response leaves the local session revoked. If the browser signed in again during the round trip, the acknowledgement preserves the newer session. A short-lived verification row holds the external NameID and SessionIndex through the local session expiry. SQL session renewal extends the binding in the same transaction. A second row holds the return destination and browser-binding digest through the logout deadline. Neither row needs a reusable session token. Avoid logging the signed Redirect query, which carries protocol identifiers. With [verification hooks](hooks.md#verification-hooks), the binding runs them when the sign-in stores it, when renewal extends it, and when either logout direction removes it; the pending return runs them when logout starts and when the response spends it. A declined binding signs in without single logout. A declined return still signs the browser out and sends it to the IdP, but its response is refused.

### Accept a logout request from the identity provider

Set both `SAMLOptions.EnableSingleLogout` and `SAMLOptions.EnableIDPInitiatedLogout` on the instances serving the SLO URL. The IdP can send a signed HTTP-Redirect `LogoutRequest` to `GET /sso/saml2/sp/slo/{providerId}` without an application cookie. The host checks the query signature, registered issuer, exact HTTPS destination, issue time and any `NotOnOrAfter` deadline. Accepted request algorithms are RSA-SHA256, RSA-SHA384 and RSA-SHA512. Supply the original plaintext NameID, including its format and qualifiers, and exactly one SessionIndex. The optional signed RelayState carries up to 80 bytes of opaque IdP state.

The database revokes every recorded local session that matches the current immutable directory registration, its configuration, the complete NameID and the SessionIndex. A matching browser cookie clears on that response. With the optional session-cookie cache enabled, another browser can display its old session view until the cache expires. Protected operations verify revocation in storage. Password logins, other IdP sessions and another directory’s records stay active, including when two directories use the same IdP certificate and subject. A directory enrolled in DNS verification must still have its matching proof. A configuration change or directory recreation requires a fresh SAML login to create a binding under its new authority.

The service returns an RSA-SHA256 signed LogoutResponse to the registered IdP endpoint, with the request ID in `InResponseTo` and the original RelayState. Imported XML may specify a separate HTTPS `ResponseLocation` on the same IdP origin. A valid request with no matching sessions receives the same success response. The shared database records the request ID once per registration and issuer for 24 hours. Replaying it returns HTTP 400 and preserves any later login. A binding a verification hook keeps stays stored, unable to end any session; its session still ends. Request and response are browser redirects. The service never fetches the IdP logout endpoint.

Run the current SQL adapter on every session-renewing instance to carry the logout binding through sliding renewal. Sessions whose bindings expired on an earlier writer need a fresh SAML sign-in. Enable single logout when issuing the original login. Both logout directions require its recorded NameID and SessionIndex. POST/SOAP logout, omitted or multiple SessionIndexes, BaseID and encrypted logout identifiers remain open.

### Sign in from a reviewed IdP portal

An IdP portal can send a signed assertion directly to its registered HTTP-POST ACS. Use this flow when users select the application in their identity provider. The default configuration requires a browser-bound service-provider request. To enable portal login, give each instance a host-owned policy that authorizes the specific directory. The service supplies the immutable registration ID, current configuration reference, provider name, actual assertion issuer, effective IdP entry point and organization ID.

```go
portal := &sso.SAMLOptions{
    IDPInitiatedCallbackURL: "/employee",
    AllowIDPInitiated: func(ctx context.Context, d sso.SAMLDirectory) (bool, error) {
        return d.RecordID == approvedRegistrationID &&
            d.Reference == approvedConfigurationReference &&
            d.OrganizationID == companyOrganizationID &&
            d.Issuer == "https://identity.example.org/metadata" &&
            d.EntryPoint == "https://identity.example.org/sso", nil
    },
}
enterprise, err := sso.New(sso.Options{SAML: portal})
```

Obtain the registration ID from the administrator’s successful registration response. Source the policy from trusted host configuration and apply it on all replicas serving the callback. Registration names can be reused after deletion. Pinning the immutable record prevents an old approval from following its name to a new directory. Use the trusted store’s `FindBrowserProvider` method with the provider name and protocol `saml` to obtain the current reference after reviewing the signing certificates. Pinning that reference requires a fresh approval after a catalog change, including signing certificate rotation. A policy error fails the request with HTTP 503.

Configure the IdP to submit a top-level form containing `SAMLResponse` directly to the HTTPS ACS. Omit `RelayState` and `InResponseTo` from an unsolicited response and its subject confirmation. The browser must send an `Origin` matching the configured IdP entry point exactly, including any nondefault port. Choose an IdP origin whose pages the organization trusts to initiate sign-in. When supplied by the browser, `Sec-Fetch-Dest` must be `document`. Some IdPs use a different frontend origin or suppress Origin through referrer policy. Those deployments can use the browser-bound SP flow. Submitting an invalid RelayState never starts portal login.

Use `samlConfig.idpInitiatedCallbackUrl` for a directory landing page. For portal requests the server tries that URL, the host’s `SAMLOptions.IDPInitiatedCallbackURL`, and then the directory’s `samlConfig.callbackUrl`. It skips untrusted destinations and the auth host’s own ACS path, and falls back to the application origin. `DisableImplicitSignUp` permits returning accounts and rejects first-time portal signup. The ACS validates signed subject, issuer, recipient, audience, time bounds and optional directory encryption. The SQL transaction checks current authority and DNS requirements and consumes the assertion once across replicas. A replay redirects with `error=replay_detected`. The Go host’s directory approval and mandatory browser Origin are additional requirements for this mode.

### Encrypt assertions for a directory

Configure the same RSA recipient key and its X.509 certificate on each instance serving that directory. Load them through the host’s secret manager or protected files. The key must be at least 2048 bits. The following helper loads PEM files and returns the setting for `SAMLOptions.Encryption`.

```go
func assertionRecipient(certFile, keyFile string) (*sso.SAMLEncryption, error) {
    pair, err := tls.LoadX509KeyPair(certFile, keyFile)
    if err != nil {
        return nil, err
    }
    key, ok := pair.PrivateKey.(*rsa.PrivateKey)
    if !ok {
        return nil, errors.New("SAML assertion recipient requires an RSA key")
    }
    cert, err := x509.ParseCertificate(pair.Certificate[0])
    if err != nil {
        return nil, err
    }
    return &sso.SAMLEncryption{PrivateKey: key, Certificate: cert}, nil
}
```

Set `samlConfig.idpMetadata.isAssertionEncrypted` to `true` when registering the directory. The Go service also accepts `samlConfig.spMetadata.isAssertionEncrypted` as a requirement for incoming assertions. When either flag is true, a host with no recipient key rejects that registration. The SQL catalog stores the directory’s public settings. Supply only public settings in HTTP registrations.

Give the IdP this directory’s SP metadata. Its encryption key descriptor advertises the public recipient certificate, AES-256-GCM and XML Encryption 1.1 RSA-OAEP with SHA-256 and MGF1-SHA256. An assertion encrypted with Triple DES or RSA 1.5 redirects with `error=saml_deprecated_algorithm`; any other cipher outside this profile redirects with `error=invalid_saml_response`. The signature algorithm policy also applies to the decrypted assertion. Configure the IdP to sign the assertion, then encrypt the entire signed assertion. The content and wrapped key must each use an inline `CipherValue`. The IdP may additionally sign the outer response. The ACS checks the recovered assertion’s signature, claims, browser state, directory authority and issuer-bound replay receipt. A signed outer response with an unsigned assertion is rejected.

One recipient key is active per host. Coordinate recipient-key changes across instances and the IdP, and start a fresh login after the switch. Each host accepts requests encrypted for its active key. The separate request-signing key and the IdP’s verification certificates can be managed independently. Encrypted NameID or attribute fields, detached encrypted keys, additional ciphers and multiple simultaneous recipient keys remain open.

### Import and rotate IdP metadata

An authorized directory manager can submit the IdP’s metadata XML directly in `samlConfig.idpMetadata.metadata` on registration. Obtain it over a trusted channel and verify the issuer and signing certificates with the IdP administrator. Include the top-level `issuer`, `domain`, `providerId` and `samlConfig.entryPoint` from the registration example. The XML supplies the effective IdP entity ID, redirect endpoint and signing certificates. A URL string is rejected. The service parses the submitted bytes locally.

Use one SAML 2.0 `EntityDescriptor` containing one `IDPSSODescriptor`, one HTTPS HTTP-Redirect SSO service, and up to eight signing keys. For each signing key, use a separate `KeyDescriptor` with one X.509 certificate and a 2048-bit or larger RSA public key. Signing and unspecified key usage are accepted. Encryption-only keys cannot authorize a login. Where the IdP requires signed requests, configure the host’s request signer and certificate. Entity and role expiry apply to the resulting authority. The default XML limit is 100 KiB. Set `SAMLOptions.MaxMetadataSize` in bytes for another limit within the 1 MiB request-body cap. MySQL’s canonical TEXT column also limits the complete serialized provider configuration to 65,535 bytes. Federation aggregates, remote metadata retrieval, periodic refresh and metadata-signature trust anchors remain open.

Use `POST /sso/update-provider` with the same manager session to replace the XML. The Go client exposes `UpdateSAMLMetadata(ctx, providerID, xml)`. The response contains sanitized directory details.

```json
{
  "providerId": "company",
  "samlConfig": {
    "idpMetadata": { "metadata": "<md:EntityDescriptor …>…</md:EntityDescriptor>" }
  }
}
```

For a rotation, publish an overlapping document containing the current and next certificates. Switch signing keys at the IdP, verify a new login, then replace the document with the next certificate alone. Each replacement invalidates sign-ins started under the prior configuration. Existing account links and an established DNS proof survive a signing-key rotation. The update holds a database lock, checks the live direct session and organization role, and rejects an issuer or SSO-service change with HTTP 409 while accounts are linked. A change of identity on an unused directory requires a new DNS proof when verification is enabled. The optional `GuardProviderMutation` receives the linked account count and the authentication-boundary change flag before the update commits. This endpoint currently accepts only replacement of the inline IdP metadata.
