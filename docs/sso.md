# Enterprise OIDC provider management

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

The native Go client exposes `RegisterOIDCProvider`, `ListSSOProviders` and `GetSSOProvider`. The current management release returns a callback URI for IdP setup. Enterprise browser sign-in, callback processing, provider updates and deletion, DNS verification and SAML are still open. [Compatibility tests](../conformance/sso-providers.mjs) · [SSO checklist](parity/plugins/sso.md)
