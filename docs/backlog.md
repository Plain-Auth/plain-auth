# Backlog

Work that is wanted but not scheduled. The [roadmap](parity/README.md) tracks feature parity; these items come from adopters.

- **TypeScript client.** A typed browser client, with types generated from the OpenAPI plugin. Today applications call the routes with `fetch` or with another runtime's client, whose routes and JSON this library follows.
- **Smaller dependency graph.** `adapters/sqlstore` serves every plugin, so a PostgreSQL-only application also compiles the SAML, WebAuthn and Stripe dependencies. Splitting plugin storage into separate packages would trim it. Builds without cgo already work for PostgreSQL and MySQL.
- **Schema from plugins.** Derive the schema profiles from the installed plugins instead of listing them by hand.
- **Consistent constructors.** `stripe.New` returns no error where `emailotp.New` and `organization.New` do.
- **Automatic Stripe organization hooks.** Wire `stripe.OrganizationHooks` into the organization plugin without manual options.
- **Team rosters for owners.** Let an owner list a team's members without belonging to the team.
- **Billing portal configuration.** Name a Stripe portal configuration instead of the account default.
- **Snippet-first guides.** Short per-feature pages that lead with a working example.
- **Tagged releases.** Tag a v0.x release so applications can pin a version.
