# Maintainer conformance tests

The harness locks its reference dependencies independently of the Go module. The HTTP test uses the official JavaScript client and two isolated SQLite installations. A second test exchanges signed account-verification and password-reset links across runtimes on the same database. All application traffic stays on the machine.

From this directory, use Node 24, npm, the root module’s Go toolchain and a C compiler.

```sh
npm ci --ignore-scripts --no-audit --no-fund
npm test
```

The passkey comparison covers the public client’s request options. The Go software authenticator also signs registration and login ceremonies against all three local engines.

The HTTP suite builds one temporary Go executable. Each fixture starts its own process, binds a loopback port and opens an isolated SQLite database. The suite compares status codes, cookie attributes and response fields, tracks token and user identity across requests and checks session lifetime. The schema tests call the installed reference migration code and the actual Go CLI. They compare generated DDL for SQLite, PostgreSQL and MySQL, and inspect SQLite columns, defaults, keys, indexes and foreign keys after a fresh installation and repeated migrations on existing data.

For live PostgreSQL and MySQL catalogs, set `AUTH_TEST_POSTGRES_DSN` and `AUTH_TEST_MYSQL_DSN` to disposable local databases. Run `go test -count=1 ./adapters/sqlstore` from the project root. The combined plugin-profile test uses isolated databases or schemas for the fresh installation and the upgrade. The organization deletion and passkey software-authenticator tests create and remove a temporary database on MySQL and a temporary schema on PostgreSQL. The corresponding test users need permission to create those objects.

## Regenerating schema presets

The Go schema package stores each dialect's ordered table, column and index definitions. A selection includes the fragments contributed by its enabled profiles. The conformance tests compare CLI output for each supported combination with a fresh reference compilation. To reproduce or verify these artifacts, run from the project root.

```sh
node conformance/sql-schema.mjs
node conformance/plugin-schema.mjs
```

Add `--write` to the relevant command to regenerate its catalog. Run the complete suite after any change to a profile or its generator.

## Regenerating the feature checklist

The reference release is v1.7.27 at commit `9faf6f6a1155a6cdaf8ba2d25ce53e4f5a3fda72`. Run these commands from this directory.

```sh
git clone --depth 1 --branch v1.7.27 https://github.com/better-auth/better-auth.git /tmp/better-auth-v1.7.27
npm run inventory -- /tmp/better-auth-v1.7.27 --check
```

Omit `--check` to regenerate the [product feature checklist](../docs/parity/README.md) and the machine-readable [reference index](reference.json). The index contains exact package and export coordinates, provider and plugin names, source anchors, and externally maintained documentation entries. Product pages use behavior names and link checked items to local tests. Keep reviewed local test markers and narrowly scoped claims in [evidence.json](evidence.json).

Each evidence entry records a passing subcase. Set `"complete": true` on one reviewed scenario when its test establishes the full capability. The generator attaches that test to the parent checkbox and keeps the parent open whenever any nested requirement is open. A new open descendant reopens the parent automatically.

[scope.json](scope.json) lists entries that exist only for JavaScript clients, frameworks or runtimes, with the reason, and integrations on the backlog. A rule names a page and optionally a section, an enclosing entry or exact labels. A not-applicable entry and everything beneath it leave the totals. A backlog entry stays open. The generator fails when a rule matches nothing, so a reference update cannot silently drop one.

The package inventory follows each published manifest’s export map. The pinned TypeScript compiler resolves local re-exports, overloads, inherited option fields and wildcard entry points. The machine-readable index records forwarded third-party types separately. The public checklist describes behavior at each entry point and links available Go and wire tests. Source-language types, externally maintained packages and provider settings still need individual review before a behavior can be marked complete. [Published interfaces](../docs/parity/packages.md) · [Extractor regression tests](public-interfaces.test.mjs)

Set `CHROME_BIN` to a local Chrome or Chromium executable to include the headless One Tap browser fixture in `node --test one-tap-browser.test.mjs`. Run `go test -count=1 ./plugins/onetap` from the project root with the same variable to exercise the secure redirect receiver in Chrome. Each uses an isolated browser profile and loopback networking.

Run `node --test oauth-popup-browser.test.mjs` for popup message, cancellation and credential-storage checks. From this directory, `node --test --test-name-pattern="released popup client|Chrome signs in through a real popup" core.test.mjs` exercises the released client on both local runtimes and Chrome in top-level and cross-site iframe contexts. Set `CHROME_BIN` when Chrome is installed outside the default locations.
