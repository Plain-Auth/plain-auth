# Database adapters

[Feature index](README.md)

## Community Adapters

- [ ] Community Adapters
  - [ ] Create Your Own Adapter
  - Browse Community Adapters — *not applicable: JavaScript only; each listed adapter is tracked under Community database adapters*

## Drizzle ORM Adapter

- Drizzle ORM Adapter — *not applicable: JavaScript only*
  - Schema generation & migration
  - Joins
  - Modifying Table Names
  - Modifying Field Names
  - Date Columns
  - Using Plural Table Names
  - Custom Schema namespace
  - Drizzle Relations v2

## MongoDB Adapter

- [ ] MongoDB Adapter
  - [ ] Schema generation & migration
    - [ ] Indexes
  - Joins — *not applicable: JavaScript database adapter option*

## MS SQL

- [ ] MS SQL
  - [ ] Schema generation & migration
  - Joins — *not applicable: JavaScript database adapter option*

## MySQL

- [ ] MySQL
  - [x] Open the MySQL store from a go-sql-driver DSN, round-trip creation timestamps at millisecond precision, reopen the populated schema and serve sign-up, sign-in, get-session, revocation and sign-out over HTTP ([test](../../adapters/sqlstore/engines_test.go#L24))
  - [x] Schema generation & migration ([test](../../cmd/authctl/main_test.go#L29))
    - [x] Emit table DDL from authctl generate for PostgreSQL, MySQL and SQLite ([test](../../cmd/authctl/main_test.go#L29))
    - [x] Generate the configured schema with authctl, apply it with authctl migrate and pass authctl check on SQLite, PostgreSQL and MySQL ([test](../../cmd/authctl/user_fields_test.go#L67))
    - [x] Run authctl migrate twice on PostgreSQL and MySQL, add a configured session column to a populated table and report drift with authctl check ([test](../../cmd/authctl/session_fields_live_test.go#L71))
  - Joins — *not applicable: JavaScript database adapter option*

## Other Relational Databases

- [ ] Other Relational Databases
  - [ ] Core Dialects
    - [x] Open SQLite, PostgreSQL and MySQL stores and run registration, credential lookup, reopening and the HTTP session lifecycle against each ([test](../../adapters/sqlstore/engines_test.go#L24))
  - Kysely Organization Dialects — *not applicable: JavaScript only; each database is listed under SQL dialect integrations*
  - Kysely Community dialects — *not applicable: JavaScript only; each database is listed under SQL dialect integrations*

## PostgreSQL

- [ ] PostgreSQL
  - [x] Open the PostgreSQL store from a pgx connection string, reopen the populated schema and serve sign-up, sign-in, get-session, revocation and sign-out over HTTP ([test](../../adapters/sqlstore/engines_test.go#L24))
  - [x] Schema generation & migration ([test](../../cmd/authctl/main_test.go#L29))
    - [x] Emit table DDL from authctl generate for PostgreSQL, MySQL and SQLite ([test](../../cmd/authctl/main_test.go#L29))
    - [x] Generate the configured schema with authctl, apply it with authctl migrate and pass authctl check on SQLite, PostgreSQL and MySQL ([test](../../cmd/authctl/user_fields_test.go#L67))
    - [x] Run authctl migrate twice on PostgreSQL and MySQL, add a configured session column to a populated table and report drift with authctl check ([test](../../cmd/authctl/session_fields_live_test.go#L71))
  - Joins — *not applicable: JavaScript database adapter option*
  - [ ] Use a non-default schema
    - [ ] Set `database.schemaName`
    - [ ] Set `search_path`
      - [x] Resolve the read-only schema check's PostgreSQL tables through the connection's search_path order ([test](../../adapters/sqlstore/check_test.go#L159))
      - [x] Migrate and check a pre-created PostgreSQL schema named by search_path in the connection string from the CLI, then read the same tables through a store opened on that schema ([test](../../cmd/authctl/wallet_schema_test.go#L51))

## Prisma

- Prisma — *not applicable: JavaScript only*
  - Setup
    - Configure Prisma
    - Create the Prisma client
    - Configure authentication
  - Schema generation & migration
  - Joins

## SQLite

- [x] SQLite ([test](../../adapters/sqlstore/engines_test.go#L24))
  - [x] Open a SQLite file store, reopen it and serve sign-up, sign-in, get-session, revocation and sign-out over HTTP ([test](../../adapters/sqlstore/engines_test.go#L24))
  - [x] Reopen a SQLite file and read back the stored credential and session, then revoke the session ([test](../../adapters/sqlstore/sqlite_test.go#L85))
  - [x] Schema generation & migration ([test](../../cmd/authctl/main_test.go#L29))
    - [x] Roll back a failed initialization atomically ([test](../../adapters/sqlstore/sqlite_test.go#L49))
    - [x] Emit table DDL from authctl generate for PostgreSQL, MySQL and SQLite ([test](../../cmd/authctl/main_test.go#L29))
    - [x] Run authctl migrate twice against a SQLite file ([test](../../cmd/authctl/main_test.go#L38))
    - [x] Generate the configured schema with authctl, apply it with authctl migrate and pass authctl check on SQLite, PostgreSQL and MySQL ([test](../../cmd/authctl/user_fields_test.go#L67))
  - Joins — *not applicable: JavaScript database adapter option*

## Create a Database Adapter

- [ ] Create a Database Adapter
  - Adapter — *not applicable: JavaScript adapter factory API; Go custom stores implement typed store interfaces*
    - `options`
    - `schema`
    - `debugLog`
    - `getModelName`
    - `getFieldName`
    - `getDefaultModelName`
    - `getDefaultFieldName`
    - `getFieldAttributes`
    - `transformInput`
    - `transformOutput`
    - `transformWhereClause`
    - Adapter Methods
    - `create` method
      - `model`
      - `data`
      - `select`
    - `update` method
      - `model`
      - `where`
      - `update`
    - `updateMany` method
      - `model`
      - `where`
      - `update`
    - `delete` method
      - `model`
      - `where`
    - `deleteMany` method
      - `model`
      - `where`
    - `consumeOne` method
      - `model`
      - `where`
    - `incrementOne` method
      - `model`
      - `where`
      - `increment`
      - `set`
    - `findOne` method
      - `model`
      - `where`
      - `select`
      - `join`
    - `findMany` method
      - `model`
      - `where`
      - `limit`
      - `select`
      - `sortBy`
      - `offset`
      - `join`
    - `count` method
      - `model`
      - `where`
    - `options` (optional)
    - `createSchema` (optional)
      - `tables`
      - `file`
  - [ ] Test your adapter
  - Config — *not applicable: the JavaScript createAdapterFactory config object; Go custom stores implement typed plainauth.Store and per-feature interfaces with no adapter config*
    - Required Config
    - `adapterId`
    - `adapterName`
    - Optional Config
    - `supportsNumericIds`
    - `supportsUUIDs`
    - `supportsJSON`
    - `supportsDates`
    - `supportsBooleans`
    - `supportsArrays`
    - `usePlural`
    - `transaction`
    - `debugLogs`
    - `disableIdGeneration`
    - `customIdGenerator`
    - `mapKeysTransformInput`
    - `mapKeysTransformOutput`
    - `customTransformInput`
      - `data`
      - `field`
      - `fieldAttributes`
      - `action`
      - `model`
      - `schema`
      - `options`
    - `customTransformOutput`
    - `disableTransformInput`
    - `disableTransformOutput`
    - `disableTransformJoin`

## Database adapter operations

- Database adapter operations — *not applicable: JavaScript DBAdapter interface; Go stores expose typed methods (plainauth.Store and per-feature interfaces), not generic model/where operations (docs/databases.md)*
  - `id`
  - `create`
  - `findOne`
  - `findMany`
  - `count`
  - `update`
  - `updateMany`
  - `delete`
  - `deleteMany`
  - `consumeOne`
  - `incrementOne`
  - `transaction`
  - `createSchema`
  - `options`

## Adapter capabilities and data representation

- [ ] Adapter capabilities and data representation
  - [ ] `usePlural`
  - [ ] `debugLogs`
  - `adapterName` — *not applicable: JavaScript adapter factory option; the other runtime uses the name only to prefix factory debug logs and errors, while a Go store is a concrete value passed as Options.Store that no factory names*
  - `adapterId` — *not applicable: JavaScript adapter factory option; the other runtime reads the id for telemetry, a memory-store misconfiguration warning, CLI generator selection and schema-check messages, while Go stores are concrete types with no adapter registry or telemetry and authctl takes --dialect*
  - [ ] `supportsNumericIds`
  - [ ] `supportsUUIDs`
  - [ ] `supportsJSON`
    - [x] Keep JSON string, boolean, number, object, empty-array and null values of an organization role field intact on SQLite text, PostgreSQL jsonb and MySQL json columns ([test](../../adapters/sqlstore/organization_role_fields_test.go#L192))
  - [x] `supportsDates` ([test](../../adapters/sqlstore/date_fields_test.go#L17))
    - [x] Store date fields at UTC millisecond precision and read them back as ISO strings on memory, SQLite, PostgreSQL and MySQL ([test](../../adapters/sqlstore/date_fields_test.go#L17))
    - [x] Write user and session date fields through either runtime on one shared SQLite database, then read the same ISO instants through the other runtime and from the stored column ([test](../../conformance/date-fields.mjs#L5))
  - [ ] `supportsBooleans`
    - [x] Set a boolean session field to false through either runtime on a SQLite database both runtimes share, find 0 in the stored row, and read it back as false ([test](../../conformance/session-fields.mjs#L75))
    - [x] Read a migrated boolean user column backfilled with false as a Go false on SQLite, PostgreSQL and MySQL ([test](../../cmd/authctl/user_fields_test.go#L165))
  - [ ] `supportsArrays`
    - [x] Return string[] and number[] organization role fields as typed arrays from SQLite text, PostgreSQL jsonb and MySQL json columns, and reject mistyped elements ([test](../../adapters/sqlstore/organization_role_fields_test.go#L143))
  - [ ] `transaction`
    - [x] Roll back a registration whose initial session insert fails, leaving no user, on SQLite, PostgreSQL and MySQL ([test](../../adapters/sqlstore/engines_test.go#L77))
    - [x] Roll back an email-code sign-up whose required session field is missing, then succeed on retry, on memory, SQLite, PostgreSQL and MySQL ([test](../../adapters/sqlstore/emailotp_user_fields_test.go#L191))
  - [ ] `disableIdGeneration`
  - `mapKeysTransformInput` — *not applicable: JavaScript database adapter option; Go stores write each field to its own column or document key in typed code*
  - `mapKeysTransformOutput` — *not applicable: JavaScript database adapter option; Go stores scan rows straight into typed values*
  - `customTransformInput` — *not applicable: JavaScript database adapter option; it hooks the generic adapter pipeline, which Go stores do not have*
  - `customTransformOutput` — *not applicable: JavaScript database adapter option; it hooks the generic adapter pipeline, which Go stores do not have*
  - [ ] `customIdGenerator`
  - `disableTransformOutput` — *not applicable: JavaScript database adapter option; it switches off the generic adapter pipeline, which Go stores do not have*
  - `disableTransformInput` — *not applicable: JavaScript database adapter option; it switches off the generic adapter pipeline, which Go stores do not have*
  - `disableTransformJoin` — *not applicable: JavaScript database adapter option; Go stores write their own SQL joins and have no generic join pipeline*

## Secondary storage operations

- [ ] Secondary storage operations
  - [x] `get` ([test](../../adapters/redis/storage_test.go#L116))
    - [x] Distinguish a missing key from a stored empty string ([test](../../adapters/redis/storage_test.go#L116))
  - [x] `getAndDelete` ([test](../../adapters/redis/storage_test.go#L221))
    - [x] Allow one successful claim across simultaneous clients with GETDEL and the Lua fallback ([test](../../adapters/redis/storage_test.go#L221))
  - [x] `increment` ([test](../../adapters/redis/storage_test.go#L144))
    - [x] Increment atomically and preserve the TTL from creation ([test](../../adapters/redis/storage_test.go#L144))
  - [x] `set` ([test](../../adapters/redis/storage_test.go#L409))
    - [x] Replace a value and its expiry and remove an expired string ([test](../../adapters/redis/storage_test.go#L409))
  - [x] `delete` ([test](../../adapters/redis/storage_test.go#L129))
    - [x] Delete present and absent keys idempotently ([test](../../adapters/redis/storage_test.go#L129))

## Redis storage configuration

- [ ] Redis storage configuration
  - [x] `client` ([test](../../adapters/redis/storage_test.go#L341))
    - [x] Share one rate-limit budget across two handlers with separate client connections ([test](../../adapters/redis/storage_test.go#L341))
  - [x] `keyPrefix` ([test](../../adapters/redis/storage_test.go#L374))
    - [x] Apply a default namespace or explicitly scope a prefix with Redis glob characters ([test](../../adapters/redis/storage_test.go#L374))

## Redis-backed operations

- [ ] Redis-backed operations
  - [x] `clear` ([test](../../adapters/redis/storage_test.go#L295))
    - [x] Resume a partially failed prefix-scoped clear while preserving neighboring data ([test](../../adapters/redis/storage_test.go#L295))
  - [x] `delete` ([test](../../adapters/redis/storage_test.go#L129))
    - [x] Delete present and absent keys idempotently ([test](../../adapters/redis/storage_test.go#L129))
  - [x] `get` ([test](../../adapters/redis/storage_test.go#L116))
    - [x] Distinguish a missing key from a stored empty string ([test](../../adapters/redis/storage_test.go#L116))
  - [x] `getAndDelete` ([test](../../adapters/redis/storage_test.go#L221))
    - [x] Allow one successful claim across simultaneous clients with GETDEL and the Lua fallback ([test](../../adapters/redis/storage_test.go#L221))
  - [x] `increment` ([test](../../adapters/redis/storage_test.go#L144))
    - [x] Increment atomically and preserve the TTL from creation ([test](../../adapters/redis/storage_test.go#L144))
  - [x] `listKeys` ([test](../../adapters/redis/storage_test.go#L278))
    - [x] Deduplicate paged SCAN results and strip a literal prefix containing glob metacharacters ([test](../../adapters/redis/storage_test.go#L278))
  - [x] `set` ([test](../../adapters/redis/storage_test.go#L409))
    - [x] Replace a value and its expiry and remove an expired string ([test](../../adapters/redis/storage_test.go#L409))

## SQL dialect integrations

Plain Auth ships SQL adapters for SQLite, PostgreSQL and MySQL. The checklist also tracks additional database drivers and runtimes.

- [ ] Core Dialects
  - [x] MySQL ([test](../../adapters/sqlstore/engines_test.go#L24))
    - [x] Run the account and session lifecycle against MySQL ([test](../../adapters/sqlstore/account_contract_test.go#L15))
    - [x] Run the user, credential and session store contract against MySQL, including reopening a populated schema ([test](../../adapters/sqlstore/engines_test.go#L24))
    - [x] Generate, migrate and check a MySQL schema with authctl, then sign up against the migrated database ([test](../../cmd/authctl/user_fields_test.go#L67))
    - [x] Compare the core MySQL tables that Open migrates with a fresh install of the other runtime's pinned SQL ([test](../../adapters/sqlstore/schema_test.go#L18))
  - [x] SQLite ([test](../../adapters/sqlstore/engines_test.go#L24))
    - [x] Run the account and session lifecycle against SQLite ([test](../../adapters/sqlstore/account_contract_test.go#L15))
    - [x] Run the user, credential and session store contract against SQLite, including reopening a populated schema ([test](../../adapters/sqlstore/engines_test.go#L24))
    - [x] Generate SQL for every dialect and migrate a SQLite file twice with authctl ([test](../../cmd/authctl/main_test.go#L14))
    - [x] Generate, migrate and check a SQLite schema with authctl, then sign up against the migrated database ([test](../../cmd/authctl/user_fields_test.go#L67))
  - [x] PostgreSQL ([test](../../adapters/sqlstore/engines_test.go#L24))
    - [x] Run the account and session lifecycle against PostgreSQL ([test](../../adapters/sqlstore/account_contract_test.go#L15))
    - [x] Run the user, credential and session store contract against PostgreSQL, including reopening a populated schema ([test](../../adapters/sqlstore/engines_test.go#L24))
    - [x] Generate, migrate and check a PostgreSQL schema with authctl, then sign up against the migrated database ([test](../../cmd/authctl/user_fields_test.go#L67))
    - [x] Compare the core PostgreSQL tables that Open migrates with a fresh install of the other runtime's pinned SQL ([test](../../adapters/sqlstore/schema_test.go#L18))
  - [ ] MS SQL
- [ ] Kysely Organization Dialects
  - Postgres.js — *not applicable: JavaScript only*
  - [ ] SingleStore Data API (backlog)
  - Supabase — *uses the PostgreSQL adapter*
- [ ] Kysely Community dialects
  - PlanetScale Serverless Driver — *uses the MySQL adapter*
  - Cloudflare D1 — *not applicable: JavaScript only*
  - [ ] AWS RDS Data API (backlog)
  - Prisma Postgres — *uses the PostgreSQL adapter*
  - [ ] SurrealDB (backlog)
  - Neon — *uses the PostgreSQL adapter*
  - [ ] Xata (backlog)
  - AWS S3 Select (backlog) — *not applicable: S3 Select only runs SELECT queries over stored objects, so it cannot write auth data*
  - [ ] libSQL/sqld (backlog)
  - Fetch driver — *not applicable: JavaScript only*
  - SQLite WASM — *not applicable: JavaScript only*
  - Deno SQLite — *not applicable: JavaScript only*
  - TiDB Cloud Serverless Driver — *uses the MySQL adapter*
  - Capacitor SQLite Kysely — *not applicable: JavaScript only*
  - [ ] BigQuery (backlog)
  - [ ] Clickhouse (backlog)
  - PGLite — *not applicable: JavaScript only*

## Community database adapters

This is on the backlog: it stays on the roadmap but is not scheduled.

Each row tracks Go compatibility with a database integration. Maintainer names distinguish projects for the same database. The [source catalog](../../conformance/reference.json) records their repositories.

- Convex (get-convex) — *not applicable: JavaScript only; it runs the auth server inside Convex's JavaScript runtime, and scope.json already treats the Convex Integration as a JavaScript framework*
- [ ] SurrealDB (oskar-gmerek)
- [ ] SurrealDB (Necmttn)
- [ ] SurrealDB (msanchezdev)
- Payload CMS (payload-auth) — *not applicable: JavaScript only; it is a plugin for the Node.js Payload CMS*
- Payload CMS (delmaredigital) — *not applicable: JavaScript only; it is a plugin for the Node.js Payload CMS*
- TypeORM (Zastinian) — *not applicable: JavaScript only*
- [ ] InstantDB (daveyplate)
- Remult (nerdfolio) — *not applicable: JavaScript only; Remult is a TypeScript ORM*
- [ ] PocketBase (LightInn)
- [ ] Firebase Firestore (yultyyev)
- ZenStack (zenstackhq) — *not applicable: JavaScript only; ZenStack is a TypeScript ORM toolkit*
- Strapi CMS (strapi-community) — *not applicable: JavaScript only; it is a plugin for the Node.js Strapi CMS*
- [ ] Neo4j (florianamette)
- MikroORM (lubiah) — *not applicable: JavaScript only; MikroORM is a TypeScript ORM*
- MikroORM (octet-stream) — *not applicable: JavaScript only; MikroORM is a TypeScript ORM*
- [ ] FileMaker OData (proofsh)
- [ ] DynamoDB (datar-platform)
- [ ] DynamoDB (bjorntech)
- [ ] Azure Cosmos DB (9hsein5)
- Mongoose (AshwinSathian) — *not applicable: JavaScript only; Mongoose is a Node.js ODM, and MongoDB itself is covered by the planned MongoDB adapter*
- Bun SQL (ilbertt) — *not applicable: JavaScript runtime; Bun SQL is the Bun runtime's built-in SQL client*
- MikroORM (a77ay) — *not applicable: JavaScript only; MikroORM is a TypeScript ORM*
- [ ] ArcadeDB (DevSnap)
- TypeSQL (ismailkarsli) — *not applicable: JavaScript only; TypeSQL is a TypeScript library for typed raw SQL on PostgreSQL, SQLite and MySQL (confirmed from its repository), and Go reaches those databases through the SQL stores*
