# Database adapters

[Feature index](README.md)

## Community Adapters

- [ ] Community Adapters
  - [ ] Create Your Own Adapter
  - [ ] Browse Community Adapters

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
  - [ ] Joins

## MS SQL

- [ ] MS SQL
  - [ ] Schema generation & migration
  - [ ] Joins

## MySQL

- [ ] MySQL
  - [ ] Schema generation & migration
  - [ ] Joins

## Other Relational Databases

- [ ] Other Relational Databases
  - [ ] Core Dialects
  - Kysely Organization Dialects — *not applicable: JavaScript only; each database is listed under SQL dialect integrations*
  - Kysely Community dialects — *not applicable: JavaScript only; each database is listed under SQL dialect integrations*

## PostgreSQL

- [ ] PostgreSQL
  - [ ] Schema generation & migration
  - [ ] Joins
  - [ ] Use a non-default schema
    - [ ] Set `database.schemaName`
    - [ ] Set `search_path`

## Prisma

- Prisma — *not applicable: JavaScript only*
  - Setup
    - Configure Prisma
    - Create the Prisma client
    - Configure authentication
  - Schema generation & migration
  - Joins

## SQLite

- [ ] SQLite
  - [ ] Schema generation & migration
    - [x] Roll back a failed initialization atomically ([test](../../adapters/sqlstore/sqlite_test.go#L49))
  - [ ] Joins

## Create a Database Adapter

- [ ] Create a Database Adapter
  - [ ] Adapter
    - [ ] `options`
    - [ ] `schema`
    - [ ] `debugLog`
    - [ ] `getModelName`
    - [ ] `getFieldName`
    - [ ] `getDefaultModelName`
    - [ ] `getDefaultFieldName`
    - [ ] `getFieldAttributes`
    - [ ] `transformInput`
    - [ ] `transformOutput`
    - [ ] `transformWhereClause`
    - [ ] Adapter Methods
    - [ ] `create` method
      - [ ] `model`
      - [ ] `data`
      - [ ] `select`
    - [ ] `update` method
      - [ ] `model`
      - [ ] `where`
      - [ ] `update`
    - [ ] `updateMany` method
      - [ ] `model`
      - [ ] `where`
      - [ ] `update`
    - [ ] `delete` method
      - [ ] `model`
      - [ ] `where`
    - [ ] `deleteMany` method
      - [ ] `model`
      - [ ] `where`
    - [ ] `consumeOne` method
      - [ ] `model`
      - [ ] `where`
    - [ ] `incrementOne` method
      - [ ] `model`
      - [ ] `where`
      - [ ] `increment`
      - [ ] `set`
    - [ ] `findOne` method
      - [ ] `model`
      - [ ] `where`
      - [ ] `select`
      - [ ] `join`
    - [ ] `findMany` method
      - [ ] `model`
      - [ ] `where`
      - [ ] `limit`
      - [ ] `select`
      - [ ] `sortBy`
      - [ ] `offset`
      - [ ] `join`
    - [ ] `count` method
      - [ ] `model`
      - [ ] `where`
    - [ ] `options` (optional)
    - [ ] `createSchema` (optional)
      - [ ] `tables`
      - [ ] `file`
  - [ ] Test your adapter
  - [ ] Config
    - [ ] Required Config
    - [ ] `adapterId`
    - [ ] `adapterName`
    - [ ] Optional Config
    - [ ] `supportsNumericIds`
    - [ ] `supportsUUIDs`
    - [ ] `supportsJSON`
    - [ ] `supportsDates`
    - [ ] `supportsBooleans`
    - [ ] `supportsArrays`
    - [ ] `usePlural`
    - [ ] `transaction`
    - [ ] `debugLogs`
    - [ ] `disableIdGeneration`
    - [ ] `customIdGenerator`
    - [ ] `mapKeysTransformInput`
    - [ ] `mapKeysTransformOutput`
    - [ ] `customTransformInput`
      - [ ] `data`
      - [ ] `field`
      - [ ] `fieldAttributes`
      - [ ] `action`
      - [ ] `model`
      - [ ] `schema`
      - [ ] `options`
    - [ ] `customTransformOutput`
    - [ ] `disableTransformInput`
    - [ ] `disableTransformOutput`
    - [ ] `disableTransformJoin`

## Database adapter operations

- [ ] Database adapter operations
  - [ ] `id`
  - [ ] `create`
  - [ ] `findOne`
  - [ ] `findMany`
  - [ ] `count`
  - [ ] `update`
  - [ ] `updateMany`
  - [ ] `delete`
  - [ ] `deleteMany`
  - [ ] `consumeOne`
  - [ ] `incrementOne`
  - [ ] `transaction`
  - [ ] `createSchema`
  - [ ] `options`

## Adapter capabilities and data representation

- [ ] Adapter capabilities and data representation
  - [ ] `usePlural`
  - [ ] `debugLogs`
  - [ ] `adapterName`
  - [ ] `adapterId`
  - [ ] `supportsNumericIds`
  - [ ] `supportsUUIDs`
  - [ ] `supportsJSON`
  - [ ] `supportsDates`
  - [ ] `supportsBooleans`
  - [ ] `supportsArrays`
  - [ ] `transaction`
  - [ ] `disableIdGeneration`
  - [ ] `mapKeysTransformInput`
  - [ ] `mapKeysTransformOutput`
  - [ ] `customTransformInput`
  - [ ] `customTransformOutput`
  - [ ] `customIdGenerator`
  - [ ] `disableTransformOutput`
  - [ ] `disableTransformInput`
  - [ ] `disableTransformJoin`

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
  - [ ] MySQL
    - [x] Run the account and session lifecycle against MySQL ([test](../../adapters/sqlstore/account_contract_test.go#L15))
  - [ ] SQLite
    - [x] Run the account and session lifecycle against SQLite ([test](../../adapters/sqlstore/account_contract_test.go#L15))
  - [ ] PostgreSQL
    - [x] Run the account and session lifecycle against PostgreSQL ([test](../../adapters/sqlstore/account_contract_test.go#L15))
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
  - [ ] AWS S3 Select (backlog)
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

- [ ] Convex (get-convex)
- [ ] SurrealDB (oskar-gmerek)
- [ ] SurrealDB (Necmttn)
- [ ] SurrealDB (msanchezdev)
- [ ] Payload CMS (payload-auth)
- [ ] Payload CMS (delmaredigital)
- TypeORM (Zastinian) — *not applicable: JavaScript only*
- [ ] InstantDB (daveyplate)
- [ ] Remult (nerdfolio)
- [ ] PocketBase (LightInn)
- [ ] Firebase Firestore (yultyyev)
- [ ] ZenStack (zenstackhq)
- [ ] Strapi CMS (strapi-community)
- [ ] Neo4j (florianamette)
- [ ] MikroORM (lubiah)
- [ ] MikroORM (octet-stream)
- [ ] FileMaker OData (proofsh)
- [ ] DynamoDB (datar-platform)
- [ ] DynamoDB (bjorntech)
- [ ] Azure Cosmos DB (9hsein5)
- [ ] Mongoose (AshwinSathian)
- [ ] Bun SQL (ilbertt)
- [ ] MikroORM (a77ay)
- [ ] ArcadeDB (DevSnap)
- [ ] TypeSQL (ismailkarsli)
