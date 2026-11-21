# Database adapters

[Feature index](README.md)

## Community Adapters

- [ ] Community Adapters
  - [ ] Create Your Own Adapter
  - [ ] Browse Community Adapters

## Drizzle ORM Adapter

- [ ] Drizzle ORM Adapter
  - [ ] Schema generation & migration
  - [ ] Joins
  - [ ] Modifying Table Names
  - [ ] Modifying Field Names
  - [ ] Date Columns
  - [ ] Using Plural Table Names
  - [ ] Custom Schema namespace
  - [ ] Drizzle Relations v2

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
  - [ ] Kysely Organization Dialects
  - [ ] Kysely Community dialects

## PostgreSQL

- [ ] PostgreSQL
  - [ ] Schema generation & migration
  - [ ] Joins
  - [ ] Use a non-default schema
    - [ ] Set `database.schemaName`
    - [ ] Set `search_path`

## Prisma

- [ ] Prisma
  - [ ] Setup
    - [ ] Configure Prisma
    - [ ] Create the Prisma client
    - [ ] Configure authentication
  - [ ] Schema generation & migration
  - [ ] Joins

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

Core dialects ship with the query builder. The organization and community lists identify separately maintained integrations.

- [ ] Core Dialects
  - [ ] MySQL
    - [x] Run the account and session lifecycle against MySQL ([test](../../adapters/sqlstore/account_contract_test.go#L15))
  - [ ] SQLite
    - [x] Run the account and session lifecycle against SQLite ([test](../../adapters/sqlstore/account_contract_test.go#L15))
  - [ ] PostgreSQL
    - [x] Run the account and session lifecycle against PostgreSQL ([test](../../adapters/sqlstore/account_contract_test.go#L15))
  - [ ] MS SQL
- [ ] Kysely Organization Dialects
  - [ ] Postgres.js
  - [ ] SingleStore Data API
  - [ ] Supabase
- [ ] Kysely Community dialects
  - [ ] PlanetScale Serverless Driver
  - [ ] Cloudflare D1
  - [ ] AWS RDS Data API
  - [ ] Prisma Postgres
  - [ ] SurrealDB
  - [ ] Neon
  - [ ] Xata
  - [ ] AWS S3 Select
  - [ ] libSQL/sqld
  - [ ] Fetch driver
  - [ ] SQLite WASM
  - [ ] Deno SQLite
  - [ ] TiDB Cloud Serverless Driver
  - [ ] Capacitor SQLite Kysely
  - [ ] BigQuery
  - [ ] Clickhouse
  - [ ] PGLite

## Community database adapters

These adapter projects have their own maintainers and releases.

- [ ] Convex integration from [get-convex](https://github.com/get-convex/better-auth)
- [ ] SurrealDB integration from [oskar-gmerek](https://github.com/oskar-gmerek/surreal-better-auth)
- [ ] SurrealDB integration from [Necmttn](https://github.com/Necmttn/surrealdb-better-auth)
- [ ] SurrealDB integration from [msanchezdev](https://github.com/msanchezdev/better-auth-surrealdb)
- [ ] Payload CMS integration from [payload-auth](https://github.com/payload-auth/payload-auth)
- [ ] Payload CMS integration from [delmaredigital](https://github.com/delmaredigital/payload-better-auth)
- [ ] TypeORM integration from [Zastinian](https://github.com/Zastinian/better-auth-typeorm)
- [ ] InstantDB integration from [daveyplate](https://github.com/daveyplate/better-auth-instantdb)
- [ ] Remult integration from [nerdfolio](https://github.com/nerdfolio/remult-better-auth)
- [ ] PocketBase integration from [LightInn](https://github.com/LightInn/pocketbase-better-auth)
- [ ] Firebase Firestore integration from [yultyyev](https://github.com/yultyyev/better-auth-firestore)
- [ ] ZenStack integration from [zenstackhq](https://github.com/zenstackhq/zenstack/tree/main/packages/auth-adapters/better-auth)
- [ ] Strapi CMS integration from [strapi-community](https://github.com/strapi-community/plugin-better-auth)
- [ ] Neo4j integration from [florianamette](https://github.com/florianamette/better-auth-neo4j)
- [ ] MikroORM integration from [lubiah](https://github.com/lubiah/better-auth-mikro-orm)
- [ ] MikroORM integration from [octet-stream](https://github.com/octet-stream/better-auth-mikro-orm)
- [ ] FileMaker OData integration from [proofsh](https://github.com/proofsh/proofkit/tree/main/packages/better-auth)
- [ ] DynamoDB integration from [datar-platform](https://github.com/datar-platform/better-auth-dynamodb)
- [ ] DynamoDB integration from [bjorntech](https://github.com/bjorntech/betterauth-dynamodb)
- [ ] Azure Cosmos DB integration from [9hsein5](https://github.com/9hsein5/better-auth-azure-cosmos)
- [ ] Mongoose integration from [AshwinSathian](https://github.com/AshwinSathian/better-auth-mongoose)
- [ ] Bun SQL integration from [ilbertt](https://github.com/ilbertt/better-auth-bun-sql)
- [ ] MikroORM integration from [a77ay](https://github.com/a77ay/better-auth-mikro-orm)
- [ ] ArcadeDB integration from [DevSnap](https://github.com/DevSnap/better-auth-arcadedb)
- [ ] TypeSQL integration from [ismailkarsli](https://github.com/ismailkarsli/TypeSQL/tree/main/packages/better-auth)
