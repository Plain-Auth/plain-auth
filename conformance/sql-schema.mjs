// Reproduce the pinned Better Auth CLI's SQL for a fresh database.
import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { getMigrations } from "better-auth/db/migration";
import {
  Kysely, DummyDriver, MysqlDialect, PostgresDialect, SqliteDialect,
} from "kysely";

const dialects = { sqlite: SqliteDialect, postgres: PostgresDialect, mysql: MysqlDialect };
for (const [type, Dialect] of Object.entries(dialects)) {
  const dialect = new Dialect({});
  // Only introspection executes. An empty driver returns the empty catalog,
  // while the official dialect retains its real compiler and type mapping.
  dialect.createDriver = () => new DummyDriver();
  const db = new Kysely({ dialect });
  const migration = await getMigrations({ database: { db, type }, logger: { disabled: true } });
  const sql = (await migration.compileMigrations()).trim() + "\n";
  const dest = new URL(`../adapters/sqlstore/schema/${type}.sql`, import.meta.url);
  if (process.argv.includes("--write")) await writeFile(dest, sql);
  else assert.equal(await readFile(dest, "utf8"), sql, type);
  await db.destroy();
}
