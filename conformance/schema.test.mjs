import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { copyFileSync, mkdtempSync, rmSync } from "node:fs";
import { createInterface } from "node:readline";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { getMigrations } from "better-auth/db/migration";
import { combinations, dialects, freshSchema, schemaOptions } from "./plugin-schema.mjs";

const root = fileURLToPath(new URL("../", import.meta.url));

function sqliteSchema(db) {
  const tables = db.prepare(`
    SELECT name, type, ncol, wr, strict FROM pragma_table_list
    WHERE schema='main' AND name NOT LIKE 'sqlite_%' ORDER BY name
  `).all();
  const indexes = db.prepare(`
    SELECT name, "unique", origin, partial FROM pragma_index_list(?) ORDER BY name
  `);
  const indexParts = db.prepare('SELECT seqno, cid, name, "desc", coll, "key" FROM pragma_index_xinfo(?) ORDER BY seqno');
  const fields = db.prepare('SELECT cid, name, UPPER(type) AS type, "notnull", dflt_value, pk, hidden FROM pragma_table_xinfo(?) ORDER BY cid');
  const foreignKeys = db.prepare('SELECT * FROM pragma_foreign_key_list(?) ORDER BY id, seq');
  return {
    tables: tables.map((table) => ({
      ...table,
      columns: fields.all(table.name),
      indexes: indexes.all(table.name).map((index) => ({ ...index, columns: indexParts.all(index.name) })),
      foreignKeys: foreignKeys.all(table.name),
    })),
    viewsAndTriggers: db.prepare("SELECT type, name, sql FROM sqlite_schema WHERE type IN ('view','trigger') ORDER BY type, name").all(),
  };
}

test("fresh and repeated Go SQLite migrations produce the upstream default schema", async () => {
  const dir = mkdtempSync(join(tmpdir(), "stonewrit-auth-schema-"));
  const reference = new DatabaseSync(":memory:");
  try {
    const options = { database: reference, baseURL: "http://localhost", secret: "conformance-only-secret-0123456789-abcdefgh" };
    await (await getMigrations(options)).runMigrations();
    const expected = sqliteSchema(reference);
    const database = join(dir, "go.sqlite");
    const binary = join(dir, "authctl");
    execFileSync("go", ["build", "-o", binary, "./cmd/authctl"], { cwd: root, timeout: 180000 });
    for (const stage of ["fresh", "repeat"]) {
      execFileSync(binary, ["migrate", "--dialect", "sqlite"], {
        env: { ...process.env, AUTH_DSN: database }, timeout: 30000,
      });
      const db = new DatabaseSync(database, { readOnly: true });
      try {
        const actual = sqliteSchema(db);
        assert.deepEqual(actual.tables.map((t) => t.name), expected.tables.map((t) => t.name), stage + " table names");
        assert.deepEqual(actual, expected, stage + " schema structure");
      } finally {
        db.close();
      }
    }
  } finally {
    reference.close();
    rmSync(dir, { recursive: true, force: true });
  }
});


// All profile combinations use the same Go generator and live migration API.
// Reuse one process per test and run individual selectors through the public CLI.
function batchFixture(dir) {
  const binary = join(dir, "schemafixture");
  execFileSync("go", ["build", "-o", binary, "./conformance/schemafixture"], { cwd: root, timeout: 180000 });
  const child = spawn(binary, [], { cwd: dir, stdio: ["pipe", "pipe", "inherit"] });
  const lines = createInterface({ input: child.stdout })[Symbol.asyncIterator]();
  const done = new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code) => code === 0 ? resolve() : reject(new Error("schemafixture exited " + code)));
  });
  // A failed fixture can exit while the client waits for a data line.
  done.catch(() => {});
  return {
    async call(dialect, profiles, path) {
      child.stdin.write(JSON.stringify({ dialect, profiles, path }) + "\n");
      const row = await lines.next();
      assert.equal(row.done, false, "schemafixture closed before replying");
      return JSON.parse(row.value);
    },
    async close() { child.stdin.end(); await done; },
  };
}

// SQLite uses an implicit index for a fresh inline UNIQUE constraint. Its
// ALTER TABLE grammar requires an explicitly named index on an added column.
function normalizeAdditiveIndexes(structure) {
  const user = structure.tables.find((t) => t.name === "user");
  if (user) for (const index of user.indexes) {
    const keys = index.columns.filter((column) => column.key);
    if (index.unique === 1 && index.partial === 0 && keys.length === 1 && ["username", "phoneNumber"].includes(keys[0].name)) {
      index.name = "user." + keys[0].name + " UNIQUE";
      index.origin = "unique";
    }
  }
  if (user) user.indexes.sort((a,b)=>a.name.localeCompare(b.name,"en"));
  return structure;
}

test("the CLI emits the pinned plugin schema for every supported preset and SQL dialect", async () => {
  const dir = mkdtempSync(join(tmpdir(), "auth-schema-plugin-cli-"));
  try {
    const binary = join(dir, "authctl");
    execFileSync("go", ["build", "-o", binary, "./cmd/authctl"], { cwd: root, timeout: 180000 });
    const batch = batchFixture(dir);
    try {
      for (const type of Object.keys(dialects)) {
        for (const profiles of combinations()) {
          const output = await batch.call(type, profiles);
          assert.equal(output.trim(), (await freshSchema(type, profiles)).trim(), type + " / " + profiles.join(","));
          if (profiles.length <= 1) {
            const flags = profiles.length ? ["--plugins", profiles[0]] : [];
            assert.equal(execFileSync(binary, ["generate", "--dialect", type, ...flags], { encoding: "utf8" }), output);
          }
        }
      }
    } finally { await batch.close(); }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("adding plugin profiles to a populated SQLite database preserves existing accounts and matches a fresh schema", async () => {
  const dir = mkdtempSync(join(tmpdir(), "auth-schema-plugin-upgrade-"));
  try {
    const binary = join(dir, "authctl");
    execFileSync("go", ["build", "-o", binary, "./cmd/authctl"], { cwd: root, timeout: 180000 });
    const seed = join(dir, "seed.db"), database = join(dir, "candidate.db");
    execFileSync(binary, ["migrate", "--dialect", "sqlite"], { env: { ...process.env, AUTH_DSN: seed } });
    const seeded = new DatabaseSync(seed);
    try {
      seeded.prepare('INSERT INTO "user" ("id","name","email","emailVerified","createdAt","updatedAt") VALUES (?,?,?,?,?,?)')
        .run("existing", "Existing Profile", "person@example.test", 0, "2026-01-01", "2026-01-01");
    } finally { seeded.close(); }
    const batch = batchFixture(dir);
    try {
      for (const profiles of combinations()) {
        if (!profiles.length) continue;
        copyFileSync(seed, database);
        if (profiles.length === 1) {
          execFileSync(binary, ["migrate", "--dialect", "sqlite", "--plugins", profiles[0]], { env: { ...process.env, AUTH_DSN: database } });
        }
        await batch.call("sqlite", profiles, "candidate.db");
        const db = new DatabaseSync(database, { readOnly: true });
        const reference = new DatabaseSync(":memory:");
        try {
          const options = { database: reference, ...schemaOptions(profiles) };
          await (await getMigrations(options)).runMigrations();
          assert.deepEqual(normalizeAdditiveIndexes(sqliteSchema(db)), normalizeAdditiveIndexes(sqliteSchema(reference)), profiles.join(","));
          assert.equal(db.prepare('SELECT email FROM "user" WHERE id=?').get("existing").email, "person@example.test");
        } finally {
          db.close();
          reference.close();
        }
      }
    } finally { await batch.close(); }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
