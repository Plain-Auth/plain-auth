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
import { verifiedCombinations, ssoCombinations, ssoDomainCombinations, scimCombinations, managedSCIMCombinations, organizationBillingCombinations, dialects, freshSchema, schemaOptions } from "./plugin-schema.mjs";

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

test("the CLI emits the pinned plugin schema across exhaustive base combinations and SCIM and organization billing witnesses on three dialects", async () => {
  const dir = mkdtempSync(join(tmpdir(), "auth-schema-plugin-cli-"));
  try {
    const binary = join(dir, "authctl");
    execFileSync("go", ["build", "-o", binary, "./cmd/authctl"], { cwd: root, timeout: 180000 });
    const batch = batchFixture(dir);
    try {
      for (const type of Object.keys(dialects)) {
        for (const profiles of verifiedCombinations()) {
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
      for (const profiles of verifiedCombinations()) {
        if (!profiles.length) continue;
        copyFileSync(seed, database);
        if (profiles.length === 1) {
          execFileSync(binary, ["migrate", "--dialect", "sqlite", "--plugins", profiles[0]], { env: { ...process.env, AUTH_DSN: database } });
        }
        await batch.call("sqlite", profiles, "candidate.db");
        if (profiles.includes("scim") || profiles.includes("scim-managed") || profiles.includes("sso") || profiles.includes("sso-domain-verification")) await batch.call("sqlite", profiles, "candidate.db");
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

test("SCIM adds seven independent tables and leaves each existing schema object intact", async () => {
  const tables = ["scimConnectionBinding", "scimGroup", "scimGroupMember", "scimIdentityTombstone", "scimProjectionGrant", "scimSubject", "scimUser"];
  const statements = sql => sql.trim().split(/;\s*\n\s*\n/).map(s => s.replace(/;$/, ""));
  for (const type of Object.keys(dialects)) {
    const core = new Set(statements(await freshSchema(type, [])));
    const additions = statements(await freshSchema(type, ["scim"])).filter(s => !core.has(s));
    const tableNames = additions.flatMap(sql => /^create table ["`]([^"`]+)["`]/.exec(sql)?.slice(1) ?? []);
    assert.deepEqual(tableNames.sort(), tables, type);
    for (const statement of additions) {
      assert.ok(tables.some(name => new RegExp('^(?:create table|create (?:unique )?index .+ on) ["`]' + name + '["`]').test(statement)),
        "SCIM contributed an object outside its seven tables");
    }
    for (const selected of scimCombinations()) {
      const baseline = statements(await freshSchema(type, selected.filter(name => name !== "scim")));
      const combined = statements(await freshSchema(type, selected));
      assert.deepEqual(new Set(combined), new Set([...baseline, ...additions]), "SCIM changed baseline DDL for " + selected.join(","));
      assert.deepEqual(combined.filter(s => !additions.includes(s)), baseline, "SCIM changed baseline SQL ordering");
    }
  }
});

test("organization billing adds the organization customer column and preserves the organization and subscription tables", async () => {
  const dir = mkdtempSync(join(tmpdir(), "auth-org-billing-schema-"));
  const fixture = batchFixture(dir);
  try {
    for (const dialect of Object.keys(dialects)) {
      const ordinary = await freshSchema(dialect, ["organization", "stripe-subscriptions"]);
      const combined = await freshSchema(dialect, ["stripe-organization"]);
      const table = /create table ["`]organization["`] \([^;]*?\);/;
      const extra = combined.match(table)?.[0];
      const symbol = dialect === "mysql" ? "`" : '"';
      const field = ", " + symbol + "stripeCustomerId" + symbol + " text";
      assert.ok(extra?.includes(field), dialect);
      assert.equal(combined.replace(extra, extra.replace(field, "")), ordinary);
      for (const profiles of organizationBillingCombinations()) {
        assert.equal((await fixture.call(dialect, profiles)).trim(), (await freshSchema(dialect, profiles)).trim(), profiles.join(","));
      }
    }
  } finally { await fixture.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("SCIM managed credentials add three independent catalog tables while preserving directory data", async () => {
  const tables = ["scimManagedConnection", "scimManagedConnectionEvent", "scimManagedCredential"];
  const statements = sql => sql.trim().split(/;\s*\n\s*\n/).map(s => s.replace(/;$/, ""));
  const witnesses = [...managedSCIMCombinations()];
  assert.equal(witnesses.length, 26);
  for (const dialect of Object.keys(dialects)) {
    const original = new Set(statements(await freshSchema(dialect, ["scim"])));
    const additions = statements(await freshSchema(dialect, ["scim-managed"])).filter(s => !original.has(s));
    const tableNames = additions.flatMap(s => /^create table ["`]([^"`]+)["`]/.exec(s)?.slice(1) ?? []);
    assert.deepEqual(tableNames.sort(), tables);
    for (const statement of additions) {
      const owner = /^(?:create table|create (?:unique )?index .+ on) ["`]([^"`]+)["`]/.exec(statement)?.[1];
      assert.ok(tables.includes(owner), statement);
    }
    for (const profiles of witnesses) {
      const baseline = [...profiles.filter(p => p !== "scim" && p !== "scim-managed"), "scim"];
      const base = statements(await freshSchema(dialect, baseline));
      const combined = statements(await freshSchema(dialect, profiles));
      assert.deepEqual(new Set(combined), new Set([...base, ...additions]), dialect + " / " + profiles.join(","));
      assert.deepEqual(combined.filter(s => !additions.includes(s)), base);
    }
  }
});

test("enterprise OIDC registration adds only the canonical provider table to each SSO sample", async () => {
  const statements = sql => sql.trim().split(/;\s*\n\s*\n/).map(s => s.replace(/;$/, ""));
  for (const dialect of Object.keys(dialects)) {
    const original = new Set(statements(await freshSchema(dialect, [])));
    const additions = statements(await freshSchema(dialect, ["sso"])).filter(s => !original.has(s));
    assert.equal(additions.filter(s => /^create table ["`]ssoProvider["`]/.test(s)).length, 1);
    for (const statement of additions) {
      assert.match(statement, /^(?:create table|create (?:unique )?index .+ on) ["`]ssoProvider["`]/);
    }
    for (const profiles of ssoCombinations()) {
      const combined = statements(await freshSchema(dialect, profiles));
      const base = statements(await freshSchema(dialect, profiles.filter(id => id !== "sso")));
      assert.deepEqual(new Set(combined), new Set([...base, ...additions]), dialect + " / " + profiles.join(","));
      assert.deepEqual(combined.filter(s => !additions.includes(s)), base);
    }
  }
});

test("enterprise DNS verification extends only the canonical provider flag across schema samples", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sso-domain-schema-"));
  const batch = batchFixture(dir);
  try {
    let n = 0;
    for (const group of ssoDomainCombinations()) {
      const base = [...group.filter(id => id !== "sso-domain-verification" && id !== "sso"), "sso"];
      for (const dialect of Object.keys(dialects)) {
        const before = await freshSchema(dialect, base);
        const after = await freshSchema(dialect, group);
        const flag = /, ["`]domainVerified["`] (?:boolean|integer|tinyint)(?:\(1\))?/gi;
        assert.equal((after.match(flag) ?? []).length, 1, dialect+" "+group);
        assert.equal(after.replace(flag, ""), before, dialect+" "+group);
        assert.equal(await batch.call(dialect,group), after, dialect+" "+group);
      }
      const filename = "upgraded-"+(n++)+".db";
      await batch.call("sqlite",base,filename);
      const path = join(dir,filename);
      const existing = new DatabaseSync(path);
      existing.exec("INSERT INTO user(id,name,email,emailVerified,createdAt,updatedAt) VALUES ('owner','Owner','owner@example.test',0,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)");
      existing.exec("INSERT INTO ssoProvider(id,providerId,issuer,domain,userId) VALUES ('old','old','https://idp.example','domain.example','owner')");
      existing.close();
      await batch.call("sqlite",group,filename);
      const upgraded = new DatabaseSync(path,{readOnly:true});
      const reference = new DatabaseSync(":memory:");
      try {
        await (await getMigrations({database:reference,...schemaOptions(group)})).runMigrations();
        assert.deepEqual(sqliteSchema(upgraded),sqliteSchema(reference),group.join(","));
        assert.deepEqual({...upgraded.prepare("SELECT domain,domainVerified FROM ssoProvider WHERE id='old'").get()},
          {domain:"domain.example",domainVerified:null});
      } finally { reference.close(); upgraded.close(); }
    }
  } finally {
    await batch.close();
    rmSync(dir,{recursive:true,force:true});
  }
});
