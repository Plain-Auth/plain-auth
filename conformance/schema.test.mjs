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
import { oauthProviderCombinations, walletCombinations, verifiedCombinations, ssoCombinations, ssoDomainCombinations, scimCombinations, managedSCIMCombinations, organizationBillingCombinations, dialects, freshSchema, schemaOptions } from "./plugin-schema.mjs";

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
  const dir = mkdtempSync(join(tmpdir(), "plain-auth-schema-"));
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
    async call(dialect, profiles, path, wallet) {
      child.stdin.write(JSON.stringify({ dialect, profiles, path, wallet }) + "\n");
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

test("wallet registrations add the canonical address table and owner index on each dialect", async () => {
  const dir = mkdtempSync(join(tmpdir(), "auth-wallet-schema-"));
  const batch = batchFixture(dir);
  try {
    for (const dialect of Object.keys(dialects)) {
      for (const profiles of walletCombinations()) {
        const before = await freshSchema(dialect, profiles.filter(p => p !== "siwe"));
        const expected = await freshSchema(dialect, profiles);
        assert.equal((await batch.call(dialect, profiles)).trim(), expected.trim(), dialect + " " + profiles);
        const additions = expected.trim().split(/;\s*\n\s*\n/).filter(statement => !before.includes(statement.replace(/;$/, "")));
        assert.equal(additions.length, 2);
        assert.match(additions[0], /^create table ["`]walletAddress["`]/);
        assert.match(additions[1], /create index ["`]walletAddress_userId_idx["`]/);
      }
    }
  } finally {
    await batch.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("session transfer uses the canonical verification table on every SQL dialect", async () => {
  const { oneTimeToken } = await import("better-auth/plugins");
  for (const dialect of Object.keys(dialects)) {
    const baseline = await freshSchema(dialect, []);
    assert.match(baseline, /create table ["`]?verification/i);
    assert.equal(await freshSchema(dialect, [], [oneTimeToken()]), baseline);
  }
});


test("custom wallet model, columns and owner indexes match the three released SQL dialects", async t => {
  const { siwe } = await import("better-auth/plugins/siwe");
  const dir = mkdtempSync(join(tmpdir(), "plain-auth-wallet-mapping-"));
  const batch = batchFixture(dir);
  try {
    for (const [i, wallet] of [
      { Table: "wallet_address" },
      { UserID: "member_id", Address: "address", ChainID: "network" },
      { Table: "wallet_address", UserID: "user_id", Address: "wallet_address", ChainID: "chain_id", IsPrimary: "is_primary", CreatedAt: "created_at" },
      { Table: "long_" + "w".repeat(55), UserID: "owner_" + "u".repeat(50) },
    ].entries()) {
      const columns = { userId: wallet.UserID, address: wallet.Address, chainId: wallet.ChainID, isPrimary: wallet.IsPrimary, createdAt: wallet.CreatedAt };
      const plugin = siwe({ domain: "wallet.test", schema: { walletAddress: { modelName: wallet.Table, fields: columns } } });
      for (const dialect of Object.keys(dialects)) {
        const rendered = await batch.call(dialect, ["siwe"], undefined, wallet);
        const released = await freshSchema(dialect, [], [plugin]);
        assert.equal(rendered.trim(), released.trim(), dialect + " layout " + i);
      }
      const filename = "layout" + i + ".sqlite";
      await batch.call("sqlite", ["siwe"], filename, wallet);
      const actual = new DatabaseSync(join(dir,filename));
      const reference = new DatabaseSync(":memory:");
      try {
        await (await getMigrations({ database: reference, plugins: [plugin] })).runMigrations();
        assert.deepEqual(sqliteSchema(actual), sqliteSchema(reference));
      } finally { actual.close(); reference.close(); }
    }
  } finally { await batch.close(); rmSync(dir,{recursive:true,force:true}); }
});

// Recover the reference spelling of the new MySQL tables for a full column,
// key and index comparison. Only the declared MySQL differences are accepted.
function referenceMySQLConstraints(sql) {
  return sql.replace(/^create table `(oauth\w+|organizationRole)` \((.+)\);$/gm, (_, table, body) => {
    const columns = new Map();
    for (const part of body.split(", ")) {
      const key = /^constraint `\w+` foreign key \((`\w+`)\)( references .+)$/.exec(part);
      if (key) {
        assert.ok(columns.has(key[1]));
        columns.set(key[1], columns.get(key[1]) + key[2]);
        continue;
      }
      const name = part.split(" ")[0];
      let column = part.replace(" character set utf8mb4 collate utf8mb4_0900_bin", "");
      if ((name === "`clientId`" && table !== "oauthClient") || name === "`resourceId`") {
        assert.match(column, /varchar\(255\)/);
        column = column.replace("varchar(255)", table === "oauthClientResource" ? "varchar(191)" : "varchar(36)");
      }
      columns.set(name, column);
    }
    return "create table `" + table + "` (" + [...columns.values()].join(", ") + ");";
  });
}

test("OAuth provider schema preserves all seven models and composes with other profiles on three dialects", async t => {
  const dir = mkdtempSync(join(tmpdir(), "plain-auth-oauth-provider-schema-"));
  const batch = batchFixture(dir);
  t.after(async () => { await batch.close(); rmSync(dir, {recursive:true, force:true}); });
  const expectedTables = ["oauthAccessToken", "oauthClient", "oauthClientAssertion", "oauthClientResource", "oauthConsent", "oauthRefreshToken", "oauthResource"];
  for (const dialect of Object.keys(dialects)) {
    for (const profiles of oauthProviderCombinations()) {
      const baseline = await batch.call(dialect, profiles.filter(p => p !== "oauth-provider"));
      const generated = await batch.call(dialect, profiles);
      const statements = generated.trim().split("\n\n");
      const existing = new Set(baseline.trim().split("\n\n"));
      const additions = statements.filter(s => !existing.has(s));
      assert.deepEqual(additions.flatMap(s => /^create table ["`](\w+)["`]/.exec(s)?.slice(1) ?? []).sort(), expectedTables);
      assert.equal(statements.filter(s => !additions.includes(s)).join("\n\n") + "\n", baseline);
      const logical = dialect === "mysql" ? referenceMySQLConstraints(generated) : generated;
      assert.equal(logical, await freshSchema(dialect, profiles), dialect + " " + profiles.join(","));
    }
  }
});

test("organization role migrations preserve the organization schema and add its scoped grants and indexes on three dialects", async t => {
  const dir = mkdtempSync(join(tmpdir(), "plain-auth-role-schema-"));
  const batch = batchFixture(dir);
  t.after(async () => { await batch.close(); rmSync(dir, {recursive:true, force:true}); });
  for (const dialect of Object.keys(dialects)) {
    for (const base of [[], ["organization"], ["organization-teams"], ["admin","organization-teams","stripe-organization","oauth-provider"], ["organization","scim-managed","sso-domain-verification","siwe"]]) {
      const profiles = [...base,"organization-roles"];
      const before = await batch.call(dialect, base.length ? base : ["organization"]);
      const generated = await batch.call(dialect, profiles);
      const statements = generated.trim().split("\n\n");
      const extra = statements.filter(s => s.includes("organizationRole"));
      assert.equal(extra.length, 3);
      assert.match(extra[0], /^create table ["`]organizationRole["`]/);
      assert.match(extra[1], /organizationRole_organizationId_idx/);
      assert.match(extra[2], /organizationRole_role_idx/);
      assert.equal(statements.filter(s => !extra.includes(s)).join("\n\n") + "\n", before);
      const logical = dialect === "mysql" ? referenceMySQLConstraints(generated) : generated;
      assert.equal(logical, await freshSchema(dialect, profiles), dialect+" "+profiles.join(","));
    }
  }
});

test("authctl installs the OAuth provider schema on an existing database and preserves clients on rerun", async t => {
  const dir = mkdtempSync(join(tmpdir(), "plain-auth-oauth-provider-cli-"));
  t.after(() => rmSync(dir, {recursive:true, force:true}));
  const cli = join(dir, "authctl"), file = join(dir, "auth.db");
  execFileSync("go", ["build", "-o", cli, "./cmd/authctl"], {cwd: root, timeout:180000});
  const run = (command, ...args) => execFileSync(cli, [command, "--dialect", "sqlite", ...args],
    {encoding:"utf8", env:{...process.env, AUTH_DSN:file}, stdio:["ignore","pipe","pipe"]});
  const flags = ["--plugins", "oauth-provider"];
  run("migrate");
  assert.throws(() => run("check", "--json", ...flags), err =>
    err.status === 1 && JSON.parse(err.stdout).filter(f => f.kind === "missing-table").length === 7);
  assert.equal(run("generate", ...flags), await freshSchema("sqlite", ["oauth-provider"]));
  run("migrate", ...flags);
  const db = new DatabaseSync(file), ref = new DatabaseSync(":memory:");
  try {
    db.prepare('INSERT INTO oauthClient (id,clientId,redirectUris) VALUES (?,?,?)').run("one","app","[]");
    run("migrate", ...flags);
    assert.deepEqual(JSON.parse(run("check", "--json", ...flags)), []);
    await (await getMigrations({database:ref, ...schemaOptions(["oauth-provider"])})).runMigrations();
    assert.deepEqual(sqliteSchema(db), sqliteSchema(ref));
    assert.equal(db.prepare("SELECT clientId FROM oauthClient WHERE id = 'one'").get().clientId, "app");
  } finally { ref.close(); db.close(); }
});

test("authctl generates, checks and repeatedly migrates organization role storage", async t => {
  const dir = mkdtempSync(join(tmpdir(), "plain-auth-cli-roles-"));
  t.after(() => rmSync(dir, {recursive:true,force:true}));
  const binary = join(dir,"authctl"), file = join(dir,"auth.sqlite");
  execFileSync("go", ["build","-o",binary,"./cmd/authctl"], {cwd:root});
  const run = (cmd, profiles, ...args) => execFileSync(binary,
    [cmd,"--dialect","sqlite","--plugins",profiles,...args],
    {encoding:"utf8",env:{...process.env,AUTH_DSN:file},stdio:["ignore","pipe","pipe"]});
  run("migrate","organization-teams");
  const target = "organization-teams,organization-roles";
  assert.throws(() => run("check",target,"--json"), err =>
    err.status === 1 && JSON.parse(err.stdout).some(f => f.kind === "missing-table" && f.table === "organizationRole"));
  assert.equal(run("generate",target), await freshSchema("sqlite",target.split(",")));
  run("migrate",target);
  run("migrate",target);
  assert.deepEqual(JSON.parse(run("check",target,"--json")), []);
  const db = new DatabaseSync(file), ref = new DatabaseSync(":memory:");
  try {
    await (await getMigrations({database:ref,...schemaOptions(target.split(","))})).runMigrations();
    assert.deepEqual(sqliteSchema(db),sqliteSchema(ref));
  } finally { db.close(); ref.close(); }
});
