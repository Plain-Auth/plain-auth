// Compile reusable, dialect-specific schema fragments from the pinned implementations.
import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { apiKey } from "@better-auth/api-key";
import { oauthProvider } from "@better-auth/oauth-provider";
import { passkey } from "@better-auth/passkey";
import { stripe } from "@better-auth/stripe";
import { sso } from "@better-auth/sso";
import { scim } from "@better-auth/scim";
import { getMigrations } from "better-auth/db/migration";
import { admin, anonymous, deviceAuthorization, jwt, lastLoginMethod, organization, phoneNumber, siwe, twoFactor, username } from "better-auth/plugins";
import { DummyDriver, Kysely, MysqlDialect, PostgresDialect, SqliteDialect } from "kysely";
import Stripe from "stripe";

export const dialects = { sqlite: SqliteDialect, postgres: PostgresDialect, mysql: MysqlDialect };

export function pluginInstances(profiles) {
  if (profiles.includes("oauth-provider")) {
    return [...pluginInstances(profiles.filter(p => p !== "oauth-provider")),
      oauthProvider({ loginPage: "/login", consentPage: "/consent" })];
  }
  if (profiles.includes("siwe")) {
    return [...pluginInstances(profiles.filter(p => p !== "siwe")), siwe({ domain: "wallet.test" })];
  }
  const dynamicRoles = profiles.includes("organization-roles");
  if (dynamicRoles) {
    const selected = new Set(profiles);
    if (!selected.has("organization-teams")) selected.add("organization");
    profiles = existingProfiles.filter(name => selected.has(name));
  }
  const verifiedDomains = profiles.includes("sso-domain-verification");
  if (verifiedDomains) profiles = [...profiles.filter(p => p !== "sso" && p !== "sso-domain-verification"), "sso"];
  const managed = profiles.includes("scim-managed");
  if (managed) profiles = [...profiles.filter(p => p !== "scim" && p !== "scim-managed"), "scim"];
  if (profiles.includes("sso")) profiles = [...profiles.filter(p => p !== "sso"), "sso"];
  if (profiles.includes("stripe-organization")) {
    const enabled = new Set(profiles);
    if (!enabled.has("organization-teams")) enabled.add("organization");
    enabled.add("stripe-subscriptions");
    profiles = [...profileGroups.flat(), "scim", "sso"].filter(id => enabled.has(id))
      .map(id => id === "stripe-subscriptions" ? "stripe-organization" : id);
  }
  return profiles.map((id) => {
    switch (id) {
      case "sso": return sso(verifiedDomains ? {domainVerification:{enabled:true}} : {});
      case "admin": return admin();
      case "anonymous": return anonymous();
      case "api-key": return apiKey();
      case "last-login-method": return lastLoginMethod({ storeInDatabase: true });
      case "device-authorization": return deviceAuthorization();
      case "jwt": return jwt();
      case "passkey": return passkey();
      case "phone-number": return phoneNumber({ sendOTP() {} });
      case "organization":
      case "organization-teams": return organization({
        teams: { enabled: id === "organization-teams" },
        dynamicAccessControl: { enabled: dynamicRoles },
      });
      case "scim": return scim({
        managedConnections: managed ? { credentialHashSecret: "fixture-only-managed-catalog-credential-secret" } : undefined,
        connections: [{ id: "schema", credentials: [{ type: "bearer", id: "test", token: "fixture" }] }],
      });
      case "stripe-organization":
      case "stripe-subscriptions": return stripe({
        organization: { enabled: id === "stripe-organization" },
        stripeClient: new Stripe("sk_test_local_schema_only"),
        stripeWebhookSecret: "whsec_local_schema_only",
        subscription: { enabled: true, plans: [] },
      });
      case "two-factor": return twoFactor();
      case "username": return username();
      case "username-only": return username({ displayUsername: false });
      default: throw new Error("Unknown plugin schema profile: " + id);
    }
  });
}

const profileGroups = [
  ["admin"], ["anonymous"], ["api-key"], ["device-authorization"], ["jwt"], ["last-login-method"],
  ["organization", "organization-teams"], ["passkey"], ["phone-number"], ["rate-limit"], ["stripe-subscriptions"], ["two-factor"], ["username", "username-only"],
];
// SCIM owns separate tables. The existing cross product remains exhaustive;
// its new combinations are checked with structural isolation and explicit witnesses.
const existingProfiles = [...profileGroups.flat(), "scim", "stripe-organization", "scim-managed", "sso", "sso-domain-verification", "siwe"];
const profileNames = [...existingProfiles, "oauth-provider", "organization-roles"];
export function* scimCombinations() {
  yield ["scim"];
  for (const name of profileGroups.flat()) yield [name, "scim"];
  for (const organization of ["organization", "organization-teams"]) {
    for (const username of ["username", "username-only"]) {
      yield [...profileGroups.map(group => group.includes("organization") ? organization : group.includes("username") ? username : group[0]), "scim"];
    }
  }
}

export function* organizationBillingCombinations() {
  yield ["stripe-organization"];
  for (const name of [...profileGroups.flat(), "scim"]) yield [name, "stripe-organization"];
  for (const name of ["organization", "organization-teams"]) {
    yield [...profileGroups.map(group => group.includes("organization") ? name : group[0]), "scim", "stripe-organization"];
  }
}

export function* managedSCIMCombinations() {
  for (const profiles of scimCombinations()) {
    yield [...profiles.filter(p => p !== "scim"), "scim-managed"];
  }
  yield ["scim", "scim-managed"];
  yield ["stripe-organization", "scim-managed"];
  for (const profiles of scimCombinations()) {
    if (profiles.length > 2) yield [...profiles.filter(p => p !== "scim"), "stripe-organization", "scim-managed"];
  }
}

export function* ssoCombinations() {
  yield ["sso"];
  for (const name of existingProfiles.filter(id => id !== "sso" && id !== "sso-domain-verification" && id !== "siwe")) yield [name, "sso"];
  for (const profiles of managedSCIMCombinations()) {
    if (profiles.includes("stripe-organization") && profiles.length > 2) yield [...profiles, "sso"];
  }
}

export function* ssoDomainCombinations() {
  for (const group of ssoCombinations()) yield [...group.filter(id => id !== "sso"), "sso-domain-verification"];
  yield ["sso", "sso-domain-verification"];
}

export function* walletCombinations() {
  yield ["siwe"];
  for (const profile of existingProfiles.filter(id => id !== "siwe")) yield [profile, "siwe"];
}

export function* oauthProviderCombinations() {
  yield ["oauth-provider"];
  for (const name of existingProfiles) yield [name, "oauth-provider"];
  yield [...existingProfiles.filter(p => !["username-only", "organization"].includes(p)), "oauth-provider"];
}

export function* verifiedCombinations() {
  yield* combinations();
  yield* scimCombinations();
  yield* organizationBillingCombinations();
  yield* managedSCIMCombinations();
  yield* ssoCombinations();
  yield* ssoDomainCombinations();
  yield* walletCombinations();
}


export function* combinations(index = 0, selected = []) {
  if (index === profileGroups.length) {
    yield selected;
    return;
  }
  yield* combinations(index + 1, selected);
  for (const name of profileGroups[index]) {
    yield* combinations(index + 1, [...selected, name]);
  }
}

export function schemaOptions(profiles) {
  return {
    plugins: pluginInstances(profiles.filter((name) => name !== "rate-limit")),
    rateLimit: profiles.includes("rate-limit") ? { storage: "database" } : undefined,
    logger: { disabled: true },
  };
}

export async function freshSchema(type, profiles, additionalPlugins = []) {
  const Dialect = dialects[type];
  const dialect = new Dialect({});
  // No catalog tables exist. The actual dialect compiles all types and constraints.
  dialect.createDriver = () => new DummyDriver();
  const db = new Kysely({ dialect });
  try {
    const options = schemaOptions(profiles);
    const config = { ...options, database: { db, type }, plugins: [...options.plugins, ...additionalPlugins] };
    return (await (await getMigrations(config)).compileMigrations()).trim() + "\n";
  } finally {
    await db.destroy();
  }
}

// Kysely emits a table definition or an index per statement. Split table
// definitions only at the outer level, preserving quoted identifiers, SQL type
// arguments, default literals, and the exact spelling of each fragment.
function tableColumns(body) {
  const parts = [];
  let start = 0, depth = 0, quote = "";
  for (let i = 0; i < body.length; i++) {
    const c = body[i];
    if (quote) {
      if (c === quote && body[i + 1] === quote) i++;
      else if (c === quote) quote = "";
    } else if (["'", '"', "`"].includes(c)) quote = c;
    else if (c === "(") depth++;
    else if (c === ")") depth--;
    else if (c === "," && depth === 0) {
      parts.push(body.slice(start, i).trim());
      start = i + 1;
    }
  }
  assert.equal(depth, 0);
  assert.equal(quote, "");
  return [...parts, body.slice(start).trim()];
}

function objects(sql) {
  const result = new Map();
  for (const part of sql.trim().split(/;\s*\n\s*\n/)) {
    const text = part.replace(/;$/, "");
    const table = /^(create table ["`][^"`]+["`]) \((.*)\)$/s.exec(text);
    if (table) result.set(table[1], tableColumns(table[2]));
    else {
      assert.match(text, /^create (?:unique )?index /);
      result.set(text + ";", null);
    }
  }
  return result;
}


async function catalog() {
  const data = {};
  for (const dialect of Object.keys(dialects)) {
    const base = objects(await freshSchema(dialect, []));
    const singles = new Map();
    for (const profile of profileNames) {
      singles.set(profile, objects(await freshSchema(dialect, [profile])));
    }
    // The teams profile includes the ordinary organization tables. The
    // maximal schema provides the canonical foreign-key and column order.
    const all = objects(await freshSchema(dialect, profileNames.filter((p) => p !== "organization" && p !== "username-only")));
    function owners(inCore, matches) {
      if (inCore) return {};
      const profiles = profileNames.filter((p) => matches(singles.get(p)));
      assert.ok(profiles.length, "a composite-only schema fragment needs an explicit rule");
      return { profiles };
    }
    data[dialect] = [...all].map(([sql, columns]) => {
      const item = { sql, ...owners(base.has(sql), (one) => one.has(sql)) };
      if (columns) {
        item.columns = columns.map((column) => {
          // A column present whenever this table exists needs no additional selector.
          const always = [...singles.values(), base].every((one) => !one.has(sql) || one.get(sql).includes(column));
          return { sql: column, ...owners(always, (one) => one.get(sql)?.includes(column)) };
        });
      }
      if (dialect === "mysql" && columns && (item.profiles?.includes("oauth-provider") || sql === "create table `organizationRole`")) {
        mysqlConstraints(item);
      }
      return item;
    });
    for (const [profile, schema] of singles) {
      for (const [sql, columns] of schema) {
        assert.ok(all.has(sql), "missing " + sql + " from " + profile);
        for (const column of columns ?? []) assert.ok(all.get(sql).includes(column), "missing " + column);
      }
    }
  }
  return JSON.stringify({profiles: profileNames, dialects: data}, null, 2) + "\n";
}

// MySQL 8.4 ignores inline REFERENCES. Emit enforceable table constraints,
// and give public key references the same length and collation as their target.
function mysqlConstraints(item) {
  const table = item.sql.split("`")[1];
  const constraints = [];
  for (const column of item.columns) {
    const name = column.sql.split("`")[1];
    const ref = / references (`\w+`) \((`\w+`)\) on delete (cascade|set null)$/.exec(column.sql);
    if (ref) {
      constraints.push("constraint `" + table + "_" + name + "_fk` foreign key (`" + name + "`)" + ref[0]);
      column.sql = column.sql.slice(0, ref.index);
    }
    const publicKey = ["clientId", "resourceId", "identifier"].includes(name);
    if (publicKey || name === "token" || (table === "oauthClientAssertion" && name === "id")) {
      column.sql = column.sql.replace(/varchar\((\d+)\)/, (_, width) =>
        "varchar(" + (publicKey ? 255 : width) + ") character set utf8mb4 collate utf8mb4_0900_bin");
    }
  }
  if (constraints.length) item.constraints = constraints;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const destination = new URL("../schema/catalog.json", import.meta.url);
  const expected = await catalog();
  if (process.argv[2] === "--write") await writeFile(destination, expected);
  else assert.equal(await readFile(destination, "utf8") === expected, true, "stale Go schema presets");
}
