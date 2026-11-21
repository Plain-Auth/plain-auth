// Compile reusable, dialect-specific schema fragments from the pinned implementations.
import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { apiKey } from "@better-auth/api-key";
import { passkey } from "@better-auth/passkey";
import { stripe } from "@better-auth/stripe";
import { getMigrations } from "better-auth/db/migration";
import { admin, anonymous, deviceAuthorization, jwt, lastLoginMethod, organization, twoFactor, username } from "better-auth/plugins";
import { DummyDriver, Kysely, MysqlDialect, PostgresDialect, SqliteDialect } from "kysely";
import Stripe from "stripe";

export const dialects = { sqlite: SqliteDialect, postgres: PostgresDialect, mysql: MysqlDialect };

export function pluginInstances(profiles) {
  return profiles.map((id) => {
    switch (id) {
      case "admin": return admin();
      case "anonymous": return anonymous();
      case "api-key": return apiKey();
      case "last-login-method": return lastLoginMethod({ storeInDatabase: true });
      case "device-authorization": return deviceAuthorization();
      case "jwt": return jwt();
      case "passkey": return passkey();
      case "organization": return organization();
      case "organization-teams": return organization({ teams: { enabled: true } });
      case "stripe-subscriptions": return stripe({
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
  ["organization", "organization-teams"], ["passkey"], ["rate-limit"], ["stripe-subscriptions"], ["two-factor"], ["username", "username-only"],
];
const profileNames = profileGroups.flat();

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

export async function freshSchema(type, profiles) {
  const Dialect = dialects[type];
  const dialect = new Dialect({});
  // No catalog tables exist. The actual dialect compiles all types and constraints.
  dialect.createDriver = () => new DummyDriver();
  const db = new Kysely({ dialect });
  try {
    const config = { database: { db, type }, ...schemaOptions(profiles) };
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

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const destination = new URL("../schema/catalog.json", import.meta.url);
  const expected = await catalog();
  if (process.argv[2] === "--write") await writeFile(destination, expected);
  else assert.equal(await readFile(destination, "utf8") === expected, true, "stale Go schema presets");
}
