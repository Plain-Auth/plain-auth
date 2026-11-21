// Compile the finite schema presets from the locked plugin implementations.
import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { passkey } from "@better-auth/passkey";
import { stripe } from "@better-auth/stripe";
import { getMigrations } from "better-auth/db/migration";
import { deviceAuthorization, jwt, organization, twoFactor } from "better-auth/plugins";
import { DummyDriver, Kysely, MysqlDialect, PostgresDialect, SqliteDialect } from "kysely";
import Stripe from "stripe";

export const dialects = { sqlite: SqliteDialect, postgres: PostgresDialect, mysql: MysqlDialect };

export function pluginInstances(profiles) {
  return profiles.map((id) => {
    switch (id) {
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
      default: throw new Error("Unknown plugin schema profile: " + id);
    }
  });
}

export function* combinations() {
  for (const device of ["", "device-authorization"]) for (const signing of ["", "jwt"]) {
    for (const org of ["", "organization", "organization-teams"]) {
      for (const keys of ["", "passkey"]) for (const limits of ["", "rate-limit"]) {
        for (const billing of ["", "stripe-subscriptions"]) {
          for (const mfa of ["", "two-factor"]) yield [device, signing, org, keys, limits, billing, mfa].filter(Boolean);
        }
      }
    }
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

async function catalog() {
  const data = {};
  for (const dialect of Object.keys(dialects)) {
    const statements = [];
    const plans = {};
    for (const profiles of combinations()) {
      const sql = await freshSchema(dialect, profiles);
      const keys = [];
      for (const statement of sql.trim().split(/;\s*\n\s*\n/).map((s) => s.replace(/;$/, "") + ";")) {
        let id = statements.indexOf(statement);
        if (id === -1) id = statements.push(statement) - 1;
        keys.push(id);
      }
      plans[profiles.join(",")] = keys;
    }
    data[dialect] = { statements, plans };
  }
  return JSON.stringify(data, null, 2) + "\n";
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const destination = new URL("../schema/catalog.json", import.meta.url);
  const expected = await catalog();
  if (process.argv[2] === "--write") await writeFile(destination, expected);
  else assert.equal(await readFile(destination, "utf8") === expected, true, "stale Go schema presets");
}
