// Rebuild the HTTP request contracts from the pinned public plugin. The Go server
// selects operations from its own registry and supplies its own response models.
import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { betterAuth } from "better-auth";
import { emailOTP, magicLink, multiSession, oneTap, oneTimeToken, openAPI } from "better-auth/plugins";
import { pluginInstances } from "./plugin-schema.mjs";

async function contracts(plugins) {
  const server = betterAuth({
    baseURL: "https://openapi.example.test", secret: "local-openapi-catalog-0123456789-abcdef",
    telemetry: { enabled: false }, logger: { disabled: true }, plugins: [...plugins, openAPI()],
  });
  return (await server.api.generateOpenAPISchema()).paths;
}

function compact(value) {
  if (Array.isArray(value)) return value.map(compact);
  if (value && typeof value === "object") {
    const result = {};
    for (const [key, field] of Object.entries(value)) {
      if (["description", "example", "examples", "nullable"].includes(key)) continue;
      result[key] = compact(field);
    }
    if (value.nullable && typeof result.type === "string") result.type = [result.type, "null"];
    return result;
  }
  return value;
}

export async function buildCatalog() {
  const profiles = [
    "admin", "anonymous", "api-key", "device-authorization", "jwt", "organization-teams", "passkey", "phone-number",
    "stripe-subscriptions", "two-factor", "username",
  ];
  const plugins = [
    ...pluginInstances(profiles), emailOTP({ sendVerificationOTP() {} }), magicLink({ sendMagicLink() {} }),
    multiSession(), oneTimeToken(), oneTap(),
  ];
  const base = await contracts([]);
  const configured = await contracts(plugins);
  const rows = {};
  for (const [path, methods] of Object.entries(configured)) {
    for (const [method, value] of Object.entries(methods)) {
      const original = base[path]?.[method] ?? value;
      const entry = {};
      if (original.operationId) entry.operationId = original.operationId;
      if (original.parameters?.length) entry.parameters = compact(original.parameters);
      if (original.requestBody) entry.requestBody = compact(original.requestBody);
      rows[method.toUpperCase() + " " + path] = entry;
    }
  }
  return "{\n" + Object.keys(rows).sort().map(key => "  " + JSON.stringify(key) + ": " + JSON.stringify(rows[key])).join(",\n") + "\n}\n";
}

if (fileURLToPath(import.meta.url) === process.argv[1]) {
  const file = new URL("../plugins/openapi/catalog.json", import.meta.url);
  const result = await buildCatalog();
  if (process.argv.includes("--check")) assert.equal(await readFile(file, "utf8"), result);
  else await writeFile(file, result);
}
