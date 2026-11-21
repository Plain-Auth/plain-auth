// Product labels describe the observable contract represented by each source
// entry. Exact package coordinates and public names live in reference.json.
const titles = {
  "api-key": "API keys", "better-auth": "Authentication server and framework bindings", cimd: "Client ID metadata documents", cli: "Command-line tools", core: "Core authentication contracts",
  "drizzle-adapter": "Drizzle adapter", electron: "Electron integration", expo: "Expo integration", i18n: "Localization", "kysely-adapter": "Kysely adapter",
  mcp: "Model Context Protocol", "memory-adapter": "In-memory adapter", "mongo-adapter": "MongoDB adapter", "oauth-provider": "OAuth authorization server",
  passkey: "Passkeys", "prisma-adapter": "Prisma adapter", "redis-storage": "Redis secondary storage", scim: "SCIM provisioning", sso: "Single sign-on",
  stripe: "Stripe billing", telemetry: "Telemetry", "test-utils": "Adapter and provisioning test utilities",
};
const entries = {
  ".": "Default interface", minimal: "Minimal server initialization", "social-providers": "Social provider registration and profiles",
  client: "Client integration", "client/plugins": "Client-side plugin registration", types: "Configuration and result types", crypto: "Cryptographic functions",
  cookies: "Session cookie handling", "cookies/utils": "Cookie parsing and serialization", oauth2: "OAuth protocol operations", react: "React client hooks",
  solid: "Solid client bindings", lynx: "Lynx client bindings", test: "Authentication test fixtures", api: "Programmatic API", db: "Database interfaces",
  vue: "Vue client bindings", svelte: "Svelte client bindings", plugins: "Plugin registration", "svelte-kit": "SvelteKit request handling",
  "solid-start": "SolidStart request handling", "next-js": "Next.js request handling", "tanstack-start": "TanStack Start request handling",
  "tanstack-start/solid": "TanStack Start for Solid", node: "Node host integration", "db/adapter": "Database adapter contract",
  "db/adapter/minimal": "Minimal database adapter contract", "db/migration": "Schema discovery and migration", adapters: "Database adapter selection",
  "relations-v2": "Relations v2", "node-sqlite-dialect": "Node SQLite dialect", proxy: "Browser-to-desktop proxy",
  preload: "Renderer preload bridge", storage: "Desktop credential storage", locales: "Bundled locale dictionaries",
  "resource-client": "Protected resource client", internal: "Low-level protocol operations", adapter: "Database adapter contract tests",
  scim: "SCIM lifecycle test helpers", async_hooks: "Request-local execution context", context: "Authentication context",
  env: "Environment configuration", error: "Error representation", "db/internal": "Underlying database operations",
  "oauth2/internal": "Underlying OAuth operations", instrumentation: "Instrumentation and tracing",
};
const entryEvidence = {
  "better-auth:.": ["core/signUpEmail", "core/getSession"],
  "better-auth:./social-providers": ["provider/google"], "better-auth:./client": ["go/client"],
  "better-auth:./db/migration": ["cli/generate"], "better-auth:./plugins/access": ["plugin-symbol/access/Role"],
  "api-key:./client": ["plugin-symbol/api-key/apiKeyClient"], "api-key:.": ["plugin/api-key/POST /api-key/create"],
  "i18n:.": ["plugin-symbol/i18n/i18n"], "i18n:./client": ["plugin-symbol/i18n/i18nClient"],
  "core:./env": ["go/environment"], "stripe:.": ["plugin/stripe/POST /subscription/upgrade"],
  "passkey:.": ["plugin/passkey/GET /passkey/list-user-passkeys"],
};
function entryLabel(key) {
  if (key === ".") return entries[key];
  const name = key.slice(2);
  if (entries[name]) return entries[name];
  if (name.startsWith("utils/")) return "Shared utilities for " + name.slice(6).replaceAll("-", " ");
  if (name.startsWith("plugins/")) return "Plugin interface for " + name.slice(8).replaceAll("-", " ").replace("/access", " permissions");
  if (name.startsWith("adapters/")) return "Adapter binding for " + name.slice(9);
  throw Error("Add a reviewed product label for entry point " + key);
}

export function renderPublicPackages({lines, interfaces, pending, addEvidence}) {
  lines.push("Each row tracks the behavior exposed by a published entry point. The Go implementation can provide that behavior through a native package, HTTP endpoint or client integration. The [maintainer catalog](../../conformance/reference.json) records exact package coordinates, source files, runtime conditions and named exports. The checks below link to tested behavior.", "");
  for (const pkg of interfaces.packages.filter(p => !p.private)) {
    const id = pkg.source.split("/")[1], title = titles[id];
    if (!title) throw Error("Classify new published package " + pkg.name);
    lines.push("## " + title, "", pending(title));
    addEvidence(lines, "published/" + id, "packages.md", 1);
    for (const entry of pkg.entries) {
      lines.push(pending(entryLabel(entry.subpath) + " (`" + entry.subpath + "`)", 1));
      addEvidence(lines, "published/" + id + "/" + entry.subpath, "packages.md", 2);
      for (const evidence of entryEvidence[id + ":" + entry.subpath] ?? []) addEvidence(lines, evidence, "packages.md", 2, false);
      if (entry.conditions.length) {
        for (const condition of entry.conditions) lines.push(pending("Runtime target " + condition, 2));
      }
    }
    lines.push("");
  }
}

export function renderDatabaseContracts({lines, interfaces, dialects, communityAdapters, pending, addEvidence}) {
  const db = "packages/core/src/db/";
  const specs = [
    ["Database adapter operations", db + "adapter/index.ts", "DBAdapter"],
    ["Adapter capabilities and data representation", db + "adapter/index.ts", "DBAdapterFactoryConfig"],
    ["Secondary storage operations", db + "type.ts", "SecondaryStorage"],
    ["Redis storage configuration", "packages/redis-storage/src/redis-storage.ts", "RedisStorageConfig"],
  ];
  for (const [title, file, name] of specs) {
    const decl = interfaces.exportsOf(file).find(s => s.name === name);
    if (!decl) throw Error("Missing storage interface " + name);
    lines.push("## " + title, "", pending(title));
    for (const field of interfaces.members(decl.symbol)) {
      lines.push(pending("`" + field.name + "`", 1));
      addEvidence(lines, "database/" + name + "/" + field.name, "adapters.md", 2);
    }
    lines.push("");
  }
  const redis = interfaces.exportsOf("packages/redis-storage/src/redis-storage.ts").find(s => s.name === "redisStorage");
  lines.push("## Redis-backed operations", "", pending("Redis-backed operations"));
  for (const name of interfaces.returnedFields(redis.symbol)) {
    lines.push(pending("`" + name + "`", 1));
    addEvidence(lines, "database/redisStorage/" + name, "adapters.md", 2);
  }
  lines.push("");
  lines.push("## SQL dialect integrations", "", "StoneWrit ships SQL adapters for SQLite, PostgreSQL and MySQL. The checklist also tracks additional database drivers and runtimes.", "");
  for (const [category, items] of dialects) {
    lines.push(pending(category));
    for (const item of items) {
      lines.push(pending(item.name, 1));
      addEvidence(lines, "sql-dialect/" + item.name, "adapters.md", 2);
    }
  }
  lines.push("", "## Community database adapters", "", "Each row tracks Go compatibility with a database integration. Maintainer names distinguish projects for the same database. The [source catalog](../../conformance/reference.json) records their repositories.", "");
  for (const adapter of communityAdapters) {
    const maintainer = new URL(adapter.url).pathname.split("/")[1];
    lines.push(pending(adapter.database + " (" + maintainer + ")"));
    addEvidence(lines, "community-adapter/" + adapter.name, "adapters.md", 1);
  }
  lines.push("");
}
