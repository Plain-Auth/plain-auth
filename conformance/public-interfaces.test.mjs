import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { readInterfaces } from "./public-interfaces.mjs";

test("published entry points resolve aliases, overloads, wildcard files and third-party forwards", t => {
  const root = mkdtempSync(join(tmpdir(), "auth-interfaces-"));
  t.after(() => rmSync(root, {recursive:true, force:true}));
  const directory = "packages/example/";
  const sources = {
    "package.json": JSON.stringify({name: "fixture", version: "1", exports: {
      ".": {"dev-source": "./src/index.ts", default: "./dist/index.mjs"},
      "./utils/*": {"dev-source": "./src/utils/*.ts", default: "./dist/utils/*.mjs"},
    }}),
    "src/index.ts": 'export * from "./definitions"; export { internal as publicName } from "./implementation"; export type * from "outside";',
    "src/implementation.ts": "export const internal = true;",
    "src/definitions.ts": 'type Base = { first: boolean; second: number }; export type PublicOptions = Pick<Base, "first">; export function auth(input: string): boolean; export function auth(input: string) { return true; } interface Unrelated { wrongProperty: boolean }',
    "src/utils/service.ts": 'export const consumeToken = () => createAuthEndpoint({method:"POST"}, () => true);',
    "src/utils/service.test.ts": "export const testArtifact = true;",
  };
  for (const [file, content] of Object.entries(sources)) {
    const path = join(root, directory, file);
    mkdirSync(dirname(path), {recursive:true});
    writeFileSync(path, content);
  }
  const interfaces = readInterfaces(root, Object.keys(sources).map(s => directory + s));
  const entries = interfaces.packages[0].entries;
  assert.deepEqual(entries.map(e => e.subpath), [".", "./utils/service"]);
  assert.deepEqual(entries[0].symbols, ["PublicOptions", "auth", "publicName"]);
  assert.deepEqual(entries[0].externalForwards, ["types outside"]);
  const options = interfaces.exportsOf(directory + "src/index.ts").find(e => e.name === "PublicOptions");
  assert.deepEqual(interfaces.members(options.symbol).map(p => p.name), ["first"]);
  assert.equal(interfaces.serverOperations(entries[1].file)[0].name, "consumeToken");
});

const json = file => JSON.parse(readFileSync(new URL(file, import.meta.url), "utf8"));
const page = path => readFileSync(new URL("../docs/parity/" + path, import.meta.url), "utf8");
test("release catalog and rendered checklists retain published packages, storage integrations and server operations", () => {
  const reference = json("./reference.json");
  const packages = reference.packages.filter(pkg => !pkg.private);
  const entries = packages.flatMap(pkg => pkg.entries);
  assert.equal(packages.length, 22);
  assert.equal(packages.flatMap(pkg => pkg.exports).length, 111);
  assert.equal(entries.length, 125);
  assert.equal((page("packages.md").match(/^## /gm) ?? []).length, packages.length);
  assert.equal((page("packages.md").match(/^  - \[[x ]\] /gm) ?? []).length, entries.length);
  for (const pkg of packages) {
    assert.deepEqual([...new Set(pkg.entries.map(e => e.pattern ?? e.subpath))].sort(), [...pkg.exports].sort());
    for (const entry of pkg.entries) assert.equal(entry.symbols.length, new Set(entry.symbols).size, pkg.name + "/" + entry.subpath);
  }
  assert.equal(reference.communityAdapters.length, 25);
  for (const row of reference.communityAdapters) {
    const maintainer = new URL(row.url).pathname.split("/")[1];
    assert.ok(page("adapters.md").includes(row.database + " (" + maintainer + ")"), row.url);
  }
  assert.ok(page("adapters.md").includes("[source catalog](../../conformance/reference.json)"));
  assert.equal(Object.values(reference.additionalSQLDialects).flat().length, 24);
  for (const row of Object.values(reference.additionalSQLDialects).flat()) assert.ok(page("adapters.md").includes(row.name), row.name);
  assert.ok(page("adapters.md").includes("`consumeOne`"));
  assert.ok(page("adapters.md").includes("`listKeys`"));
  assert.ok(page("runtime.md").includes("`tokenEndpointAuthMethod`"));
  assert.ok(page("plugins/access.md").includes("`createAccessControl`"));
  assert.ok(page("plugins/electron.md").includes("`setupRenderer`"));
  assert.ok(page("plugins/mcp.md").includes("`requireMcpAuth`"));
  assert.ok(page("plugins/organization.md").includes("`addMember (server API only)`"));
  assert.ok(page("plugins/phone-number.md").includes("`consumePhoneNumberOTP (server API only)`"));
  assert.ok(!reference.sourceAnchors.some(x => x.symbol === "Operation (server API only)"));
  const sso = page("plugins/sso.md").split("## Interfaces")[1].split("## ")[0];
  assert.equal((sso.match(/^  - \[[ x]\] `sso`$/gm) ?? []).length, 1);
});

test("configured public plugin operations appear with their exact method or server-only name", async () => {
  const {pluginInstances} = await import("./plugin-schema.mjs");
  const {emailOTP, magicLink, oneTap, oneTimeToken, multiSession, openAPI, phoneNumber, organization} = await import("better-auth/plugins");
  const plugins = [
    ...pluginInstances(["admin", "anonymous", "api-key", "device-authorization", "jwt", "organization-teams",
      "passkey", "stripe-subscriptions", "two-factor", "username"]),
    emailOTP({sendVerificationOTP(){}}), magicLink({sendMagicLink(){}}), oneTap(), oneTimeToken(),
    multiSession(), phoneNumber({sendOTP(){}}), openAPI(),
    organization({teams:{enabled:true}, dynamicAccessControl:{enabled:true}}),
  ];
  for (const plugin of plugins) {
    const id = plugin.id === "two-factor" ? "2fa" : plugin.id;
    const rendered = page("plugins/" + id + ".md").split("## Interfaces")[1].split("## ")[0];
    for (const [name, endpoint] of Object.entries(plugin.endpoints ?? {})) {
      const label = endpoint.path
        ? [endpoint.options.method].flat().join(" / ") + " " + endpoint.path
        : name + " (server API only)";
      assert.ok(rendered.includes("`" + label + "`") || rendered.includes("`" + label + " (configurable)`"), id + ": " + label);
    }
  }
});
