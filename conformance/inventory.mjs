import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { basename, dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { betterAuth } from "better-auth";
import { socialProviderList } from "better-auth/social-providers";

import { checklistReport } from "./checklist-state.mjs";
import { readInterfaces, documentedDialects, readCommunityAdapters } from "./public-interfaces.mjs";
import { renderPublicPackages, renderDatabaseContracts } from "./package-checklist.mjs";

const commit = "9faf6f6a1155a6cdaf8ba2d25ce53e4f5a3fda72";
const source = process.argv[2];
const check = process.argv[3] === "--check";
if (!source || source.startsWith("-") || (process.argv[3] && !check)) {
  throw Error("Usage: npm run inventory -- <Better Auth Git checkout at v1.7.27> [--check]");
}
const git = (...args) => execFileSync("git", ["-C", source, ...args], { encoding: "utf8" }).trim();
assert.equal(git("rev-parse", "HEAD"), commit, "Upstream revision mismatch");
assert.equal(git("status", "--porcelain", "--untracked-files=no"), "", "Upstream tracked files changed");
const tracked = git("ls-files").split("\n");
const root = fileURLToPath(new URL("../", import.meta.url));
const output = join(root, "docs/parity");
const interfaces = readInterfaces(source, tracked);

const read = (path) => readFileSync(join(source, path), "utf8");
const evidence = JSON.parse(readFileSync(new URL("evidence.json", import.meta.url)));
const used = new Set();
const pages = new Map();
const pending = (label, depth = 0) => "  ".repeat(depth) + "- [ ] " + label;
const inline = (s) => "`" + s + "`";
const sourceAnchors = [];
const link = (sourcePath, title) => {
  sourceAnchors.push({ source: sourcePath, symbol: title.replaceAll("`", "") });
  return title;
};
const clean = (text) => text.replace(/\[([^\]]+)\]\([^)]+\)/g, "$1").replace(/\*\*/g, "").trim();
const page = (name, title) => {
  const lines = ["# " + title, "", "[Feature index](" + relative(dirname(name), "README.md") + ")", ""];
  pages.set(name, lines);
  return lines;
};
function addEvidence(lines, id, filename, depth, wholeFeature = true) {
  const parentIndex = lines.length - 1;
  for (const scenario of evidence[id] ?? []) {
    used.add(id);
    const path = relative(join(output, dirname(filename)), join(root, scenario.test));
    const test = readFileSync(join(root, scenario.test), "utf8").split("\n");
    const markers = test.flatMap((line, i) => line.includes(scenario.marker) ? [i + 1] : []);
    assert.equal(markers.length, 1, "Expected exactly one test marker for " + id + " / " + scenario.marker);
    const testLink = "[test](" + path + "#L" + markers[0] + ")";
    if (scenario.complete && wholeFeature) {
      assert.equal(typeof lines[parentIndex], "string", "Only one whole-feature review is allowed for " + id);
      lines[parentIndex] = { text: lines[parentIndex], wholeTest: testLink };
    }
    lines.push("  ".repeat(depth) + "- [x] " + scenario.label + " (" + testLink + ")");
  }
}

const runtimePage = "runtime.md";
const runtime = page(runtimePage, "Core API and tooling");
const options = { baseURL: "http://localhost", secret: "local-inventory-0123456789-abcdefghijk", telemetry: { enabled: false } };
const auth = betterAuth(options);
runtime.push("## Core API", "", "Each entry groups the configured endpoint’s behaviors. A checked child records a tested case. The parent stays open while options, error cases or alternate configurations still need coverage.", "", pending("Base API operations"));
for (const [name, ep] of Object.entries(auth.api).sort(([a], [b]) => a.localeCompare(b, "en"))) {
  const method = [ep.options.method].flat().join(" / ");
  const route = !ep.path || ep.options.metadata?.SERVER_ONLY ? "server API only" : method + " " + ep.path;
  runtime.push(pending(inline(name) + " (" + inline(route) + ")", 1));
  addEvidence(runtime, "core/" + name, runtimePage, 2);
}
runtime.push("", "## Social sign-in", "", pending("Built-in social providers"));
for (const id of [...socialProviderList].sort()) {
  runtime.push(pending(inline(id), 1));
  addEvidence(runtime, "provider/" + id, runtimePage, 2);
}
const providerTypes = "packages/core/src/social-providers/";
const fileForProvider = { microsoft: "microsoft-entra-id" };
const sharedType = interfaces.exportsOf("packages/core/src/oauth2/oauth-provider.ts").find(s => s.name === "ProviderOptions");
assert.ok(sharedType, "Missing shared social provider options");
runtime.push(pending("Shared social sign-in configuration"));
for (const field of interfaces.members(sharedType.symbol)) {
  runtime.push(pending(inline(field.name), 1));
  addEvidence(runtime, "provider-option/shared/" + field.name, runtimePage, 2);
}
runtime.push(pending("Provider-specific settings and overrides"));
for (const id of [...socialProviderList].sort()) {
  const file = providerTypes + (fileForProvider[id] ?? id) + ".ts";
  const settings = interfaces.exportsOf(file).find(s => /Options?$/.test(s.name) && !s.name.startsWith("Verify"));
  assert.ok(settings, "Missing provider configuration for " + id);
  const fields = interfaces.members(settings.symbol).filter(s => s.file === file);
  if (fields.length) {
    runtime.push(pending(inline(id), 1));
    for (const field of fields) {
      runtime.push(pending(inline(field.name), 2));
      addEvidence(runtime, "provider-option/" + id + "/" + field.name, runtimePage, 3);
    }
  }
}
runtime.push(pending("Generic OAuth provider presets"));
for (const file of tracked.filter((f) => /^packages\/better-auth\/src\/plugins\/generic-oauth\/providers\/[^/]+\.ts$/.test(f) && !f.endsWith("index.ts"))) {
  runtime.push(pending(link(file, basename(file, ".ts")), 1));
  for (const opt of interfaces.exportsOf(file).filter(s => /Options$/.test(s.name))) {
    for (const field of interfaces.members(opt.symbol).filter(s => s.file === file)) {
      runtime.push(pending(inline(field.name), 2));
      addEvidence(runtime, "oauth-preset/" + basename(file, ".ts") + "/" + field.name, runtimePage, 3);
    }
  }
}

runtime.push("", "## Client SDK and host integrations", "");
const packageFile = "packages/better-auth/package.json";
for (const subpath of Object.keys(JSON.parse(read(packageFile)).exports)) {
  const clients = new Set(["react", "vue", "svelte", "solid", "lynx", "client", "client/plugins"]);
  const hosts = new Set(["node", "svelte-kit", "solid-start", "next-js", "tanstack-start", "tanstack-start/solid"]);
  const name = subpath.slice(2);
  if (clients.has(name)) runtime.push(pending(inline(name) + " client interface"));
  if (hosts.has(name)) runtime.push(pending(inline(name) + " host binding"));
}
runtime.push("", "## CLI", "", pending("CLI command behavior"));
for (const file of tracked.filter((f) => f.startsWith("packages/cli/src/commands/") && f.endsWith(".ts") && !f.includes(".test."))) {
  const text = read(file);
  for (const cmd of text.matchAll(/new Command\("([^"]+)"\)/g)) {
    runtime.push(pending(link(file, inline(cmd[1])), 1));
    addEvidence(runtime, "cli/" + cmd[1], runtimePage, 2);
    for (const sub of text.matchAll(/\.command\("([^"]+)"\)/g)) runtime.push(pending(inline(cmd[1] + " " + sub[1]), 2));
    // Login and logout are the only command declarations sharing one source file.
    const end = text.indexOf('new Command("', cmd.index + cmd[0].length);
    const declaration = text.slice(cmd.index, end < 0 ? text.length : end);
    const flags = new Set([...declaration.matchAll(/\.option\(\s*["']([^"']+)["']/g)].map((m) => m[1]));
    for (const flag of flags) runtime.push(pending(inline(flag), 2));
  }
}

const corePrefix = "packages/better-auth/src/plugins/";
const bundled = new Set(tracked.filter((p) => p.startsWith(corePrefix) && p.slice(corePrefix.length).includes("/")).map((p) => p.slice(corePrefix.length).split("/")[0]));
const standalone = new Set(["api-key", "cimd", "electron", "expo", "i18n", "mcp", "oauth-provider", "passkey", "scim", "sso", "stripe"]);
const sourceNames = { "two-factor": "2fa", "haveibeenpwned": "have-i-been-pwned" };
const pluginPages = new Map();
function pluginTitle(slug) {
  const names = { "2fa": "Two-factor authentication", "sso": "Single sign-on", "scim": "SCIM provisioning", "siwe": "Sign in with Ethereum", "mcp": "Model Context Protocol", "cimd": "Client ID metadata documents", "jwt": "JSON Web Tokens", "api-key": "API keys", "i18n": "Internationalization", "open-api": "OpenAPI", "have-i-been-pwned": "Have I Been Pwned", "oauth-provider": "OAuth provider", "generic-oauth": "Generic OAuth", "oauth-proxy": "OAuth proxy", "oauth-popup": "OAuth popup" };
  return names[slug] || (slug[0].toUpperCase() + slug.slice(1).replaceAll("-", " "));
}
function pluginPage(slug) {
  if (!pluginPages.has(slug)) pluginPages.set(slug, page("plugins/" + slug + ".md", pluginTitle(slug)));
  return pluginPages.get(slug);
}
for (const slug of [...bundled, ...standalone]) {
  const lines = pluginPage(sourceNames[slug] ?? slug);
  const prefix = bundled.has(slug) ? corePrefix + slug + "/" : "packages/" + slug + "/src/";
  lines.push("## Interfaces", "", pending(pluginTitle(sourceNames[slug] ?? slug) + " endpoints, types and options"));
  const sources = tracked.filter((f) => f.startsWith(prefix) && f.endsWith(".ts") && !/\.(test|spec|typecheck)\./.test(f));
  const seenSymbols = new Set();
  const seenRoutes = new Set();
  const publicName = sourceNames[slug] ?? slug;
  const filename = "plugins/" + publicName + ".md";
  addEvidence(lines, "plugin/" + publicName, filename, 1);
  for (const file of sources) {
    const content = read(file);
    const rows = content.split("\n");
    function addRoute(method, label, line, serverOnly = false) {
      const route = method + " " + label;
      if (seenRoutes.has(route)) return;
      seenRoutes.add(route);
      lines.push(pending(link(file + "#L" + line, inline(route.trim())) + (serverOnly ? " (server API only)" : ""), 1));
      addEvidence(lines, "plugin/" + publicName + "/" + route, filename, 2);
    }
    const serverOperations = interfaces.serverOperations(file);
    for (const op of serverOperations.filter(op => !op.path)) addRoute("", op.name + " (server API only)", op.line);
    const declaration = /\b(?:createAuthEndpoint|createOAuthEndpoint|createSiweNonceEndpoint)\(\s*(?:"([^"]+)"|([\w.]+),)/g;
    for (const match of content.matchAll(declaration)) {
      const line = content.slice(0, match.index).split("\n").length;
      if (rows[line - 1].trimStart().startsWith("*")) continue;
      let label = match[1] ?? match[2];
      if (label === "path" && slug === "open-api") label = "/reference (configurable)";
      if (label === "jwksPath") label = "/jwks (configurable)";
      if (!label.startsWith("/")) continue;
      const method = content.slice(match.index + match[0].length).match(/^\s*,?\s*\{?\s*method:\s*("[A-Z]+"|\[[^\]]+\])/);
      addRoute(method ? [...method[1].matchAll(/"([A-Z]+)"/g)].map(m => m[1]).join(" / ") : "", label, line,
        serverOperations.some(op => op.path === label && op.line === line));
    }
    const declarations = ["index.ts", "client.ts", "types.ts", "options.ts"].includes(basename(file))
      ? interfaces.declarationExports(file) : [...(interfaces.published.get(file)?.values() ?? [])];
    for (const item of declarations) {
      if (seenSymbols.has(item.name)) continue;
      seenSymbols.add(item.name);
      lines.push(pending(link(item.file + "#L" + item.line, inline(item.name)), 1));
      const feature = "plugin-symbol/" + publicName + "/" + item.name;
      addEvidence(lines, feature, filename, 2);
      if (!/(Options|Config)$/.test(item.name)) continue;
      for (const field of interfaces.members(item.symbol)) {
        lines.push(pending(link(field.file + "#L" + field.line, inline(field.name)), 2));
        addEvidence(lines, feature + "/" + field.name, filename, 3);
      }
    }
  }
  lines.push("");
}

const groupNames = { authentication: "Authentication", adapters: "Database adapters", concepts: "Core concepts", integrations: "Framework integrations", reference: "Reference and configuration", infrastructure: "Managed infrastructure", guides: "Guides", examples: "Examples", "ai-resources": "AI resources", overview: "Getting started" };
const groups = new Map();
const docPrefix = "docs/content/docs/";
function extractPage(file, lines) {
  const content = read(file);
  const title = content.match(/^title:\s*["']?(.+?)["']?\s*$/m)?.[1] || basename(file, ".mdx");
  lines.push("## " + clean(title), "", pending(clean(title)));
  const parts = content.split("\n");
  const stack = [];
  let fence, table, optionObject, frontmatter = parts[0].trim() === "---";
  let inAPI = false, featureList = false, hiddenDepth, sourceLine;
  const filename = [...pages].find(([, content]) => content === lines)[0];
  addEvidence(lines, file, filename, 1);
  const seenBySection = new Set();
  function add(text, depth, key = text) {
    if (seenBySection.has(key)) return;
    seenBySection.add(key);
    lines.push(pending(text, depth));
    addEvidence(lines, file + "#L" + sourceLine + "/" + key, filename, depth + 1);
  }
  for (let i = 1; i < parts.length; i++) {
    sourceLine = i + 1;
    const raw = parts[i];
    const text = raw.trim();
    if (frontmatter) { if (text === "---") frontmatter = false; continue; }
    const fenceMarker = text.match(/^(`{3,}|~{3,})/);
    if (fenceMarker) {
      if (!fence) fence = fenceMarker[1];
      else if (fenceMarker[1][0] === fence[0] && fenceMarker[1].length >= fence.length) fence = undefined;
      continue;
    }
    if (fence) {
      if (inAPI) {
        const param = raw.match(/^\s*(\w+)(\?)?: (?:string|number|boolean|Date|Record|Array|[\"']|\{)/);
        if (param) add("Parameter " + inline(param[1]) + (param[2] ? " (optional)" : ""), stack.length + 2);
      }
      continue;
    }
    if (text.startsWith("</APIMethod")) inAPI = false;
    const heading = text.match(/^(#{1,6})\s+(.+?)\s*#*$/);
    if (heading) {
      if (hiddenDepth && heading[1].length > hiddenDepth) continue;
      hiddenDepth = undefined;
      const headingName = clean(heading[2]).replace(/[^\p{L}\p{N} ]/gu, "").trim();
      // "Resources" can introduce a protocol concept or a list of external reading.
      const resourceLinks = /^resources$/i.test(headingName) && /^\s*[-*]\s+\[/.test(parts.slice(i + 1).find(line => line.trim()) ?? "");
      if (resourceLinks || /^(?:installation|install .+?|getting started|quick start|quickstart|what is saml|youre now ready|thats it|wrapping up|example usage|usage example|next steps|additional resources|additional information|further reading|see also|troubleshooting|faq|frequently asked questions|changelog|release notes|migration from.*|contributing|related|done|credits|prerequisites|before you (?:begin|start)|table of contents|features overview)$/i.test(headingName)) {
        hiddenDepth = heading[1].length;
        continue;
      }
      while (stack.length && stack.at(-1).level >= heading[1].length) stack.pop();
      stack.push({ level: heading[1].length, text: clean(heading[2]) });
      lines.push(pending(clean(heading[2]), stack.length));
      addEvidence(lines, file + "#L" + (i + 1), filename, stack.length + 1);
      seenBySection.clear();
      featureList = false;
      table = undefined;
      continue;
    }
    if (hiddenDepth) continue;
    const depth = stack.length + 1;
    if (text.startsWith("<APIMethod")) {
      inAPI = true;
      let tag = text;
      while (!tag.includes(">") && i + 1 < parts.length) tag += " " + parts[++i].trim();
      const path = tag.match(/\bpath="([^"]+)"/)?.[1];
      const method = tag.match(/\bmethod="([^"]+)"/)?.[1];
      if (path) {
        const route = inline((method ? method + " " : "") + path);
        if (/\bisClientOnly\b/.test(tag)) {
          const action = path.slice(1).replace(/-([a-z])/g, (_, letter) => letter.toUpperCase()).replaceAll("/", ".");
          add("Browser client action " + inline(action), depth, route);
        } else {
          add(route + (tag.includes("isServerOnly") ? " (server API)" : ""), depth);
        }
      }
    }
    const declaration = text.match(/^export const (\w+)\s*=\s*([\[{])/);
    if (declaration) { optionObject = { name: declaration[1], kind: declaration[2], indent: null }; continue; }
    if (optionObject) {
      if (/^[}\]];?$/.test(raw)) { optionObject = undefined; continue; }
      if (optionObject.kind === "[") {
        const field = text.match(/^name:\s*"([^"]+)"/);
        if (field) add(inline(optionObject.name + "." + field[1]), depth);
      } else {
        const prop = raw.match(/^(\s+)(?:["']([^"']+)["']|([\w$.-]+)):\s*\{/);
        if (prop) {
          optionObject.indent ??= prop[1].length;
          if (optionObject.indent === prop[1].length) add(inline(optionObject.name + "." + (prop[2] || prop[3])), depth);
        }
      }
      continue;
    }
    if (text.startsWith("|")) {
      const cells = text.split("|").slice(1).map(cell => cell.trim());
      const [first, second] = cells;
      if (!table) {
        table = {
          routes: /^method$/i.test(first) && /^(path|endpoint|route)$/i.test(second),
          serverOnly: cells.findIndex(cell => /^server[- ]only$/i.test(cell)),
        };
        continue;
      }
      if (first && !/^[-:]+$/.test(first)) {
        // A method repeats for many endpoints in a routing table.
        const path = table.routes && second?.match(/^`?(\/[^\s`]+)`?$/)?.[1];
        const methods = path && first.match(/\b(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b/g);
        const label = methods?.length ? inline(methods.join(" / ") + " " + path) : clean(first);
        const serverOnly = methods?.length && /^yes$/i.test(cells[table.serverOnly]);
        add(label + (serverOnly ? " (server API only)" : ""), depth, label);
      }
      continue;
    }
    table = undefined;
    if (/\b(?:features|capabilities) (?:also )?include[s]?:/i.test(text)) { featureList = true; continue; }
    const label = text.match(/^(?:[-*]\s+|\d+\.\s+)?(?:\*\*(.+?)\*\*|`([^`]+)`)(?:\s*[:(—–-]|\s*$)/);
    if (label) { add(clean(label[1] || inline(label[2])), depth); continue; }
    // Some guides list independent capabilities as simple bullets under Features.
    if ((featureList || /features|capabilities/i.test(stack.at(-1)?.text ?? "")) && /^[-*]\s+/.test(text)) {
      add(clean(text.slice(2).split(/\s+[–—]\s+|:\s+/)[0]), depth);
    }
  }
  lines.push("");
}
const external = new Set(["agent-auth", "autumn", "chargebee", "commet", "community-plugins", "creem", "dodopayments", "dub", "polar"]);
const technicalGuides = {
  "browser-extension-guide": "integrations", cloudflare: "integrations", "saml-sso-with-okta": "integrations",
  "create-a-db-adapter": "adapters", "dynamic-base-url": "concepts", "your-first-plugin": "concepts",
  "optimizing-for-performance": "concepts",
};
for (const file of tracked.filter((f) => f.startsWith(docPrefix) && f.endsWith(".mdx"))) {
  const subpath = file.slice(docPrefix.length);
  const parts = subpath.split("/");
  const group = parts.length > 1 ? parts[0] : "overview";
  if (group === "plugins") {
    const slug = parts[1].replace(/\.mdx$/, "");
    if (slug !== "index") extractPage(file, pluginPage(slug));
  } else {
    const section = group === "guides" ? technicalGuides[basename(file, ".mdx")] : group;
    if (!["authentication", "concepts", "adapters", "integrations", "reference", "infrastructure"].includes(section)) continue;
    if (group === "reference" && !/^(options|security|instrumentation|telemetry)\.mdx$/.test(parts[1]) && parts[1] !== "errors") continue;
    if (!groups.has(section)) groups.set(section, page(section + ".md", groupNames[section] || section));
    extractPage(file, groups.get(section));
  }
}
const screeningPage = "plugins/have-i-been-pwned.md";
const screening = pages.get(screeningPage);
screening.push("## Credential-setting paths", "", pending("Apply default checks inside each credential-setting flow"));
addEvidence(screening, "password-screening/default-paths", screeningPage, 1);
const pathDeclaration = read(corePrefix + "haveibeenpwned/index.ts").match(/const paths = options\?\.paths \|\| \[([^\]]+)\]/);
assert.ok(pathDeclaration, "Missing default password-screening paths");
for (const [, path] of pathDeclaration[1].matchAll(/"([^"]+)"/g)) {
  screening.push(pending(inline(path), 1));
  addEvidence(screening, "password-screening/" + path, screeningPage, 2);
}
screening.push("");
const goPage = "go.md";
const go = page(goPage, "Go packages and integrations");
go.push("These checks exercise the Go HTTP client, router mounts and SQL drivers.", "");
for (const [key, label] of [["client", "Native Go HTTP client"], ["environment", "Environment configuration"], ["routers", "HTTP framework mounts"], ["databases", "SQL engine contracts"]]) {
  go.push(pending(label));
  addEvidence(go, "go/" + key, goPage, 1);
}
const communityAdapters = readCommunityAdapters(read("docs/lib/community-adapters-data.ts"));
const dialects = documentedDialects(read(docPrefix + "adapters/other-relational-databases.mdx"));
renderDatabaseContracts({lines: groups.get("adapters"), interfaces, communityAdapters, dialects, pending, addEvidence});
renderPublicPackages({lines: page("packages.md", "Published package interfaces"), interfaces, pending, addEvidence});
assert.deepEqual([...used].sort(), Object.keys(evidence).sort(), "Unknown evidence IDs");
const communitySource = "docs/lib/community-plugins-data.ts";
const communityData = read(communitySource);
const community = [...communityData.matchAll(/^\t\tname: "([^"]+)",\s*url: "([^"]+)"/gm)]
  .map(([_, name, url]) => ({ name, url }));
assert.equal(community.length, [...communityData.matchAll(/^\t\tname: "/gm)].length, "Unparsed community extension");
const communityPage = pluginPage("community-plugins");
communityPage.push("## Listed extensions", "", "These integrations are tracked for the Go library. Each row requires its own implementation and tests.", "");
for (const { name } of community) {
  const label = name.replace(/better[- ]?auth/gi, "").replace(/-{2,}/g, "-")
    .replace(/\/-/g, "/").replace(/[-/]+$/, "").replace(/^-+/, "");
  communityPage.push(pending(inline(label || name)));
}
communityPage.push("");
const progressHeader = ["| Checklist | Checked | Open |", "| --- | ---: | ---: |"];
const reports = new Map();
const totals = {verified:0, partial:0, unverified:0, scenarios:0};
for (const [path, lines] of pages) {
  const report = checklistReport(lines);
  reports.set(path, report);
  for (const key of Object.keys(totals)) totals[key] += report.counts[key];
}
const inventoryTotal = totals.verified + totals.partial + totals.unverified;
const count = value => value.toLocaleString("en-US");
function progressRow(title, path) {
  const {verified, partial, unverified, scenarios} = reports.get(path).counts;
  return `| [${title}](${path}) | ${verified + scenarios} | ${partial + unverified} |`;
}
const index = [
  "# Feature checklist", "",
  "## Verification progress", "",
  `**${count(totals.verified)} of ${count(inventoryTotal)} inventory entries are fully verified (${(totals.verified * 100 / inventoryTotal).toFixed(1)}%).**`, "",
  "| Inventory status | Entries |", "| --- | ---: |",
  `| Fully verified | ${count(totals.verified)} |`,
  `| Partially verified | ${count(totals.partial)} |`,
  `| No linked test evidence | ${count(totals.unverified)} |`, "",
  `The inventory covers features, options, integrations and documentation topics. Partial verification means an open entry has a passing case somewhere beneath it. The checklists also contain ${count(totals.scenarios)} links from passing scenarios to tests. Adding a scenario leaves the inventory denominator unchanged.`, "",
  "A checked item links to a local test for that behavior. An open parent means the feature still has unverified cases. Browser, protocol and storage options each have their own checkboxes.", "",
  "Browse [authentication, storage and tools](#authentication-storage-and-tools), [plugins](#plugins-and-integrations) or [third-party integrations](#third-party-integrations). Each table counts the checked and open boxes on its linked pages, including individual options and tested scenarios. A behavior can appear in more than one checklist.", "",
  "## Implementation guides", "",
  "| Capability | Documentation |", "| --- | --- |",
  "| Credentials, cookies and session lifecycle | [Authentication](../authentication.md) · [Account management](../account.md) |",
  "| Remember and switch accounts in one browser | [Account switching](../multi-session.md) |",
  "| Guest sessions and account upgrades | [Guest sessions](../anonymous.md) |",
  "| OAuth popup sign-in for top-level and embedded applications | [OAuth popup sign-in](../oauth-popup.md) |",
  "| Share a registered OAuth callback across trusted preview deployments | [OAuth proxy setup](../oauth-proxy.md) |",
  "| Google One Tap popup, button and browser challenges | [Google One Tap](../one-tap.md) |",
  "| Publish discovery metadata and respond to access-token failures | [Resource discovery and challenges](../oauth-resource-discovery.md) |",
  "| Manage OAuth resource policies and client grants from server code | [Resource management](../oauth-resource-management.md) |",
  "| Manage the signed-in user’s OAuth consent grants | [Authorized applications](../oauth-consents.md) |",
  "| Register OAuth clients and rotate shared secrets | [OAuth client registration](../oauth-client-registration.md) |",
  "| Grant or revoke machine-to-machine scopes from Go server code | [Machine scope management](../oauth-client-registration.md#grant-machine-to-machine-scopes) |",
  "| Issue opaque machine access tokens and check their current scopes and expiry | [Machine access tokens](../machine-tokens.md) · [Token introspection](../machine-tokens.md#check-whether-a-token-is-active) |",
  "| Authenticate an OAuth application with its own signing key | [Signed client assertions](../oauth-client-assertions.md) |",
  "| Revoke an OAuth token or invalidate a replayed refresh-token family | [Token revocation](../oauth-token-revocation.md) |",
  "| List or delete owned applications and show public client details | [Manage registered applications](../oauth-client-directory.md) |",
  "| OAuth authorization-server database tables | [Schema and migration](../schema.md#oauth-authorization-server-tables) |",
  "| First-party device grants and authorization | [Sign in a device](../device-authorization.md) |",
  "| Sign in with an Ethereum wallet | [Wallet sign-in](../siwe.md) |",
  "| Passkey registration, login and credential management | [Passkeys](../passkeys.md) |",
  "| Email link sign-in and single-use session transfer | [Magic links](../magic-link.md) · [One-time tokens](../one-time-token.md) |",
  "| Application-defined fields on users and sessions | [User fields](../user-fields.md) · [Session fields](../session-fields.md) · [Schema commands](../schema.md) |",
  "| Breached-password screening for credential writes | [Password checks](../password-checks.md) |",
  "| CAPTCHA verification and trusted request conditions | [CAPTCHA](../captcha.md) |",
  "| Service tokens, key rotation and public verification keys | [JWT and JWKS](../jwt.md) |",
  "| TOTP enrollment, challenge verification and backup codes | [Two-factor authentication](../2fa.md) |",
  "| Runtime settings, key rotation and startup | [Environment](../environment.md) |",
  "| OAuth sign-in, identity verification and account linking | [Social providers](../social.md) |",
  "| Enterprise provider registration, browser sign-in and organization membership | [Enterprise single sign-on](../sso.md) |",
  "| Go client and router integrations | [HTTP client](../client.md) · [Routers](../routers.md) |",
  "| Memory, SQLite, PostgreSQL and MySQL | [Databases](../databases.md) · [Schema generation and migrations](../schema.md) |",
  "| Username registration, sign-in and availability | [Username sign-in](../username.md) |",
  "| Administrative roles, bans and impersonation | [Administrator accounts](../admin.md) |",
  "| Organization membership and invitations | [Organizations](../organizations.md) |",
  "| Personal checkout, customer portal, billing state and signed notifications | [Polar billing](../polar.md) |",
  "| Checkout, subscription changes, cancellation, restoration and signed webhooks | [Subscription lifecycle](../subscriptions.md) · [Billing portal](../plugins.md#open-the-users-stripe-billing-portal) |",
  "| Role definitions and action checks | [Role permissions](../access.md) |",
  "| Personal and organization application credentials | [API keys](../api-keys.md) |",
  "| Verify a phone number, sign in or recover a password by SMS | [Phone accounts](../phone-number.md) |",
  "| Provision directory users with scoped bearer credentials | [SCIM provisioning](../scim.md) |",
  "| Translate authentication errors and select a locale | [Localization](../localization.md) |",
  "| Share rate limits and store short-lived application values in Redis | [Redis secondary storage](../redis.md) |",
  "| Describe installed HTTP endpoints and render their reference | [OpenAPI](../openapi.md) |",
  "| Extension hooks, bearer sessions and login method | [Plugins](../plugins.md) |", "",
  "## Authentication, storage and tools", "", ...progressHeader,
  progressRow("Published package interfaces", "packages.md"),
  progressRow("Native Go client, routers and databases", "go.md"),
  progressRow("Core API, sign-in providers and CLI", "runtime.md"),
];
for (const group of [...groups.keys()].sort()) index.push(progressRow(groupNames[group] || group, group + ".md"));
index.push("", "## Plugins and integrations", "", ...progressHeader);
for (const slug of [...pluginPages.keys()].filter((slug) => !external.has(slug)).sort()) index.push(progressRow(pluginTitle(slug), "plugins/" + slug + ".md"));
index.push("", "## Third-party integrations", "", "These integrations have independent release cycles.", "", ...progressHeader);
for (const slug of [...external].sort()) index.push(progressRow(pluginTitle(slug), "plugins/" + slug + ".md"));
index.push("");
pages.set("README.md", index);
for (const [name, lines] of pages) {
  const path = join(output, name);
  // Documentation headings can contain the reference project's product name.
  // Product-facing pages describe capabilities independently; the verification
  // guide retains exact source names and package coordinates for maintainers.
  const body = (reports.get(name)?.markdown ?? checklistReport(lines).markdown).split(/(\]\([^)]+\))/).map(part =>
    part.startsWith("](") ? part : part.replace(/@better-auth\//gi, "")
      .replace(/better[- ]auth(?:’s|'s)?/gi, "authentication").replace(/BetterAuth/g, "Auth")
      .replace(/better_auth\./g, "auth.").replace(/(?:process\.env\.)?BETTER_AUTH_/g, "AUTH_")
  ).join("").trimEnd() + "\n";
  if (check) assert.equal(readFileSync(path, "utf8") === body, true, "Stale parity file: " + name);
  else { mkdirSync(dirname(path), { recursive: true }); writeFileSync(path, body); }
}
const referenceIndex = {
  upstream: "https://github.com/better-auth/better-auth",
  release: "v1.7.27",
  commit,
  packages: interfaces.packages,
  communityAdapters,
  additionalSQLDialects: Object.fromEntries(dialects),
  core: Object.entries(auth.api).map(([name, ep]) => ({
    name, path: ep.path ?? null, methods: [ep.options.method].flat(), serverOnly: !ep.path || !!ep.options.metadata?.SERVER_ONLY,
  })),
  providers: [...socialProviderList].sort(),
  plugins: [...pluginPages.keys()].sort(),
  sourceAnchors,
  externalPluginDocumentation: [...external].sort(),
  communityExtensions: community,
  hostedServices: tracked.filter((f) => f.startsWith(docPrefix + "infrastructure/") && f.endsWith(".mdx")),
};
const referenceFile = new URL("reference.json", import.meta.url);
const json = JSON.stringify(referenceIndex, null, 2) + "\n";
if (check) assert.equal(readFileSync(referenceFile, "utf8") === json, true, "Stale reference index");
else writeFileSync(referenceFile, json);
const current = readdirSync(output, { recursive: true }).filter((name) => name.endsWith(".md")).sort();
assert.deepEqual(current, [...pages.keys()].sort(), "Untracked or stale parity pages");
console.log("Validated " + pages.size + " checklist files for Better Auth v1.7.27");
