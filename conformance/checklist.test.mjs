import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));

test("the feature index counts every checkbox on each linked checklist", () => {
  const directory = join(root, "docs/parity");
  const index = readFileSync(join(directory, "README.md"), "utf8");
  const expected = readdirSync(directory, {recursive: true}).filter(path => path.endsWith(".md") && path !== "README.md");
  const listed = [];
  let checkedRows = 0, openRows = 0;
  for (const row of index.matchAll(/^\| \[[^\]]+\]\(([^)]+)\) \| (\d+) \| (\d+) \|$/gm)) {
    const [, path, checked, open] = row;
    const lines = readFileSync(join(directory, path), "utf8").split("\n").map(line => line.trimStart());
    assert.equal(Number(checked), lines.filter(line => line.startsWith("- [x] ")).length, path);
    assert.equal(Number(open), lines.filter(line => line.startsWith("- [ ] ")).length, path);
    checkedRows += Number(checked);
    openRows += Number(open);
    listed.push(path);
  }
  assert.deepEqual(listed.sort(), expected.sort());
  const number = value => Number(value.replaceAll(",", ""));
  const summary = Object.fromEntries([...index.matchAll(/^\| (Fully verified|Partially verified|No linked test evidence) \| ([0-9,]+) \|$/gm)]
    .map(([, label, count]) => [label, number(count)]));
  const scenarioCount = number(index.match(/contain ([0-9,]+) links from passing scenarios/)[1]);
  assert.equal(summary["Fully verified"] + scenarioCount, checkedRows);
  assert.equal(summary["Partially verified"] + summary["No linked test evidence"], openRows);
  const [, verified, total, percent] = index.match(/\*\*([0-9,]+) of ([0-9,]+) inventory entries are fully verified \(([0-9.]+)%\)/);
  assert.equal(number(verified), summary["Fully verified"]);
  assert.equal(number(total), checkedRows + openRows - scenarioCount);
  assert.equal(percent, (100 * number(verified) / number(total)).toFixed(1));

});

test("the passkey checklist distinguishes browser actions from their HTTP endpoints", () => {
  const page = readFileSync(join(root, "docs/parity/plugins/passkey.md"), "utf8");
  for (const action of ["passkey.addPasskey", "signIn.passkey"]) {
    assert.ok(page.includes("Browser client action `" + action + "`"));
  }
  for (const path of ["/passkey/add-passkey", "/sign-in/passkey"]) {
    assert.ok(!page.includes("POST " + path));
  }
  for (const action of ["registration", "authentication"]) {
    assert.ok(page.includes("POST /passkey/verify-" + action));
  }
});

function checkedScenarios(directory) {
  const results = new Set();
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const file = join(directory, entry.name);
    if (entry.isDirectory()) {
      for (const scenario of checkedScenarios(file)) results.add(scenario);
    } else if (entry.name.endsWith(".md")) {
      for (const line of readFileSync(file, "utf8").split("\n")) {
        const match = line.match(/^\s*- \[x\] (.+) \(\[test\]\(([^)]+)\)\)$/);
        if (match) results.add(match[1] + "\n" + resolve(dirname(file), match[2]));
      }
    }
  }
  return results;
}

test("every checked scenario links to its current local test line", () => {
  const checked = checkedScenarios(join(root, "docs/parity"));
  const evidence = JSON.parse(readFileSync(join(root, "conformance/evidence.json"), "utf8"));
  const sources = new Map();
  const targetsByLabel = new Map();
  for (const [feature, cases] of Object.entries(evidence)) {
    for (const { label, test: path, marker } of cases) {
      if (!sources.has(path)) sources.set(path, readFileSync(join(root, path), "utf8").split("\n"));
      const matches = sources.get(path).flatMap((line, i) => line.includes(marker) ? [i + 1] : []);
      assert.equal(matches.length, 1, feature + " has an ambiguous or missing test marker: " + marker);
      const target = join(root, path) + "#L" + matches[0];
      assert.ok(checked.has(label + "\n" + target), feature + " needs an updated checklist link for " + label);
      if (!targetsByLabel.has(label)) targetsByLabel.set(label, new Set());
      targetsByLabel.get(label).add(target);
    }
  }
  // A scenario may appear in both its feature guide and the package index.
  // Every copy must point to a current test line.
  for (const entry of checked) {
    const [label, target] = entry.split("\n");
    const expected = targetsByLabel.get(label);
    if (expected) assert.ok(expected.has(target), "Stale checklist link for " + label + ": " + target);
  }
});
