import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));

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
