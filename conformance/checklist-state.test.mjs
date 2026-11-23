import assert from "node:assert/strict";
import test from "node:test";
import { checklistReport } from "./checklist-state.mjs";

test("only reviewed tasks with passing evidence and no open descendants can close", () => {
  const testLink = "[test](case_test.go#L7)";
  const review = (text) => ({ text, wholeTest: testLink });
  const result = checklistReport([
    review("- [ ] Completed feature"), review("  - [ ] Reviewed child"), "    - [x] Verified subcase",
    review("- [ ] Growing feature"), review("  - [ ] Child with new option"), "    - [ ] New option",
    "- [ ] Unreviewed feature", "  - [x] Verified subcase", "## Next section", review("- [ ] Complete leaf"),
  ]);
  assert.deepEqual(result.counts, {verified: 3, partial: 1, unverified: 3, scenarios: 2, notApplicable: 0});
  assert.equal(result.markdown, [
    "- [x] Completed feature (" + testLink + ")", "  - [x] Reviewed child (" + testLink + ")", "    - [x] Verified subcase",
    "- [ ] Growing feature", "  - [ ] Child with new option", "    - [ ] New option",
    "- [ ] Unreviewed feature", "  - [x] Verified subcase", "## Next section", "- [x] Complete leaf (" + testLink + ")",
  ].join("\n"));
});

test("additional scenarios preserve the inventory denominator and propagate evidence to open ancestors", () => {
  const lines = ["- [ ] Root", "  - [ ] Nested option", "    - [x] Scenario", "  - [ ] Other option", "## Unrelated", "- [ ] Separate feature"];
  const first = checklistReport(lines).counts;
  assert.deepEqual(first, {verified:0, partial:2, unverified:2, scenarios:1, notApplicable:0});
  lines.splice(3, 0, "    - [x] Second scenario");
  assert.deepEqual(checklistReport(lines).counts, {...first, scenarios:2});
});

test("not-applicable items leave the totals and keep later siblings under their parent", () => {
  const result = checklistReport([
    "- [ ] Feature", {text: "  - [ ] Browser hook", notApplicable: "not applicable: JavaScript only"}, {text: "    - [ ] Hook option", notApplicable: ""},
    "  - [ ] Server option", "    - [x] Scenario",
  ]);
  assert.deepEqual(result.counts, {verified: 0, partial: 2, unverified: 0, scenarios: 1, notApplicable: 2});
  assert.equal(result.markdown, [
    "- [ ] Feature", "  - Browser hook — *not applicable: JavaScript only*", "    - Hook option",
    "  - [ ] Server option", "    - [x] Scenario",
  ].join("\n"));
});
