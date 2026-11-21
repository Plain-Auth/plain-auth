import assert from "node:assert/strict";
import test from "node:test";
import { renderChecklist } from "./checklist-state.mjs";

test("only reviewed tasks with passing evidence and no open descendants can close", () => {
  const testLink = "[test](case_test.go#L7)";
  const review = (text) => ({ text, wholeTest: testLink });
  const result = renderChecklist([
    review("- [ ] Completed feature"), review("  - [ ] Reviewed child"), "    - [x] Verified subcase",
    review("- [ ] Growing feature"), review("  - [ ] Child with new option"), "    - [ ] New option",
    "- [ ] Unreviewed feature", "  - [x] Verified subcase", "## Next section", review("- [ ] Complete leaf"),
  ]);
  assert.equal(result, [
    "- [x] Completed feature (" + testLink + ")", "  - [x] Reviewed child (" + testLink + ")", "    - [x] Verified subcase",
    "- [ ] Growing feature", "  - [ ] Child with new option", "    - [ ] New option",
    "- [ ] Unreviewed feature", "  - [x] Verified subcase", "## Next section", "- [x] Complete leaf (" + testLink + ")",
  ].join("\n"));
});
