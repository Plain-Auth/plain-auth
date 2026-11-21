import test from "node:test";

test("checked-in social provider contracts match the pinned reference", async () => {
  await import("./social-profiles.mjs");
});
