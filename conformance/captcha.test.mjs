import test from "node:test";

test("CAPTCHA verification protocols and errors match the pinned providers", async () => {
  await import("./captcha-contract.mjs");
});
