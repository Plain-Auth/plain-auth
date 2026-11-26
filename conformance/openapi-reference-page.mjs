import assert from "node:assert/strict";
import { chromeBinary, openChromePage } from "./browser-debug.mjs";

// In Chrome, the API reference page sends nothing on load; its Send request
// buttons then reach the page's own origin with the viewer's cookies and show
// each status and JSON body.
export async function referencePageRequests(t, goFixture) {
  const binary = chromeBinary();
  if (!binary) return t.skip("requires a local Chrome or Chromium");
  const go = await goFixture(t, [], { CONFORMANCE_OPENAPI: "1" });
  const call = await openChromePage(t, go.baseURL + "/identity/manual", binary);
  const page = async (expression) => {
    const { result, exceptionDetails } = await call("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true });
    assert.equal(exceptionDetails, undefined, exceptionDetails?.exception?.description);
    return result.value;
  };
  const send = async (method, path, body) => {
    const panel = `document.querySelector('.try[data-method="${method}"][data-path="${path}"]')`;
    await page(`(() => {
      const panel = ${panel};
      const field = panel.querySelector('textarea[name="body"]');
      if (field) field.value = ${JSON.stringify(JSON.stringify(body ?? {}))};
      panel.querySelector(".result").textContent = "";
      panel.querySelector("button").click();
    })()`);
    for (let i = 0; i < 100; i++) {
      const text = await page(`${panel}.querySelector(".result").textContent`);
      if (text && text !== "Sending…") return text;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    throw Error("the request panel did not answer");
  };
  assert.deepEqual(await page(`[performance.getEntriesByType("resource").filter(e => e.initiatorType === "fetch").length,
    [...document.querySelectorAll(".try .result")].every(r => r.textContent === "")]`), [0, true]);
  const created = await send("POST", "/sign-up/email", {name: "Page User", email: "page@example.test", password: "page-password-123"});
  assert.match(created, /^200 OK\n/);
  assert.equal(JSON.parse(created.slice(created.indexOf("\n") + 1)).user.email, "page@example.test");
  assert.match(await send("POST", "/sign-in/email", { email: "page@example.test", password: "wrong-password-123" }), /^401 /);
  assert.match(await send("POST", "/sign-in/email", { email: "page@example.test", password: "page-password-123" }), /^200 OK\n/);
  const session = await page(`fetch("/identity/get-session").then(r => r.json())`);
  assert.equal(session.user.email, "page@example.test");
  assert.equal(await page(`(() => {
    const panel = document.querySelector('.try[data-method="GET"][data-path="/get-session"]');
    panel.querySelector('input[name="target"]').value = "get-session";
    panel.querySelector("button").click();
    return panel.querySelector(".result").textContent;
  })()`), "Enter a path that starts with /.");
}
