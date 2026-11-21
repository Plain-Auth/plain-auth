import assert from "node:assert/strict";
import test from "node:test";
import { lastLoginMethodClient } from "better-auth/client/plugins";
import { loginPreference } from "../plugins/lastlogin/browser.mjs";

test("login preference readers agree on reading, matching and clearing a scoped cookie", (t) => {
  let header = "other=value; staff.preference=github; staff.preference.extra=unused";
  let write;
  const document = {
    get cookie() { return header; },
    set cookie(value) { write = value; header = "other=value"; },
  };
  const previous = Object.getOwnPropertyDescriptor(globalThis, "document");
  Object.defineProperty(globalThis, "document", { configurable: true, value: document });
  t.after(() => {
    if (previous) Object.defineProperty(globalThis, "document", previous);
    else delete globalThis.document;
  });
  const options = { cookieName: "staff.preference", domain: ".example.test" };
  const pinned = lastLoginMethodClient(options).getActions();
  const own = loginPreference(options);
  assert.equal(own.read(), pinned.getLastUsedLoginMethod());
  assert.equal(own.is("github"), pinned.isLastUsedLoginMethod("github"));
  assert.equal(own.is("email"), false);
  header = "staff.preference=email%20%2B%20SSO%20%2F%20%C3%A9quipe";
  assert.equal(own.read(), "email + SSO / équipe");
  assert.equal(own.read(), pinned.getLastUsedLoginMethod());
  own.clear();
  assert.match(write, /Domain=\.example\.test/i);
  assert.match(write, /Path=\//i);
  assert.match(write, /Max-Age=0/i);
  assert.equal(own.read(), null);
});

test("a server-side render can read and clear the preference before a browser exists", () => {
  const preference = loginPreference();
  assert.equal(preference.read(), null);
  assert.equal(preference.is("email"), false);
  preference.clear();
  assert.throws(() => loginPreference({ cookieName: "bad;name" }), TypeError);
  assert.throws(() => loginPreference({ domain: "example.test; Path=/" }), TypeError);
});
