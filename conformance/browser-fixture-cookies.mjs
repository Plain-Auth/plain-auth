import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { betterAuth } from "better-auth";
import { testUtils } from "better-auth/plugins";
import { chromeBinary, openChromePage } from "./browser-debug.mjs";

export async function browserFixtureCookies(t, goFixture) {
  const binary = chromeBinary();
  if (!binary) return t.skip("requires a local Chrome or Chromium");
  const dir = await mkdtemp(join(tmpdir(), "plainauth-cookie-fixture-"));
  t.after(() => rm(dir, {recursive: true, force: true}));
  const path = join(dir, "login.json");
  const go = await goFixture(t, [], {CONFORMANCE_BROWSER_COOKIE_FILE: path});
  const saved = JSON.parse(await readFile(path, "utf8"));
  const db = new DatabaseSync(go.databasePath);
  t.after(() => db.close());
  const reference = betterAuth({
    database: db, baseURL: go.baseURL, secret: "local-conformance-0123456789-abcdefghijk",
    advanced: {cookiePrefix: "authn"}, telemetry: {enabled: false}, plugins: [testUtils()],
  });
  const helpers = (await reference.$context).test;
  const peer = await helpers.saveUser(helpers.createUser());
  const js = await helpers.login({userId: peer.id});
  const projected = saved.cookies[0];
  assert.deepEqual(Object.keys(projected).sort(), Object.keys(js.cookies[0]).sort());
  assert.equal(projected.expires, saved.expiresAt);
  assert.ok(Number.isSafeInteger(projected.expires));
  for (const key of ["name", "domain", "path", "httpOnly", "secure", "sameSite"]) {
    assert.equal(projected[key], js.cookies[0][key], key);
  }
  const call = await openChromePage(t, go.baseURL + "/api/auth/ok", binary);
  async function session() {
    const result = await call("Runtime.evaluate", {
      expression: "fetch('/api/auth/get-session').then(r => r.json())",
      awaitPromise: true, returnByValue: true,
    });
    assert.equal(result.exceptionDetails, undefined);
    return result.result.value;
  }
  for (const [userId, cookies] of [[saved.userId, saved.cookies], [peer.id, js.cookies]]) {
    await call("Network.setCookies", {cookies});
    const {cookies: installed} = await call("Network.getCookies", {urls: [go.baseURL]});
    const cookie = installed.find(c => c.name === projected.name);
    assert.equal(cookie.httpOnly, true);
    assert.equal(cookie.expires, cookies[0].expires);
    const script = await call("Runtime.evaluate", {expression: "document.cookie", returnByValue: true});
    assert.equal(script.result.value, "");
    assert.equal((await session()).user.id, userId);
    const headers = new Headers({cookie: cookie.name + "=" + cookie.value});
    assert.equal((await reference.api.getSession({headers})).user.id, userId);
    await helpers.deleteUser(userId);
    assert.equal(await session(), null);
  }
}
