import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { createAuthClient } from "better-auth/client";

export async function exerciseBearer({ baseURL, send, database, databasePath }, signedOnly) {
  const request = (path, headers = {}, body) => send(new Request(baseURL + "/api/auth" + path, {
    method: body ? "POST" : "GET",
    headers: { ...headers, ...(body && { "content-type": "application/json", origin: baseURL }) },
    body: body && JSON.stringify(body),
  }));
  const password = "local-comparison-password";
  async function register(label) {
    const email = label + "@example.test";
    const response = await request("/sign-up/email", {}, { name: label, email, password });
    assert.equal(response.status, 200);
    const user = (await response.json()).user;
    return { email, id: user.id };
  }
  async function login({email}) {
    const response = await request("/sign-in/email", {}, {email, password});
    assert.equal(response.status, 200);
    const {token: raw} = await response.json();
    const credential = response.headers.get("set-auth-token");
    assert.ok(credential?.includes("."));
    const cookie = response.headers.getSetCookie().map(line => line.split(";")[0]).find(pair => pair.startsWith("authn.session_token="));
    assert.ok(cookie);
    assert.equal(decodeURIComponent(cookie.slice("authn.session_token=".length)), credential);
    const exposed = response.headers.get("access-control-expose-headers").toLowerCase().split(/\s*,\s*/);
    assert.equal(exposed.filter(name => name === "set-auth-token").length, 1);
    return {raw, credential, cookie, encoded: cookie.slice("authn.session_token=".length)};
  }

  const alice = await register("alice");
  const bob = await register("bob");
  const device = await login(alice);
  const browser = await login(bob);
  async function who(authorization, cookie) {
    const response = await request("/get-session", {
      ...(authorization && {authorization}),
      ...(cookie && {cookie}),
    });
    assert.equal(response.status, 200);
    return (await response.json())?.user.id ?? null;
  }
  for (const scheme of ["Bearer", "bEaReR", "BEARER "]) {
    assert.equal(await who(scheme + " " + device.credential), alice.id);
  }
  assert.equal(await who("Bearer " + device.encoded), alice.id);
  assert.equal(await who("Bearer " + device.raw), signedOnly ? null : alice.id);
  assert.equal(await who("Bearer " + device.credential, browser.cookie), alice.id);
  assert.equal(await who("Bearer invalid.signature", browser.cookie), bob.id);
  assert.equal(await who("Basic unrelated", browser.cookie), bob.id);
  assert.equal(await who("Bearer invalid.signature"), null);

  const client = createAuthClient({baseURL, fetchOptions: {
    customFetchImpl: (url, init) => send(new Request(url, init)),
    auth: {type: "Bearer", token: () => device.credential},
  }});
  const {data: sessions, error} = await client.listSessions();
  assert.equal(error, null);
  assert.ok(sessions.length >= 1);
  assert.ok(sessions.every(s => s.userId === alice.id));

  // Make the stored session eligible for renewal on the next read.
  const db = database ?? new DatabaseSync(databasePath);
  try {
    const nearExpiry = new Date(Date.now() + 60 * 60 * 1000).toISOString();
    assert.equal(db.prepare('UPDATE session SET "expiresAt" = ? WHERE token = ?').run(nearExpiry, device.raw).changes, 1);
  } finally {
    if (!database) db.close();
  }
  const authorization = "Bearer " + device.credential;
  const unchanged = await request("/get-session?disableRefresh=true", {authorization});
  assert.equal(unchanged.headers.get("set-auth-token"), null);
  const renewed = await request("/get-session", {authorization});
  assert.equal(renewed.headers.get("set-auth-token"), device.credential);
  assert.equal((await renewed.json()).user.id, alice.id);

  const signout = await request("/sign-out", {authorization: "Bearer " + device.credential}, {});
  assert.equal(signout.status, 200);
  assert.equal(signout.headers.get("set-auth-token"), null);
  assert.equal(await who("Bearer " + device.credential), null);
  assert.equal(await who(undefined, browser.cookie), bob.id);
}
