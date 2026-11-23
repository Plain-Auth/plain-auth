import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";

export async function exerciseBrowserAuthorization({ server, issuer, db }) {
  const base = server.baseURL + "/api/auth";
  const callback = "https://reports.example.test/browser?tab=details";
  const json = (path, body, headers) => server.send(new Request(base + path, {
    method: "POST", headers: { "content-type": "application/json", origin: server.baseURL, ...headers }, body: JSON.stringify(body),
  }));
  const signup = await json("/sign-up/email", { name: "Browser owner", email: "authorize-browser@issuer.test", password: "browser authorization fixture" });
  assert.equal(signup.status, 200);
  const owner = (await signup.json()).user.id;
  const cookie = signup.headers.getSetCookie().map(v => v.split(";")[0]).join("; ");
  const registration = await json("/oauth2/register", { redirect_uris: [callback], grant_types: ["authorization_code"],
    scope: "reports", token_endpoint_auth_method: "none" }, { cookie });
  assert.equal(registration.status, 201);
  const app = await registration.json();
  const verifier = randomUUID() + randomUUID();
  const digest = value => createHash("sha256").update(value).digest("base64url");
  const params = { response_type: "code", client_id: app.client_id, redirect_uri: callback,
    scope: "reports", state: randomUUID(), prompt: "none", code_challenge_method: "S256", code_challenge: digest(verifier) };
  async function authorize(extra = {}, { method = "GET", headers = { cookie }, fetchResult = false } = {}) {
    const q = new URLSearchParams({ ...params, ...extra });
    const target = base + "/oauth2/authorize" + (method === "GET" ? "?" + q : "?client_id=ignored-query");
    const res = await server.send(new Request(target, { method, mode: fetchResult ? "cors" : "same-origin", redirect: "manual", headers: {
      ...headers, ...(method === "POST" && { "content-type": "application/x-www-form-urlencoded", origin: server.baseURL }),
      ...(fetchResult && { accept: "application/json" }),
    }, ...(method === "POST" && { body: q }) }));
    if (fetchResult) {
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.redirect, true);
      return new URL(body.url);
    }
    assert.equal(res.status, 302);
    return new URL(res.headers.get("location"));
  }
  function rejected(u, code) {
    assert.equal(u.origin + u.pathname, "https://reports.example.test/browser");
    assert.equal(u.searchParams.get("error"), code);
    assert.equal(u.searchParams.get("state"), params.state);
    assert.equal(u.searchParams.get("iss"), base);
    assert.equal(u.searchParams.has("code"), false);
  }
  rejected(await authorize({}, { headers: {} }), "login_required");
  rejected(await authorize(), "consent_required");
  const untrusted = await authorize({ redirect_uri: "https://unregistered.example.test/return" });
  assert.equal(untrusted.origin + untrusted.pathname, base + "/error");
  assert.equal(untrusted.searchParams.has("state"), false);
  rejected(await authorize({ code_challenge: "" }), "invalid_request");
  rejected(await authorize({ scope: "unapproved" }), "invalid_scope");
  const timestamp = new Date().toISOString();
  db.prepare("INSERT INTO oauthConsent(id,clientId,userId,referenceId,scopes,createdAt,updatedAt) VALUES(?,?,?,?,?,?,?)")
    .run(randomUUID(), app.client_id, owner, "other-tenant", '["reports"]', timestamp, timestamp);
  rejected(await authorize(), "consent_required");
  db.prepare("INSERT INTO oauthConsent(id,clientId,userId,scopes,createdAt,updatedAt) VALUES(?,?,?,?,?,?)")
    .run(randomUUID(), app.client_id, owner, '["reports"]', timestamp, timestamp);
  rejected(await authorize({ max_age: "0" }), "login_required");
  for (const [method, consumer] of [["GET", "self"], ["POST", "peer"]]) {
    const u = await authorize({ max_age: "3600" }, { method, fetchResult: method === "POST" });
    assert.equal(u.searchParams.get("tab"), "details");
    assert.equal(u.searchParams.get("state"), params.state);
    assert.equal(u.searchParams.get("iss"), base);
    const code = u.searchParams.get("code");
    assert.match(code, /^[a-zA-Z0-9]{32}$/);
    const record = db.prepare("SELECT * FROM verification WHERE identifier=?").get(digest(code));
    assert.equal(Date.parse(record.expiresAt) - Date.parse(record.updatedAt), 600_000);
    const value = JSON.parse(record.value);
    assert.equal(value.userId, owner);
    assert.equal(value.query.max_age, undefined);
    assert.equal(value.query.redirect_uri, callback);
    const tokenBase = consumer === "self" ? base : "http://issuer.localhost/api/auth";
    const req = new Request(tokenBase + "/oauth2/token", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "authorization_code", code, client_id: app.client_id, code_verifier: verifier, redirect_uri: callback }) });
    const res = consumer === "self" ? await server.send(req) : await issuer.handler(req);
    const output = await res.json();
    assert.equal(res.status, 200, JSON.stringify(output));
    assert.ok(output.access_token);
    assert.equal(output.scope, "reports");
  }
}
