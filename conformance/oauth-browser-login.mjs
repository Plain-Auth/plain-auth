import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { verifyOAuthQueryParams } from "@better-auth/oauth-provider";

export async function exerciseBrowserLogin({ server, db, created, cookie, request }) {
  const base = server.baseURL + "/api/auth";
  const callback = "https://login-client.example.test/return";
  const app = await created({ redirect_uris: [callback], grant_types: ["authorization_code"], token_endpoint_auth_method: "none" }, { cookie });
  const verifier = randomUUID() + randomUUID();
  const state = "state ~ & " + randomUUID();
  const params = { response_type: "code", client_id: app.client_id, redirect_uri: callback, scope: "reports", state,
    code_challenge_method: "S256", code_challenge: createHash("sha256").update(verifier).digest("base64url") };
  const credentials = { email: "oauth-login-owner@example.test", password: "browser reauthentication fixture" };
  function cookies(res) { return res.headers.getSetCookie().map(v => v.split(";")[0]).join("; "); }
  async function start(extra = {}, headers = {}) {
    const q = new URLSearchParams({ ...params, ...extra });
    const res = await server.send(new Request(base + "/oauth2/authorize?" + q, { headers: { ...headers, accept: "application/json" } }));
    assert.equal(res.status, 200);
    const result = await res.json();
    return new URL(result.url, server.baseURL);
  }
  async function signed(page) {
    const raw = page.search.slice(1);
    assert.equal(await verifyOAuthQueryParams(raw, "local-conformance-0123456789-abcdefghijk"), true);
    assert.equal(page.searchParams.get("state"), state);
    return raw;
  }
  async function jsonRedirect(res) {
    const info = await res.json();
    assert.equal(res.status, 200, JSON.stringify(info));
    assert.equal(info.redirect, true);
    return new URL(info.url, server.baseURL);
  }
  const silent = await start({ prompt: "none" });
  assert.equal(silent.searchParams.get("error"), "login_required");
  const page = await start({ prompt: "login consent", max_age: "0" });
  assert.equal(page.pathname, "/login");
  const q = await signed(page);
  const altered = new URLSearchParams(q);
  altered.set("scope", "reports email");
  const body = { ...credentials, name: "OAuth login owner" };
  const invalid = await request("sign-up/email", { ...body, oauth_query: altered.toString() });
  assert.equal(invalid.status, 400);
  assert.equal((await invalid.json()).error, "invalid_signature");
  assert.equal(db.prepare("SELECT count(*) AS n FROM user WHERE email=?").get(credentials.email).n, 0);
  const signup = await request("sign-up/email", { ...body, oauth_query: q });
  const ownerCookie = cookies(signup);
  assert.ok(ownerCookie);
  const consent = await jsonRedirect(signup);
  assert.equal(consent.pathname, "/consent");
  assert.equal(consent.searchParams.has("max_age"), false);
  assert.equal(consent.searchParams.get("prompt"), "consent");
  const approve = await request("oauth2/consent", { accept: true, oauth_query: await signed(consent) }, { cookie: ownerCookie });
  const success = await jsonRedirect(approve);
  assert.equal(success.origin + success.pathname, callback);
  assert.equal(success.searchParams.get("state"), state);
  assert.equal(success.searchParams.get("iss"), base);
  const exchange = await server.send(new Request(base + "/oauth2/token", { method: "POST", body: new URLSearchParams({
    grant_type: "authorization_code", code: success.searchParams.get("code"), client_id: app.client_id,
    redirect_uri: callback, code_verifier: verifier }) }));
  assert.equal(exchange.status, 200);
  assert.equal((await exchange.json()).scope, "reports");

  const forced = await start({ max_age: "0" }, { cookie: ownerCookie });
  assert.equal(forced.pathname, "/login");
  const forcedQuery = await signed(forced);
  const wrong = await request("sign-in/email", { ...credentials, password: "incorrect fixture password", oauth_query: forcedQuery }, { cookie: ownerCookie });
  assert.equal(wrong.status, 401);
  const login = await request("sign-in/email", { ...credentials, oauth_query: forcedQuery }, { cookie: ownerCookie });
  const renewedCookie = cookies(login);
  const authorized = await jsonRedirect(login);
  assert.ok(renewedCookie);
  assert.notEqual(renewedCookie, ownerCookie);
  assert.ok(authorized.searchParams.get("code"));

  const create = await start({ prompt: "create" });
  assert.equal(create.pathname, "/signup");
  const newUser = await request("sign-up/email", { ...body, email: "oauth-created@example.test", oauth_query: await signed(create) });
  const newCookie = cookies(newUser);
  const signupPage = await jsonRedirect(newUser);
  assert.equal(signupPage.pathname, "/signup");
  const next = await request("oauth2/continue", { created: true, oauth_query: await signed(signupPage) }, { cookie: newCookie });
  const freshConsent = await jsonRedirect(next);
  assert.equal(freshConsent.pathname, "/consent");
  assert.equal(freshConsent.searchParams.has("prompt"), false);
}
