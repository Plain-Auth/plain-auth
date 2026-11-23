import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { verifyOAuthQueryParams } from "@better-auth/oauth-provider";

export async function exerciseSignupPolicy({ server, db, created, cookie, request }) {
  const base = server.baseURL + "/api/auth";
  const callback = "https://onboarding.example.test/callback";
  const app = await created({ redirect_uris: [callback], grant_types: ["authorization_code"], scope: "reports email",
    token_endpoint_auth_method: "none" }, { cookie });
  const verifier = randomUUID() + randomUUID();
  const params = { response_type: "code", client_id: app.client_id, redirect_uri: callback, scope: "reports email",
    state: randomUUID(), code_challenge_method: "S256", code_challenge: createHash("sha256").update(verifier).digest("base64url") };
  const login = await request("sign-up/email", { name: "Registration", email: "onboarding@issuer.test", password: "local signup policy fixture" });
  assert.equal(login.status, 200);
  const owner = (await login.json()).user.id;
  const headers = { cookie: login.headers.getSetCookie().map(v => v.split(";")[0]).join("; ") };

  async function redirect(response) {
    const body = await response.json();
    assert.equal(response.status, 200, JSON.stringify(body));
    assert.equal(body.redirect, true);
    return new URL(body.url, server.baseURL);
  }
  function begin(prompt) {
    const query = new URLSearchParams(params);
    if (prompt) query.set("prompt", prompt);
    return server.send(new Request(base + "/oauth2/authorize?" + query, { headers: { ...headers, accept: "application/json" } })).then(redirect);
  }
  async function signed(page) {
    const query = page.search.slice(1);
    assert.equal(await verifyOAuthQueryParams(query, "local-conformance-0123456789-abcdefghijk"), true);
    assert.equal(page.searchParams.get("state"), params.state);
    return query;
  }
  async function resume(page) {
    return redirect(await request("oauth2/continue", { created: true, oauth_query: await signed(page) }, headers));
  }
  async function profile(name) {
    const updated = await request("update-user", { name }, headers);
    assert.equal(updated.status, 200);
  }
  function grants() {
    return db.prepare("SELECT userId,scopes FROM oauthConsent WHERE clientId=?").all(app.client_id);
  }
  const silent = await begin("none");
  assert.equal(silent.origin + silent.pathname, callback);
  assert.equal(silent.searchParams.get("error"), "interaction_required");
  assert.equal(silent.searchParams.get("state"), params.state);
  assert.equal(silent.searchParams.get("iss"), base);

  const first = await begin("consent");
  assert.equal(first.pathname, "/signup");
  const unfinished = await resume(first);
  assert.equal(unfinished.pathname, "/signup");
  assert.equal(unfinished.searchParams.has("code"), false);
  assert.equal(grants().length, 0);

  await profile("Profile");
  const custom = await resume(unfinished);
  assert.equal(custom.pathname, "/setup");
  await profile("Ready");
  const consent = await resume(custom);
  assert.equal(consent.pathname, "/consent");
  assert.equal(consent.searchParams.get("prompt"), "consent");

  // The host's requirement can change while the browser is on the consent page.
  await profile("Profile");
  const deferred = await redirect(await request("oauth2/consent", { accept: true, scope: "reports", oauth_query: await signed(consent) }, headers));
  assert.equal(deferred.pathname, "/setup");
  assert.equal(deferred.searchParams.get("scope"), "reports");
  assert.equal(deferred.searchParams.has("code"), false);
  const approvals = grants();
  assert.equal(approvals.length, 1);
  assert.equal(approvals[0].userId, owner);
  assert.deepEqual(JSON.parse(approvals[0].scopes), ["reports"]);
  assert.equal((await resume(deferred)).pathname, "/setup");

  await profile("Ready");
  const returned = await resume(deferred);
  assert.equal(returned.origin + returned.pathname, callback);
  assert.equal(returned.searchParams.get("state"), params.state);
  assert.equal(returned.searchParams.get("iss"), base);
  const token = await server.send(new Request(base + "/oauth2/token", { method: "POST", body: new URLSearchParams({
    grant_type: "authorization_code", client_id: app.client_id, redirect_uri: callback,
    code: returned.searchParams.get("code"), code_verifier: verifier,
  }) }));
  assert.equal(token.status, 200);
  assert.equal((await token.json()).scope, "reports");
}
