import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { verifyOAuthQueryParams } from "@better-auth/oauth-provider";

export async function exerciseAccountSelection({ server, db, created, cookie, request }) {
  const base = server.baseURL + "/api/auth";
  const callback = "https://select.example.test/return";
  const app = await created({ redirect_uris: [callback], grant_types: ["authorization_code"],
    token_endpoint_auth_method: "none" }, { cookie });
  const verifier = randomUUID() + randomUUID();
  const state = randomUUID();
  const params = { response_type: "code", client_id: app.client_id, redirect_uri: callback, scope: "reports", state,
    code_challenge_method: "S256", code_challenge: createHash("sha256").update(verifier).digest("base64url") };

  async function destination(response) {
    const result = await response.json();
    assert.equal(response.status, 200, JSON.stringify(result));
    assert.equal(result.redirect, true);
    return new URL(result.url, server.baseURL);
  }
  function start(prompt, headers) {
    const q = new URLSearchParams(params);
    if (prompt) q.set("prompt", prompt);
    return server.send(new Request(base + "/oauth2/authorize?" + q, {
      headers: { accept: "application/json", ...headers },
    })).then(destination);
  }
  async function signed(page) {
    const value = page.search.slice(1);
    assert.equal(await verifyOAuthQueryParams(value, "local-conformance-0123456789-abcdefghijk"), true);
    return value;
  }
  const policy = { cookie, "X-Choose-Account": "yes" };
  const ordinary = await start(null, { cookie });
  assert.equal(ordinary.pathname, "/consent");
  const silent = await start("none", policy);
  assert.equal(silent.origin + silent.pathname, callback);
  assert.equal(silent.searchParams.get("error"), "account_selection_required");
  assert.equal(silent.searchParams.get("state"), state);
  assert.equal(silent.searchParams.get("iss"), base);
  const forced = await start("select_account consent", { cookie });
  assert.equal(forced.pathname, "/choose-account");
  const continued = await request("oauth2/continue", { selected: true, oauth_query: await signed(forced) }, policy);
  const forcedConsent = await destination(continued);
  assert.equal(forcedConsent.pathname, "/consent");
  assert.equal(forcedConsent.searchParams.get("prompt"), "consent");

  const choice = await start(null, policy);
  assert.equal(choice.pathname, "/choose-account");
  const selected = await signed(choice);
  const other = await request("sign-up/email", { name: "Selected account", email: "selected@account.example.test", password: "local account selector password" });
  assert.equal(other.status, 200);
  const selectedUser = (await other.json()).user.id;
  const selectedCookie = other.headers.getSetCookie().map(v => v.split(";")[0]).join("; ");
  const headers = { cookie: selectedCookie, "X-Choose-Account": "yes" };
  const modified = new URLSearchParams(selected);
  modified.set("redirect_uri", "https://other.example.test");
  const invalid = await request("oauth2/continue", { selected: true, oauth_query: modified.toString() }, headers);
  assert.equal(invalid.status, 400);
  const consent = await destination(await request("oauth2/continue", { selected: true, oauth_query: selected }, headers));
  assert.equal(consent.pathname, "/consent");
  const returned = await destination(await request("oauth2/consent", { accept: true, oauth_query: await signed(consent) }, headers));
  assert.equal(returned.origin + returned.pathname, callback);
  assert.equal(returned.searchParams.get("state"), state);
  const exchanged = await server.send(new Request(base + "/oauth2/token", { method: "POST", body: new URLSearchParams({
    grant_type: "authorization_code", client_id: app.client_id, redirect_uri: callback,
    code: returned.searchParams.get("code"), code_verifier: verifier,
  }) }));
  assert.equal(exchanged.status, 200);
  assert.equal((await exchanged.json()).scope, "reports");
  const issued = db.prepare("SELECT t.userId, s.userId AS sessionOwner FROM oauthAccessToken t JOIN session s ON s.id=t.sessionId WHERE t.clientId=?").all(app.client_id);
  assert.equal(issued.length, 1);
  assert.equal(issued[0].userId, selectedUser);
  assert.equal(issued[0].sessionOwner, selectedUser);
  const grants = db.prepare("SELECT userId FROM oauthConsent WHERE clientId=?").all(app.client_id);
  assert.deepEqual(grants.map(row => row.userId), [selectedUser]);
  const afterApproval = await start("none", { cookie: selectedCookie });
  assert.ok(afterApproval.searchParams.get("code"));
  const loginFirst = await start("login select_account", headers);
  assert.equal(loginFirst.pathname, "/login");
  const login = await request("sign-in/email", { email: "selected@account.example.test", password: "local account selector password", oauth_query: await signed(loginFirst) }, headers);
  const afterLogin = await destination(login);
  assert.equal(afterLogin.origin + afterLogin.pathname, callback);
  assert.ok(afterLogin.searchParams.get("code"));

  const stillForced = await start("select_account consent", { cookie: selectedCookie });
  const reconfirm = await destination(await request("oauth2/continue", { selected: true, oauth_query: await signed(stillForced) }, headers));
  assert.equal(reconfirm.pathname, "/consent");
}
