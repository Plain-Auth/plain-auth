import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { jwt, organization } from "better-auth/plugins";
import { oauthProvider, verifyOAuthQueryParams } from "@better-auth/oauth-provider";

export async function comparePostLogin(t, reference, goFixture) {
  for (const runtime of ["reference", "Go"]) await t.test(runtime, async t => {
    let db;
    const plugin = oauthProvider({
      loginPage: "/login", consentPage: "/consent", scopes: ["reports", "email"],
      allowDynamicClientRegistration: true, clientRegistrationAllowedScopes: ["reports", "email"],
      postLogin: {
        page: "/select-organization",
        shouldRedirect: ({ session, user, isContinuation }) => {
          const memberships = db.prepare("SELECT organizationId FROM member WHERE userId=?").all(user.id);
          return !memberships.some(m => m.organizationId === session.activeOrganizationId) || (!isContinuation && memberships.length > 1);
        },
        consentReferenceId: ({ session }) => {
          return session.activeOrganizationId ?? "";
        },
      },
    });
    const server = runtime === "Go" ? await goFixture(t, ["organization", "oauth-provider", "jwt"], { CONFORMANCE_CLIENT_REGISTRATION: "post-login" })
      : await reference(t, [organization(), jwt(), plugin], { rateLimit: { enabled: false } });
    db = server.database ?? new DatabaseSync(server.databasePath);
    if (!server.database) t.after(() => db.close());
    const base = server.baseURL + "/api/auth";
    let cookie = "";
    async function post(path, body) {
      return server.send(new Request(base + path, { method: "POST", redirect: "manual",
        headers: { cookie, origin: server.baseURL, "content-type": "application/json" }, body: JSON.stringify(body) }));
    }
    async function result(response, status = 200) {
      const body = await response.json();
      assert.equal(response.status, status, JSON.stringify(body));
      return body;
    }
    async function destination(response) {
      const body = await result(response);
      assert.equal(body.redirect, true);
      return new URL(body.url, server.baseURL);
    }
    const account = await post("/sign-up/email", { name: "Owner", email: "post-login@issuer.test", password: "local organization flow" });
    const owner = (await result(account)).user.id;
    cookie = account.headers.getSetCookie().map(v => v.split(";")[0]).join("; ");
    const session = db.prepare("SELECT id FROM session WHERE userId=?").get(owner).id;
    const groups = [];
    for (const slug of ["first", "second"]) groups.push((await result(await post("/organization/create", {
      name: slug, slug, keepCurrentActiveOrganization: true,
    }))).id);
    const callback = "https://organization.example.test/return";
    const app = await result(await post("/oauth2/register", { redirect_uris: [callback], grant_types: ["authorization_code"],
      scope: "reports email", token_endpoint_auth_method: "none" }), 201);
    const verifier = randomUUID() + randomUUID();
    const params = { response_type: "code", client_id: app.client_id, redirect_uri: callback, scope: "reports email", state: randomUUID(),
      code_challenge_method: "S256", code_challenge: createHash("sha256").update(verifier).digest("base64url") };
    async function begin(extra = {}) {
      const q = new URLSearchParams({ ...params, ...extra });
      return destination(await server.send(new Request(base + "/oauth2/authorize?" + q, { headers: { cookie, accept: "application/json" } })));
    }
    async function query(page) {
      assert.equal(page.searchParams.get("state"), params.state);
      assert.equal(await verifyOAuthQueryParams(page.search.slice(1), "local-conformance-0123456789-abcdefghijk"), true);
      return page.search.slice(1);
    }
    const select = id => post("/organization/set-active", { organizationId: id }).then(result);
    async function resume(page) { return destination(await post("/oauth2/continue", { postLogin: true, oauth_query: await query(page) })); }
    async function exchange(page, scope, organizationId) {
      assert.equal(page.origin + page.pathname, callback);
      assert.equal(page.searchParams.get("iss"), base);
      const code = page.searchParams.get("code");
      assert.ok(code);
      const response = await server.send(new Request(base + "/oauth2/token", { method: "POST", body: new URLSearchParams({
        grant_type: "authorization_code", code, client_id: app.client_id, redirect_uri: callback, code_verifier: verifier,
      }) }));
      assert.equal((await result(response)).scope, scope);
      const digest = createHash("sha256").update(code).digest("base64url");
      assert.equal(db.prepare("SELECT referenceId FROM oauthAccessToken WHERE authorizationCodeId=?").get(digest).referenceId, organizationId);
    }
    const silent = await begin({ prompt: "none" });
    assert.equal(silent.origin + silent.pathname, callback);
    assert.equal(silent.searchParams.get("error"), "interaction_required");
    assert.equal(silent.searchParams.get("iss"), base);
    assert.equal(silent.searchParams.get("state"), params.state);

    const gate = await begin({ ba_pl: session });
    assert.equal(gate.pathname, "/select-organization");
    assert.equal(gate.searchParams.has("ba_pl"), false);
    const stillRequired = await resume(gate);
    assert.equal(stillRequired.pathname, "/select-organization");
    assert.equal(stillRequired.searchParams.has("code"), false);
    assert.equal(stillRequired.searchParams.has("ba_pl"), false);
    for (const [index, id] of groups.entries()) {
      const current = index === 0 ? stillRequired : await begin();
      assert.equal(current.pathname, "/select-organization");
      // The cookie reissued by set-active can also resume the signed request.
      // A host that asks on every fresh authorization still needs explicit continuation.
      const picked = await destination(await post("/organization/set-active", { organizationId: id, oauth_query: await query(current) }));
      assert.equal(picked.pathname, "/select-organization");
      const consent = await resume(current);
      assert.equal(consent.pathname, "/consent");
      assert.equal(consent.searchParams.get("ba_pl"), session);
      const accepted = index === 0 ? "reports" : "reports email";
      const redirect = await destination(await post("/oauth2/consent", { accept: true, scope: accepted, oauth_query: await query(consent) }));
      await exchange(redirect, accepted, id);
    }
    const grants = db.prepare("SELECT referenceId,scopes FROM oauthConsent WHERE userId=? AND clientId=?").all(owner, app.client_id);
    assert.equal(grants.length, 2);
    assert.deepEqual(JSON.parse(grants.find(g => g.referenceId === groups[0]).scopes), ["reports"]);
    assert.deepEqual(JSON.parse(grants.find(g => g.referenceId === groups[1]).scopes), ["reports", "email"]);
    const returning = await begin({ scope: "reports" });
    assert.equal(returning.pathname, "/select-organization");
    await select(groups[0]);
    await exchange(await resume(returning), "reports", groups[0]);

    const forceConsent = await begin({ prompt: "consent", scope: "reports" });
    const oldConsent = await resume(forceConsent);
    assert.equal(oldConsent.pathname, "/consent");
    const fresh = await post("/sign-in/email", { email: "post-login@issuer.test", password: "local organization flow" });
    await result(fresh);
    cookie = fresh.headers.getSetCookie().map(v => v.split(";")[0]).join("; ");
    // Give the new session a valid reference. The previous session's clearance
    // cannot satisfy its policy, even for the same user and organization.
    await select(groups[0]);
    const repeat = await destination(await post("/oauth2/consent", { accept: true, oauth_query: await query(oldConsent) }));
    assert.equal(repeat.pathname, "/select-organization");
    assert.equal(repeat.searchParams.has("ba_pl"), false);
    assert.equal(repeat.searchParams.has("code"), false);

    await select(null);
    const gateOnly = await begin({ prompt: "consent" });
    const misplaced = await destination(await post("/oauth2/consent", { accept: true, oauth_query: await query(gateOnly) }));
    assert.equal(misplaced.pathname, "/select-organization");
    assert.equal(misplaced.searchParams.has("code"), false);
    if (runtime === "Go") {
      assert.equal(db.prepare("SELECT COUNT(*) AS n FROM oauthConsent WHERE clientId=? AND (referenceId IS NULL OR referenceId='')").get(app.client_id).n, 0);
    }
  });
}
