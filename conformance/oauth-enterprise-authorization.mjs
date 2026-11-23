import assert from "node:assert/strict";
import {randomUUID} from "node:crypto";
import {DatabaseSync} from "node:sqlite";
import {oauthProvider} from "@better-auth/oauth-provider";
import {sso} from "@better-auth/sso";
import {jwt} from "better-auth/plugins";
import {enterpriseIdentityFixture} from "./sso-browser.mjs";
import {exerciseExternalLogin, issuerBrowser} from "./oauth-social-authorization.mjs";

export async function compareEnterpriseAuthorization(t, reference, goFixture) {
  const {issuer, grants} = await enterpriseIdentityFixture(t);
  for (const shared of [false, true]) {
    for (const runtime of ["reference", "Go"]) await t.test(`${runtime} ${shared ? "shared" : "directory"} callback`, async t => {
      const server = runtime === "Go"
        ? await goFixture(t, ["sso", "oauth-provider", "jwt"], {CONFORMANCE_CLIENT_REGISTRATION: "open",
          CONFORMANCE_SSO_DISCOVERY_ORIGIN: issuer, CONFORMANCE_SSO_SHARED_CALLBACK: shared ? "1" : "0"})
        : await reference(t, [sso(shared ? {redirectURI: "/sso/callback"} : {}), jwt(), oauthProvider({
          loginPage: "/login", consentPage: "/consent", scopes: ["reports"], allowDynamicClientRegistration: true,
          allowUnauthenticatedClientRegistration: true, clientRegistrationAllowedScopes: ["reports"],
        })], {trustedOrigins: [issuer], rateLimit: {enabled: false}});
      const db = server.database ?? new DatabaseSync(server.databasePath);
      if (!server.database) t.after(() => db.close());
      const browser = issuerBrowser(runtime, server);
      const {post, json, send, base} = browser;
      await json(await post("/sign-up/email", {email: "admin@example.test", password: "valid-long-password", name: "Admin"}));
      await json(await post("/sso/register", {providerId: "company", domain: "enterprise.example", issuer,
        oidcConfig: {skipDiscovery: true, authorizationEndpoint: issuer + "/authorize", tokenEndpoint: issuer + "/token",
          jwksEndpoint: issuer + "/keys", clientId: "catalog-client", clientSecret: "catalog-secret",
          tokenEndpointAuthentication: "client_secret_post", pkce: true}}));
      const email = "employee@enterprise.example";
      const returns = {callbackURL: server.baseURL + "/ordinary", newUserCallbackURL: server.baseURL + "/welcome",
        errorCallbackURL: server.baseURL + "/retry"};
      const signin = signed => post("/sign-in/sso", {domain: "enterprise.example", ...returns, oauth_query: signed});
      const approve = async (external, subject = "enterprise-employee", mailbox = email) => {
        const q = external.searchParams, code = randomUUID();
        const redirect = q.get("redirect_uri");
        assert.equal(redirect, base + "/sso/callback" + (shared ? "" : "/company"));
        grants.set(code, {redirect, challenge: q.get("code_challenge"), nonce: q.get("nonce"), email: mailbox, subject});
        const target = new URL(redirect);
        target.search = new URLSearchParams({code, state: q.get("state")});
        return target;
      };
      await exerciseExternalLogin({runtime, server, db, browser, signin, approve, issuer, email});
      assert.equal(db.prepare("SELECT count(*) AS n FROM account WHERE providerId='company'").get().n, 1);
      const missingReturn = await post("/sign-in/sso", {providerId: "company"});
      assert.equal(missingReturn.status, 400);
      for (const path of ["/welcome", "/ordinary"]) {
        const started = await json(await post("/sign-in/sso", {providerId: "company", ...returns}));
        const callback = await approve(new URL(started.url), "ordinary-employee", "ordinary@enterprise.example");
        const returned = await send(callback);
        assert.equal(returned.status, 302);
        assert.equal(returned.headers.get("location"), server.baseURL + path);
      }
      const pending = await json(await post("/sign-in/sso", {providerId: "company", ...returns}));
      const q = new URL(pending.url).searchParams;
      const denied = new URL(q.get("redirect_uri"));
      denied.search = new URLSearchParams({state: q.get("state"), error: "access_denied"});
      const failure = await send(denied);
      assert.equal(failure.status, 302);
      const retry = new URL(failure.headers.get("location"));
      assert.equal(retry.origin + retry.pathname, returns.errorCallbackURL);
      assert.ok(retry.searchParams.get("error"));
    });
  }
}
