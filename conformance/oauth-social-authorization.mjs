import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { get } from "node:http";
import { DatabaseSync } from "node:sqlite";
import { jwt } from "better-auth/plugins";
import { genericOAuth } from "better-auth/plugins/generic-oauth";
import { oauthProvider } from "@better-auth/oauth-provider";
import { issuerFixture } from "./social-user-fields.mjs";

export async function compareSocialAuthorization(t, reference, goFixture) {
  for (const runtime of ["reference", "Go"]) await t.test(runtime, async t => {
    const identity = await issuerFixture(t);
    identity.profile({id: "social-owner", name: "Owner", email: "owner@social.test", emailVerified: true});
    const server = runtime === "Go"
      ? await goFixture(t, ["oauth-provider", "jwt"], { CONFORMANCE_CLIENT_REGISTRATION: "open",
        CONFORMANCE_SOCIAL_FIELD_ISSUER: identity.base, CONFORMANCE_PROVIDER: "1" })
      : await reference(t, [
        genericOAuth({config: [{providerId: "work", clientId: "profile-app", clientSecret: "local-secret",
          pkce: true, scopes: ["profile"], authorizationUrl: identity.base + "/authorize",
          tokenUrl: identity.base + "/token", userInfoUrl: identity.base + "/userinfo",
          accountSubject: ({profile}) => profile.id}]}),
        jwt(), oauthProvider({loginPage: "/login", consentPage: "/consent", scopes: ["reports"],
          allowDynamicClientRegistration: true, allowUnauthenticatedClientRegistration: true,
          clientRegistrationAllowedScopes: ["reports"]}),
      ], {rateLimit: {enabled: false}});
    const db = server.database ?? new DatabaseSync(server.databasePath);
    if (!server.database) t.after(() => db.close());
    const base = server.baseURL + "/api/auth";
    const jar = new Map();
    async function send(url, options = {}) {
      const headers = new Headers(options.headers);
      headers.set("cookie", [...jar].map(([name, value]) => name + "=" + value).join("; "));
      let response;
      if (runtime === "Go" && headers.get("sec-fetch-mode") === "navigate") {
        // fetch supplies its own CORS mode on the wire. Send the headers of a
        // top-level browser GET for the navigation case.
        response = await new Promise((resolve, reject) => {
          get(url, {headers: Object.fromEntries(headers)}, res => {
            res.resume();
            const reply = new Headers();
            for (let i = 0; i < res.rawHeaders.length; i += 2) reply.append(res.rawHeaders[i], res.rawHeaders[i + 1]);
            resolve(new Response(null, {status: res.statusCode, headers: reply}));
          }).on("error", reject);
        });
      } else {
        response = await server.send(new Request(url, {...options, headers, redirect: "manual"}));
      }
      for (const line of response.headers.getSetCookie()) {
        const pair = line.split(";")[0], index = pair.indexOf("=");
        if (pair.length === index + 1) jar.delete(pair.slice(0, index));
        else jar.set(pair.slice(0, index), pair.slice(index + 1));
      }
      return response;
    }
    const post = (path, body) => send(base + path, {method: "POST", headers: {
      origin: server.baseURL, "content-type": "application/json", accept: "application/json",
    }, body: JSON.stringify(body)});
    async function json(response, status = 200) {
      const data = await response.json();
      assert.equal(response.status, status, JSON.stringify(data));
      return data;
    }
    async function destination(response, status = 200) {
      const data = await json(response, status);
      assert.equal(data.redirect, true);
      return new URL(data.url, server.baseURL);
    }
    const callback = "https://reports.example.test/finish";
    const app = await json(await post("/oauth2/register", {redirect_uris: [callback], application_type: "native",
      scope: "reports", grant_types: ["authorization_code"], token_endpoint_auth_method: "none"}), 201);
    const verifier = randomUUID() + randomUUID(), state = randomUUID();
    const params = new URLSearchParams({response_type: "code", client_id: app.client_id, redirect_uri: callback, scope: "reports",
      state, prompt: "login consent", max_age: "0", code_challenge_method: "S256",
      code_challenge: createHash("sha256").update(verifier).digest("base64url")});
    async function begin() {
      const login = await destination(await send(base + "/oauth2/authorize?" + params, {headers: {accept: "application/json"}}));
      assert.equal(login.pathname, "/login");
      return login.search.slice(1);
    }
    const signin = signed => post("/sign-in/social", {provider: "work", disableRedirect: true,
      oauth_query: signed, callbackURL: "/ordinary", newUserCallbackURL: "/welcome", errorCallbackURL: "/retry",
      additionalData: {query: "state=untrusted", serverContext: {query: "state=untrusted"}}});
    const signed = await begin();
    const changed = new URLSearchParams(signed);
    changed.set("state", "changed");
    assert.equal((await json(await signin(changed.toString()), 400)).error, "invalid_signature");
    assert.equal(db.prepare("SELECT count(*) AS n FROM session").get().n, 0);
    for (const navigation of [false, true]) {
      const started = await json(await signin(await begin()));
      const external = new URL(started.url);
      assert.equal(external.origin, identity.base);
      assert.notEqual(external.searchParams.get("state"), state);
      assert.equal(external.searchParams.get("code_challenge_method"), "S256");
      assert.ok(external.searchParams.get("code_challenge"));
      assert.notEqual(external.searchParams.get("code_challenge"), params.get("code_challenge"));
      assert.equal(external.searchParams.has("oauth_query"), false);
      const approval = await fetch(external, {redirect: "manual"});
      assert.equal(approval.status, 302);
      const providerCallback = approval.headers.get("location");
      const finished = await send(providerCallback, {headers: navigation
        ? {accept: "text/html", "sec-fetch-mode": "navigate"} : {accept: "application/json"}});
      let consent;
      if (navigation) {
        assert.equal(finished.status, 302);
        consent = new URL(finished.headers.get("location"), server.baseURL);
      } else {
        // The reference keeps the outer callback's 302 on its JSON result.
        // A Go JSON client receives the destination without an automatic hop.
        if (runtime === "Go") assert.equal(finished.headers.get("location"), null);
        consent = await destination(finished, runtime === "Go" ? 200 : 302);
      }
      assert.equal(consent.pathname, "/consent");
      assert.equal(consent.searchParams.get("state"), state);
      assert.equal(consent.searchParams.get("prompt"), "consent");
      assert.equal(consent.searchParams.has("max_age"), false);
      const session = await json(await send(base + "/get-session"));
      assert.equal(session.user.email, "owner@social.test");
      const issued = await destination(await post("/oauth2/consent", {accept: true, oauth_query: consent.search.slice(1)}));
      assert.equal(issued.origin + issued.pathname, callback);
      assert.equal(issued.searchParams.get("state"), state);
      const code = issued.searchParams.get("code");
      assert.ok(code);
      const tokens = await json(await server.send(new Request(base + "/oauth2/token", {method: "POST", body: new URLSearchParams({
        grant_type: "authorization_code", code, client_id: app.client_id, code_verifier: verifier, redirect_uri: callback,
      })})));
      assert.equal(tokens.scope, "reports");
      const hash = createHash("sha256").update(code).digest("base64url");
      const row = db.prepare("SELECT userId,sessionId FROM oauthAccessToken WHERE authorizationCodeId=?").get(hash);
      assert.equal(row.userId, session.user.id);
      assert.equal(row.sessionId, session.session.id);
    }
    // An ordinary social login keeps its own callback, even if the caller
    // includes an otherwise valid issuer query in arbitrary additional data.
    const ordinary = await json(await post("/sign-in/social", {provider: "work", disableRedirect: true,
      callbackURL: "/ordinary", additionalData: {serverContext: {query: signed}, query: signed}}));
    const approval = await fetch(ordinary.url, {redirect: "manual"});
    const returned = await send(approval.headers.get("location"));
    assert.equal(returned.status, 302);
    const location = new URL(returned.headers.get("location"), server.baseURL);
    assert.equal(location.pathname, "/ordinary");
    assert.equal(location.searchParams.has("code"), false);
  });
}
