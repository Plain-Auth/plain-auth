import assert from "node:assert/strict";
import {createHash, randomUUID} from "node:crypto";
import {DatabaseSync} from "node:sqlite";
import {jwt} from "better-auth/plugins";
import {oauthProvider} from "@better-auth/oauth-provider";
import {issuerBrowser} from "./oauth-social-authorization.mjs";

const scopes = ["openid", "email", "profile", "offline_access"];
const callback = "https://reader.example.test/signin";
const logoutURI = "https://reader.example.test/logged-out";

// RP-Initiated Logout on both runtimes: discovery, the JSON refusals, the
// browser confirmation page and its cookie, confirming, and a valid hint
// that ends the browser's session and follows the registered redirect.
export async function compareEndSession(t, {reference, goFixture}) {
  const results = {};
  for (const runtime of ["reference", "Go"]) await t.test(runtime, async t => {
    const server = runtime === "Go"
      ? await goFixture(t, ["oauth-provider", "jwt"], {CONFORMANCE_CLIENT_REGISTRATION: "oidc"})
      : await reference(t, [jwt(), oauthProvider({
        loginPage: "/login", consentPage: "/consent", scopes, allowDynamicClientRegistration: true,
        clientRegistrationAllowedScopes: scopes, prefix: {opaqueAccessToken: "at_"},
      })], {rateLimit: {enabled: false}});
    const db = server.database ?? new DatabaseSync(server.databasePath);
    if (!server.database) t.after(() => db.close());
    const {base, post, send, destination, json} = issuerBrowser(runtime, server);
    const record = {};
    const metadata = await json(await server.send(new Request(server.baseURL + "/api/auth/.well-known/openid-configuration")));
    record.endpoint = metadata.end_session_endpoint.slice(base.length);
    await json(await post("/sign-up/email", {name: "Logout Person", email: "logout@oidc.test", password: "local logout credential"}));
    const app = await json(await post("/oauth2/register", {redirect_uris: [callback], post_logout_redirect_uris: [logoutURI], grant_types: ["authorization_code"],
      token_endpoint_auth_method: "none", scope: "openid", application_type: "native"}), 201);
    db.prepare("UPDATE oauthClient SET enableEndSession=1 WHERE clientId=?").run(app.client_id);
    const endSession = (params, headers = {}) => send(metadata.end_session_endpoint + "?" + new URLSearchParams(params), {headers});
    const answer = async response => ({status: response.status, body: await response.json()});
    // Callers other than browsers get JSON refusals.
    record.refusals = [];
    for (const params of [{}, {client_id: "absent"}, {id_token_hint: "a.b.c", client_id: app.client_id}]) {
      record.refusals.push(await answer(await endSession(params, {accept: "application/json"})));
    }
    // A browser without a hint gets the confirmation page and its cookie.
    const navigate = {accept: "text/html", "sec-fetch-mode": "navigate"};
    const page = await endSession({}, navigate);
    const html = await page.text();
    const confirmation = page.headers.getSetCookie().find(line => line.split("=")[0].endsWith(".oauth_logout_confirmation"));
    assert.ok(confirmation, page.status + " " + page.headers.getSetCookie().join("\n"));
    const attributes = confirmation.split(";").slice(1).map(part => part.trim().toLowerCase()).filter(part => !part.startsWith("expires=") && part !== "secure").sort();
    record.page = {status: page.status, form: html.includes(`<form method="post" data-oidc-logout-confirmation action="${base}/oauth2/end-session/confirm">`),
      policy: page.headers.get("content-security-policy"), attributes};
    // Confirming ends the browser's session.
    const confirmed = await send(base + "/oauth2/end-session/confirm", {method: "POST", headers: {...navigate, origin: server.baseURL,
      "content-type": "application/x-www-form-urlencoded"}, body: "action=confirm"});
    record.confirmed = {status: confirmed.status, loggedOut: (await confirmed.text()).includes(`<p data-oidc-logout-state="logged-out">Logged out.</p>`)};
    record.afterConfirm = await (await send(base + "/get-session")).json();
    // A valid hint for the browser's session ends it and redirects with state.
    await json(await post("/sign-in/email", {email: "logout@oidc.test", password: "local logout credential"}));
    const verifier = randomUUID() + randomUUID();
    const query = {response_type: "code", client_id: app.client_id, redirect_uri: callback, scope: "openid", state: randomUUID(),
      code_challenge_method: "S256", code_challenge: createHash("sha256").update(verifier).digest("base64url")};
    const consent = await destination(await send(metadata.authorization_endpoint + "?" + new URLSearchParams(query), {headers: {accept: "application/json"}}));
    const approved = await destination(await post("/oauth2/consent", {oauth_query: consent.search.slice(1), accept: true}));
    const tokens = await json(await server.send(new Request(metadata.token_endpoint, {method: "POST", body: new URLSearchParams({
      client_id: app.client_id, grant_type: "authorization_code", code: approved.searchParams.get("code"), code_verifier: verifier, redirect_uri: callback,
    })})));
    const ended = await endSession({id_token_hint: tokens.id_token, post_logout_redirect_uri: logoutURI, state: "after"}, navigate);
    record.hinted = {status: ended.status, location: ended.headers.get("location")};
    record.afterHint = await (await send(base + "/get-session")).json();
    results[runtime] = record;
  });
  assert.deepEqual(results.Go, results.reference);
  assert.equal(results.Go.endpoint, "/oauth2/end-session");
  assert.deepEqual(results.Go.hinted, {status: 302, location: logoutURI + "?state=after"});
}
