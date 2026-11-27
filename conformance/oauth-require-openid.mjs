import assert from "node:assert/strict";
import { jwt } from "better-auth/plugins";
import { oauthProvider } from "@better-auth/oauth-provider";

// With the openid scope required, an authorization request whose scope
// parameter is missing or omits openid returns invalid_scope to the
// client's callback with its state and the issuer; one naming openid goes on
// to the login page.
export async function compareRequiredOpenID(t, { reference, goFixture }) {
  const callback = "https://reader.example.test/callback";
  for (const runtime of ["reference", "Go"]) {
    await t.test(runtime, async t => {
      const server = runtime === "reference" ? await reference(t, [jwt(), oauthProvider({
        loginPage: "/login", consentPage: "/consent", allowDynamicClientRegistration: true,
        scopes: ["openid", "email", "reports", "extra"], clientRegistrationDefaultScopes: ["openid", "email"],
        clientRegistrationAllowedScopes: ["reports"], requireOpenId: true,
      })], { rateLimit: { enabled: false } }) : await goFixture(t, ["oauth-provider", "jwt"], {
        CONFORMANCE_CLIENT_REGISTRATION: "protected", CONFORMANCE_REQUIRE_OPENID: "1",
      });
      const post = (path, body, headers = {}) => server.send(new Request(server.baseURL + "/api/auth" + path, {
        method: "POST", headers: { "content-type": "application/json", origin: server.baseURL, ...headers }, body: JSON.stringify(body),
      }));
      const signup = await post("/sign-up/email", { name: "Reader", email: "require-openid@issuer.test", password: "require openid fixture" });
      assert.equal(signup.status, 200);
      const cookie = signup.headers.getSetCookie().map(v => v.split(";")[0]).join("; ");
      const registered = await post("/oauth2/register", { redirect_uris: [callback], token_endpoint_auth_method: "none", grant_types: ["authorization_code"] }, { cookie });
      assert.equal(registered.status, 201);
      const app = await registered.json();
      const authorize = async scope => {
        const q = new URLSearchParams({ response_type: "code", client_id: app.client_id, redirect_uri: callback, state: "kept",
          code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", code_challenge_method: "S256" });
        if (scope !== undefined) q.set("scope", scope);
        const res = await server.send(new Request(server.baseURL + "/api/auth/oauth2/authorize?" + q, { mode: "same-origin", redirect: "manual" }));
        assert.equal(res.status, 302);
        return new URL(res.headers.get("location"), server.baseURL);
      };
      for (const scope of [undefined, "", "email"]) {
        const refused = await authorize(scope);
        assert.equal(refused.origin + refused.pathname, callback);
        assert.equal(refused.searchParams.get("error"), "invalid_scope");
        assert.equal(refused.searchParams.get("error_description"), "the openid scope is required");
        assert.equal(refused.searchParams.get("state"), "kept");
        assert.equal(refused.searchParams.get("iss"), server.baseURL + "/api/auth");
      }
      const unknown = await authorize("openid write extra-thing");
      assert.equal(unknown.searchParams.get("error_description"), "The following scopes are invalid: write, extra-thing");
      const login = await authorize("openid email");
      assert.equal(login.pathname, "/login");
    });
  }
}
