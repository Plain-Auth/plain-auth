import assert from "node:assert/strict";
import { jwt } from "better-auth/plugins";
import { oauthProvider } from "@better-auth/oauth-provider";

export const pushedCallback = "https://reader.example.test/callback";

// The pushed request both runtimes resolve for urn:par:good.
export function pushedRequest() {
  return { response_type: "code", redirect_uri: pushedCallback, scope: "openid", state: "pushed",
    code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", code_challenge_method: "S256" };
}

// A pushed authorization request resolves through the host callback: the
// login page carries the stored parameters, and an unknown URI or a missing
// client goes to the error page.
export async function compareRequestURI(t, { reference, goFixture }) {
  for (const runtime of ["reference", "Go"]) {
    await t.test(runtime, async t => {
      const server = runtime === "reference" ? await reference(t, [jwt(), oauthProvider({
        loginPage: "/login", consentPage: "/consent", allowDynamicClientRegistration: true,
        scopes: ["openid", "email", "reports", "extra"], clientRegistrationDefaultScopes: ["openid", "email"],
        clientRegistrationAllowedScopes: ["reports"],
        requestUriResolver: async ({ requestUri }) => (requestUri === "urn:par:good" ? pushedRequest() : null),
      })], { rateLimit: { enabled: false } }) : await goFixture(t, ["oauth-provider", "jwt"], {
        CONFORMANCE_CLIENT_REGISTRATION: "protected", CONFORMANCE_REQUEST_URI: "1",
      });
      const post = (path, body, headers = {}) => server.send(new Request(server.baseURL + "/api/auth" + path, {
        method: "POST", headers: { "content-type": "application/json", origin: server.baseURL, ...headers }, body: JSON.stringify(body),
      }));
      const signup = await post("/sign-up/email", { name: "Reader", email: "pushed-request@issuer.test", password: "pushed request fixture" });
      const cookie = signup.headers.getSetCookie().map(v => v.split(";")[0]).join("; ");
      const registered = await post("/oauth2/register", { redirect_uris: [pushedCallback], token_endpoint_auth_method: "none", grant_types: ["authorization_code"] }, { cookie });
      assert.equal(registered.status, 201);
      const app = await registered.json();
      const authorize = async params => {
        const res = await server.send(new Request(server.baseURL + "/api/auth/oauth2/authorize?" + new URLSearchParams(params), { mode: "same-origin", redirect: "manual" }));
        assert.equal(res.status, 302);
        return new URL(res.headers.get("location"), server.baseURL);
      };
      const login = await authorize({ client_id: app.client_id, request_uri: "urn:par:good", state: "url", scope: "reports" });
      assert.equal(login.pathname, "/login");
      assert.equal(login.searchParams.get("state"), "pushed");
      assert.equal(login.searchParams.get("scope"), "openid");
      assert.equal(login.searchParams.get("client_id"), app.client_id);
      assert.equal(login.searchParams.has("request_uri"), false);
      for (const [params, error, description] of [
        [{ client_id: app.client_id, request_uri: "urn:par:gone" }, "invalid_request_uri", "request_uri is invalid or expired"],
        [{ request_uri: "urn:par:good" }, "invalid_request", "client_id is required"],
      ]) {
        const refused = await authorize(params);
        assert.equal(refused.origin + refused.pathname, server.baseURL + "/api/auth/error");
        assert.equal(refused.searchParams.get("error"), error);
        assert.equal(refused.searchParams.get("error_description"), description);
      }
    });
  }
}
