import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { jwt } from "better-auth/plugins";
import { oauthProvider } from "@better-auth/oauth-provider";
import { betterAuth } from "better-auth";
import { exportJWK, generateKeyPair, SignJWT } from "jose";

function options(mode) {
  if (mode === "disabled") return { loginPage: "/login", consentPage: "/consent" };
  return {
    loginPage: "/login",
    consentPage: "/consent",
    allowDynamicClientRegistration: true,
    allowUnauthenticatedClientRegistration: mode === "open",
    scopes: ["openid", "email", "reports", "extra"],
    clientRegistrationDefaultScopes: ["openid", "email"],
    clientRegistrationAllowedScopes: ["reports"],
    clientRegistrationDefaultApplicationType: "infer",
    clientRegistrationRequirePKCE: false,
    prefix: { clientSecret: "fixture_" },
    pairwiseSecret: "p".repeat(32),
    allowInsecureRedirectUri: (u) => u.hostname === "dev.example.test",
    clientPrivileges: ({ headers }) => !headers.get("X-Deny"),
    validateInitialAccessToken: ({ initialAccessToken }) => {
      if (initialAccessToken === "callback-error") throw new Error("private fixture message");
      return initialAccessToken === "initial" && { referenceId: "workspace" };
    },
    ...(mode === "resources"
      ? {
          resources: ["urn:reports", "urn:billing", "urn:disabled", "urn:missing"],
          clientRegistrationDefaultResources: ["urn:reports"],
          clientRegistrationAllowedResources: ["urn:billing", "urn:disabled", "urn:missing"],
        }
      : {}),
  };
}
export async function compareClientRegistration(t, reference, goFixture) {
  const standard = { redirect_uris: ["https://client.example.test/callback"] };
  for (const runtime of ["reference", "Go"]) {
    for (const mode of ["disabled", "protected", "open", "resources"]) {
      await t.test(runtime + " " + mode, async (t) => {
        const config = options(mode);
        const server =
          runtime === "Go"
            ? await goFixture(t, ["oauth-provider", "jwt"], { CONFORMANCE_CLIENT_REGISTRATION: mode })
            : await reference(t, [jwt(), oauthProvider(config)], { rateLimit: { enabled: false } });
        const db = server.database ?? new DatabaseSync(server.databasePath);
        if (!server.database) t.after(() => db.close());
        async function request(path, body, headers = {}) {
          return server.send(
            new Request(server.baseURL + "/api/auth/" + path, {
              method: "POST",
              headers: { "content-type": "application/json", origin: server.baseURL, ...headers },
              body: JSON.stringify(body),
            }),
          );
        }
        const register = (body, headers) => request("oauth2/register", body, headers);
        const token = { authorization: "Bearer initial" };
        async function problem(input, headers, status, code, challenge) {
          const r = await register(input, headers);
          const body = await r.json();
          assert.equal(r.status, status, JSON.stringify(body));
          assert.equal(body.error, code, JSON.stringify(body));
          assert.ok(body.error_description);
          if (challenge) assert.equal(r.headers.get("www-authenticate"), challenge);
          assert.doesNotMatch(JSON.stringify(body), /private fixture message/);
          return body;
        }
        if (mode === "disabled") {
          await problem(standard, {}, 403, "access_denied");
          return;
        }
        async function created(input, headers) {
          const r = await register(input, headers);
          const body = await r.json();
          assert.equal(r.status, 201, JSON.stringify(body));
          assert.match(r.headers.get("cache-control") ?? "", /no-store/);
          assert.match(body.client_id, /^[a-zA-Z]{32}$/);
          assert.ok(Number.isSafeInteger(body.client_id_issued_at));
          return body;
        }
        if (mode === "resources") {
          // Get the reference's startup migrations and seeds through a real request.
          await request("sign-up/email", {
            email: "fixture@resources.test",
            name: "owner",
            password: "local registration password",
          });
          if (runtime === "Go") {
            for (const id of ["urn:reports", "urn:billing", "urn:disabled", "urn:missing"]) {
              db.prepare(
                "INSERT INTO oauthResource(id,identifier,name,createdAt,updatedAt) VALUES(?,?,?,?,?)",
              ).run(id, id, id, new Date().toISOString(), new Date().toISOString());
            }
          }
          db.prepare("UPDATE oauthResource SET disabled=1 WHERE identifier='urn:disabled'").run();
          db.prepare("DELETE FROM oauthResource WHERE identifier='urn:missing'").run();
          const app = await created(
            { ...standard, resources: ["urn:billing", "urn:reports", "urn:billing"] },
            token,
          );
          assert.deepEqual(app.resources, ["urn:reports", "urn:billing"]);
          assert.deepEqual(
            db
              .prepare("SELECT resourceId FROM oauthClientResource WHERE clientId=? ORDER BY resourceId")
              .all(app.client_id)
              .map((v) => v.resourceId),
            ["urn:billing", "urn:reports"],
          );
          for (const id of ["urn:missing", "urn:disabled", "urn:outside"]) {
            await problem({ ...standard, resources: ["urn:billing", id] }, token, 400, "invalid_target");
          }
          assert.equal(db.prepare("SELECT count(*) AS count FROM oauthClient").get().count, 1);
          return;
        }
        for (const [bearer, status, code] of [
          ["Bearer", 400, "invalid_request"],
          ["Bearer invalid", 401, "invalid_token"],
        ]) {
          await problem(standard, { authorization: bearer }, status, code, 'Bearer error="' + code + '"');
        }
        await problem(standard, { authorization: "Bearer callback-error" }, 500, "server_error");
        if (mode === "open") {
          const app = await created(standard, {});
          assert.equal(app.user_id, undefined);
          assert.equal(app.reference_id, undefined);
          await problem({ grant_types: ["client_credentials"] }, {}, 400, "invalid_client_metadata");
          await problem({ ...standard, skip_consent: true }, {}, 400, "invalid_client_metadata");
          return;
        }
        await problem(standard, {}, 401, undefined, "Bearer");
        const response = await request("sign-up/email", {
          name: "Owner",
          email: "owner@registration.test",
          password: "local registration password",
        });
        assert.equal(response.status, 200);
        const { user } = await response.json();
        const cookie = response.headers
          .getSetCookie()
          .map((line) => line.split(";")[0])
          .join("; ");
        const input = {
          ...standard,
          grant_types: ["authorization_code", "client_credentials", "unavailable"],
          scope: "email",
          client_name: "Reports",
          client_uri: "https://client.example.test",
          logo_uri: "https://client.example.test/logo",
          contacts: ["support@example.test"],
          software_id: "app",
          software_version: "2.0",
          software_statement: "signed metadata",
          tos_uri: "https://client.example.test/terms",
          policy_uri: "https://client.example.test/privacy",
          dpop_bound_access_tokens: false,
          subject_type: "public",
          disabled: true,
          client_secret: "caller-value",
          reference_id: "wrong",
          user_id: "wrong",
          client_id: "wrong",
          client_credentials_scopes: ["reports"],
        };
        const app = await created(input, { cookie, authorization: "Bearer invalid" });
        assert.equal(app.user_id, user.id);
        assert.equal(app.reference_id, undefined);
        assert.deepEqual(app.grant_types, ["authorization_code", "client_credentials"]);
        assert.deepEqual(app.response_types, ["code"]);
        assert.equal(app.client_secret_expires_at, 0);
        assert.equal(app.require_pkce, false);
        assert.equal(app.scope, "openid email reports");
        assert.equal(app.application_type, "web");
        assert.equal(app.token_endpoint_auth_method, "client_secret_basic");
        assert.equal(app.dpop_bound_access_tokens, false);
        assert.equal(app.disabled, false);
        assert.equal(app.client_credentials_scopes, undefined);
        for (const field of [
          "client_name",
          "client_uri",
          "logo_uri",
          "contacts",
          "software_id",
          "software_version",
          "software_statement",
          "tos_uri",
          "policy_uri",
          "subject_type",
        ])
          assert.deepEqual(app[field], input[field], field);
        assert.match(app.client_secret, /^fixture_[a-zA-Z]{32}$/);
        const row = db.prepare("SELECT * FROM oauthClient WHERE clientId=?").get(app.client_id);
        assert.equal(
          row.clientSecret,
          createHash("sha256").update(app.client_secret.slice("fixture_".length)).digest("base64url"),
        );
        assert.deepEqual(JSON.parse(row.clientCredentialsScopes), []);
        assert.deepEqual(JSON.parse(row.scopes), ["openid", "email", "reports"]);
        assert.equal(row.userId, user.id);
        const denied = await register(standard, { cookie, "X-Deny": "1" });
        assert.equal(denied.status, 401);
        const pub = await created(
          {
            redirect_uris: ["com.example.app:/callback", "http://127.0.0.1:8252/cb"],
            token_endpoint_auth_method: "none",
          },
          token,
        );
        assert.equal(pub.application_type, "native");
        assert.equal(pub.client_secret, undefined);
        assert.equal(pub.client_secret_expires_at, undefined);
        assert.equal(pub.require_pkce, undefined);
        assert.equal(pub.reference_id, "workspace");
        assert.equal(pub.user_id, undefined);
        const credentials = await created(
          { grant_types: ["client_credentials"], token_endpoint_auth_method: "client_secret_post" },
          token,
        );
        assert.deepEqual(credentials.redirect_uris, []);
        assert.equal(credentials.response_types, undefined);
        const signer = await generateKeyPair("ES256");
        const key = { ...(await exportJWK(signer.publicKey)), alg: "ES256", kid: "fixture-signing-key" };
        const keyed = await created(
          {
            ...standard,
            grant_types: ["authorization_code", "client_credentials"],
            token_endpoint_auth_method: "private_key_jwt",
            jwks: { keys: [key] },
          },
          token,
        );
        assert.equal(keyed.client_secret, undefined);
        assert.deepEqual(keyed.jwks, { keys: [key] });
        for (const [bad, code] of [
          [{ scope: "extra" }, "invalid_scope"],
          [{ grant_types: ["unavailable"] }, "invalid_client_metadata"],
          [{ redirect_uris: ["http://client.example.test/cb"] }, "invalid_redirect_uri"],
          [{ redirect_uris: ["com.example:/cb"], application_type: "web" }, "invalid_redirect_uri"],
          [{ redirect_uris: ["https://user@client.example.test/cb"] }, "invalid_redirect_uri"],
          [{ token_endpoint_auth_method: "private_key_jwt" }, "invalid_client_metadata"],
          [{ jwks: { keys: [{ ...key, d: "private" }] } }, "invalid_client_metadata"],
          [{ backchannel_logout_uri: "https://localhost/logout" }, "invalid_client_metadata"],
        ])
          await problem({ ...standard, ...bad }, token, 400, code);

        // A separately initialized authorization server authenticates the actual
        // client row written by the registration endpoint and issues an M2M token.
        const issuer = betterAuth({
          database: db,
          baseURL: "http://issuer.localhost",
          secret: "local-registration-fixture-secret-0123456789",
          telemetry: { enabled: false },
          emailAndPassword: { enabled: true },
          plugins: [jwt(), oauthProvider(config)],
        });
        async function exchange(secret) {
          return issuer.handler(
            new Request("http://issuer.localhost/api/auth/oauth2/token", {
              method: "POST",
              headers: { "content-type": "application/x-www-form-urlencoded" },
              body: new URLSearchParams({
                grant_type: "client_credentials",
                client_id: credentials.client_id,
                client_secret: secret,
                scope: "reports",
              }),
            }),
          );
        }
        const unapproved = await exchange(credentials.client_secret);
        assert.equal(unapproved.status, 400);
        assert.equal((await unapproved.json()).error, "unauthorized_client");
        const operator = await issuer.api.signUpEmail({
          body: { name: "Operator", email: "operator@issuer.test", password: "local operator password" },
          asResponse: true,
        });
        assert.equal(operator.status, 200);
        const operatorCookie = operator.headers
          .getSetCookie()
          .map((line) => line.split(";")[0])
          .join("; ");
        const configured = await issuer.api.adminUpdateOAuthClient({
          headers: { cookie: operatorCookie },
          body: { client_id: credentials.client_id, update: { client_credentials_scopes: ["reports"] } },
        });
        assert.deepEqual(configured.client_credentials_scopes, ["reports"]);
        const exchanged = await exchange(credentials.client_secret);
        const result = await exchanged.json();
        assert.equal(exchanged.status, 200, JSON.stringify(result));
        assert.ok(result.access_token);
        assert.equal(result.scope, "reports");
        assert.equal((await (await exchange("incorrect")).json()).error, "invalid_client");
        await issuer.api.adminUpdateOAuthClient({
          headers: { cookie: operatorCookie },
          body: { client_id: keyed.client_id, update: { client_credentials_scopes: ["reports"] } },
        });
        const endpoint = "http://issuer.localhost/api/auth/oauth2/token";
        const assertion = await new SignJWT({})
          .setProtectedHeader({ alg: "ES256", kid: key.kid })
          .setIssuer(keyed.client_id)
          .setSubject(keyed.client_id)
          .setAudience(endpoint)
          .setIssuedAt()
          .setExpirationTime("90s")
          .setJti(randomUUID())
          .sign(signer.privateKey);
        const signedExchange = await issuer.handler(
          new Request(endpoint, {
            method: "POST",
            headers: { "content-type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({
              grant_type: "client_credentials",
              client_id: keyed.client_id,
              scope: "reports",
              client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
              client_assertion: assertion,
            }),
          }),
        );
        const signedToken = await signedExchange.json();
        assert.equal(signedExchange.status, 200, JSON.stringify(signedToken));
        assert.ok(signedToken.access_token);
      });
    }
  }
}
