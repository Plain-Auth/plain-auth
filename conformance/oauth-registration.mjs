import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { jwt } from "better-auth/plugins";
import { oauthProvider } from "@better-auth/oauth-provider";
import { betterAuth } from "better-auth";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { exerciseMachineTokens } from "./oauth-machine-tokens.mjs";
import { exerciseIntrospection } from "./oauth-introspection.mjs";
import { exerciseClientKeyRotation } from "./oauth-key-rotation.mjs";
import { exerciseClientAssertions } from "./oauth-client-assertions.mjs";
import { exerciseRevocation } from "./oauth-revocation.mjs";

function options(mode) {
  if (mode === "disabled") return { loginPage: "/login", consentPage: "/consent" };
  return {
    loginPage: "/login",
    consentPage: "/consent",
    allowDynamicClientRegistration: true,
    cachedTrustedClients: new Set(["operator-managed"]),
    clientReference: ({ user }) => (user.email === "tenant-rotation@registration.test" ? "workspace" : undefined),
    allowUnauthenticatedClientRegistration: mode === "open",
    scopes: ["openid", "email", "reports", "extra"],
    clientRegistrationDefaultScopes: ["openid", "email"],
    clientRegistrationAllowedScopes: ["reports"],
    clientRegistrationDefaultApplicationType: "infer",
    clientRegistrationRequirePKCE: false,
    prefix: { clientSecret: "fixture_", ...(mode === "protected" && { opaqueAccessToken: "access_" }) },
    ...(mode === "protected" && { allowClientKeyRotation: true, m2mAccessTokenExpiresIn: 600, scopeExpirations: { reports: "90s" } }),
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
          const closed = await request("oauth2/client/rotate-keys", {
            client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            client_assertion: "unused", jwks: { keys: [{ kty: "EC", crv: "P-256", x: "x", y: "y" }] },
          });
          assert.equal(closed.status, 403);
          assert.equal((await closed.json()).error, "access_denied");
          for (const jwks of [{}, { keys: [] }, { keys: ["invalid"] }]) {
            const invalid = await request("oauth2/client/rotate-keys", {
              client_assertion: "unused", client_assertion_type: "unused", jwks,
            });
            assert.equal(invalid.status, 400);
            assert.equal((await invalid.json()).error, "invalid_client_metadata");
          }
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
        async function exchange(secret, clientID = credentials.client_id, scope = "reports") {
          const body = new URLSearchParams({
            grant_type: "client_credentials",
            client_id: clientID,
            client_secret: secret,
          });
          if (scope !== null) body.set("scope", scope);
          return issuer.handler(
            new Request("http://issuer.localhost/api/auth/oauth2/token", {
              method: "POST",
              headers: { "content-type": "application/x-www-form-urlencoded" },
              body,
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
        async function setMachineScopes(id, scopes) {
          if (runtime === "reference") {
            return server.api.adminUpdateOAuthClient({
              headers: { cookie },
              body: { client_id: id, update: { client_credentials_scopes: scopes } },
            });
          }
          const result = await server.send(new Request(server.baseURL + "/__fixture/client-scopes", {
            method: "POST",
            headers: { "content-type": "application/json", cookie },
            body: JSON.stringify({ client_id: id, client_credentials_scopes: scopes }),
          }));
          const body = await result.json();
          if (!result.ok) throw Object.assign(new Error("scope configuration failed"), { statusCode: result.status, body });
          return body;
        }
        const configured = await setMachineScopes(credentials.client_id, [" reports ", "reports"]);
        assert.deepEqual(configured.client_credentials_scopes, ["reports"]);
        await t.test("issue opaque machine tokens accepted by an independent authorization server", async () => {
          await exerciseMachineTokens({ server, issuer, db, credentials, cookie, created, setMachineScopes });
        });
        await t.test("introspect opaque machine tokens minted and revoked by an independent issuer", async () => {
          await exerciseIntrospection({ server, issuer, exchange, credentials, created, cookie, setMachineScopes });
        });
        await t.test("revoke access and refresh tokens and recognize independently signed access tokens", async () => {
          await exerciseRevocation({ runtime, server, issuer, db, credentials, created, cookie, exchange });
        });
        const exchanged = await exchange(credentials.client_secret);
        const result = await exchanged.json();
        assert.equal(exchanged.status, 200, JSON.stringify(result));
        assert.ok(result.access_token);
        assert.equal(result.scope, "reports");
        assert.equal((await (await exchange("incorrect")).json()).error, "invalid_client");
        await t.test("machine scope changes control issuance independently of user scopes", async () => {
          for (const blank of ["", " \t "]) {
            await assert.rejects(setMachineScopes(credentials.client_id, ["reports", blank]), (failure) =>
              failure.statusCode === 400 && failure.body.code === "VALIDATION_ERROR" &&
              failure.body.message === "[body.update.client_credentials_scopes.1] Too small: expected string to have >=1 characters",
            );
          }
          const cleared = await setMachineScopes(credentials.client_id, []);
          assert.deepEqual(cleared.client_credentials_scopes, []);
          const refused = await exchange(credentials.client_secret);
          assert.equal(refused.status, 400);
          assert.equal((await refused.json()).error, "unauthorized_client");
          const narrowed = await setMachineScopes(credentials.client_id, ["extra"]);
          assert.deepEqual(narrowed.client_credentials_scopes, ["extra"]);
          assert.equal((await (await exchange(credentials.client_secret)).json()).error, "invalid_scope");
          const implicit = await exchange(credentials.client_secret, credentials.client_id, null);
          assert.equal(implicit.status, 200);
          assert.equal((await implicit.json()).scope, "extra");
          assert.deepEqual((await setMachineScopes(credentials.client_id, ["reports"])).client_credentials_scopes, ["reports"]);
        });
        await issuer.api.adminUpdateOAuthClient({
          headers: { cookie: operatorCookie },
          body: { client_id: keyed.client_id, update: { client_credentials_scopes: ["reports"] } },
        });
        await t.test("authenticate with signed client assertions and share replay protection between issuers", async () => {
          await exerciseClientAssertions({ server, issuer, keyed, signer, key });
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

        await t.test("rotate inline application keys with a single-use endpoint-specific assertion", async () => {
          await exerciseClientKeyRotation({ server, issuer, keyed, signer, key });
        });
        await t.test("rotate shared client secrets and invalidate the original credential", async () => {
          const rotate = (headers, payload) => request("oauth2/client/rotate-secret", payload, headers);
          const tenant = await request("sign-up/email", {
            name: "Workspace",
            email: "tenant-rotation@registration.test",
            password: "local tenant password",
          });
          assert.equal(tenant.status, 200);
          const tenantCookie = tenant.headers
            .getSetCookie()
            .map((line) => line.split(";")[0])
            .join("; ");
          const machine = { client_id: credentials.client_id };
          assert.equal((await rotate({}, machine)).status, 401);
          assert.equal((await rotate({ cookie }, machine)).status, 401);
          assert.equal((await rotate({ cookie: tenantCookie, "X-Deny": "yes" }, machine)).status, 401);
          for (const [id, status, code] of [
            ["missing", 404, "not_found"],
            ["operator-managed", 400, "invalid_client"],
            [keyed.client_id, 400, "invalid_client"],
            [pub.client_id, 400, "invalid_client"],
          ]) {
            const failure = await rotate({ cookie: tenantCookie }, { client_id: id });
            assert.equal(failure.status, status);
            assert.equal((await failure.json()).error, code);
          }
          const invalid = await rotate({ cookie }, { client_id: 123 });
          assert.equal(invalid.status, 400);
          assert.equal((await invalid.json()).code, "VALIDATION_ERROR");
          const response = await rotate({ cookie: tenantCookie }, machine);
          const updated = await response.json();
          assert.equal(response.status, 200, JSON.stringify(updated));
          assert.match(response.headers.get("cache-control") ?? "", /no-store/);
          assert.match(updated.client_secret, /^fixture_[a-zA-Z]{32}$/);
          assert.notEqual(updated.client_secret, credentials.client_secret);
          assert.deepEqual({ ...updated, client_secret: credentials.client_secret }, credentials);
          assert.equal((await (await exchange(credentials.client_secret)).json()).error, "invalid_client");
          const issuedAfterRotation = await exchange(updated.client_secret);
          assert.equal(issuedAfterRotation.status, 200);
          assert.ok((await issuedAfterRotation.json()).access_token);
          assert.equal(
            db.prepare("SELECT clientSecret FROM oauthClient WHERE clientId=?").get(credentials.client_id)
              .clientSecret,
            createHash("sha256").update(updated.client_secret.slice("fixture_".length)).digest("base64url"),
          );
          const personalResponse = await rotate({ cookie }, { client_id: app.client_id });
          const personal = await personalResponse.json();
          assert.equal(personalResponse.status, 200);
          assert.equal(personal.user_id, user.id);
          assert.notEqual(personal.client_secret, app.client_secret);
        });
        await t.test("deleting a machine client ends further token exchanges", async () => {
          const machine = await created(
            { grant_types: ["client_credentials"], token_endpoint_auth_method: "client_secret_post" },
            { cookie },
          );
          await issuer.api.adminUpdateOAuthClient({
            headers: { cookie: operatorCookie },
            body: { client_id: machine.client_id, update: { client_credentials_scopes: ["reports"] } },
          });
          const token = await exchange(machine.client_secret, machine.client_id);
          assert.equal(token.status, 200);
          assert.ok((await token.json()).access_token);
          const deleted = await request("oauth2/delete-client", { client_id: machine.client_id }, { cookie });
          assert.equal(deleted.status, 200);
          const refused = await exchange(machine.client_secret, machine.client_id);
          assert.equal((await refused.json()).error, "invalid_client");
          assert.ok(refused.status >= 400);
        });
      });
    }
  }
}
