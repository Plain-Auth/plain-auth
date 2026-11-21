import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { once } from "node:events";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { createInterface } from "node:readline";
import { DatabaseSync } from "node:sqlite";
import test, { after } from "node:test";
import { fileURLToPath } from "node:url";
import { betterAuth } from "better-auth";
import { passkey } from "@better-auth/passkey";
import { passkeyClient } from "@better-auth/passkey/client";
import { haveIBeenPwned } from "better-auth/plugins/haveibeenpwned";
import { createAuthClient } from "better-auth/client";
import { getMigrations } from "better-auth/db/migration";
import { customSession, emailOTP, organization, twoFactor, magicLink, oneTimeToken, jwt } from "better-auth/plugins";
import { emailOTPClient, organizationClient, twoFactorClient, magicLinkClient, oneTimeTokenClient, jwtClient } from "better-auth/client/plugins";
import { createOTP } from "@better-auth/utils/otp";
import { base32 } from "@better-auth/utils/base32";

const harness = fileURLToPath(new URL(".", import.meta.url));
const email = "fixture@example.test";
const name = "Local Fixture";
const password = "local-conformance-password";

test("both runtimes publish the email login preference and persist it on the user", async (t) => {
  const { lastLoginMethod } = await import("better-auth/plugins");
  const cookieName = "authn.last_used_login_method";
  for (const setup of [
    () => reference(t, [lastLoginMethod({ storeInDatabase: true, cookieName })]),
    () => goFixture(t, ["last-login-method"]),
  ]) {
    const { client, requests } = instrument(await setup());
    const result = await client.signUp.email({ email, name, password });
    assert.equal(result.error, null);
    const cookie = requests.at(-1).cookies.find(item => item.name === cookieName);
    assert.ok(cookie, "registration should publish the preference");
    assert.ok(cookie.attributes.includes("max-age=2592000"));
    assert.ok(!cookie.attributes.includes("httponly"));
    const session = await client.getSession();
    assert.equal(session.data.user.lastLoginMethod, "email");
  }
});

async function reference(t, plugins = []) {
  const database = new DatabaseSync(":memory:");
  t.after(() => database.close());
  const baseURL = "http://reference.localhost";
  const options = {
    advanced: { cookiePrefix: "authn" },
    baseURL,
    database,
    plugins,
    secret: "local-conformance-0123456789-abcdefghijk",
    emailAndPassword: { enabled: true },
    telemetry: { enabled: false },
  };
  await (await getMigrations(options)).runMigrations();
  const auth = betterAuth(options);
  return { baseURL, send: (request) => auth.handler(request) };
}

let fixtureBuild;
let buildDirectory;

async function buildFixture() {
  buildDirectory = await mkdtemp(join(tmpdir(), "authn-fixture-binary-"));
  const binary = join(buildDirectory, "fixture");
  const build = spawnSync("go", ["build", "-o", binary, "./fixture"], {
    cwd: harness, encoding: "utf8", timeout: 180_000,
  });
  if (build.error) throw build.error;
  assert.equal(build.status, 0, build.stderr);
  return binary;
}

after(async () => {
  if (buildDirectory) await rm(buildDirectory, { recursive: true, force: true });
});

async function goFixture(t, profiles = [], env = {}) {
  const binary = await (fixtureBuild ??= buildFixture());
  const dir = await mkdtemp(join(tmpdir(), "authn-conformance-"));
  let child;
  let exited;
  t.after(async () => {
    if (child && child.exitCode === null && !child.signalCode) {
      child.kill();
      await exited;
    }
    await rm(dir, { recursive: true, force: true });
  });
  const databasePath = join(dir, "auth.db");
  child = spawn(binary, [databasePath, ...profiles], { env: { ...process.env, ...env }, stdio: ["ignore", "pipe", "inherit"] });
  exited = once(child, "exit");
  const lines = createInterface({ input: child.stdout });
  const signal = AbortSignal.timeout(15_000);
  const [baseURL] = await Promise.race([
    once(lines, "line", { signal }),
    exited.then(([code]) => { throw new Error("Go fixture exited before listening (" + code + ")"); }),
  ]);
  lines.close();
  return { baseURL, send: fetch, databasePath };
}

// The official client calls this fetch hook for both runtimes. Each client owns
// one origin and a fresh, root-path cookie jar for this loopback HTTP fixture.
function instrument({ baseURL, send }, plugins = []) {
  const cookies = new Map();
  const requests = [];
  const client = createAuthClient({ baseURL, plugins, fetchOptions: {
    customFetchImpl: async (url, options) => {
      assert.equal(new URL(url).origin, baseURL);
      const headers = new Headers(options.headers);
      headers.set("origin", baseURL);
      headers.set("user-agent", "authn-conformance");
      headers.set("x-forwarded-for", "127.0.0.1");
      if (cookies.size) {
        headers.set("cookie", [...cookies].map(([k, v]) => k + "=" + v).join("; "));
      }
      const request = new Request(url, { ...options, headers, redirect: "manual" });
      const response = await send(request);
      const cookieHeaders = [];
      for (const header of response.headers.getSetCookie()) {
        const [pair, ...attrs] = header.split(/;\s*/);
        const eq = pair.indexOf("=");
        const key = pair.slice(0, eq);
        const value = pair.slice(eq + 1);
        const attributes = attrs.map((a) => a.toLowerCase()).sort();
        if (attributes.includes("max-age=0")) cookies.delete(key);
        else cookies.set(key, value);
        cookieHeaders.push({ name: key, attributes });
      }
      cookieHeaders.sort((a, b) => a.name.localeCompare(b.name));
      requests.push({ method: request.method, path: new URL(url).pathname,
        status: response.status, cookies: cookieHeaders });
      return response;
    },
  } });
  return { client, requests };
}

// Preserve equality relationships between generated IDs and tokens across calls.
// Datetimes vary per run; assert that they parse and check the session lifetime.
function normalize(value, ids, key = "") {
  if (value === null || value === undefined) return value;
  if (value instanceof Date || ["createdAt", "updatedAt", "expiresAt"].includes(key)) {
    assert.ok(Number.isFinite(new Date(value).getTime()), "invalid " + key);
    return "<date>";
  }
  if (typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((k) => [k, normalize(value[k], ids, k)]));
  }
  if (["id", "userId", "token"].includes(key)) {
    assert.equal(typeof value, "string");
    assert.ok(value.length);
    if (!ids.has(value)) ids.set(value, (key === "token" ? "token-" : "id-") + ids.size);
    return ids.get(value);
  }
  return value;
}

async function accountFlow(server) {
  const health = await server.send(new Request(server.baseURL + "/api/auth/ok"));
  assert.equal(health.status, 200);
  assert.match(health.headers.get("content-type"), /application\/json/);
  assert.deepEqual(await health.json(), { ok: true });
  const { client, requests } = instrument(server);
  const ids = new Map();
  const bodies = [];
  function record(result) {
    if (result.error) {
      const { code, message, status } = result.error;
      bodies.push({ code, message, status });
    } else {
      bodies.push(normalize(result.data, ids));
    }
    return result.data;
  }
  assert.equal(record(await client.getSession()), null);
  const registered = record(await client.signUp.email({ email, name, password }));
  assert.equal(registered?.user.email, email);
  const active = record(await client.getSession());
  assert.equal(active?.session.userId, registered.user.id);
  assert.equal(active.session.token, registered.token);
  assert.ok(Math.abs(+active.session.expiresAt - +active.session.createdAt - 604800000) < 1000);
  assert.ok(record(await client.signOut())?.success);
  assert.equal(record(await client.getSession()), null);
  record(await client.signIn.email({ email, password: "incorrect-password" }));
  const signedIn = record(await client.signIn.email({ email, password }));
  assert.equal(signedIn?.user.id, registered.user.id);
  assert.notEqual(signedIn.token, registered.token);
  assert.equal(record(await client.getSession())?.session.token, signedIn.token);
  assert.ok(record(await client.signOut())?.success); // final sign-out
  assert.equal(record(await client.getSession()), null);
  return { requests, bodies };
}

test("the official client sees the same email account and session lifecycle", async (t) => {
  const expected = await accountFlow(await reference(t));
  const actual = await accountFlow(await goFixture(t));
  assert.deepEqual(actual, expected);
});

test("a shared SQLite account consumes reference verification and password reset links in Go", async (t) => {
  const go = await goFixture(t);
  const db = new DatabaseSync(go.databasePath);
  t.after(() => db.close());
  let verification;
  let reset;
  const auth = betterAuth({
    advanced: { cookiePrefix: "authn" },
    baseURL: go.baseURL, database: db,
    secret: "local-conformance-0123456789-abcdefghijk",
    emailAndPassword: {
      enabled: true,
      sendResetPassword: async (message) => { reset = message; },
    },
    emailVerification: {
      sendVerificationEmail: async (message) => { verification = message; },
    },
    telemetry: { enabled: false },
  });
  const person = { email: "links@example.test", name: "Mail Fixture", password: "old fixture password" };
  const { user } = await auth.api.signUpEmail({ body: person });
  await auth.api.sendVerificationEmail({ body: { email: person.email } });
  assert.equal(verification.user.id, user.id);
  const verified = await fetch(go.baseURL + "/api/auth/verify-email?" + new URLSearchParams({ token: verification.token }));
  assert.equal(verified.status, 200);
  assert.deepEqual(await verified.json(), { status: true, user: null });
  await auth.api.requestPasswordReset({ body: { email: person.email, redirectTo: "/recover" } });
  assert.equal(reset.user.id, user.id);
  const callback = await fetch(reset.url, { redirect: "manual" });
  assert.equal(callback.status, 302);
  assert.equal(new URL(callback.headers.get("location")).searchParams.get("token"), reset.token);
  const newPassword = "replacement fixture password";
  const change = () => fetch(go.baseURL + "/api/auth/reset-password", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ token: reset.token, newPassword }),
  });
  assert.equal((await change()).status, 200);
  assert.equal((await change()).status, 400);
  const signedIn = await auth.api.signInEmail({ body: { email: person.email, password: newPassword } });
  assert.equal(signedIn.user.id, user.id);
  assert.equal(signedIn.user.emailVerified, true);
});

test("the official organization client can create, select, invite and accept across both runtimes", async (t) => {
  for (const target of [await reference(t, [organization()]), await goFixture(t, ["organization"])]) {
    const owner = instrument(target, [organizationClient()]).client;
    const invitee = instrument(target, [organizationClient()]).client;
    function ok(response) { assert.equal(response.error, null); return response.data; }
    const creator = ok(await owner.signUp.email({ email: "owner@example.test", name, password })).user;
    const recipient = ok(await invitee.signUp.email({ email: "member@example.test", name, password })).user;
    const org = ok(await owner.organization.create({ name: "Team Example", slug: "team-example" }));
    assert.equal(org.members[0].userId, creator.id);
    assert.equal(org.members[0].role, "owner");
    assert.equal(ok(await owner.getSession()).session.activeOrganizationId, org.id);
    assert.deepEqual(ok(await invitee.organization.list()), []);
    const denied = await invitee.organization.getOrganization({ query: { organizationId: org.id } });
    assert.equal(denied.error?.status, 403);
    const pending = ok(await owner.organization.inviteMember({ email: recipient.email, role: "member" }));
    assert.equal(pending.organizationId, org.id);
    const accepted = ok(await invitee.organization.acceptInvitation({ invitationId: pending.id }));
    assert.equal(accepted.invitation.status, "accepted");
    assert.equal(accepted.member.role, "member");
    assert.equal(accepted.member.userId, recipient.id);
    assert.deepEqual(ok(await invitee.organization.list()).map((item) => item.id), [org.id]);
    ok(await invitee.organization.setActive({ organizationId: null }));
    assert.equal(ok(await invitee.organization.getOrganization()), null);
    assert.equal(ok(await invitee.organization.setActive({ organizationSlug: org.slug })).id, org.id);
  }
});

test("authenticator enrollment and backup challenges work through the public client", async (t) => {
  function ok(response) { assert.equal(response.error, null); return response.data; }
  for (const target of [await reference(t, [twoFactor()]), await goFixture(t, ["two-factor"])]) {
    const { client } = instrument(target, [twoFactorClient()]);
    const user = ok(await client.signUp.email({ email, name, password })).user;
    const enrollment = ok(await client.twoFactor.enable({ password }));
    const uri = new URL(enrollment.totpURI);
    assert.equal(uri.protocol, "otpauth:");
    const generator = createOTP(base32.decode(uri.searchParams.get("secret")));
    assert.equal(ok(await client.twoFactor.verifyTotp({ code: await generator.totp() })).user.id, user.id);
    assert.equal(ok(await client.getSession()).user.twoFactorEnabled, true);
    ok(await client.signOut());
    assert.equal(ok(await client.signIn.email({ email, password })).twoFactorRedirect, true);
    assert.equal(ok(await client.getSession()), null);
    const [used, spare] = enrollment.backupCodes;
    assert.equal(ok(await client.twoFactor.verifyBackupCode({ code: used })).user.id, user.id);
    assert.equal(ok(await client.getSession()).user.id, user.id);
    ok(await client.signOut());
    assert.equal(ok(await client.signIn.email({ email, password })).twoFactorRedirect, true);
    assert.ok((await client.twoFactor.verifyBackupCode({ code: used })).error);
    assert.equal(ok(await client.twoFactor.verifyBackupCode({ code: spare })).user.id, user.id);
  }
});

test("the official client enforces the password range policy on credential writes", async (t) => {
  const blocked = "local breached fixture with a synthetic range";
  const safe = "local clean fixture with a different synthetic range";
  const digest = createHash("sha1").update(blocked).digest("hex").toUpperCase();
  const go = await goFixture(t, [], { CONFORMANCE_SYNTHETIC_BREACH: digest });
  const upstream = await reference(t, [haveIBeenPwned()]);
  let ranges = 0;
  t.mock.method(globalThis, "fetch", async (input, init) => {
    const r = new Request(input, init);
    const u = new URL(r.url);
    assert.equal(u.origin, "https://api.pwnedpasswords.com");
    assert.match(u.pathname, /^\/range\/[A-F0-9]{5}$/);
    assert.equal(r.headers.get("add-padding"), "true");
    ranges++;
    return new Response(u.pathname.endsWith(digest.slice(0, 5)) ? digest.slice(5) + ":3\r\n" : "0".repeat(35) + ":0\r\n", {
      headers: { "content-type": "text/plain" },
    });
  });
  for (const server of [upstream, go]) {
    const { client } = instrument(server);
    const signUp = (password) => client.signUp.email({ email, name, password });
    const denied = await signUp(blocked);
    assert.equal(denied.error?.status, 400);
    assert.equal(denied.error.code, "PASSWORD_COMPROMISED");
    assert.equal((await signUp(safe)).data?.user.email, email);
    const change = await client.changePassword({ currentPassword: safe, newPassword: blocked });
    assert.equal(change.error?.code, "PASSWORD_COMPROMISED");
    const before = ranges;
    assert.equal((await client.signIn.email({ email, password: safe })).data?.user.email, email);
    assert.equal(ranges, before);
  }
  assert.equal(ranges, 3);
});

test("shared SQLite verifies hashed magic links in either runtime", async (t) => {
  const go = await goFixture(t, [], { CONFORMANCE_MAILBOX: "1" });
  const database = new DatabaseSync(go.databasePath);
  t.after(() => database.close());
  let sent;
  const ref = betterAuth({
    advanced: { cookiePrefix: "authn" },
    baseURL: go.baseURL, database, secret: "local-conformance-0123456789-abcdefghijk",
    plugins: [magicLink({storeToken:"hashed", sendMagicLink: async (message) => { sent = message; }})],
    emailAndPassword: {enabled: true}, telemetry: {enabled: false},
  });
  const browser = instrument(go, [magicLinkClient()]).client;
  const official = instrument({baseURL:go.baseURL,send:(r)=>ref.handler(r)},[magicLinkClient()]).client;
  const mailbox = "shared-inbox@example.test";
  assert.equal((await official.signIn.magicLink({email:mailbox,name})).data.status,true);
  const goUser = (await browser.magicLink.verify({query:{token:sent.token}})).data.user;
  assert.equal(goUser.emailVerified,true);
  assert.equal(goUser.email,mailbox);
  assert.equal((await browser.signIn.magicLink({email:mailbox})).data.status,true);
  const fromGo = JSON.parse(await readFile(join(dirname(go.databasePath),"mailbox.json"),"utf8"));
  const verified = await official.magicLink.verify({query:{token:fromGo.Token}});
  assert.equal(verified.error,null);
  assert.equal(verified.data.user.id,goUser.id);
  const replay = await fetch(fromGo.URL,{redirect:"manual"});
  assert.equal(replay.status,302);
  assert.equal(new URL(replay.headers.get("location")).searchParams.get("error"),"INVALID_TOKEN");
});

test("stored provider account selection, refresh, and user info match the reference", async (t) => {
  const { providerCredentials } = await import("./provider-credentials.mjs");
  await providerCredentials(t, goFixture);
});

test("shared SQLite transfers a session with one-time tokens from either runtime", async (t) => {
  const go = await goFixture(t, [], { CONFORMANCE_TRANSFER: "1" });
  const database = new DatabaseSync(go.databasePath);
  t.after(() => database.close());
  const ref = betterAuth({
    advanced: { cookiePrefix: "authn" },
    baseURL: go.baseURL, database, secret: "local-conformance-0123456789-abcdefghijk",
    plugins: [oneTimeToken({storeToken:"hashed"})],
    emailAndPassword: {enabled: true}, telemetry: {enabled:false},
  });
  const official = instrument({baseURL:go.baseURL,send:(r)=>ref.handler(r)},[oneTimeTokenClient()]).client;
  const receiver = instrument(go,[oneTimeTokenClient()]).client;
  const original = (await official.signUp.email({email,name,password})).data;
  const fromReference = (await official.oneTimeToken.generate()).data.token;
  const accepted = (await receiver.oneTimeToken.verify({token:fromReference})).data;
  assert.equal(accepted.session.token,original.token);
  assert.equal(accepted.user.id,original.user.id);
  assert.equal((await official.oneTimeToken.verify({token:fromReference})).error.status,400);
  const fromGo = (await receiver.oneTimeToken.generate()).data.token;
  const third = instrument({baseURL:go.baseURL,send:(r)=>ref.handler(r)},[oneTimeTokenClient()]).client;
  assert.equal((await third.oneTimeToken.verify({token:fromGo})).data.session.token,original.token);
  assert.equal((await third.getSession()).data.user.id,original.user.id);
  assert.equal((await receiver.oneTimeToken.verify({token:fromGo})).error.status,400);
});

test("the official passkey client obtains registration and discoverable login options", async (t) => {
  const config = { rpID: "example.test", rpName: "Local Test", origin: "https://accounts.example.test", authenticatorSelection: { userVerification: "required" } };
  for (const server of [await reference(t, [passkey(config)]), await goFixture(t, ["passkey"])]) {
    const { client } = instrument(server, [passkeyClient()]);
    const login = await client.passkey.generateAuthenticateOptions();
    assert.equal(login.error, null);
    assert.equal(login.data.rpId, config.rpID);
    assert.equal(login.data.userVerification, "required");
    assert.ok(login.data.challenge.length >= 22);
    assert.equal((await client.signUp.email({ email, name, password })).data.user.email, email);
    const creation = await client.passkey.generateRegisterOptions();
    assert.equal(creation.error, null);
    assert.deepEqual(creation.data.rp, { id: config.rpID, name: config.rpName });
    assert.ok(creation.data.user.id.length > 0);
    assert.ok(creation.data.pubKeyCredParams.some((p) => p.type === "public-key" && p.alg === -7));
    assert.deepEqual((await client.passkey.listUserPasskeys()).data, []);
  }
});

test("the official client reads the configured custom session response", async (t) => {
  const ref = await reference(t, [customSession(async ({ user }) => ({ viewer: user.email }))]);
  const go = await goFixture(t, [], { CONFORMANCE_SESSION_VIEW: "1" });
  for (const server of [ref, go]) {
    const { client } = instrument(server);
    assert.equal((await client.getSession()).data, null);
    assert.equal((await client.signUp.email({ email, name, password })).error, null);
    assert.deepEqual((await client.getSession()).data, { viewer: email });
  }
});

test("isolated issuers publish public keys and issue verifiable service tokens", async (t) => {
  const { createLocalJWKSet, jwtVerify } = await import("jose");
  const issued = [];
  for (const target of [await reference(t, [jwt()]), await goFixture(t, ["jwt"])]) {
    const { client } = instrument(target, [jwtClient()]);
    const keys = (await client.jwks()).data;
    assert.equal(keys.keys.length, 1);
    assert.equal(keys.keys[0].d, undefined);
    const registration = await client.signUp.email({ email, name, password });
    assert.equal(registration.error, null);
    const response = await client.token();
    assert.equal(response.error, null);
    const token = response.data.token;
    const jwks = createLocalJWKSet(keys);
    const { payload, protectedHeader } = await jwtVerify(token, jwks, {
      algorithms: ["EdDSA"], issuer: target.baseURL, audience: target.baseURL,
    });
    assert.equal(payload.sub, registration.data.user.id);
    assert.equal(payload.exp - payload.iat, 900);
    assert.equal(protectedHeader.kid, keys.keys[0].kid);
    issued.push({ token, jwks });
  }
  await assert.rejects(jwtVerify(issued[0].token, issued[1].jwks));
  await assert.rejects(jwtVerify(issued[1].token, issued[0].jwks));
});

test("device grants created in either runtime can issue a first-party session in the other", async (t) => {
  const { deviceAuthorization } = await import("better-auth/plugins");
  const { deviceAuthorizationClient } = await import("better-auth/client/plugins");
  const go = await goFixture(t, ["device-authorization"]);
  const db = new DatabaseSync(go.databasePath);
  t.after(() => db.close());
  const refOrigin = "http://reference.localhost";
  const refAuth = betterAuth({ baseURL: refOrigin, database: db, secret: "local-conformance-0123456789-abcdefghijk",
    plugins: [deviceAuthorization()], emailAndPassword: { enabled: true }, telemetry: { enabled: false } });
  const ref = { baseURL: refOrigin, send: (req) => refAuth.handler(req) };
  const identities = new Map();
  for (const runtime of [go, ref]) {
    const owner = instrument(runtime, [deviceAuthorizationClient()]).client;
    const login = identities.size ? await owner.signIn.email({ email, password }) : await owner.signUp.email({ email, password, name });
    assert.equal(login.error, null);
    identities.set(runtime, owner);
  }
  for (const [issuer, redeemer] of [[ref, go], [go, ref]]) {
    const machine = instrument(issuer, [deviceAuthorizationClient()]).client;
    const otherMachine = instrument(redeemer, [deviceAuthorizationClient()]).client;
    const { data: code, error } = await machine.device.code({ client_id: "console", scope: "read" });
    assert.equal(error, null);
    const review = await identities.get(redeemer).device({ query: { user_code: code.user_code } });
    assert.equal(review.data?.scope, "read");
    assert.equal(review.data?.client_id, "console");
    assert.deepEqual((await identities.get(issuer).device.approve({ userCode: code.user_code })).data, { success: true });
    const args = { client_id: "console", device_code: code.device_code, grant_type: "urn:ietf:params:oauth:grant-type:device_code" };
    const grant = await otherMachine.device.token(args);
    assert.equal(grant.error, null);
    assert.equal(grant.data.token_type, "Bearer");
    assert.equal(grant.data.scope, "read");
    const persisted = db.prepare('SELECT u.email FROM session s JOIN user u ON u.id=s.userId WHERE s.token=?').get(grant.data.access_token);
    assert.equal(persisted.email, email);
    assert.equal((await machine.device.token(args)).error.error, "invalid_grant");
    const denied = await machine.device.code({ client_id: "console" });
    await identities.get(redeemer).device({ query: { user_code: denied.data.user_code } });
    assert.equal((await identities.get(issuer).device.deny({ userCode: denied.data.user_code })).data.success, true);
    assert.equal((await otherMachine.device.token({ ...args, device_code: denied.data.device_code })).error.error, "access_denied");
  }
});


test("shared SQLite accepts email OTP codes and prevents replay across runtimes", async (t) => {
  const go = await goFixture(t, [], { AUTH_TEST_EMAIL_OTP_MAILBOX: "1" });
  const database = new DatabaseSync(go.databasePath);
  t.after(() => database.close());
  let sent;
  const ref = betterAuth({
    baseURL: go.baseURL, database, secret: "local-conformance-0123456789-abcdefghijk",
    plugins: [emailOTP({ storeOTP: "hashed", changeEmail: {enabled:true, verifyCurrentEmail:true}, sendVerificationOTP: async (m) => { sent = m; } })],
    emailAndPassword: { enabled: true }, telemetry: { enabled: false },
  });
  const official = instrument({baseURL: go.baseURL, send: (r) => ref.handler(r)}, [emailOTPClient()]).client;
  const browser = instrument(go, [emailOTPClient()]).client;
  const email = "otp-inbox@example.test";
  assert.equal((await official.emailOtp.sendVerificationOtp({ email, type: "sign-in" })).data.success, true);
  const firstCode = sent.otp;
  const login = await browser.signIn.emailOtp({ email, otp: firstCode, name: "Mailbox" });
  assert.equal(login.data?.user.emailVerified, true);
  assert.equal((await official.signIn.emailOtp({ email, otp: firstCode })).error?.code, "INVALID_OTP");
  assert.equal((await browser.emailOtp.requestPasswordReset({ email })).data.success, true);
  const delivered = JSON.parse(await readFile(join(dirname(go.databasePath), "email-otp.json"), "utf8"));
  assert.equal(delivered.Type, "forget-password");
  assert.equal((await official.emailOtp.checkVerificationOtp({ email, otp: delivered.OTP, type: "forget-password" })).data.success, true);
  assert.equal((await official.emailOtp.resetPassword({ email, otp: delivered.OTP, password })).data.success, true);
  assert.equal((await browser.emailOtp.resetPassword({ email, otp: delivered.OTP, password })).error?.code, "INVALID_OTP");
  assert.equal((await browser.signIn.email({ email, password })).data?.user.id, login.data.user.id);
  assert.equal((await official.signIn.email({ email, password })).data?.user.id, login.data.user.id);
  const currentProof = await ref.api.createVerificationOTP({body: {email, type:"email-verification"}});
  const newEmail = "updated-otp@example.test";
  assert.equal((await browser.emailOtp.requestEmailChange({newEmail, otp:currentProof})).data?.success, true);
  const change = JSON.parse(await readFile(join(dirname(go.databasePath),"email-otp.json"),"utf8"));
  assert.equal(change.Type,"change-email");
  assert.equal((await official.emailOtp.changeEmail({newEmail, otp:change.OTP})).data?.success,true);
  assert.equal((await browser.getSession()).data?.user.email, newEmail);
  assert.equal((await browser.emailOtp.sendVerificationOtp({email:newEmail, type:"email-verification"})).data?.success,true);
  const existing = JSON.parse(await readFile(join(dirname(go.databasePath),"email-otp.json"),"utf8"));
  assert.equal((await official.emailOtp.requestEmailChange({newEmail:email,otp:existing.OTP})).data?.success,true);
  assert.equal(sent.email,email);
  assert.equal((await browser.emailOtp.changeEmail({newEmail:email,otp:sent.otp})).data?.success,true);
  assert.equal((await browser.getSession()).data?.user.email,email);
});

test("the official multi-session client remembers, switches and revokes accounts per device", async (t) => {
  const { multiSession } = await import("better-auth/plugins");
  const { multiSessionClient } = await import("better-auth/client/plugins");
  for (const runtime of [await reference(t, [multiSession({ maximumSessions: 2 })]),
    await goFixture(t, [], { CONFORMANCE_MULTI_SESSION: "1" })]) {
    const device = instrument(runtime, [multiSessionClient()]).client;
    const second = instrument(runtime, [multiSessionClient()]).client;
    const api = device.multiSession;
    assert.deepEqual((await api.listDeviceSessions()).data, []);
    const logins = [];
    for (const label of ["alice", "bob", "carol"]) {
      const result = await device.signUp.email({ email: label + "@example.test", name: label, password });
      assert.equal(result.error, null);
      logins.push(result.data.token);
    }
    const rows = (await api.listDeviceSessions()).data;
    assert.deepEqual(rows.map((r) => r.user.name).sort(), ["alice", "bob"]);
    assert.equal((await device.getSession()).data.session.token, logins[2]);
    assert.equal((await api.setActive({ sessionToken: logins[2] })).error.code, "INVALID_SESSION_TOKEN");
    assert.equal((await second.multiSession.setActive({ sessionToken: logins[0] })).error.code, "INVALID_SESSION_TOKEN");
    assert.equal((await api.setActive({ sessionToken: logins[0] })).data.session.token, logins[0]);
    assert.equal((await device.getSession()).data.user.name, "alice");
    assert.deepEqual((await api.revoke({ sessionToken: logins[0] })).data, { status: true });
    assert.equal((await device.getSession()).data.user.name, "bob");
    assert.equal((await api.setActive({ sessionToken: logins[0] })).error.code, "INVALID_SESSION_TOKEN");
    assert.equal((await second.signIn.email({ email: "bob@example.test", password })).error, null);
    assert.deepEqual((await device.signOut()).data, { success: true });
    assert.deepEqual((await api.listDeviceSessions()).data, []);
    assert.equal((await second.getSession()).data.user.name, "bob");
  }
});

test("custom session projection on the device list is opt-in", async (t) => {
  const { multiSession } = await import("better-auth/plugins");
  const { multiSessionClient } = await import("better-auth/client/plugins");
  for (const enabled of [false, true]) {
    const plugins = [multiSession(), customSession(async ({ user }) => ({ viewer: user.email }), {},
      { shouldMutateListDeviceSessionsEndpoint: enabled })];
    const fixtures = [await reference(t, plugins), await goFixture(t, [], {
      CONFORMANCE_MULTI_SESSION: "1", CONFORMANCE_SESSION_VIEW: "1", CONFORMANCE_DEVICE_VIEW: enabled ? "1" : "0",
    })];
    for (const runtime of fixtures) {
      const { client } = instrument(runtime, [multiSessionClient()]);
      const first = await client.signUp.email({ email, password, name });
      assert.equal(first.error, null);
      assert.equal((await client.signUp.email({ email: "second@example.test", password, name })).error, null);
      const rows = (await client.multiSession.listDeviceSessions()).data;
      if (enabled) {
        assert.deepEqual(rows.map((r) => Object.keys(r)), [["viewer"], ["viewer"]]);
        assert.deepEqual(rows.map((r) => r.viewer).sort(), [email, "second@example.test"].sort());
      } else {
        assert.deepEqual(rows.map((r) => r.user.email).sort(), [email, "second@example.test"].sort());
      }
      assert.equal((await client.multiSession.setActive({ sessionToken: first.data.token })).data.user.email, email);
    }
  }
});

test("organization teams manage memberships and scoped invitations with the official client", async (t) => {
  const teamOptions = { teams: { enabled: true } };
  for (const runtime of [await reference(t, [organization(teamOptions)]),
    await goFixture(t, ["organization-teams"])]) {
    const make = () => instrument(runtime, [organizationClient(teamOptions)]).client;
    const owner = make(), alice = make(), outsider = make();
    const ok = (res) => { assert.equal(res.error, null, JSON.stringify(res.error)); return res.data; };
    const boss = ok(await owner.signUp.email({ name, email, password })).user;
    const peer = ok(await alice.signUp.email({ name: "Alice", email: "alice@example.test", password })).user;
    ok(await outsider.signUp.email({ name: "Other", email: "other@example.test", password }));
    const org = owner.organization;
    const group = ok(await org.create({ name: "Studio", slug: "studio" }));
    const initial = ok(await org.listTeams())[0];
    assert.equal(initial.name, "Studio");
    assert.equal(ok(await owner.getSession()).session.activeTeamId, initial.id);
    const made = ok(await org.createTeam({ name: "Editing" }));
    assert.equal(made.organizationId, group.id);
    assert.equal(ok(await org.updateTeam({ teamId: made.id, data: { name: "Editorial" } })).name, "Editorial");
    assert.equal((await org.setActiveTeam({ teamId: made.id })).error.code, "USER_IS_NOT_A_MEMBER_OF_THE_TEAM");
    const member = ok(await org.addTeamMember({ teamId: made.id, userId: boss.id }));
    assert.equal(ok(await org.addTeamMember({ teamId: made.id, userId: boss.id })).id, member.id);
    assert.equal(ok(await org.setActiveTeam({ teamId: made.id })).id, made.id);
    const otherGroup = ok(await outsider.organization.create({ name: "Independent", slug: "independent" }));
    const foreign = ok(await outsider.organization.listTeams())[0];
    assert.equal((await org.inviteMember({ email: peer.email, role: "member", organizationId: group.id, teamId: foreign.id })).error.code, "TEAM_NOT_FOUND");
    assert.equal((await org.updateTeam({ teamId: foreign.id, data: { organizationId: group.id, name: "Invalid" } })).error.code, "TEAM_NOT_FOUND");
    assert.equal((await outsider.organization.listTeams({ query: { organizationId: group.id } })).error.code, "YOU_ARE_NOT_ALLOWED_TO_ACCESS_THIS_ORGANIZATION");
    const invitation = ok(await org.inviteMember({ email: peer.email, role: "member", teamId: [initial.id, made.id] }));
    ok(await alice.organization.acceptInvitation({ invitationId: invitation.id }));
    assert.deepEqual(ok(await alice.organization.listUserTeams()).map((t) => t.name).sort(), ["Editorial", "Studio"]);
    const set = ok(await alice.organization.setActiveTeam({ teamId: made.id }));
    assert.equal(set.id, made.id);
    assert.deepEqual(ok(await alice.organization.listTeamMembers()).map((m) => m.userId).sort(), [boss.id, peer.id].sort());
    assert.equal((await alice.organization.createTeam({ name: "Denied" })).error.code, "YOU_ARE_NOT_ALLOWED_TO_CREATE_TEAMS_IN_THIS_ORGANIZATION");
    assert.deepEqual(ok(await org.removeTeamMember({ teamId: made.id, userId: peer.id })), { message: "Team member removed successfully." });
    assert.equal((await alice.organization.listTeamMembers({ query: { teamId: made.id } })).error.code, "USER_IS_NOT_A_MEMBER_OF_THE_TEAM");
    ok(await org.setActiveTeam({ teamId: initial.id }));
    assert.deepEqual(ok(await org.removeTeam({ teamId: made.id })), { message: "Team removed successfully." });
    assert.deepEqual(ok(await org.listTeams()).map((t) => t.id), [initial.id]);
    assert.equal(otherGroup.id, ok(await outsider.getSession()).session.activeOrganizationId);
  }
});

test("the pinned One Tap client signs in to Go with a nonce issued by the application host", async (t) => {
  const { oneTapClient, anonymousClient } = await import("better-auth/client/plugins");
  const { generateKeyPair, exportJWK, SignJWT } = await import("jose");
  const { publicKey, privateKey } = await generateKeyPair("RS256", { extractable: true });
  const key = await exportJWK(publicKey);
  const go = await goFixture(t, ["anonymous"], { CONFORMANCE_ONE_TAP_JWKS: JSON.stringify({ keys: [{ ...key, alg: "RS256", kid: "local" }] }) });
  const clientId = "fixture.apps.googleusercontent.com";
  const { client } = instrument(go, [oneTapClient({ clientId }), anonymousClient()]);
  const guest = await client.signIn.anonymous();
  assert.equal(guest.data.user.isAnonymous, true);
  const { data } = await client.$fetch("/test/host-challenge", { method: "POST", body: {} });
  assert.equal(data.clientId, clientId);
  const name = "Host-bound Google user", email = "host-nonce@example.test";
  const credential = await new SignJWT({ nonce: data.nonce, name, email, email_verified: true })
    .setProtectedHeader({ alg: "RS256", kid: "local" }).setSubject("subject").setIssuer("https://accounts.google.com")
    .setAudience(clientId).setIssuedAt().setExpirationTime("5m").sign(privateKey);
  let init;
  const previous = globalThis.window;
  globalThis.window = { document: {}, googleScriptInitialized: true, google: { accounts: { id: {
    initialize(config) { init = config; }, prompt() { init.callback({ credential }); },
  } } } };
  t.after(() => { if (previous === undefined) delete globalThis.window; else globalThis.window = previous; });
  await client.oneTap({ nonce: data.nonce, fetchOptions: {} });
  assert.equal(init.nonce, data.nonce);
  assert.equal((await client.getSession()).data.user.email, email);
  const db = new DatabaseSync(go.databasePath);
  try { assert.equal(db.prepare("SELECT COUNT(*) AS n FROM user WHERE id=?").get(guest.data.user.id).n, 0, "One Tap did not retire the current guest"); }
  finally { db.close(); }
  const replay = await client.$fetch("/one-tap/callback", { method: "POST", body: { idToken: credential } });
  assert.equal(replay.error.status, 400);
});

test("independent organization servers share team invitations, memberships and seat counts", async (t) => {
  const go = await goFixture(t, ["organization-teams"]);
  const db = new DatabaseSync(go.databasePath);
  t.after(() => db.close());
  const options = { teams: { enabled: true } };
  const auth = betterAuth({ baseURL: "http://reference.localhost", database: db,
    secret: "local-conformance-0123456789-abcdefghijk", plugins: [organization(options)],
    emailAndPassword: { enabled: true }, telemetry: { enabled: false } });
  const ref = { baseURL: "http://reference.localhost", send: (req) => auth.handler(req) };
  const ok = (res) => { assert.equal(res.error, null, JSON.stringify(res.error)); return res.data; };
  for (const [index, [issuer, recipient]] of [[go, ref], [ref, go]].entries()) {
    const owner = instrument(issuer, [organizationClient(options)]).client;
    const member = instrument(recipient, [organizationClient(options)]).client;
    const boss = ok(await owner.signUp.email({ name, email: "owner" + index + "@example.test", password })).user;
    const peer = ok(await member.signUp.email({ name, email: "peer" + index + "@example.test", password })).user;
    ok(await owner.organization.create({ name, slug: "org-" + index }));
    const group = ok(await owner.organization.createTeam({ name: "Shared" }));
    const invite = ok(await owner.organization.inviteMember({ email: peer.email, role: "member", teamId: group.id }));
    ok(await member.organization.acceptInvitation({ invitationId: invite.id }));
    const persisted = db.prepare('SELECT "id","membershipKey" FROM "teamMember" WHERE "teamId"=? AND "userId"=?').get(group.id, peer.id);
    assert.equal(persisted.membershipKey, createHash("sha256").update(JSON.stringify([group.id, peer.id])).digest("base64url"));
    assert.equal(ok(await owner.organization.addTeamMember({ teamId: group.id, userId: peer.id })).id, persisted.id);
    ok(await owner.organization.addTeamMember({ teamId: group.id, userId: boss.id }));
    const listed = ok(await member.organization.listTeamMembers({ query: { teamId: group.id } }));
    assert.deepEqual(listed.map((m) => m.userId).sort(), [boss.id, peer.id].sort());
    assert.ok(listed.every((m) => !("membershipKey" in m)));
    assert.equal(db.prepare('SELECT "memberCount" FROM "team" WHERE "id"=?').get(group.id).memberCount, 2);
    ok(await owner.organization.removeTeamMember({ teamId: group.id, userId: peer.id }));
    assert.equal(db.prepare('SELECT "memberCount" FROM "team" WHERE "id"=?').get(group.id).memberCount, 1);
  }
});

test("the public client completes delivered second-factor codes and remembers its browser", async (t) => {
  let sent;
  const ts = await reference(t,[twoFactor({otpOptions:{storeOTP:"hashed", sendOTP:async(data)=>{sent=data;}}})]);
  const go = await goFixture(t,["two-factor"],{AUTH_TEST_FACTOR_MAILBOX:"1"});
  const ok = (response) => {assert.equal(response.error,null);return response.data;};
  for (const target of [ts,go]) {
    const {client}=instrument(target,[twoFactorClient()]);
    const user=ok(await client.signUp.email({email,name,password})).user;
    assert.equal(ok(await client.twoFactor.enable({method:"otp",password})).method,"otp");
    ok(await client.signOut());
    const challenge=ok(await client.signIn.email({email,password}));
    assert.equal(challenge.twoFactorRedirect,true);
    assert.deepEqual(challenge.twoFactorMethods,["otp"]);
    assert.equal(ok(await client.twoFactor.sendOtp({})).status,true);
    let code;
    if(target===go) {
      const delivered=JSON.parse(await readFile(join(dirname(go.databasePath),"factor-otp.json"),"utf8"));
      assert.equal(delivered.User.id,user.id);code=delivered.Code;
    }else{assert.equal(sent.user.id,user.id);code=sent.otp;}
    assert.equal(ok(await client.twoFactor.verifyOtp({code,trustDevice:true})).user.id,user.id);
    ok(await client.signOut());
    const remembered=ok(await client.signIn.email({email,password}));
    assert.equal(remembered.user.id,user.id);
    assert.ok(remembered.token);
    assert.equal(ok(await client.getSession()).user.id,user.id);
  }
});

test("the official admin client manages roles, bans, sessions and impersonation on shared accounts", async (t) => {
  const { admin } = await import("better-auth/plugins");
  const { adminClient } = await import("better-auth/client/plugins");
  const go = await goFixture(t, ["admin"]);
  const db = new DatabaseSync(go.databasePath);
  t.after(() => db.close());
  const ref = betterAuth({ baseURL: "http://reference.localhost", database: db, plugins: [admin()],
    secret: "local-conformance-0123456789-abcdefghijk", emailAndPassword: { enabled: true }, telemetry: { enabled: false } });
  const ts = { baseURL: "http://reference.localhost", send: (request) => ref.handler(request) };
  const ok = (res) => { assert.equal(res.error, null, JSON.stringify(res.error)); return res.data; };
  const bootstrap = instrument(go, [adminClient()]).client;
  const account = ok(await bootstrap.signUp.email({ name, email, password })).user;
  db.prepare('UPDATE "user" SET "role"=? WHERE "id"=?').run("admin", account.id);
  for (const [i, [source, other]] of [[go, ts], [ts, go]].entries()) {
    const actor = instrument(source, [adminClient()]).client;
    const target = instrument(other, [adminClient()]).client;
    const original = ok(await actor.signIn.email({ email, password, rememberMe: false }));
    const api = actor.admin;
    assert.equal(ok(await api.hasPermission({ permissions: { user: ["list"] } })).success, true);
    const created = ok(await api.createUser({ email: "admin-target" + i + "@example.test", name: "Target", password })).user;
    ok(await api.setRole({ userId: created.id, role: "user" }));
    const auth = ok(await target.signIn.email({ email: created.email, password }));
    assert.equal((await target.admin.getUser({ query: { id: account.id } })).error.code, "YOU_ARE_NOT_ALLOWED_TO_GET_USER");
    assert.equal(ok(await api.getUser({ query: { id: created.id } })).role, "user");
    assert.equal(ok(await api.updateUser({ userId: created.id, data: { name: "Updated" } })).name, "Updated");
    const page = ok(await api.listUsers({ query: { searchValue: created.email, searchField: "email", limit: 1 } }));
    assert.equal(page.total, 1);
    assert.equal(page.users[0].id, created.id);
    const listed = ok(await api.listUserSessions({ userId: created.id })).sessions;
    assert.equal(listed.length, 1);
    assert.equal(listed[0].userId, created.id);
    if (source === go) assert.notEqual(listed[0].token, auth.token);
    assert.deepEqual(ok(await api.revokeUserSession({ sessionToken: listed[0].token })), { success: true });
    assert.equal(ok(await target.getSession()), null);
    assert.equal(ok(await api.banUser({ userId: created.id, banReason: "Fixture", banExpiresIn: 1800 })).user.banReason, "Fixture");
    assert.equal((await target.signIn.email({ email: created.email, password })).error.code, "BANNED_USER");
    assert.equal(ok(await api.unbanUser({ userId: created.id })).user.banned, false);
    assert.deepEqual(ok(await api.setUserPassword({ userId: created.id, newPassword: password + "-changed" })), { status: true });
    ok(await target.signIn.email({ email: created.email, password: password + "-changed" }));
    const delegated = ok(await api.impersonateUser({ userId: created.id }));
    assert.equal(delegated.session.impersonatedBy, account.id);
    assert.equal(ok(await actor.getSession()).user.id, created.id);
    const restored = ok(await api.stopImpersonating());
    assert.equal(restored.user.id, account.id);
    assert.equal(restored.session.token, original.token);
    assert.deepEqual(ok(await api.revokeUserSessions({ userId: created.id })), { success: true });
    assert.equal(ok(await target.getSession()), null);
    assert.deepEqual(ok(await api.removeUser({ userId: created.id })), { success: true });
    assert.equal((await api.getUser({ query: { id: created.id } })).error.code, "USER_NOT_FOUND");
  }
});

test("the pinned anonymous client signs in, upgrades and deletes guests on either server", async(t)=>{
  const { anonymous } = await import("better-auth/plugins");
  const { anonymousClient } = await import("better-auth/client/plugins");
  for (const runtime of [await reference(t,[anonymous()]), await goFixture(t,["anonymous"])]) {
    const { client } = instrument(runtime,[anonymousClient()]);
    const guest = await client.signIn.anonymous();
    assert.equal(guest.error,null);
    assert.equal(guest.data.user.isAnonymous,true);
    assert.match(guest.data.user.email,/@anonymous\.placeholder\.invalid$/);
    assert.equal((await client.getSession()).data.user.id,guest.data.user.id);
    const repeated=await client.signIn.anonymous();
    assert.equal(repeated.error.code,"ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY");
    const signup=await client.signUp.email({name,email,password});
    assert.equal(signup.error,null);
    assert.notEqual(signup.data.user.id,guest.data.user.id);
    assert.equal((await client.getSession()).data.user.isAnonymous,false);
    assert.equal((await client.deleteAnonymousUser()).error.code,"USER_IS_NOT_ANONYMOUS");
    await client.signOut();
    assert.equal((await client.signIn.anonymous()).data.user.isAnonymous,true);
    assert.equal((await client.deleteAnonymousUser()).data.success,true);
    assert.equal((await client.getSession()).data,null);
    if (runtime.databasePath) {
      const db=new DatabaseSync(runtime.databasePath);
      try { assert.equal(db.prepare('SELECT count(*) AS n FROM user WHERE isAnonymous').get().n,0); }
      finally { db.close(); }
    }
  }
});

test("the pinned username client shares normalized identities, display names and renames across servers", async (t) => {
  const { username } = await import("better-auth/plugins");
  const { usernameClient } = await import("better-auth/client/plugins");
  const ok = (result) => { assert.equal(result.error, null, JSON.stringify(result.error)); return result.data; };
  for (const displayUsername of [true, false]) {
    const go = await goFixture(t, [displayUsername ? "username" : "username-only"]);
    const db = new DatabaseSync(go.databasePath);
    t.after(() => db.close());
    const ref = betterAuth({ baseURL: "http://reference.localhost", database: db, plugins: [username({ displayUsername })],
      secret: "local-conformance-0123456789-abcdefghijk", emailAndPassword: { enabled: true }, telemetry: { enabled: false } });
    const js = { baseURL: "http://reference.localhost", send: (request) => ref.handler(request) };
    for (const [i, [source, other]] of [[go, js], [js, go]].entries()) {
      const actor = instrument(source, [usernameClient({ displayUsername })]).client;
      const alternate = instrument(other, [usernameClient({ displayUsername })]).client;
      const address = "username" + i + "@example.test";
      const raw = "Display_Only" + i, next = "Renamed." + i;
      const initial = ok(await actor.signUp.email({ name, email: address, password, displayUsername: raw })).user;
      assert.equal(initial.username, raw.toLowerCase());
      assert.equal(initial.displayUsername, displayUsername ? raw : undefined);
      assert.deepEqual(ok(await alternate.isUsernameAvailable({ username: raw })), { available: false });
      assert.equal((await alternate.signIn.username({ username: raw, password: "wrong" })).error.code, "INVALID_USERNAME_OR_PASSWORD");
      const signed = ok(await alternate.signIn.username({ username: raw, password, rememberMe: false, callbackURL: "/welcome?ref=name" }));
      assert.equal(signed.user.id, initial.id);
      assert.equal(signed.redirect, true);
      assert.equal(signed.url, "/welcome?ref=name");
      ok(await alternate.updateUser({ username: next }));
      const current = ok(await actor.getSession()).user;
      assert.equal(current.username, next.toLowerCase());
      assert.equal(current.displayUsername, displayUsername ? raw : undefined);
      assert.deepEqual(ok(await actor.isUsernameAvailable({ username: raw })), { available: true });
      assert.equal((await alternate.isUsernameAvailable({ username: "ab" })).error.code, "USERNAME_TOO_SHORT");
      if (displayUsername) {
        ok(await alternate.updateUser({ displayUsername: null }));
        const visible = ok(await actor.getSession()).user;
        assert.equal(visible.displayUsername, null);
        assert.equal(visible.username, next.toLowerCase());
      }
      ok(await actor.updateUser({ username: null }));
      const cleared = ok(await alternate.getSession()).user;
      assert.equal(cleared.username, null);
      assert.equal(cleared.displayUsername, displayUsername ? null : undefined);
      assert.deepEqual(ok(await alternate.isUsernameAvailable({ username: next })), { available: true });
      assert.equal((await alternate.signIn.username({ username: next, password })).error.code, "INVALID_USERNAME_OR_PASSWORD");
      const noName = ok(await actor.signUp.email({ name, email: "no." + address, password })).user;
      assert.equal(noName.username, null);
      assert.equal(noName.displayUsername, displayUsername ? null : undefined);
    }
  }
});

test("the pinned API key client manages owner credentials on both runtimes", async (t) => {
  const { apiKey, defaultKeyHasher } = await import("@better-auth/api-key");
  const { apiKeyClient } = await import("@better-auth/api-key/client");
  const plugin = () => apiKey({ enableMetadata: true });
  for (const runtime of [await reference(t, [plugin()]), await goFixture(t, ["api-key"])]) {
    const { client } = instrument(runtime, [apiKeyClient()]);
    const account = await client.signUp.email({ name, email, password });
    assert.equal(account.error, null);
    const made = await client.apiKey.create({ name: "Client", prefix: "test_", metadata: { env: "ci" } });
    assert.equal(made.error, null);
    const row = made.data;
    assert.equal(row.referenceId, account.data.user.id);
    assert.equal(row.configId, "default");
    assert.equal(row.start, row.key.slice(0, 6));
    assert.equal(row.key.length, 69);
    assert.deepEqual(row.metadata, { env: "ci" });
    const read = await client.apiKey.get({ query: { id: row.id } });
    assert.equal(read.error, null);
    assert.equal(read.data.key, undefined);
    const change = await client.apiKey.update({ keyId: row.id, name: "Renamed" });
    assert.equal(change.data.name, "Renamed");
    if (runtime.databasePath) {
      const database = new DatabaseSync(runtime.databasePath);
      try {
        const saved = database.prepare('SELECT key FROM apikey WHERE id=?').get(row.id);
        assert.equal(saved.key, await defaultKeyHasher(row.key));
        const peer = betterAuth({ baseURL: runtime.baseURL, database, secret: "local-conformance-0123456789-abcdefghijk", plugins: [plugin()], telemetry: { enabled: false } });
        const verified = await peer.api.verifyApiKey({ body: { key: row.key } });
        assert.equal(verified.valid, true);
        assert.equal(verified.key.id, row.id);
        assert.equal(verified.key.key, undefined);
        const source = await peer.api.createApiKey({ body: { userId: row.referenceId, name: "Reference key", permissions: { reports: ["read"] } } });
        const application = await fetch(runtime.baseURL + "/reports", { headers: { "X-API-Key": source.key } });
        assert.equal(application.status, 200);
        assert.deepEqual(await application.json(), { owner: row.referenceId, id: source.id });
        const spent = database.prepare('SELECT requestCount FROM apikey WHERE id=?').get(source.id);
        assert.equal(spent.requestCount, 1);
        assert.equal((await client.apiKey.delete({ keyId: source.id })).data.success, true);
      } finally { database.close(); }
    }
    const result = await client.apiKey.list({ query: { limit: 4, offset: 0 } });
    assert.equal(result.error, null);
    assert.equal(result.data.total, 1);
    assert.equal(result.data.apiKeys[0].id, row.id);
    assert.equal(result.data.apiKeys[0].key, undefined);
    const removed = await client.apiKey.delete({ keyId: row.id });
    assert.equal(removed.data.success, true);
    assert.equal((await client.apiKey.get({ query: { id: row.id } })).error.code, "KEY_NOT_FOUND");
  }
});
