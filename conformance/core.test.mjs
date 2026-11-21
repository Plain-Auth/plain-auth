import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { once } from "node:events";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { createInterface } from "node:readline";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { betterAuth } from "better-auth";
import { passkey } from "@better-auth/passkey";
import { passkeyClient } from "@better-auth/passkey/client";
import { haveIBeenPwned } from "better-auth/plugins/haveibeenpwned";
import { createAuthClient } from "better-auth/client";
import { getMigrations } from "better-auth/db/migration";
import { organization, twoFactor, magicLink, oneTimeToken } from "better-auth/plugins";
import { organizationClient, twoFactorClient, magicLinkClient, oneTimeTokenClient } from "better-auth/client/plugins";
import { symmetricDecrypt } from "better-auth/crypto";

const harness = fileURLToPath(new URL(".", import.meta.url));
const email = "fixture@example.test";
const name = "Local Fixture";
const password = "local-conformance-password";

async function reference(t, plugins = []) {
  const database = new DatabaseSync(":memory:");
  t.after(() => database.close());
  const baseURL = "http://reference.localhost";
  const options = {
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

async function goFixture(t, profiles = [], env = {}) {
  const dir = await mkdtemp(join(tmpdir(), "go-better-auth-conformance-"));
  const binary = join(dir, "fixture");
  let child;
  let exited;
  t.after(async () => {
    if (child && child.exitCode === null && !child.signalCode) {
      child.kill();
      await exited;
    }
    await rm(dir, { recursive: true, force: true });
  });
  const build = spawnSync("go", ["build", "-o", binary, "./fixture"], {
    cwd: harness, encoding: "utf8", timeout: 180_000,
  });
  if (build.error) throw build.error;
  assert.equal(build.status, 0, build.stderr);
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
      headers.set("user-agent", "go-better-auth-conformance");
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

test("shared SQLite authenticator credentials and pending challenges work in both runtimes", async (t) => {
  const go = await goFixture(t, ["two-factor"]);
  const database = new DatabaseSync(go.databasePath);
  t.after(() => database.close());
  const key = "local-conformance-0123456789-abcdefghijk";
  const ref = betterAuth({
    baseURL: go.baseURL, database, secret: key, plugins: [twoFactor()],
    emailAndPassword: { enabled: true }, telemetry: { enabled: false },
  });
  let send = (req) => ref.handler(req);
  const { client } = instrument({ baseURL: go.baseURL, send: (req) => send(req) }, [twoFactorClient()]);
  function ok(response) { assert.equal(response.error, null); return response.data; }
  const user = ok(await client.signUp.email({ email, name, password })).user;
  const enrollment = ok(await client.twoFactor.enable({ password }));
  const { secret } = database.prepare('SELECT secret FROM twoFactor WHERE userId = ?').get(user.id);
  const raw = await symmetricDecrypt({key, data: secret});
  const { code } = await ref.api.generateTOTP({body: {secret: raw}});
  send = go.send;
  assert.equal(ok(await client.twoFactor.verifyTotp({code})).user.twoFactorEnabled, true);
  ok(await client.signOut());

  send = (req) => ref.handler(req);
  assert.equal(ok(await client.signIn.email({email,password})).twoFactorRedirect,true);
  send = go.send;
  assert.equal(ok(await client.twoFactor.verifyBackupCode({code: enrollment.backupCodes[0]})).user.id,user.id);
  ok(await client.signOut());
  assert.equal(ok(await client.signIn.email({email,password})).twoFactorRedirect,true);
  send = (req) => ref.handler(req);
  assert.equal(ok(await client.twoFactor.verifyBackupCode({code: enrollment.backupCodes[1]})).user.id,user.id);
  assert.equal(ok(await client.getSession()).user.id,user.id);
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
