import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { oneTimeToken } from "better-auth/plugins";
import { oneTimeTokenClient } from "better-auth/client/plugins";

export async function compareTransferOptions(t, { reference, goFixture, instrument }) {
  for (const mode of ["plain","hashed","custom"]) {
    await t.test(mode, async t => {
      const go = await goFixture(t, [], {CONFORMANCE_TRANSFER:mode});
      const db = new DatabaseSync(go.databasePath);
      t.after(() => db.close());
      const encoded = raw => mode === "plain" ? raw : createHash("sha256").update(raw).digest(mode === "hashed" ? "base64url" : "hex");
      const ref = await reference(t, [oneTimeToken({
        storeToken: mode === "custom" ? {type:"custom-hasher", hash:async raw => encoded(raw)} : mode,
        setOttHeaderOnNewSession:true, disableSetSessionCookie:true,
        generateToken: async (session, c) => {
          assert.equal(session.session.userId, session.user.id);
          return new URL(c.request.url).pathname.split("/").at(-1) + "-" + randomUUID();
        },
      })], {database:db, baseURL:go.baseURL});
      ref.baseURL = go.baseURL;
      const client = runtime => instrument(runtime, [oneTimeTokenClient()]).client;
      for (const [i, pair] of [[go,ref],[ref,go]].entries()) {
        const [a,b] = pair;
        let signupHeader;
        const wrapped = {...a, send:async r => {
          const response = await a.send(r);
          if (new URL(r.url).pathname.endsWith("/sign-up/email")) signupHeader = response.headers.get("set-ott");
          return response;
        }};
        const sender = client(wrapped);
        const signup = await sender.signUp.email({email:`transfer-${i}@example.test`,name:"Member",password:"fixture-password-321"});
        assert.ok(signup.data, signup.error?.message);
        assert.ok(signupHeader.startsWith("email-"));
        const raw = (await sender.oneTimeToken.generate()).data.token;
        assert.ok(raw.startsWith("generate-"));
        const recipient = client(b);
        for (const proof of [signupHeader,raw]) {
          const stored = db.prepare("SELECT value FROM verification WHERE identifier=?").get("one-time-token:"+encoded(proof));
          assert.equal(stored.value, signup.data.token);
          const verified = await recipient.oneTimeToken.verify({token:proof});
          assert.equal(verified.data.session.token,signup.data.token);
          assert.equal(verified.data.user.id,signup.data.user.id);
          assert.equal((await recipient.getSession()).data,null);
          assert.equal((await recipient.oneTimeToken.verify({token:proof})).error.status,400);
        }
      }
    });
  }
}

function observeTransfer(runtime, instrument) {
  const replies = [];
  const { client } = instrument({ ...runtime, async send(request) {
    const response = await runtime.send(request);
    const exposed = response.headers.get("access-control-expose-headers") ?? "";
    replies.push({
      requestHeaders: new Headers(request.headers),
      ott: response.headers.get("set-ott"),
      exposed: exposed.split(",").map(s => s.trim().toLowerCase()).filter(Boolean),
      cookies: response.headers.getSetCookie(),
    });
    return response;
  } }, [oneTimeTokenClient()]);
  return { client, last: () => replies.at(-1) };
}

export async function transferContract(t, { reference, goFixture, instrument }) {
  for (const mode of ["default", "header", "restricted", "suppress", "short", "immediate"]) {
    await t.test(mode, async t => {
      const go = await goFixture(t, [], { CONFORMANCE_TRANSFER: mode });
      const sqlite = new DatabaseSync(go.databasePath);
      t.after(() => sqlite.close());
      const options = {
        setOttHeaderOnNewSession: ["header", "restricted", "suppress"].includes(mode),
        disableClientRequest: mode === "restricted",
        disableSetSessionCookie: mode === "suppress",
        ...(mode === "short" ? { expiresIn: 0.01 } : {}),
        ...(mode === "immediate" ? { expiresIn: 0 } : {}),
      };
      const ref = await reference(t, [oneTimeToken(options)]);
      for (const [runtime, db] of [[ref, ref.database], [go, sqlite]]) {
        const sender = observeTransfer(runtime, instrument);
        const recipient = observeTransfer(runtime, instrument);
        const optionsEnabled = options.setOttHeaderOnNewSession;
        function checkEmission(client, enabled) {
          const { ott, exposed } = client.last();
          assert.equal(Boolean(ott), enabled);
          assert.equal(exposed.filter(header => header === "set-ott").length, enabled ? 1 : 0);
          if (enabled) assert.match(ott, /^[A-Za-z0-9_-]{32}$/);
          return ott;
        }
        for (const body of [{}, { token: 42 }, { token: "" }, { token: "unknown-transfer-proof" }]) {
          const invalid = await recipient.client.$fetch("/one-time-token/verify", { method: "POST", body });
          assert.equal(invalid.error.status, 400, "verification requires a valid string credential");
          checkEmission(recipient, false);
          assert.equal(recipient.last().cookies.length, 0);
        }
        const anonymous = await sender.client.oneTimeToken.generate();
        assert.equal(anonymous.error.status, 401, "session validation precedes the HTTP generation policy");
        checkEmission(sender, false);
        const owner = await sender.client.signUp.email({
          name: "Original", email: "issuer@example.test", password: "issuer-test-password",
        });
        assert.ok(owner.data, owner.error?.message);
        const initial = checkEmission(sender, optionsEnabled);
        assert.equal((await sender.client.getSession()).data.user.id, owner.data.user.id);
        checkEmission(sender, false);
        const generated = await sender.client.oneTimeToken.generate();
        checkEmission(sender, false);
        let proof;
        if (mode === "restricted") {
          assert.equal(generated.error.status, 400);
          assert.equal(generated.error.message, "Client requests are disabled");
          if (runtime === ref) {
            const native = await ref.api.generateOneTimeToken({ headers: sender.last().requestHeaders });
            assert.match(native.token, /^[A-Za-z0-9_-]{32}$/);
            assert.equal((await ref.api.verifyOneTimeToken({ body: { token: native.token } })).user.id, owner.data.user.id);
          }
          proof = initial;
        } else {
          proof = generated.data.token;
          assert.match(proof, /^[A-Za-z0-9_-]{32}$/);
        }
        const stored = db.prepare("SELECT createdAt,expiresAt,value FROM verification WHERE identifier=?")
          .get("one-time-token:" + proof);
        const lifetime = new Date(stored.expiresAt) - new Date(stored.createdAt);
        const expected = { short: 600, immediate: 0 }[mode] ?? 180000;
        // The reference obtains creation and expiry from separate clock reads.
        assert.ok(Math.abs(lifetime - expected) < 60, "the transfer lifetime follows the configured duration");
        assert.equal(owner.data.token, stored.value);

        // Simulate an elapsed TTL without relying on a wall-clock timer.
        if (mode === "short" || mode === "immediate") {
          if (mode === "short") db.prepare("UPDATE verification SET expiresAt=? WHERE identifier=?")
            .run("2001-01-01T00:00:00.000Z", "one-time-token:" + proof);
          assert.equal((await recipient.client.oneTimeToken.verify({ token: proof })).error.status, 400);
          assert.equal(recipient.last().cookies.length, 0);
          continue;
        }

        assert.ok((await sender.client.updateUser({ name: "Updated" })).data);
        checkEmission(sender, optionsEnabled);
        const transient = await recipient.client.signUp.email({
          name: "Visitor", email: "visitor@example.test", password: "visitor-test-password", rememberMe: false,
        });
        assert.ok(transient.data, transient.error?.message);
        const redeemed = await recipient.client.oneTimeToken.verify({ token: proof });
        assert.equal(redeemed.data.user.id, owner.data.user.id);
        assert.equal(redeemed.data.session.token, owner.data.token);
        const forwarded = checkEmission(recipient, optionsEnabled && !options.disableSetSessionCookie);
        const cookies = recipient.last().cookies;
        if (options.disableSetSessionCookie) {
          assert.equal(cookies.length, 0);
          assert.equal((await recipient.client.getSession()).data.user.id, transient.data.user.id);
        } else {
          assert.ok(cookies.some(v => v.includes(".session_token=") && !/max-age=/i.test(v)), "preserve the receiving browser's temporary-session preference");
          assert.ok(cookies.some(v => v.includes(".dont_remember=")));
          assert.equal((await recipient.client.getSession()).data.user.id, owner.data.user.id);
        }
        if (forwarded) {
          assert.notEqual(forwarded, proof);
          assert.equal(db.prepare("SELECT value FROM verification WHERE identifier=?")
            .get("one-time-token:" + forwarded).value, owner.data.token);
        }
        const replay = await recipient.client.oneTimeToken.verify({ token: proof });
        assert.equal(replay.error.status, 400);
        checkEmission(recipient, false);
        assert.equal(recipient.last().cookies.length, 0);
        db.prepare("UPDATE session SET expiresAt=? WHERE token=?")
          .run(new Date(Date.now() + 60000).toISOString(), owner.data.token);
        const renewal = await sender.client.getSession();
        assert.equal(renewal.data.session.token, owner.data.token);
        assert.ok(sender.last().cookies.some(v => v.includes(".session_token=")), "sliding renewal republishes a session cookie");
        checkEmission(sender, optionsEnabled);
        const outstanding = mode === "restricted"
          ? sender.last().ott : (await sender.client.oneTimeToken.generate()).data.token;
        assert.ok((await sender.client.signOut()).data);
        checkEmission(sender, false);
        const revoked = await recipient.client.oneTimeToken.verify({ token: outstanding });
        assert.equal(revoked.error.message, "Session not found");
        checkEmission(recipient, false);
        assert.equal(recipient.last().cookies.length, 0);
      }
    });
  }
}
