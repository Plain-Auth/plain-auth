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
