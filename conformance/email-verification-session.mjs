import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { DatabaseSync } from "node:sqlite";

export async function compareVerifiedEmailSignIn(t, { reference, goFixture, instrument }) {
  const dir = await mkdtemp(join(tmpdir(), "verified-mail-"));
  t.after(() => rm(dir, {recursive:true,force:true}));
  const delivery = join(dir, "token");
  const go = await goFixture(t, [], {CONFORMANCE_EMAIL_VERIFY_LINK: delivery});
  const database = new DatabaseSync(go.databasePath);
  t.after(() => database.close());
  const ref = await reference(t, [], {database, emailVerification: {
    autoSignInAfterVerification: true, sendOnSignUp: true,
    sendVerificationEmail: async ({token}) => writeFile(delivery, token),
  }});
  const password = "local-verification-password";
  const signup = async (client, email) => {
    const r = await client.signUp.email({email,name:"Mail owner",password});
    assert.equal(r.error, null);
    return r.data;
  };
  for (const [issuer, receiver, prefix] of [[ref, go, "ref"], [go, ref, "go"]]) {
    for (const actor of ["anonymous", "same", "foreign", "redirect"]) {
      const ownerEmail = prefix + "-" + actor + "@verify.example.test";
      const owner = instrument(issuer);
      const signed = await signup(owner.client, ownerEmail);
      const token = await readFile(delivery, "utf8");
      let activeCookie;
      if (actor === "same") {
        const s = await receiver.send(new Request(receiver.baseURL + "/api/auth/sign-in/email", {method:"POST",
          headers:{"content-type":"application/json",origin:receiver.baseURL},
          body:JSON.stringify({email:ownerEmail,password})}));
        assert.equal(s.status, 200);
        activeCookie = s.headers.getSetCookie().map(v=>v.split(";")[0]).join("; ");
      }
      const browser = instrument({ ...receiver, send: req => {
        if (activeCookie && !req.headers.has("cookie")) req.headers.set("cookie", activeCookie);
        return receiver.send(req);
      }});
      let old;
      if (actor === "foreign") old = await signup(browser.client, prefix + "-different@verify.example.test");
      if (actor === "same") old = (await browser.client.getSession()).data.session;
      const endpoint = new URL(receiver.baseURL + "/api/auth/verify-email");
      endpoint.searchParams.set("token", token);
      if (actor === "redirect") {
        endpoint.searchParams.set("callbackURL", "https://foreign.example.test/private");
        let invalid = await receiver.send(new Request(endpoint, {redirect:"manual"}));
        assert.equal(invalid.status, 403);
        assert.equal(invalid.headers.getSetCookie().length, 0);
        endpoint.searchParams.set("callbackURL", "/complete?source=mail");
        for (const first of [true, false]) {
          const result = await receiver.send(new Request(endpoint, {redirect:"manual"}));
          assert.equal(result.status, 302);
          const url = new URL(result.headers.get("location"), receiver.baseURL);
          assert.equal(url.pathname + url.search, "/complete?source=mail");
          assert.equal(result.headers.getSetCookie().some(v=>v.startsWith("authn.session_token=")), first);
        }
        continue;
      }
      const approved = await browser.client.verifyEmail({query:{token}});
      assert.equal(approved.error, null);
      assert.deepEqual(approved.data, {status:true,user:null});
      assert.ok(browser.requests.at(-1).cookies.some(c=>c.name === "authn.session_token"));
      const account = (await browser.client.getSession()).data;
      assert.equal(account.user.id, signed.user.id);
      assert.equal(account.user.emailVerified, true);
      if (actor === "same") assert.equal(account.session.token, old.token, "same owner reuses the live session");
      else assert.notEqual(account.session.token, old?.token ?? signed.token);
      if (actor === "foreign") assert.equal(database.prepare("SELECT userId FROM session WHERE token=?").get(old.token).userId, old.user.id);
      const fresh = instrument(receiver);
      const repeated = await fresh.client.verifyEmail({query:{token}});
      assert.deepEqual(repeated.data, {status:true,user:null});
      assert.equal(fresh.requests.at(-1).cookies.length, 0);
      assert.equal((await fresh.client.getSession()).data, null);
    }
  }
}
