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
  const ref = await reference(t, [], {
    database,
    // Use one timestamp for an unchanged initial profile. The tests below
    // exercise independently sampled timestamps on either side of issuance.
    databaseHooks: {
      user: { create: { before: async user => ({ data: { ...user, updatedAt: user.createdAt } }) } },
    },
    emailVerification: {
      autoSignInAfterVerification: true,
      sendOnSignUp: true,
      sendVerificationEmail: async ({token}) => writeFile(delivery, token),
    },
  });
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
      const verification = browser.requests.findLast(r => r.path === "/api/auth/verify-email");
      assert.ok(verification.cookies.some(c=>c.name === "authn.session_token"), prefix + " to peer, " + actor);
      const account = (await browser.client.getSession()).data;
      assert.equal(account.user.id, signed.user.id);
      assert.equal(account.user.emailVerified, true);
      if (actor === "same") assert.equal(account.session.token, old.token, "same owner reuses the live session");
      else assert.notEqual(account.session.token, old?.token ?? signed.token);
      if (actor === "foreign") assert.equal(database.prepare("SELECT userId FROM session WHERE token=?").get(old.token).userId, old.user.id);
      const fresh = instrument(receiver);
      const repeated = await fresh.client.verifyEmail({query:{token}});
      assert.deepEqual(repeated.data, {status:true,user:null});
      assert.equal(fresh.requests.findLast(r => r.path === "/api/auth/verify-email").cookies.length, 0);
      assert.equal((await fresh.client.getSession()).data, null);
    }
  }

  // Exercise distinct initial timestamps against the actual whole-second iat
  // of a signed link. A new user's timestamps can differ by a single tick.
  for (const [scenario, createdOffset, updatedOffset, signsIn] of [
    ["both timestamps precede issuance", -2, -1, true],
    ["both timestamps match within the issue second", 1, 1, true],
    ["timestamps differ within the issue second", 0, 1, false],
  ]) {
    await t.test(scenario, async () => {
      const account = await signup(instrument(ref).client, "clock-" + updatedOffset + "-" + createdOffset + "@verify.example.test");
      const token = await readFile(delivery, "utf8");
      const {iat, userId, profileUpdatedAtMs} = JSON.parse(Buffer.from(token.split(".")[1], "base64url"));
      assert.equal(userId, account.user.id);
      assert.equal(profileUpdatedAtMs, undefined);
      assert.ok(Number.isSafeInteger(iat));
      const instant = iat * 1000;
      database.prepare('UPDATE "user" SET createdAt=?,updatedAt=? WHERE id=?').run(
        new Date(instant + createdOffset).toISOString(), new Date(instant + updatedOffset).toISOString(), userId);
      const browser = instrument(go);
      const before = database.prepare('SELECT COUNT(*) AS n FROM session WHERE userId=?').get(userId).n;
      const verified = await browser.client.verifyEmail({query:{token}});
      assert.equal(verified.error, null);
      assert.deepEqual(verified.data, {status:true,user:null});
      const response = browser.requests.findLast(r => r.path === "/api/auth/verify-email");
      assert.equal(response.cookies.some(c => c.name === "authn.session_token"), signsIn);
      assert.equal(database.prepare('SELECT emailVerified FROM "user" WHERE id=?').get(userId).emailVerified, 1);
      assert.equal(database.prepare('SELECT COUNT(*) AS n FROM session WHERE userId=?').get(userId).n, before + Number(signsIn));
      const session = await browser.client.getSession();
      assert.equal(session.error, null);
      assert.equal(session.data?.user.id, signsIn ? userId : undefined);
    });
  }
}
