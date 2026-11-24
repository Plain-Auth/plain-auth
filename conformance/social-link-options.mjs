import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { genericOAuth } from "better-auth/plugins/generic-oauth";

const owner = "jo@example.org";

// Run one provider round trip on both runtimes with the same linking options
// and provider profile, and compare where the browser lands.
async function scenario(t, {reference, goFixture, instrument}, {trusted = false, different = false, update = false, profile, verifiedOwner = true, foreign = false, errorPage = false, asOwner, expect}) {
  const provider = genericOAuth({config:[{
    providerId:"work", scopes:["profile"], clientId:"fixture-client", clientSecret:"fixture-secret",
    authorizationUrl:"https://id.example/authorize", tokenUrl:"https://id.example/token",
    getToken:async () => ({accessToken:"local-test", tokenType:"Bearer"}),
    getUserInfo:async () => ({id:"sample-user", email:profile.email, name:profile.name, emailVerified:profile.verified, ...(profile.image && {image:profile.image})}),
    accountSubject:({profile})=>profile.id,
  }]});
  const ref = await reference(t, [provider], {account:{accountLinking:{trustedProviders:trusted ? ["work"] : [], allowDifferentEmails:different, updateUserInfoOnLink:update}}});
  const go = await goFixture(t, [], {CONFORMANCE_PROVIDER:"1", CONFORMANCE_LINK_POLICY:"default",
    CONFORMANCE_LINK_TRUSTED:trusted ? "1" : "", CONFORMANCE_LINK_DIFFERENT:different ? "1" : "", CONFORMANCE_LINK_UPDATE:update ? "1" : "",
    CONFORMANCE_LINK_PROFILE:[profile.email, profile.verified ? "1" : "0", profile.name, profile.image ?? ""].join("|")});
  const outcomes = [];
  for (const target of [ref, go]) {
    const database = target.database ?? new DatabaseSync(target.databasePath);
    if (target === go) t.after(() => database.close());
    const jar = new Map();
    const transport = {...target, send:async r => {
      if (jar.size) r.headers.set("cookie", [...jar].map(([key, value]) => key + "=" + value).join("; "));
      const res = await target.send(r);
      for (const header of res.headers.getSetCookie()) {
        const pair = header.split(";")[0], split = pair.indexOf("=");
        if (/;\s*max-age=0(?:;|$)/i.test(header)) jar.delete(pair.slice(0, split));
        else jar.set(pair.slice(0, split), pair.slice(split + 1));
      }
      return res;
    }};
    const created = await instrument(target).client.signUp.email({email:owner, name:"Owner", password:"existing owner password"});
    assert.equal(created.error, null);
    const id = created.data.user.id;
    if (verifiedOwner) database.prepare('UPDATE "user" SET emailVerified=1 WHERE id=?').run(id);
    if (foreign) {
      // Another user already owns the provider identity.
      const other = await instrument(target).client.signUp.email({email:"other@example.org", name:"Other", password:"another owner password"});
      assert.equal(other.error, null);
      database.prepare(`INSERT INTO account (id, accountId, providerId, userId, createdAt, updatedAt)
        SELECT 'foreign-account', 'sample-user', 'work', id, createdAt, updatedAt FROM "user" WHERE id=?`).run(other.data.user.id);
    }
    const {client} = instrument(transport);
    if (asOwner) assert.equal((await client.signIn.email({email:owner, password:"existing owner password"})).error, null);
    const body = {provider:"work", callbackURL:"/complete", disableRedirect:true, ...(!errorPage && {errorCallbackURL:"/retry"})};
    const started = await (asOwner ? client.linkSocial(body) : client.signIn.social(body));
    assert.equal(started.error, null);
    const authURL = new URL(started.data.url);
    const callback = new URL(authURL.searchParams.get("redirect_uri"));
    callback.searchParams.set("state", authURL.searchParams.get("state"));
    callback.searchParams.set("code", "fixture-approval");
    const res = await transport.send(new Request(callback, {redirect:"manual", headers:{"user-agent":"authn-conformance"}}));
    assert.equal(res.status, 302);
    const landing = new URL(res.headers.get("Location"), target.baseURL);
    const user = database.prepare('SELECT email, emailVerified, name, image FROM "user" WHERE id=?').get(id);
    outcomes.push({
      landing: landing.pathname + (landing.searchParams.get("error") ? "?error=" + landing.searchParams.get("error") : ""),
      linked: database.prepare("SELECT userId FROM account WHERE providerId='work' AND accountId='sample-user'").get()?.userId === id,
      session: res.headers.getSetCookie().some(c => /session_token=[^;]/.test(c)),
      ownerEmail: user.email, ownerVerified: Boolean(user.emailVerified), ownerName: user.name, ownerImage: user.image ?? null,
      users: database.prepare('SELECT count(*) AS n FROM "user"').get().n,
    });
  }
  assert.deepEqual(outcomes[1], outcomes[0]);
  assert.equal(outcomes[0].landing, expect);
  return outcomes[0];
}

// trustedProviders lets an unverified provider email link to a verified
// owner, both on sign-in and through an explicit link.
export async function compareTrustedProviders(t, harness) {
  const unverified = {email:owner, verified:false, name:"Jo"};
  let got = await scenario(t, harness, {trusted:true, profile:unverified, asOwner:false, expect:"/complete"});
  assert.ok(got.linked && got.session && got.ownerVerified);
  got = await scenario(t, harness, {profile:unverified, asOwner:false, expect:"/retry?error=account_not_linked"});
  assert.ok(!got.linked && !got.session);
  got = await scenario(t, harness, {trusted:true, profile:unverified, verifiedOwner:false, asOwner:false, expect:"/retry?error=account_not_linked"});
  assert.ok(!got.linked && !got.ownerVerified);
  got = await scenario(t, harness, {profile:unverified, asOwner:true, expect:"/retry?error=unable_to_link_account"});
  assert.ok(!got.linked);
  got = await scenario(t, harness, {trusted:true, profile:unverified, asOwner:true, expect:"/complete"});
  assert.ok(got.linked && !got.session);
}

// allowDifferentEmails lets a signed-in user link an identity whose email
// differs from theirs without changing their email.
export async function compareDifferentEmailLinks(t, harness) {
  const other = {email:"someone@example.net", verified:true, name:"Jo"};
  let got = await scenario(t, harness, {profile:other, asOwner:true, expect:"/retry?error=email_does_not_match"});
  assert.ok(!got.linked);
  got = await scenario(t, harness, {different:true, profile:other, asOwner:true, expect:"/complete"});
  assert.ok(got.linked && got.ownerEmail === owner && got.users === 1);
  got = await scenario(t, harness, {profile:{email:owner, verified:true, name:"Jo"}, foreign:true, asOwner:true, expect:"/retry?error=account_already_linked_to_different_user"});
  assert.ok(!got.linked);
  // Trust and the email are checked before who owns the identity.
  await scenario(t, harness, {profile:other, foreign:true, asOwner:true, expect:"/retry?error=email_does_not_match"});
  await scenario(t, harness, {profile:{email:owner, verified:false, name:"Jo"}, foreign:true, asOwner:true, expect:"/retry?error=unable_to_link_account"});
  // Without an error callback the browser lands on the error page.
  await scenario(t, harness, {profile:other, asOwner:true, errorPage:true, expect:"/api/auth/error?error=email_does_not_match"});
}

// updateUserInfoOnLink copies the provider's name and image onto the user
// when an identity is linked, and never the email.
export async function compareLinkProfileCopy(t, harness) {
  const profile = {email:owner, verified:true, name:"Jo Provider", image:"https://img.example/jo.png"};
  let got = await scenario(t, harness, {update:true, profile, asOwner:true, expect:"/complete"});
  assert.ok(got.linked && got.ownerName === "Jo Provider" && got.ownerImage === profile.image && got.ownerEmail === owner);
  got = await scenario(t, harness, {profile, asOwner:true, expect:"/complete"});
  assert.ok(got.linked && got.ownerName === "Owner" && got.ownerImage === null);
  got = await scenario(t, harness, {update:true, profile, asOwner:false, expect:"/complete"});
  assert.ok(got.linked && got.session && got.ownerName === "Jo Provider");
  got = await scenario(t, harness, {update:true, different:true, profile:{...profile, email:"someone@example.net"}, asOwner:true, expect:"/complete"});
  assert.ok(got.linked && got.ownerEmail === owner && got.ownerName === "Jo Provider");
}
