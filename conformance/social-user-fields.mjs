import assert from "node:assert/strict";
import { createServer } from "node:http";
import { once } from "node:events";
import { readFile } from "node:fs/promises";
import { DatabaseSync } from "node:sqlite";
import { genericOAuth } from "better-auth/plugins/generic-oauth";
import { inferAdditionalFields } from "better-auth/client/plugins";

const mappings = {
  locale: { type: "string", required: true, fieldName: "preferred_locale" },
  count: { type: "number", required: false, defaultValue: 4 },
  flag: { type: "boolean", required: false },
  accountClass: { type: "string", required: false, input: false, defaultValue: "standard" },
  privateNote: { type: "string", required: false, returned: false },
  internalRisk: { type: "number", required: false, input: false, returned: false, defaultValue: 9 },
};

export async function issuerFixture(t) {
  let profile, grantFields, sequence = 0;
  const codes = new Map(), tokens = new Map();
  const server = createServer(async (req, res) => {
    const url = new URL(req.url, "http://localhost");
    if (url.pathname === "/authorize") {
      const callback = new URL(url.searchParams.get("redirect_uri"));
      const code = "approved-" + (++sequence);
      codes.set(code, { profile, grantFields, callback: callback.href });
      callback.searchParams.set("code", code);
      callback.searchParams.set("state", url.searchParams.get("state"));
      res.writeHead(302, { location: callback.href }).end();
      return;
    }
    if (url.pathname === "/token") {
      let body = "";
      for await (const chunk of req) body += chunk;
      const form = new URLSearchParams(body);
      const approval = codes.get(form.get("code"));
      if (req.method !== "POST" || !approval || form.get("redirect_uri") !== approval.callback) {
        res.writeHead(400).end();
        return;
      }
      codes.delete(form.get("code"));
      const token = "authorized-" + form.get("code");
      tokens.set(token, approval.profile);
      res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ access_token: token, token_type: "Bearer", ...approval.grantFields }));
      return;
    }
    const data = tokens.get(req.headers.authorization?.replace(/^Bearer /, ""));
    if (url.pathname === "/userinfo" && data) res.writeHead(200, {"content-type":"application/json"}).end(JSON.stringify(data));
    else res.writeHead(401).end();
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => new Promise(resolve => server.close(resolve)));
  return { base: "http://127.0.0.1:" + server.address().port, profile(value, fields) { profile = value; grantFields = fields; } };
}

export function browser(target, instrument, provider = "work") {
  const jar = new Map();
  const transport = { ...target, async send(req) {
    if (jar.size) req.headers.set("cookie", [...jar].map(([k,v]) => k+"="+v).join("; "));
    const response = await target.send(req);
    for (const cookie of response.headers.getSetCookie()) {
      const pair = cookie.split(";")[0], split = pair.indexOf("=");
      if (/;\s*max-age=0(?:;|$)/i.test(cookie)) jar.delete(pair.slice(0,split));
      else jar.set(pair.slice(0,split),pair.slice(split+1));
    }
    return response;
  }};
  const {client} = instrument(transport,[inferAdditionalFields()]);
  return {client, async login(linkScopes) {
    const body = { provider, disableRedirect:true, callbackURL:"/done", errorCallbackURL:"/retry",
      locale:"browser-body", privateNote:"browser-body-private", additionalData:{locale:"browser-state",accountClass:"browser-owned",privateNote:"browser-state-private"} };
    const start = await (linkScopes ? client.linkSocial({...body, scopes:linkScopes}) : client.signIn.social(body));
    assert.equal(start.error,null);
    if (linkScopes) {
      const requested = new URL(start.data.url).searchParams.get("scope").split(/\s+/);
      for (const scope of linkScopes) assert.ok(requested.includes(scope));
    }
    const approval = await fetch(start.data.url,{redirect:"manual"});
    assert.equal(approval.status,302);
    const res = await transport.send(new Request(approval.headers.get("location"), {redirect:"manual",headers:{"user-agent":"authn-conformance"}}));
    assert.equal(res.status,302);
    return new URL(res.headers.get("location"),target.baseURL);
  }};
}

function referenceProvider(issuer, options) {
  return genericOAuth({config:[{ providerId:"work",clientId:"profile-app",clientSecret:"local-secret",scopes:["profile"],
    authorizationUrl:issuer.base+"/authorize",tokenUrl:issuer.base+"/token",userInfoUrl:issuer.base+"/userinfo",
    accountSubject:({profile})=>profile.id,
    mapProfileToUser:raw=>raw.mapped??{},
    ...options,
  }]});
}

async function profileServers(t, {reference, goFixture}, defaults, syncProfile = false) {
  const issuer=await issuerFixture(t);
  const fields={...mappings,locale:{...mappings.locale}};
  if (defaults) fields.locale.defaultValue="en";
  const provider=referenceProvider(issuer, {overrideUserInfo: syncProfile});
  const go=await goFixture(t,[],{CONFORMANCE_PROVIDER:"1",CONFORMANCE_USER_FIELDS:"1",CONFORMANCE_SOCIAL_FIELD_ISSUER:issuer.base,CONFORMANCE_SOCIAL_FIELD_DEFAULT:defaults?"1":"0",CONFORMANCE_SOCIAL_PROFILE_SYNC:syncProfile?"1":"0"});
  const database=new DatabaseSync(go.databasePath);
  t.after(()=>database.close());
  const ref=await reference(t,[provider],{database,user:{additionalFields:fields},rateLimit:{enabled:false}});
  return {go, ref, issuer, database};
}

export async function compareSocialUserFields(t, { reference, goFixture, instrument }, defaults) {
  const {go, ref, issuer, database} = await profileServers(t, {reference, goFixture}, defaults);
  for (const [first,other,label] of [[go,ref,"go"],[ref,go,"ts"]]) {
    const raw={id:label+"-subject",name:"Hosted "+label,email:label+"@provider.test",emailVerified:true,locale:"unmapped-raw",privateNote:"unmapped-raw-private"};
    const actor=browser(first,instrument), peer=browser(other,instrument);
    if (!defaults) {
      issuer.profile(raw);
      const refused=await actor.login();
      assert.equal(refused.pathname,"/retry");
      assert.equal(refused.searchParams.get("error"),"MISSING_FIELD");
      assert.equal(refused.searchParams.get("error_description"),"locale is required");
      assert.equal(database.prepare('SELECT COUNT(*) AS n FROM "user" WHERE email=?').get(raw.email).n,0);
    }
    const mapped=defaults ? {} : {locale:"fr",count:0,flag:false,accountClass:"from-provider",privateNote:"provider-private",internalRisk:99};
    issuer.profile({...raw,mapped});
    assert.equal((await actor.login()).pathname,"/done");
    let current=await actor.client.getSession();
    assert.equal(current.error,null);
    const expected={locale:defaults?"en":"fr",count:defaults?4:0,flag:defaults?null:false,accountClass:"standard"};
    function publicProfile(user) {
      for(const [key,value] of Object.entries(expected)) assert.equal(user[key],value,key);
      for(const k of ["preferred_locale","privateNote","internalRisk","mapped"]) assert.ok(!(k in user),k);
    }
    publicProfile(current.data.user);
    const id=current.data.user.id;
    issuer.profile({...raw,mapped:{locale:"returning change",count:33,privateNote:"returning private",accountClass:"unexpected"}});
    assert.equal((await peer.login()).pathname,"/done");
    current=await peer.client.getSession();
    assert.equal(current.data.user.id,id);
    publicProfile(current.data.user);
    const saved=database.prepare('SELECT preferred_locale,privateNote,internalRisk FROM "user" WHERE id=?').get(id);
    assert.deepEqual({...saved},{preferred_locale:expected.locale,privateNote:defaults?null:"provider-private",internalRisk:9});
  }
}

export async function compareSocialProfileSync(t, harness) {
  const {go, ref, issuer, database} = await profileServers(t, harness, false, true);
  for (const [first, second, label] of [[go, ref, "native"], [ref, go, "reference"]]) {
    const subject = label + "-sync";
    const email = subject + "@example.test";
    const picture = "https://images.example.test/initial";
    async function signIn(server, profile, verified) {
      issuer.profile({id: subject, email, emailVerified: verified, email_verified: verified, ...profile});
      const actor = browser(server, harness.instrument);
      assert.equal((await actor.login()).pathname, "/done");
      const result = await actor.client.getSession();
      assert.equal(result.error, null);
      return result.data.user;
    }
    const initial = await signIn(first, {name: "Original", picture, mapped: {locale: "fr", count: 7, flag: true}}, true);
    const changed = await signIn(second, {
      name: "Updated", email: email.toUpperCase(),
      mapped: {count: 0, flag: false, accountClass: "other", privateNote: "updated", internalRisk: 100},
    }, false);
    assert.equal(changed.id, initial.id);
    assert.equal(changed.name, "Updated");
    assert.equal(changed.image, picture);
    assert.equal(changed.email, email);
    assert.equal(changed.emailVerified, true);
    assert.equal(changed.locale, "fr");
    assert.equal(changed.count, 0);
    assert.equal(changed.flag, false);
    assert.equal(changed.accountClass, "standard");
    assert.ok(!("privateNote" in changed));
    const saved = database.prepare('SELECT privateNote, internalRisk FROM "user" WHERE id=?').get(initial.id);
    assert.deepEqual({...saved}, {privateNote: "updated", internalRisk: 9});

    const newEmail = "new-" + email;
    const newImage = "https://images.example.test/updated";
    const moved = await signIn(first, {name: "Updated", email: newEmail.toUpperCase(), picture: newImage}, false);
    assert.equal(moved.id, initial.id);
    assert.equal(moved.image, newImage);
    assert.equal(moved.email, newEmail);
    assert.equal(moved.emailVerified, false);
    const verified = await signIn(second, {email: newEmail, name: "Verified"}, true);
    assert.equal(verified.id, initial.id);
    assert.equal(verified.emailVerified, true);
    assert.equal(database.prepare('SELECT count(*) AS n FROM "account" WHERE userId=?').get(initial.id).n, 1);
  }
  const snapshot = () => database.prepare('SELECT id, name, email, emailVerified FROM "user" ORDER BY id').all();
  const before = snapshot();
  issuer.profile({id: "native-sync", email: "new-reference-sync@example.test", emailVerified: true, name: "Conflict"});
  const visitor = browser(go, harness.instrument);
  const refused = await visitor.login();
  assert.equal(refused.pathname, "/retry");
  assert.equal(refused.searchParams.get("error"), "profile_conflict");
  assert.equal((await visitor.client.getSession()).data, null);
  assert.deepEqual(snapshot(), before);
}

export async function compareProviderEmailVerification(t, {reference, goFixture, instrument}, mode) {
  const issuer = await issuerFixture(t);
  const gated = mode !== "ungated";
  const go = await goFixture(t, [], {
    CONFORMANCE_PROVIDER: "1", CONFORMANCE_SOCIAL_FIELD_ISSUER: issuer.base, CONFORMANCE_SOCIAL_VERIFY: mode,
  });
  const database = new DatabaseSync(go.databasePath);
  t.after(() => database.close());
  const referenceMail = [];
  const emailVerification = {sendOnSignIn: mode === "resend"};
  if (["quiet", "ungated"].includes(mode)) emailVerification.sendOnSignUp = !gated;
  if (mode !== "no-sender") {
    emailVerification.sendVerificationEmail = async ({user, url, token}) => {
      if (mode === "delivery-error") throw new Error("fixture delivery unavailable");
      referenceMail.push({email:user.email, url, token});
    };
  }
  const ref = await reference(t, [referenceProvider(issuer, {requireEmailVerification:gated})], {
    database, emailAndPassword: {enabled:true, requireEmailVerification:true}, emailVerification, rateLimit:{enabled:false},
  });
  async function messages(server) {
    if (server === ref) return [...referenceMail];
    try {
      const raw = await readFile(go.databasePath + ".social-mail", "utf8");
      return raw.trimEnd().split("\n").map(line => JSON.parse(line));
    } catch (error) {
      if (error.code === "ENOENT") return [];
      throw error;
    }
  }
  for (const [sender, verifier, label] of [[go,ref,"native"],[ref,go,"reference"]]) {
    const email = label + "@issuer.test";
    issuer.profile({id:label, name:label, email, emailVerified:false, email_verified:false});
    const visitor = browser(sender, instrument);
    const startCount = (await messages(sender)).length;
    const first = await visitor.login();
    const owner = database.prepare('SELECT id, emailVerified FROM "user" WHERE email=?').get(email);
    assert.equal(owner.emailVerified, 0);
    const countSessions = () => database.prepare('SELECT count(*) AS n FROM session WHERE userId=?').get(owner.id).n;
    assert.equal(database.prepare('SELECT count(*) AS n FROM account WHERE userId=? AND providerId=?').get(owner.id,"work").n, 1);
    assert.equal(first.pathname, gated ? "/retry" : "/done");
    assert.equal(first.searchParams.get("error"), gated ? "email_not_verified" : null);
    assert.equal(countSessions(), gated ? 0 : 1);
    assert.equal(Boolean((await visitor.client.getSession()).data), !gated);
    const shouldDeliver = ["default", "resend", "ungated"].includes(mode);
    const afterSignup = await messages(sender);
    assert.equal(afterSignup.length - startCount, Number(shouldDeliver));

    const repeat = await visitor.login();
    assert.equal(repeat.pathname, first.pathname);
    assert.equal(countSessions(), gated ? 0 : 2);
    assert.equal((await messages(sender)).length - afterSignup.length, Number(mode === "resend"));
    if (shouldDeliver) {
      const message = afterSignup.at(-1);
      assert.equal(message.email, email);
      const callback = new URL(message.url).searchParams.get("callbackURL");
      assert.equal(new URL(callback, sender.baseURL).pathname, "/done");
      const approved = await browser(verifier, instrument).client.verifyEmail({query:{token:message.token}});
      assert.equal(approved.error, null);
      assert.equal((await visitor.login()).pathname, "/done");
      const session = (await visitor.client.getSession()).data;
      assert.equal(session.user.id, owner.id);
      assert.equal(session.user.emailVerified, true);
    }
  }
}

export async function compareAccountUpdateOnSignIn(t, {reference, goFixture, instrument}, preserve) {
  const issuer = await issuerFixture(t);
  const go = await goFixture(t, [], {
    CONFORMANCE_PROVIDER: "1", CONFORMANCE_SOCIAL_FIELD_ISSUER: issuer.base,
    CONFORMANCE_SOCIAL_PROFILE_SYNC: "1", CONFORMANCE_PRESERVE_PROVIDER_CREDENTIALS: preserve ? "1" : "0",
  });
  const database = new DatabaseSync(go.databasePath);
  t.after(() => database.close());
  const ref = await reference(t, [referenceProvider(issuer, {overrideUserInfo: true})], {
    database, account: preserve ? {updateAccountOnSignIn: false} : {}, rateLimit: {enabled: false},
  });
  for (const [first, second, id] of [[go, ref, "go-first"], [ref, go, "ref-first"]]) {
    const profile = {id, email: id + "@example.test", name: "Initial", emailVerified: true, email_verified: true};
    const read = () => database.prepare('SELECT * FROM account WHERE providerId=? AND accountId=?').get("work", id);
    issuer.profile(profile, {scope: "profile email", refresh_token: "original", expires_in: 600, refresh_token_expires_in: 3600});
    assert.equal((await browser(first, instrument).login()).pathname, "/done");
    const initial = read();
    assert.equal(initial.scope, "profile,email");
    assert.equal(initial.refreshToken, "original");
    assert.ok(initial.accessTokenExpiresAt && initial.refreshTokenExpiresAt);

    issuer.profile({...profile, name: "Returning"}, {scope: "write", refresh_token: "rotated", expires_in: 7200});
    const returning = browser(second, instrument);
    assert.equal((await returning.login()).pathname, "/done");
    const {data, error} = await returning.client.getSession();
    assert.equal(error, null);
    assert.equal(data.user.id, initial.userId);
    assert.equal(data.user.name, "Returning");
    const after = read();
    if (preserve) {
      assert.deepEqual(after, initial);
    } else {
      assert.notEqual(after.accessToken, initial.accessToken);
      assert.notEqual(after.accessTokenExpiresAt, initial.accessTokenExpiresAt);
      assert.equal(after.refreshToken, "rotated");
      assert.equal(after.refreshTokenExpiresAt, initial.refreshTokenExpiresAt);
      assert.equal(after.scope, initial.scope);
    }

    issuer.profile(profile, {scope: "email write write", refresh_token: "relinked"});
    const landing = await returning.login(["write"]);
    assert.equal(landing.pathname, "/done", landing.search);
    const linked = read();
    assert.equal(linked.id, initial.id);
    assert.equal(linked.userId, initial.userId);
    assert.equal(linked.scope, "profile,email,write");
    assert.equal(linked.refreshToken, "relinked");
    assert.notEqual(linked.accessToken, after.accessToken);
  }
}
