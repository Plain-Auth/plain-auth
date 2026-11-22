import assert from "node:assert/strict";
import { createServer } from "node:http";
import { once } from "node:events";
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

async function issuerFixture(t) {
  let profile, sequence = 0;
  const codes = new Map(), tokens = new Map();
  const server = createServer(async (req, res) => {
    const url = new URL(req.url, "http://localhost");
    if (url.pathname === "/authorize") {
      const callback = new URL(url.searchParams.get("redirect_uri"));
      const code = "approved-" + (++sequence);
      codes.set(code, { profile, callback: callback.href });
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
      res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ access_token: token, token_type: "Bearer" }));
      return;
    }
    const data = tokens.get(req.headers.authorization?.replace(/^Bearer /, ""));
    if (url.pathname === "/userinfo" && data) res.writeHead(200, {"content-type":"application/json"}).end(JSON.stringify(data));
    else res.writeHead(401).end();
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => new Promise(resolve => server.close(resolve)));
  return { base: "http://127.0.0.1:" + server.address().port, profile: value => { profile = value; } };
}

function browser(target, instrument) {
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
  return {client, async login() {
    const start = await client.signIn.social({ provider:"work", disableRedirect:true, callbackURL:"/done", errorCallbackURL:"/retry",
      locale:"browser-body", privateNote:"browser-body-private", additionalData:{locale:"browser-state",accountClass:"browser-owned",privateNote:"browser-state-private"} });
    assert.equal(start.error,null);
    const approval = await fetch(start.data.url,{redirect:"manual"});
    assert.equal(approval.status,302);
    const res = await transport.send(new Request(approval.headers.get("location"), {redirect:"manual",headers:{"user-agent":"authn-conformance"}}));
    assert.equal(res.status,302);
    return new URL(res.headers.get("location"),target.baseURL);
  }};
}

export async function compareSocialUserFields(t, { reference, goFixture, instrument }, defaults) {
  const issuer=await issuerFixture(t);
  const fields={...mappings,locale:{...mappings.locale}};
  if (defaults) fields.locale.defaultValue="en";
  const provider=genericOAuth({config:[{ providerId:"work",clientId:"profile-app",clientSecret:"local-secret",scopes:["profile"],
    authorizationUrl:issuer.base+"/authorize",tokenUrl:issuer.base+"/token",userInfoUrl:issuer.base+"/userinfo",
    accountSubject:({profile})=>profile.id,
    mapProfileToUser:raw=>raw.mapped??{},
  }]});
  const go=await goFixture(t,[],{CONFORMANCE_PROVIDER:"1",CONFORMANCE_USER_FIELDS:"1",CONFORMANCE_SOCIAL_FIELD_ISSUER:issuer.base,CONFORMANCE_SOCIAL_FIELD_DEFAULT:defaults?"1":"0"});
  const database=new DatabaseSync(go.databasePath);
  t.after(()=>database.close());
  const ref=await reference(t,[provider],{database,user:{additionalFields:fields},rateLimit:{enabled:false}});
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
