import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { genericOAuth } from "better-auth/plugins/generic-oauth";

export async function compareImplicitLinking(t, {reference, goFixture, instrument}) {
  const email = "jo@example.org";
  for (const mode of ["default", "explicit"]) {
    const provider = genericOAuth({config:[{
      providerId:"work", scopes:["profile"], clientId:"fixture-client", clientSecret:"fixture-secret",
      authorizationUrl:"https://id.example/authorize", tokenUrl:"https://id.example/token",
      getToken:async () => ({accessToken:"local-test", tokenType:"Bearer"}),
      getUserInfo:async () => ({id:"sample-user", email, name:"Jo", emailVerified:true}),
      accountSubject:({profile})=>profile.id,
    }]});
    const ref = await reference(t,[provider],{account:{accountLinking:{trustedProviders:["work"],disableImplicitLinking:mode==="explicit"}}});
    const go = await goFixture(t, [], {CONFORMANCE_PROVIDER:"1", CONFORMANCE_LINK_POLICY:mode});
    for (const target of [ref,go]) {
      const database = target.database ?? new DatabaseSync(target.databasePath);
      if (target === go) t.after(() => database.close());
      async function flow(asOwner, expect) {
        const jar = new Map();
        const transport = {...target, send:async r => {
          const res=await target.send(r);
          for (const header of res.headers.getSetCookie()) {
            const pair=header.split(";")[0], split=pair.indexOf("=");
            jar.set(pair.slice(0,split),pair.slice(split+1));
          }
          return res;
        }};
        const {client}=instrument(transport);
        if (asOwner) assert.equal((await client.signIn.email({email,password:"existing owner password"})).error, null);
        const body={provider:"work", callbackURL:"/complete",errorCallbackURL:"/retry",disableRedirect:true};
        const started=await (asOwner ? client.linkSocial(body) : client.signIn.social(body));
        assert.equal(started.error,null);
        const authURL=new URL(started.data.url);
        const callback=new URL(authURL.searchParams.get("redirect_uri"));
        callback.searchParams.set("state",authURL.searchParams.get("state"));
        callback.searchParams.set("code","fixture-approval");
        const res=await target.send(new Request(callback,{redirect:"manual",headers:{cookie:[...jar].map(([k,v])=>k+"="+v).join("; "),"user-agent":"authn-conformance"}}));
        assert.equal(res.status,302);
        const landing=new URL(res.headers.get("Location"),target.baseURL);
        assert.equal(landing.pathname,expect ? "/complete" : "/retry");
        if (!expect) {
          assert.equal(landing.searchParams.get("error"),"account_not_linked");
          assert.ok(!res.headers.getSetCookie().some(c => c.includes("session_token=")));
        }
      }

      const first=await instrument(target).client.signUp.email({email,name:"Owner",password:"existing owner password"});
      assert.equal(first.error,null);
      const id=first.data.user.id;
      database.prepare('UPDATE "user" SET emailVerified=1 WHERE id=?').run(id);
      const linked=()=>database.prepare("SELECT userId FROM account WHERE providerId='work' AND accountId='sample-user'").get()?.userId;
      const sessions=()=>database.prepare("SELECT count(*) AS n FROM session WHERE userId=?").get(id).n;
      const before=sessions();
      await flow(false,mode==="default");
      if (mode==="explicit") {
        assert.equal(linked(),undefined);
        assert.equal(sessions(),before);
        await flow(true,true);
      }
      assert.equal(linked(),id);
      await flow(false,true);
      assert.equal(linked(),id);
    }
  }
}
