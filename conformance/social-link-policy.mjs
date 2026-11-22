import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { genericOAuth } from "better-auth/plugins/generic-oauth";

export async function compareImplicitLinking(t, {reference, goFixture, instrument}) {
  const email = "jo@example.org";
  for (const mode of ["default", "explicit", "disabled", "disabled-existing"]) {
    const provider = genericOAuth({config:[{
      providerId:"work", scopes:["profile"], clientId:"fixture-client", clientSecret:"fixture-secret",
      authorizationUrl:"https://id.example/authorize", tokenUrl:"https://id.example/token",
      getToken:async () => ({accessToken:"local-test", tokenType:"Bearer"}),
      getUserInfo:async () => ({id:"sample-user", email, name:"Jo", emailVerified:true}),
      accountSubject:({profile})=>profile.id,
    }]});
    const ref = await reference(t,[provider],{account:{accountLinking:{trustedProviders:["work"],enabled:!mode.startsWith("disabled"),disableImplicitLinking:mode==="explicit"}}});
    const go = await goFixture(t, [], {CONFORMANCE_PROVIDER:"1", CONFORMANCE_LINK_POLICY:mode.startsWith("disabled") ? "disabled" : mode});
    for (const target of [ref,go]) {
      const database = target.database ?? new DatabaseSync(target.databasePath);
      if (target === go) t.after(() => database.close());
      async function flow(asOwner, expect, jar = new Map()) {
        const transport = {...target, send:async r => {
          if (jar.size) r.headers.set("cookie", [...jar].map(([key, value]) => key + "=" + value).join("; "));
          const res=await target.send(r);
          for (const header of res.headers.getSetCookie()) {
            const pair=header.split(";")[0], split=pair.indexOf("=");
            if (/;\s*max-age=0(?:;|$)/i.test(header)) jar.delete(pair.slice(0,split));
            else jar.set(pair.slice(0,split),pair.slice(split+1));
          }
          return res;
        }};
        const {client}=instrument(transport);
        if (asOwner && jar.size === 0) assert.equal((await client.signIn.email({email,password:"existing owner password"})).error, null);
        const body={provider:"work", callbackURL:"/complete",errorCallbackURL:"/retry",disableRedirect:true};
        const started=await (asOwner ? client.linkSocial(body) : client.signIn.social(body));
        assert.equal(started.error,null);
        const authURL=new URL(started.data.url);
        const callback=new URL(authURL.searchParams.get("redirect_uri"));
        callback.searchParams.set("state",authURL.searchParams.get("state"));
        callback.searchParams.set("code","fixture-approval");
        const res=await transport.send(new Request(callback,{redirect:"manual",headers:{cookie:[...jar].map(([k,v])=>k+"="+v).join("; "),"user-agent":"authn-conformance"}}));
        assert.equal(res.status,302);
        const landing=new URL(res.headers.get("Location"),target.baseURL);
        assert.equal(landing.pathname,expect ? "/complete" : "/retry");
        if (!expect) {
          assert.equal(landing.searchParams.get("error"),asOwner ? "unable_to_link_account" : "account_not_linked");
          assert.ok(!res.headers.getSetCookie().some(c => c.includes("session_token=")));
        }
      }

      if (mode === "disabled-existing") {
        // An identity that registered while linking was closed can still sign in.
        const owner = new Map();
        await flow(false, true, owner);
        const linked = database.prepare("SELECT userId FROM account WHERE providerId='work' AND accountId='sample-user'").get();
        assert.ok(linked?.userId);
        await flow(true, false, owner);
        await flow(false, true);
        assert.equal(database.prepare("SELECT count(*) AS n FROM account WHERE userId=? AND providerId='work'").get(linked.userId).n, 1);
        continue;
      }
      const first=await instrument(target).client.signUp.email({email,name:"Owner",password:"existing owner password"});
      assert.equal(first.error,null);
      const id=first.data.user.id;
      database.prepare('UPDATE "user" SET emailVerified=1 WHERE id=?').run(id);
      const linked=()=>database.prepare("SELECT userId FROM account WHERE providerId='work' AND accountId='sample-user'").get()?.userId;
      const sessions=()=>database.prepare("SELECT count(*) AS n FROM session WHERE userId=?").get(id).n;
      const before=sessions();
      await flow(false,mode==="default");
      if (mode!=="default") {
        assert.equal(linked(),undefined);
        assert.equal(sessions(),before);
        await flow(true,mode==="explicit");
        if (mode==="disabled") {
          assert.equal(linked(),undefined);
          assert.equal(database.prepare("SELECT count(*) AS n FROM user").get().n, 1);
          continue;
        }
      }
      assert.equal(linked(),id);
      await flow(false,true);
      assert.equal(linked(),id);
    }
  }
}
