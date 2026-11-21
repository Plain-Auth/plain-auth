import assert from "node:assert/strict";
import { genericOAuth } from "better-auth/plugins/generic-oauth";

export async function explicitSignup(t, {reference, goFixture, instrument}) {
  const provider = genericOAuth({config:[{
    providerId:"work",scopes:["profile"],clientId:"fixture-client",clientSecret:"fixture-secret",
    authorizationUrl:"https://id.example/authorize",tokenUrl:"https://id.example/token",disableImplicitSignUp:true,
    getToken: async () => ({accessToken:"local-test",tokenType:"Bearer"}),
    getUserInfo: async () => ({id:"sample-user",email:"jo@example.org",name:"Jo",emailVerified:true}),
    accountSubject: ({profile}) => profile.id,
  }]});
  for (const target of [await reference(t,[provider]), await goFixture(t,[],{CONFORMANCE_PROVIDER:"1",CONFORMANCE_EXPLICIT_SIGNUP:"1"})]) {
    for (const [requestSignUp, path] of [[false,"/declined"],[true,"/welcome"],[false,"/returning"]]) {
      const cookies = [];
      const {client} = instrument({...target,send: async (r) => {
        const response=await target.send(r);
        for (const header of response.headers.getSetCookie()) cookies.push(header.split(";")[0]);
        return response;
      }});
      const response = await client.signIn.social({
        provider:"work", requestSignUp, disableRedirect:true,
        callbackURL:target.baseURL+"/returning",newUserCallbackURL:target.baseURL+"/welcome",errorCallbackURL:target.baseURL+"/declined",
      });
      assert.equal(response.error,null);
      const authorization=new URL(response.data.url);
      const callback=new URL(authorization.searchParams.get("redirect_uri"));
      callback.searchParams.set("state",authorization.searchParams.get("state"));
      callback.searchParams.set("code","fixture");
      callback.searchParams.set("requestSignUp","true");
      const done=await target.send(new Request(callback,{headers:{cookie:cookies.join("; "),"user-agent":"authn-conformance"},redirect:"manual"}));
      assert.equal(done.status,302);
      const landing=new URL(done.headers.get("location"),target.baseURL);
      assert.equal(landing.pathname,path);
      if(path==="/declined") assert.equal(landing.searchParams.get("error"),"signup_disabled");
    }
  }
}

export async function authorizationParameters(t, {reference,goFixture,instrument}) {
  const provider=genericOAuth({config:[{
    providerId:"work",clientId:"fixture-client",clientSecret:"secret",scopes:["profile"],
    authorizationUrl:"https://id.example/authorize",tokenUrl:"https://id.example/token",
    accountSubject:({profile})=>profile.id,
  }]});
  for (const server of [await reference(t,[provider]), await goFixture(t,[],{CONFORMANCE_PROVIDER:"1",CONFORMANCE_EXPLICIT_SIGNUP:"1"})]) {
    const {client}=instrument(server);
    const signup=await client.signUp.email({email:"jo@example.org",name:"Jo",password:"fixture-long-password"});
    assert.equal(signup.error,null);
    for (const start of [(body)=>client.signIn.social(body),(body)=>client.linkSocial(body)]) {
      const base={provider:"work",callbackURL:server.baseURL+"/return",disableRedirect:true};
      const output=await start({...base,scopes:["contacts"],loginHint:"jo@example.org",additionalParams:{prompt:"consent",ui_locales:"fr"}});
      assert.equal(output.error,null);
      const q=new URL(output.data.url).searchParams;
      assert.deepEqual(q.get("scope").split(" ").sort(),["contacts","profile"]);
      assert.equal(q.get("login_hint"),"jo@example.org");
      assert.equal(q.get("prompt"),"consent");
      assert.equal(q.get("ui_locales"),"fr");
      assert.equal(q.get("code_challenge_method"),"S256");
      const fresh=await start(base);
      assert.equal(new URL(fresh.data.url).searchParams.get("scope"),"profile");
      assert.equal(new URL(fresh.data.url).searchParams.has("login_hint"),false);
      for (const key of ["state","client_id","redirect_uri","response_type","code_challenge","code_challenge_method","nonce","scope"]) {
        const denied=await start({...base,additionalParams:{[key]:"placeholder"}});
        assert.equal(denied.error?.status,400,key);
      }
    }
  }
}
