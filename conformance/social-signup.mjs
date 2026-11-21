import assert from "node:assert/strict";
import { genericOAuth } from "better-auth/plugins/generic-oauth";

export async function explicitSignup(t, {reference, goFixture, instrument}) {
  const provider = genericOAuth({config:[{
    providerId:"work",clientId:"fixture-client",clientSecret:"fixture-secret",
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
