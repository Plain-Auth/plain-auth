import assert from "node:assert/strict";
import { genericOAuth } from "better-auth/plugins/generic-oauth";

export async function compareSocialLogout(t, {reference,goFixture,instrument}) {
  const plugin=genericOAuth({config:[{
    providerId:"work",clientId:"fixture-client",clientSecret:"secret",
    authorizationUrl:"https://id.example/authorize",tokenUrl:"https://id.example/token",endSessionEndpoint:"https://id.example/end?tenant=work",
    getToken:async()=>({accessToken:"fixture",tokenType:"Bearer"}),
    getUserInfo:async()=>({id:"jo",name:"Jo",email:"jo@example.org",emailVerified:true}),
    accountSubject:({profile})=>profile.id,
  }]});
  for (const server of [await reference(t,[plugin]),await goFixture(t,[],{CONFORMANCE_PROVIDER:"1",CONFORMANCE_EXPLICIT_SIGNUP:"1"})]) {
    const cookies=new Map();
    function save(response){
      for (const line of response.headers.getSetCookie()){
        const [pair]=line.split(";");
        const at=pair.indexOf("=");
        cookies.set(pair.slice(0,at),pair.slice(at+1));
      }
      return response;
    }
    const header=()=>[...cookies].map(([k,v])=>k+"="+v).join("; ");
    const {client}=instrument({...server,send:async r=>save(await server.send(r))});
    const begin=await client.signIn.social({provider:"work",requestSignUp:true,callbackURL:server.baseURL+"/ok",disableRedirect:true});
    assert.equal(begin.error,null);
    const target=new URL(begin.data.url);
    const callback=new URL(target.searchParams.get("redirect_uri"));
    callback.searchParams.set("code","fixture");
    callback.searchParams.set("state",target.searchParams.get("state"));
    assert.equal(save(await server.send(new Request(callback,{headers:{cookie:header()},redirect:"manual"}))).status,302);
    const sessionCookie=header();
    const fresh=instrument(server).client;
    const fetchOptions={headers:{cookie:sessionCookie}};
    assert.ok((await fresh.getSession({fetchOptions})).data.user.id);
    const result=await fresh.signOut({callbackURL:server.baseURL+"/after",state:"application-state",disableRedirect:true,fetchOptions});
    assert.equal(result.error,null);
    assert.equal(result.data.success,true);
    assert.equal(result.data.redirect,false);
    const url=new URL(result.data.url);
    assert.equal(url.origin,"https://id.example");
    assert.equal(url.pathname,"/end");
    assert.equal(url.searchParams.get("tenant"),"work");
    assert.equal(url.searchParams.get("client_id"),"fixture-client");
    assert.equal(url.searchParams.get("post_logout_redirect_uri"),server.baseURL+"/after");
    assert.equal(url.searchParams.get("state"),"application-state");
    assert.equal(url.searchParams.has("id_token_hint"),false);
    assert.equal((await instrument(server).client.getSession({fetchOptions})).data,null);
  }
}
