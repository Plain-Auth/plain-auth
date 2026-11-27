import assert from "node:assert/strict";
import {createSocket} from "node:dgram";
import dns from "node:dns/promises";
import {syncBuiltinESMExports} from "node:module";
import {once} from "node:events";
import {DatabaseSync} from "node:sqlite";
import {sso} from "@better-auth/sso";
import {ssoClient} from "@better-auth/sso/client";
import {NodeSqliteDialect} from "@better-auth/kysely-adapter/node-sqlite-dialect";
import {betterAuth} from "better-auth";
import {getMigrations} from "better-auth/db/migration";

// A loopback-only authoritative responder for this fixture's TXT records.
// Each array is one RR and each string inside it is one character string.
async function localTXT(t) {
  const records = new Map();
  const server = createSocket("udp4");
  server.on("message", (query, peer) => {
    let end = 12;
    const labels = [];
    while (end < query.length && query[end]) {
      const length = query[end++];
      if (length > 63 || end+length > query.length) return;
      labels.push(query.toString("ascii", end, end+length)); end+=length;
    }
    end++;
    if (end+4 > query.length || query.readUInt16BE(end)!==16) return;
    const name=labels.join(".").toLowerCase(), values=records.get(name) ?? [];
    const header = Buffer.alloc(12);
    query.copy(header,0,0,2);
    header.writeUInt16BE(0x8580,2);
    header.writeUInt16BE(1,4);
    header.writeUInt16BE(values.length,6);
    const answer = [header,query.subarray(12,end+4)];
    for (const strings of values) {
      const body=Buffer.concat(strings.map(value=>Buffer.concat([Buffer.from([value.length]),Buffer.from(value)])));
      const rr=Buffer.alloc(12);
      rr.writeUInt16BE(0xc00c,0); rr.writeUInt16BE(16,2); rr.writeUInt16BE(1,4); rr.writeUInt16BE(body.length,10);
      answer.push(rr,body);
    }
    server.send(Buffer.concat(answer),peer.port,peer.address);
  });
  server.bind(0,"127.0.0.1"); await once(server,"listening");
  const address="127.0.0.1:"+server.address().port;
  // The pinned implementation imports the named ESM function. Rebinding only
  // the default resolver leaves that named export using the process resolver.
  const resolver=new dns.Resolver();
  resolver.setServers([address]);
  const original=dns.resolveTxt;
  dns.resolveTxt=resolver.resolveTxt.bind(resolver);
  syncBuiltinESMExports();
  t.after(async()=>{dns.resolveTxt=original;syncBuiltinESMExports();await new Promise(resolve=>server.close(resolve));});
  assert.equal((await import("node:dns/promises")).resolveTxt,dns.resolveTxt);
  return {records,address};
}

export async function compareSSODomains(t, {goFixture,instrument}) {
  const {records,address}=await localTXT(t);
  const go=await goFixture(t,["sso-domain-verification"],{CONFORMANCE_SSO_DNS:address});
  const db=new DatabaseSync(go.databasePath);t.after(()=>db.close());
  const opts={baseURL:"http://reference.localhost",secret:"local-conformance-0123456789-abcdefghijk",emailAndPassword:{enabled:true},
    database:{type:"sqlite",dialect:new NodeSqliteDialect({database:db}),transaction:true},
    plugins:[sso({domainVerification:{enabled:true,tokenPrefix:"tenant-proof"}})],telemetry:{enabled:false}};
  await (await getMigrations(opts)).runMigrations();
  const ref=betterAuth(opts),ts={baseURL:opts.baseURL,send:r=>ref.handler(r)};
  const ok=res=>{assert.equal(res.error,null,JSON.stringify(res.error));return res.data;};
  for(const [index,server] of [go,ts].entries()){
    const seen=[];
    const runtime={...server,send:async request=>{
      const response=await server.send(request);
      seen.push([new URL(request.url).pathname,response.status]);
      if(response.status===204) assert.equal(await response.clone().text(),"");
      return response;
    }};
    const api=instrument(runtime,[ssoClient()]).client;
    const credentials={email:"admin"+index+"@dns.test",password:"a local fixture password"};
    ok(await api.signUp.email({...credentials,name:"Domain owner"}));
    const providerId="dns-"+index, label="_tenant-proof-"+providerId;
    const issuer="https://identity.example";
    const domain="primary"+index+".example,secondary"+index+".example";
    const reg=ok(await api.sso.register({providerId,issuer,domain,oidcConfig:{skipDiscovery:true,clientId:"owned-client",clientSecret:"fixture-client-secret",authorizationEndpoint:issuer+"/authorize",tokenEndpoint:issuer+"/token",jwksEndpoint:issuer+"/keys"}}));
    assert.equal(reg.domainVerified,false);
    const token=reg.domainVerificationToken;
    assert.equal(token.length,24);
    assert.equal(ok(await api.sso.requestDomainVerification({providerId})).domainVerificationToken,token);
    const req=seen.at(-1);assert.equal(req[1],201);
    assert.equal((await api.signIn.sso({providerId,callbackURL:"/home"})).error.status,401);
    const absent=(await api.signIn.sso({providerId:"absent-"+index,callbackURL:"/home"})).error;
    assert.equal(absent.status,404);assert.equal(absent.message,"No provider found for the issuer");
    const names=domain.split(",").map(d=>label+"."+d);
    records.set(names[0],[["unrelated"],["  "+token.slice(0,10),token.slice(10)+"  "]]);
    assert.equal((await api.sso.verifyDomain({providerId})).error.code,"DOMAIN_VERIFICATION_FAILED");
    records.set(names[1],[[label+"=",token]]);
    ok(await api.sso.verifyDomain({providerId})); assert.equal(seen.at(-1)[1],204);
    assert.equal(ok(await api.sso.getProvider({query:{providerId}})).domainVerified,true);
    assert.equal((await api.sso.requestDomainVerification({providerId})).error.code,"DOMAIN_VERIFIED");
    assert.equal((await api.sso.verifyDomain({providerId})).error.status,409);
    assert.equal(ok(await api.signIn.sso({email:"member@dept.primary"+index+".example",callbackURL:"/home"})).redirect,true);
    const row=db.prepare("SELECT domainVerified FROM ssoProvider WHERE providerId=?").get(providerId);assert.equal(row.domainVerified,1);
  }
}
