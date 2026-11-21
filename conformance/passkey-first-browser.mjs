import assert from "node:assert/strict";
import { once } from "node:events";
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { DatabaseSync } from "node:sqlite";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { passkey } from "@better-auth/passkey";
import { passkeyClient } from "@better-auth/passkey/client";

const chromePaths = [process.env.CHROME_BIN, "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "/usr/bin/google-chrome", "/usr/bin/chromium"].filter(Boolean);

async function authenticator(t, url, binary) {
  const dir = await mkdtemp(join(tmpdir(), "stonewrit-webauthn-"));
  const proc = spawn(binary, ["--headless=new","--disable-background-networking","--disable-default-apps","--disable-sync","--no-first-run","--no-default-browser-check","--remote-debugging-address=127.0.0.1","--remote-debugging-port=0","--user-data-dir="+dir,url], {stdio:"ignore"});
  const exit = once(proc,"exit");
  let socket;
  t.after(async () => {
    socket?.close();
    if (proc.exitCode===null && proc.signalCode===null) proc.kill();
    await exit;
    await rm(dir,{recursive:true,force:true,maxRetries:3});
  });
  let target;
  for (let i=0;i<150 && !target;i++){
    if(proc.exitCode!==null) throw Error("Local browser exited during startup");
    try {
      const [port] = (await readFile(join(dir,"DevToolsActivePort"),"utf8")).split("\n");
      if(!/^\d+$/.test(port)) throw Error("Invalid local browser port");
      const targets = await (await fetch("http://127.0.0.1:"+port+"/json/list")).json();
      target=targets.find(tab=>tab.type==="page" && tab.url===url);
    }catch(e){if(e.code!=="ENOENT" && !(e instanceof TypeError)) throw e;}
    if(!target) await sleep(70);
  }
  assert.ok(target,"Chrome did not open the local fixture");
  socket=new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((r,j)=>{socket.onopen=r;socket.onerror=j});
  let id=0;
  const pending=new Map();
  socket.onmessage=({data})=>{
    const result=JSON.parse(data),p=pending.get(result.id);
    if(!p)return;
    pending.delete(result.id);
    if(result.error)p.reject(Error(result.error.message));else p.resolve(result.result);
  };
  function call(method,params={}){
    const current=++id;
    return new Promise((resolve,reject)=>{
      pending.set(current,{resolve,reject});socket.send(JSON.stringify({id:current,method,params}));
    });
  }
  await call("WebAuthn.enable");
  const add=()=>call("WebAuthn.addVirtualAuthenticator",{options:{protocol:"ctap2",transport:"internal",hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}});
  let device=await add();
  async function perform(method,{publicKey}){
    const raw=JSON.parse(JSON.stringify(publicKey,(_key,v)=>ArrayBuffer.isView(v)||v instanceof ArrayBuffer?Buffer.from(v.buffer??v,v.byteOffset??0,v.byteLength).toString("base64url"):v));
    const parse=method==="create"?"parseCreationOptionsFromJSON":"parseRequestOptionsFromJSON";
    const expression="(async()=>{const publicKey=PublicKeyCredential."+parse+"("+JSON.stringify(raw)+");const c=await navigator.credentials."+method+"({publicKey});return c.toJSON()})()";
    const result=await call("Runtime.evaluate",{expression,awaitPromise:true,returnByValue:true});
    if(result.exceptionDetails)throw Error(result.exceptionDetails.exception?.description??"WebAuthn rejected credentials");
    const credential=result.result.value, wire=credential.response;
    const decode=(x)=>Uint8Array.from(Buffer.from(x,"base64url")).buffer;
    const response={};
    for(const name of ["attestationObject","clientDataJSON","authenticatorData","signature","userHandle"])if(wire[name])response[name]=decode(wire[name]);
    if(method==="create"){
      response.getTransports=()=>wire.transports;
      response.getPublicKeyAlgorithm=()=>wire.publicKeyAlgorithm;
      response.getPublicKey=()=>wire.publicKey?decode(wire.publicKey):null;
      response.getAuthenticatorData=()=>decode(wire.authenticatorData);
    }
    return {...credential, rawId:decode(credential.rawId),response,getClientExtensionResults:()=>credential.clientExtensionResults};
  }
  // The published SDK runs in Node. Only navigator.credentials is forwarded to the actual browser.
  const oldPK=Object.getOwnPropertyDescriptor(globalThis,"PublicKeyCredential");
  Object.defineProperty(globalThis,"PublicKeyCredential",{value:class PublicKeyCredential{},configurable:true});
  Object.defineProperty(navigator,"credentials",{value:{create:o=>perform("create",o),get:o=>perform("get",o)},configurable:true});
  t.after(()=>{delete navigator.credentials;if(oldPK)Object.defineProperty(globalThis,"PublicKeyCredential",oldPK);else delete globalThis.PublicKeyCredential;});
  return async()=>{await call("WebAuthn.removeVirtualAuthenticator",device);device=await add()};
}

export async function comparePasskeyFirst(t,{goFixture,instrument}) {
  const binary=chromePaths.find(existsSync);
  if(!binary){t.skip("requires Chrome or Chromium for the virtual WebAuthn authenticator");return}
  const go=await goFixture(t,["passkey"],{CONFORMANCE_PASSKEY_FIRST:"1"});
  const database=new DatabaseSync(":memory:");t.after(()=>database.close());
  const options={baseURL:go.baseURL,database,secret:"local-webauthn-reference-0123456789-abc",telemetry:{enabled:false},plugins:[passkey({
    rpID:"localhost",origin:go.baseURL,rpName:"Local registration",authenticatorSelection:{userVerification:"required"},
    registration:{requireSession:false,resolveUser:({context})=>context==="local-enrollment"?{id:"candidate",name:"candidate@example.test",displayName:"Local device"}:null,
      afterVerification:async({ctx,context})=>{
        if(context!=="local-enrollment")return;
        const user=await ctx.context.internalAdapter.createUser({name:"Local user",email:"local@example.test"},{method:"passkey"});
        return{userId:user.id,name:"Local authenticator"};
      }},
  })]};
  await (await getMigrations(options)).runMigrations();const reference=betterAuth(options);
  const reset=await authenticator(t,go.baseURL+"/api/auth/ok",binary);
  for(const server of [go,{baseURL:go.baseURL,send:r=>reference.handler(r)}]){
    const client=instrument(server,[passkeyClient()]).client;
    const enrolled=await client.passkey.addPasskey({context:"local-enrollment",createSession:true,returnWebAuthnResponse:true});
    assert.equal(enrolled.error,null,JSON.stringify(enrolled.error));
    const {user,session,credentialID,name}=enrolled.data;
    assert.equal(user.email,"local@example.test");
    assert.equal(user.id,enrolled.data.userId);
    assert.notEqual(user.id,"candidate");
    assert.equal(name,"Local authenticator");
    assert.equal(session.userId,user.id);
    assert.equal((await client.getSession()).data.session.token,session.token);
    assert.equal(enrolled.webauthn.response.id,credentialID);
    assert.equal((await client.signOut()).error,null);
    const signed=await client.signIn.passkey();
    assert.equal(signed.error,null,JSON.stringify(signed.error));
    assert.equal((await client.getSession()).data.user.id,user.id);
    await reset();
  }
}
