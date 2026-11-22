import assert from "node:assert/strict";
import { chromeBinary, openChromePage } from "./browser-debug.mjs";
import { DatabaseSync } from "node:sqlite";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { passkey } from "@better-auth/passkey";
import { passkeyClient } from "@better-auth/passkey/client";


async function authenticator(t, url, binary) {
  const call = await openChromePage(t, url, binary);
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
  const binary=chromeBinary();
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
