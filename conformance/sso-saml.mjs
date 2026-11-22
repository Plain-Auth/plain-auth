import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createPublicKey, randomUUID, sign, verify } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { request as httpsRequest } from "node:https";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { deflateRawSync, inflateRawSync } from "node:zlib";
import { sso } from "@better-auth/sso";
import { ssoClient } from "@better-auth/sso/client";
import { NodeSqliteDialect } from "@better-auth/kysely-adapter/node-sqlite-dialect";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { SignedXml } from "xml-crypto";
import xmlEncryption from "@authenio/xml-encryption";

const issuer = "https://idp.example.test/metadata";
const entryPoint = "https://idp.example.test/sign-in";
const assertionNS = "urn:oasis:names:tc:SAML:2.0:assertion";
const protocolNS = "urn:oasis:names:tc:SAML:2.0:protocol";
const excC14n = "http://www.w3.org/2001/10/xml-exc-c14n#";
const ok = result => {
  assert.equal(result.error, null, JSON.stringify(result.error));
  return result.data;
};

function xml(value) {
  return value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll('"', "&quot;");
}

// The fixture's private signing key stays in this test process. The Go handler
// and the published TypeScript handler consume exactly the same signed format.
function signedReply({ id, acs, audience, cert, key }) {
  const correlation=id ? ` InResponseTo="${xml(id)}"` : "";
  const date = offset => new Date(Date.now() + offset).toISOString();
  const attribute = (name, value) => '<saml:Attribute Name="' + xml(name) + '"><saml:AttributeValue>' + xml(value) + '</saml:AttributeValue></saml:Attribute>';
  const response = `<samlp:Response xmlns:samlp="${protocolNS}" xmlns:saml="${assertionNS}" ID="_${randomUUID()}" Version="2.0" IssueInstant="${date(0)}" Destination="${xml(acs)}"${correlation}>
  <saml:Issuer>${issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion xmlns:saml="${assertionNS}" ID="_${randomUUID()}" Version="2.0" IssueInstant="${date(0)}"><saml:Issuer>${issuer}</saml:Issuer>
  <saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">stable-user</saml:NameID>
  <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="${date(60000)}"${correlation} Recipient="${xml(acs)}"/></saml:SubjectConfirmation></saml:Subject>
  <saml:Conditions NotBefore="${date(-15000)}" NotOnOrAfter="${date(60000)}"><saml:AudienceRestriction><saml:Audience>${xml(audience)}</saml:Audience></saml:AudienceRestriction></saml:Conditions>
  <saml:AuthnStatement AuthnInstant="${date(-1000)}" SessionIndex="local-assertion-session"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>
  <saml:AttributeStatement>${attribute("email","employee@enterprise.example")}${attribute("displayName","Enterprise Employee")}</saml:AttributeStatement></saml:Assertion></samlp:Response>`;
  const signature = new SignedXml({privateKey:key, publicCert:cert,
    signatureAlgorithm:"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", canonicalizationAlgorithm:excC14n});
  signature.addReference({xpath:"//*[local-name()='Assertion']", digestAlgorithm:"http://www.w3.org/2001/04/xmlenc#sha256",
    transforms:["http://www.w3.org/2000/09/xmldsig#enveloped-signature",excC14n]});
  signature.computeSignature(response,{prefix:"ds", location:{reference:"//*[local-name()='Assertion']/*[local-name()='Issuer']",action:"after"}});
  return Buffer.from(signature.getSignedXml()).toString("base64");
}

// An independent IdP encrypts the already signed assertion using solely the
// recipient's published certificate. The surrounding response stays unsigned.
async function encryptSignedReply(encoded, cert) {
  const original=Buffer.from(encoded,"base64").toString();
  const assertion=original.match(/<saml:Assertion (?:.|\n)*?<\/saml:Assertion>/)?.[0];
  assert.ok(assertion);
  const options={rsa_pub:createPublicKey(cert).export({type:"spki",format:"pem"}),pem:cert,
    encryptionAlgorithm:"http://www.w3.org/2009/xmlenc11#aes256-gcm",
    keyEncryptionAlgorithm:"http://www.w3.org/2009/xmlenc11#rsa-oaep",
    keyEncryptionDigest:"sha256",keyEncryptionMgf:"sha256"};
  const encrypted=await new Promise((resolve,reject)=>xmlEncryption.encrypt(assertion,options,(err,value)=>err?reject(err):resolve(value)));
  return Buffer.from(original.replace(assertion,"<saml:EncryptedAssertion>"+encrypted+"</saml:EncryptedAssertion>")).toString("base64");
}

function signedLogoutReply(destination,requestID,relay,key) {
  const response=`<samlp:LogoutResponse xmlns:samlp="${protocolNS}" xmlns:saml="${assertionNS}" ID="_${randomUUID()}" Version="2.0" IssueInstant="${new Date().toISOString()}" Destination="${xml(destination)}" InResponseTo="${xml(requestID)}"><saml:Issuer>${issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status></samlp:LogoutResponse>`;
  const data=deflateRawSync(Buffer.from(response)).toString("base64");
  let query="SAMLResponse="+encodeURIComponent(data);
  if (relay) query+="&RelayState="+encodeURIComponent(relay);
  query+="&SigAlg="+encodeURIComponent("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
  return query+"&Signature="+encodeURIComponent(sign("RSA-SHA256",Buffer.from(query),key).toString("base64"));
}

function trustedFixtureTransport(ca) {
  return async r => {
    const data = r.body ? Buffer.from(await r.arrayBuffer()) : undefined;
    return new Promise((resolve,reject) => {
      const request = httpsRequest(r.url,{ca,method:r.method,headers:Object.fromEntries(r.headers)}, incoming => {
        const chunks = [];
        incoming.on("data", part => chunks.push(part));
        incoming.on("error",reject);
        incoming.on("end", () => {
          const headers = new Headers();
          for (let i=0;i<incoming.rawHeaders.length;i+=2) headers.append(incoming.rawHeaders[i],incoming.rawHeaders[i+1]);
          resolve(new Response([204,304].includes(incoming.statusCode) ? null : Buffer.concat(chunks),{status:incoming.statusCode,headers}));
        });
      });
      request.on("error", reject);
      request.end(data);
    });
  };
}

function browserFor(runtime) {
  const jar = new Map();
  return async r => {
    const headers = new Headers(r.headers);
    headers.set("cookie",[...jar].map(([name,value])=>name+"="+value).join("; "));
    const result = await runtime.send(new Request(r,{headers}));
    for (const cookie of result.headers.getSetCookie()) {
      const first=cookie.split(";",1)[0], pos=first.indexOf("=");
      const name=first.slice(0,pos);
      if (/;\s*Max-Age=0(?:;|$)/i.test(cookie)) jar.delete(name);
      else jar.set(name,first.slice(pos+1));
    }
    return result;
  };
}

function inlineIdP(certificates, entity=issuer) {
  const ds="http://www.w3.org/2000/09/xmldsig#";
  const descriptors=certificates.map(cert=>{
    const data=cert.replace(/-----[^-]+-----/g,"").replace(/\s/g,"");
    return `<md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>${data}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>`;
  });
  return `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="${ds}" entityID="${xml(entity)}"><md:IDPSSODescriptor protocolSupportEnumeration="${protocolNS}">${descriptors.join("")}<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="${entryPoint}"/></md:IDPSSODescriptor></md:EntityDescriptor>`;
}

export async function compareEnterpriseSAML(t, {goFixture,instrument,privateDeployment=false,inline=false,encrypted=false,portal=false,logout=false}) {
  const keys = await mkdtemp(join(tmpdir(),"stonewrit-idp-"));
  t.after(()=>rm(keys,{recursive:true,force:true}));
  const keyFile=join(keys,"private.pem"), certFile=join(keys,"cert.pem");
  execFileSync("openssl",["req","-x509","-newkey","rsa:2048","-nodes","-keyout",keyFile,"-out",certFile,"-days","1","-subj","/CN=Local identity provider"],{stdio:"ignore"});
  const [key,cert]=await Promise.all([readFile(keyFile,"utf8"),readFile(certFile,"utf8")]);
  let rotating;
  if (inline) {
    const privateFile=join(keys,"next-private.pem"),publicFile=join(keys,"next-cert.pem");
    execFileSync("openssl",["req","-x509","-newkey","rsa:2048","-nodes","-keyout",privateFile,"-out",publicFile,"-days","1","-subj","/CN=Next local identity provider"],{stdio:"ignore"});
    rotating={key:await readFile(privateFile,"utf8"),cert:await readFile(publicFile,"utf8")};
  }
  const fixtureEnv={CONFORMANCE_SAML:"1"};
  let actorKey,actorCert;
  if (logout) {
    const priv=join(keys,"logout-key.pem"),certPath=join(keys,"logout-cert.pem");
    execFileSync("openssl",["req","-x509","-newkey","rsa:2048","-nodes","-keyout",priv,"-out",certPath,"-days","1","-subj","/CN=Local logout signing service"],{stdio:"ignore"});
    [actorKey,actorCert]=await Promise.all([readFile(priv,"utf8"),readFile(certPath,"utf8")]);
    fixtureEnv.CONFORMANCE_SAML_SLO_DIR=keys;
  }
  const reviewed=join(keys,"reviewed-directory");
  if (portal) fixtureEnv.CONFORMANCE_SAML_REVIEWED_DIRECTORY=reviewed;
  let spKey,spCert;
  if (encrypted) {
    const spKeyFile=join(keys,"sp-key.pem"),spCertFile=join(keys,"sp-cert.pem");
    execFileSync("openssl",["req","-x509","-newkey","rsa:2048","-nodes","-keyout",spKeyFile,"-out",spCertFile,"-days","1","-subj","/CN=Local SAML assertion recipient"],{stdio:"ignore"});
    [spKey,spCert]=await Promise.all([readFile(spKeyFile,"utf8"),readFile(spCertFile,"utf8")]);
    fixtureEnv.CONFORMANCE_SAML_ENCRYPTION_DIR=keys;
  }
  if (privateDeployment) {
    fixtureEnv.CONFORMANCE_DISABLED_PATHS="/sso/saml2/sp/metadata /sign-up/email";
    fixtureEnv.CONFORMANCE_OPENAPI="1";
  }
  const go=await goFixture(t,["sso"],fixtureEnv);
  const mount=privateDeployment ? "/identity" : "/api/auth";
  if (privateDeployment) go.basePath=mount;
  go.send=trustedFixtureTransport(await readFile(join(dirname(go.databasePath),"saml-test-ca.pem")));
  const db=new DatabaseSync(privateDeployment ? go.databasePath : ":memory:");
  t.after(()=>db.close());
  const options={baseURL:"https://saml.reference.localhost",secret:"local-conformance-0123456789-abcdefghijk",
    database:{type:"sqlite",dialect:new NodeSqliteDialect({database:db}),transaction:true},emailAndPassword:{enabled:true},
    telemetry:{enabled:false},plugins:[sso({saml:{...(portal && {allowIdpInitiated:true,idpInitiatedCallbackUrl:"/global-landing"}),...(logout && {enableSingleLogout:true,wantLogoutRequestSigned:true,wantLogoutResponseSigned:true})}})]};
  await (await getMigrations(options)).runMigrations();
  const auth=betterAuth(options);
  const reference={baseURL:options.baseURL,send:r=>auth.handler(r)};
  for (const runtime of privateDeployment ? [go] : [go,reference]) {
    const audience=runtime.baseURL+"/service-provider";
    const acs=runtime.baseURL+mount+"/sso/saml2/sp/acs/work";
    const admin=instrument(runtime,[ssoClient()]).client;
    const user={name:"Registry owner",email:"admin@enterprise.example",password:"valid-long-password"};
    if (privateDeployment) {
      const gated=await runtime.send(new Request(runtime.baseURL+mount+"/sign-up/email",{
        method:"POST",headers:{origin:runtime.baseURL,"content-type":"application/json"},body:JSON.stringify(user)}));
      assert.equal(gated.status,404);
      // A trusted provisioning process using the shared SQLite database enrolled
      // this administrator; the public Go handler only permits their sign-in.
      ok(await instrument(reference).client.signUp.email(user));
      ok(await admin.signIn.email({email:user.email,password:user.password}));
    } else {
      ok(await admin.signUp.email(user));
    }
    const idpMetadata=inline ? {metadata:inlineIdP([cert])} : {entityID:issuer};
    const spMetadata={entityID:audience};
    if (logout) {
      idpMetadata.singleLogoutService=[{Binding:"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",Location:"https://idp.example.test/logout"}];
      if (runtime===reference) spMetadata.privateKey=actorKey;
    }
    if (encrypted) {
      spMetadata.isAssertionEncrypted=true;
      if (runtime===reference) {
        idpMetadata.isAssertionEncrypted=true;
        spMetadata.encPrivateKey=spKey;
      }
    }
    const samlConfig={entryPoint:inline ? "https://manual.example.test/unused" : entryPoint,
      ...(inline ? {} : {cert}),...(portal && {idpInitiatedCallbackUrl:encrypted ? "https://unused.invalid/landing" : "/staff-portal",callbackUrl:"/fallback"}),idpMetadata,spMetadata,wantAssertionsSigned:true};
    const registration = ok(await admin.sso.register({providerId:"work",domain:"enterprise.example",issuer,samlConfig}));
    assert.equal(registration.redirectURI,runtime.baseURL+mount+"/sso/callback/work");
    if (inline) assert.equal(registration.samlConfig.idpMetadata.metadata,inlineIdP([cert]));
    else assert.equal(registration.samlConfig.cert,cert);
    assert.equal(registration.samlConfig.issuer,issuer);
    const metadata=await runtime.send(new Request(runtime.baseURL+mount+"/sso/saml2/sp/metadata?providerId=work"));
    if (privateDeployment) {
      assert.equal(metadata.status,404);
      const spec=await runtime.send(new Request(runtime.baseURL+mount+"/open-api/generate-schema"));
      assert.equal(spec.status,200);
      const {paths}=await spec.json();
      assert.equal(paths["/sign-up/email"],undefined);
      assert.equal(paths["/sso/saml2/sp/metadata"],undefined);
      assert.ok(paths["/sso/saml2/sp/acs/{providerId}"].post);
      const registrationSchema=paths["/sso/register"].post.requestBody.content["application/json"].schema;
      assert.ok(registrationSchema.properties.samlConfig);
    } else {
      assert.equal(metadata.status,200);
      assert.match(metadata.headers.get("content-type"),/application\/xml/);
      const descriptor=await metadata.text();
      if (encrypted && runtime===go) {
        const advertised=descriptor.match(/use="encryption"[\s\S]*?<X509Certificate(?: [^>]*)?>([^<]+)<\/X509Certificate>/)?.[1];
        assert.equal(advertised,spCert.replace(/-----[^-]+-----/g,"").replace(/\s/g,""));
        for (const algorithm of ["http://www.w3.org/2009/xmlenc11#aes256-gcm","http://www.w3.org/2009/xmlenc11#rsa-oaep",
          "http://www.w3.org/2001/04/xmlenc#sha256","http://www.w3.org/2009/xmlenc11#mgf1sha256"]) assert.ok(descriptor.includes(algorithm));
        assert.ok(!descriptor.includes("PRIVATE KEY"));
      }
      assert.ok(descriptor.includes('entityID="'+audience+'"'));
      assert.ok(descriptor.includes('Location="'+acs+'"'));
    }
    if (portal) {
      if (runtime===go) await writeFile(reviewed,registration.id,{mode:0o600});
      let old;
      for (const first of [true,false]) {
        const send=browserFor(runtime);
        const browser=instrument({baseURL:runtime.baseURL,send},[ssoClient()]).client;
        let reply=signedReply({acs,audience,key,cert});
        if (encrypted) reply=await encryptSignedReply(reply,spCert);
        if (first) {
          const absent=await send(new Request(acs.replace(/\/work$/,"/removed-directory"),{method:"POST",headers:{origin:new URL(entryPoint).origin},body:new URLSearchParams({SAMLResponse:reply})}));
          assert.equal(absent.status,404);
        }
        const submit=()=>send(new Request(acs,{method:"POST",headers:{origin:new URL(entryPoint).origin},body:new URLSearchParams({SAMLResponse:reply})}));
        const response=await submit();
        assert.equal(response.status,302,await response.text());
        assert.equal(new URL(response.headers.get("location"),runtime.baseURL).href,runtime.baseURL+(encrypted ? "/global-landing" : "/staff-portal"));
        const session=ok(await browser.getSession());
        assert.equal(session.user.email,"employee@enterprise.example");
        if (first) old=session.user.id; else assert.equal(session.user.id,old);
        const duplicate=await submit();
        assert.equal(new URL(duplicate.headers.get("location"),runtime.baseURL).searchParams.get("error"),"replay_detected");
        assert.ok(!duplicate.headers.getSetCookie().some(value=>value.split("=",1)[0].endsWith(".session_token")));
      }
      continue;
    }
    let initialID;
    for (const first of [true,false]) {
      const transport=browserFor(runtime);
      let logoutStart;
      const send=async r => {
        const response=await transport(r);
        if (logout && new URL(r.url).pathname.endsWith("/sso/saml2/logout/work")) logoutStart=response.clone();
        if (runtime===go && new URL(r.url).pathname.endsWith("/sign-in/sso")) {
          const binding=response.headers.getSetCookie().find(s=>s.split("=",1)[0].endsWith(".saml_state"));
          assert.ok(binding);
          for (const attr of ["Secure","HttpOnly","SameSite=None"]) assert.ok(binding.split(/;\s*/).includes(attr));
        }
        return response;
      };
      const browser=instrument({baseURL:runtime.baseURL,basePath:runtime.basePath,send},[ssoClient()]).client;
      const result=ok(await browser.signIn.sso({providerId:"work",providerType:"saml",callbackURL:runtime.baseURL+"/home",newUserCallbackURL:runtime.baseURL+"/welcome"}));
      assert.equal(result.redirect,true);
      const url=new URL(result.url);
      if(logout) assert.equal(url.searchParams.has("Signature"),false);
      assert.equal(url.origin+url.pathname,entryPoint);
      const request=inflateRawSync(Buffer.from(url.searchParams.get("SAMLRequest"),"base64")).toString();
      const id=request.match(/\bID="([^"]+)"/)?.[1];
      assert.ok(id);
      assert.ok(request.includes(acs));
      assert.ok(request.includes(audience));
      const relay=url.searchParams.get("RelayState");
      assert.ok(relay);
      let reply=signedReply({id,acs,audience,...(inline && !first ? rotating : {key,cert})});
      if (encrypted) reply=await encryptSignedReply(reply,spCert);
      const form=new URLSearchParams({SAMLResponse:reply,RelayState:relay});
      const callback=await send(new Request(acs,{method:"POST",headers:{origin:new URL(entryPoint).origin},body:form}));
      assert.equal(callback.status,302,await callback.text());
      assert.equal(callback.headers.get("location"),runtime.baseURL+"/home");
      const current=ok(await browser.getSession());
      assert.equal(current.user.email,"employee@enterprise.example");
      assert.equal(current.user.emailVerified,false);
      assert.equal(current.user.name,"Enterprise Employee");
      if (first) initialID=current.user.id;
      else assert.equal(current.user.id,initialID);
      if (logout) {
        await browser.$fetch("/sso/saml2/logout/work",{method:"POST",body:{callbackURL:runtime.baseURL+"/signed-out"},redirect:"manual"});
        assert.equal(logoutStart?.status,302);
        const request=new URL(logoutStart.headers.get("location"));
        assert.equal(request.origin+request.pathname,"https://idp.example.test/logout");
        if (runtime===reference) {
          assert.equal(request.searchParams.has("Signature"),false);
          assert.equal(request.searchParams.has("RelayState"),false);
        }
        const raw=inflateRawSync(Buffer.from(request.searchParams.get("SAMLRequest"),"base64")).toString();
        assert.ok(raw.includes("stable-user"));assert.ok(raw.includes("local-assertion-session"));
        if (runtime===go) {
          const binding=logoutStart.headers.getSetCookie().find(v=>v.split("=",1)[0].endsWith(".saml_logout"));
          assert.ok(binding);
          for (const attr of ["Secure","HttpOnly","SameSite=Lax","Max-Age=300"]) assert.ok(binding.split(/;\s*/).includes(attr));
          const fields=request.search.slice(1).split("&");
          const signed=["SAMLRequest","RelayState","SigAlg"].map(name=>fields.find(field=>field.startsWith(name+"="))).join("&");
          assert.equal(request.searchParams.get("SigAlg"),"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
          assert.ok(verify("RSA-SHA256",Buffer.from(signed),actorCert,Buffer.from(request.searchParams.get("Signature"),"base64")));
        }
        assert.equal((await browser.getSession()).data,null);
        const reqID=raw.match(/\bID="([^"]+)"/)?.[1];assert.ok(reqID);
        const slo=runtime.baseURL+mount+"/sso/saml2/sp/slo/work";
        const params=signedLogoutReply(slo,reqID,request.searchParams.get("RelayState"),key);
        const finish=await send(new Request(slo+"?"+params));
        if (runtime===go) {
          assert.equal(finish.status,302,await finish.text());
          assert.equal(new URL(finish.headers.get("location"),runtime.baseURL).href,runtime.baseURL+"/signed-out");
        } else {
          // The pinned route omits the raw HTTP-Redirect octet string when it
          // calls samlify. With signed responses required it rejects this reply.
          assert.equal(finish.status,400);
          assert.equal((await finish.json()).code,"INVALID_LOGOUT_RESPONSE");
        }
      }
      if (inline && first) {
        const change=xml=>admin.sso.updateProvider({providerId:"work",samlConfig:{idpMetadata:{metadata:xml}}});
        const updated=ok(await change(inlineIdP([cert,rotating.cert])));
        assert.equal(updated.type,"saml");
        assert.equal(updated.samlConfig.entryPoint,"https://manual.example.test/unused");
        assert.ok(!JSON.stringify(updated).includes("X509Certificate"));
        assert.equal((await change(inlineIdP([rotating.cert],"urn:example:different-authority"))).error.status,409);
        ok(await change(inlineIdP([rotating.cert])));
      }
    }
  }
}
