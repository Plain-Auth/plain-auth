import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { request as httpsRequest } from "node:https";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { inflateRawSync } from "node:zlib";
import { sso } from "@better-auth/sso";
import { ssoClient } from "@better-auth/sso/client";
import { NodeSqliteDialect } from "@better-auth/kysely-adapter/node-sqlite-dialect";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { SignedXml } from "xml-crypto";

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
  const date = offset => new Date(Date.now() + offset).toISOString();
  const attribute = (name, value) => '<saml:Attribute Name="' + xml(name) + '"><saml:AttributeValue>' + xml(value) + '</saml:AttributeValue></saml:Attribute>';
  const response = `<samlp:Response xmlns:samlp="${protocolNS}" xmlns:saml="${assertionNS}" ID="_${randomUUID()}" Version="2.0" IssueInstant="${date(0)}" Destination="${xml(acs)}" InResponseTo="${xml(id)}">
  <saml:Issuer>${issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion ID="_${randomUUID()}" Version="2.0" IssueInstant="${date(0)}"><saml:Issuer>${issuer}</saml:Issuer>
  <saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">stable-user</saml:NameID>
  <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="${date(60000)}" InResponseTo="${xml(id)}" Recipient="${xml(acs)}"/></saml:SubjectConfirmation></saml:Subject>
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

export async function compareEnterpriseSAML(t, {goFixture,instrument,privateDeployment=false}) {
  const keys = await mkdtemp(join(tmpdir(),"stonewrit-idp-"));
  t.after(()=>rm(keys,{recursive:true,force:true}));
  const keyFile=join(keys,"private.pem"), certFile=join(keys,"cert.pem");
  execFileSync("openssl",["req","-x509","-newkey","rsa:2048","-nodes","-keyout",keyFile,"-out",certFile,"-days","1","-subj","/CN=Local identity provider"],{stdio:"ignore"});
  const [key,cert]=await Promise.all([readFile(keyFile,"utf8"),readFile(certFile,"utf8")]);
  const fixtureEnv={CONFORMANCE_SAML:"1"};
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
    telemetry:{enabled:false},plugins:[sso()]};
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
    const registration = ok(await admin.sso.register({providerId:"work",domain:"enterprise.example",issuer,
      samlConfig:{entryPoint,cert,spMetadata:{entityID:audience},idpMetadata:{entityID:issuer},wantAssertionsSigned:true}}));
    assert.equal(registration.redirectURI,runtime.baseURL+mount+"/sso/callback/work");
    assert.equal(registration.samlConfig.cert,cert);
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
      assert.ok(descriptor.includes('entityID="'+audience+'"'));
      assert.ok(descriptor.includes('Location="'+acs+'"'));
    }
    let initialID;
    for (const first of [true,false]) {
      const transport=browserFor(runtime);
      const send=async r => {
        const response=await transport(r);
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
      assert.equal(url.origin+url.pathname,entryPoint);
      const request=inflateRawSync(Buffer.from(url.searchParams.get("SAMLRequest"),"base64")).toString();
      const id=request.match(/\bID="([^"]+)"/)?.[1];
      assert.ok(id);
      assert.ok(request.includes(acs));
      assert.ok(request.includes(audience));
      const relay=url.searchParams.get("RelayState");
      assert.ok(relay);
      const form=new URLSearchParams({SAMLResponse:signedReply({id,acs,audience,key,cert}),RelayState:relay});
      const callback=await send(new Request(acs,{method:"POST",headers:{origin:new URL(entryPoint).origin},body:form}));
      assert.equal(callback.status,302,await callback.text());
      assert.equal(callback.headers.get("location"),runtime.baseURL+"/home");
      const current=ok(await browser.getSession());
      assert.equal(current.user.email,"employee@enterprise.example");
      assert.equal(current.user.emailVerified,false);
      assert.equal(current.user.name,"Enterprise Employee");
      if (first) initialID=current.user.id;
      else assert.equal(current.user.id,initialID);
    }
  }
}
