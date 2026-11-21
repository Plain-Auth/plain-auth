import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { NodeSqliteDialect } from "@better-auth/kysely-adapter/node-sqlite-dialect";
import { scim } from "@better-auth/scim";

const userSchema = "urn:ietf:params:scim:schemas:core:2.0:User";
const patchSchema = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
const connections = [{ id: "directory", provisioningDomainId: "tenant", credentials: [
  { type: "bearer", id: "directory-key", token: "local-directory-only" },
]}];

async function reference(t, path = ":memory:") {
  const database = new DatabaseSync(path);
  t.after(() => database.close());
  const baseURL = "http://reference.localhost";
  const options = { baseURL, database: { type: "sqlite", dialect: new NodeSqliteDialect({ database }), transaction: true },
    secret: "local-conformance-0123456789-abcdefghijk", plugins: [scim({ connections })], telemetry: { enabled: false } };
  await (await getMigrations(options)).runMigrations();
  const auth = betterAuth(options);
  return { baseURL, send: req => auth.handler(req) };
}
function client(runtime) {
  return async (method, path, status, body, authenticated = true) => {
    const url = runtime.baseURL + "/api/auth/scim/v2/" + path;
    const headers = new Headers({ accept: "application/scim+json" });
    if (authenticated) headers.set("authorization", "Bearer local-directory-only");
    if (body) headers.set("content-type", "application/scim+json");
    const res = await runtime.send(new Request(url, {method, headers, body: body && JSON.stringify(body)}));
    const json = res.status === 204 ? null : await res.json();
    assert.equal(res.status, status, path + " " + JSON.stringify(json));
    if (status !== 204) assert.match(res.headers.get("content-type"), /^application\/scim\+json/);
    if (status === 201) {
      assert.equal(res.headers.get("location"), url + "/" + json.id);
      assert.equal(res.headers.get("content-location"), res.headers.get("location"));
    }
    if (status === 200 && ["PUT","PATCH"].includes(method)) assert.equal(res.headers.get("location"), url);
    if (status >= 400) assert.equal(json.status, String(status));
    return json;
  };
}
export async function directoryContract(t, goFixture) {
  const go = await goFixture(t, ["scim"]);
  const a = client(await reference(t)), b = client(go);
  const create = { schemas: [userSchema], userName: "Directory-01", externalId: "id-one",
    name: {givenName:"Rae",familyName:"Doe"}, emails:[{value:"PERSON@example.test",type:"work"}] };
  const operations = (path, value) => ({schemas:[patchSchema],Operations:[{op:"replace",path,value}]});
  for (const call of [a,b]) {
    const meta = await call("GET","ServiceProviderConfig",200,undefined,false);
    assert.deepEqual(meta.filter, {supported:true,maxResults:100});
    assert.deepEqual(meta.patch, {supported:true});
    const discovery=await call("GET","ResourceTypes/User",200,undefined,false);
    assert.equal(discovery.schema,userSchema);
    const noToken=await call("GET","Users",401,undefined,false);
    assert.deepEqual(noToken.schemas,["urn:ietf:params:scim:api:messages:2.0:Error"]);
    const user=await call("POST","Users",201,create);
    assert.equal(user.displayName,"Rae Doe");
    assert.deepEqual(user.emails,[{value:"person@example.test",type:"work",primary:true}]);
    assert.equal(user.active,true);
    const path="Users/"+user.id;
    const dup=await call("POST","Users",409,create);
    assert.equal(dup.scimType,"uniqueness");
    const page=await call("GET","Users?"+new URLSearchParams({ filter:'userName eq "directory-01" and emails[type eq "work"].value eq "PERSON@example.test"', attributes:"userName" }),200);
    assert.deepEqual(page.Resources,[{id:user.id,schemas:[userSchema],userName:"Directory-01"}]);
    assert.equal(page.totalResults,1);
    const inactive=await call("PATCH",path,200,operations("active",false));assert.equal(inactive.active,false);
    assert.equal((await call("POST","Users",201,create)).id,user.id);
    const replaced=await call("PUT",path,200,{...create,displayName:"Updated",title:"Manager"});assert.equal(replaced.title,"Manager");
    await call("DELETE",path,204);
    await call("GET",path,404);
  }
  // Each runtime reads and changes rows written by the other adapter. This
  // exercises hashed tuple keys, normalized attributes and retained identities.
  const shared=client(await reference(t, go.databasePath));
  const one=await b("POST","Users",201,create);
  const path="Users/"+one.id;
  assert.equal((await shared("GET",path,200)).externalId,"id-one");
  assert.equal((await shared("GET","Users?"+new URLSearchParams({filter:'emails.value eq "PERSON@example.test"'}),200)).totalResults,1);
  await shared("PATCH",path,200,operations("displayName","Reference edited"));
  assert.equal((await b("GET",path,200)).displayName,"Reference edited");
  await shared("DELETE",path,204);
  const two=await b("POST","Users",201,create);
  assert.notEqual(two.id,one.id);
  await b("DELETE","Users/"+two.id,204);
  const three=await shared("POST","Users",201,create);
  assert.equal((await b("GET","Users/"+three.id,200)).externalId,"id-one");
}

export async function groupContract(t, goFixture) {
  const go = await goFixture(t, ["scim"]);
  const groupSchema = "urn:ietf:params:scim:schemas:core:2.0:Group";
  const makeUser = name => ({schemas:[userSchema], userName:name.toLowerCase()+"@example.test",displayName:name});
  const profile = (name, external, ids) => ({schemas:[groupSchema],displayName:name,externalId:external,members:ids.map(value=>({value,type:"User"}))});
  const patch = (...Operations) => ({schemas:[patchSchema],Operations});
  const select = id => 'members[value eq "'+id+'"]';
  for (const call of [client(await reference(t)),client(go)]) {
    for (const [collection, name] of [["ResourceTypes","Group"],["Schemas",groupSchema]]) {
      const page=await call("GET",collection,200,undefined,false);
      assert.ok(page.Resources.some(resource=>resource.id===name));
      assert.equal((await call("GET",collection+"/"+name,200,undefined,false)).id,name);
    }
    const one=await call("POST","Users",201,makeUser("First"));
    const two=await call("POST","Users",201,makeUser("Second"));
    const group=await call("POST","Groups",201,profile("Sales","org-02",[one.id,one.id]));
    const path="Groups/"+group.id;
    assert.equal(group.members.length,1);assert.equal(group.members[0].type,"User");assert.equal(group.members[0].display,"First");
    assert.equal(new URL(group.members[0].$ref).pathname,"/api/auth/scim/v2/Users/"+one.id);
    const duplicate=await call("POST","Groups",409,profile("SALES","other",[]));assert.equal(duplicate.scimType,"uniqueness");
    const bad=await call("PATCH",path,400,patch({op:"add",path:"members",value:[{value:group.id}]}));assert.equal(bad.scimType,"invalidValue");
    const noop=await call("PATCH",path,200,patch());assert.equal(noop.meta.lastModified,group.meta.lastModified);
    const updated=await call("PATCH",path,200,patch({op:"add",path:"members",value:[{value:two.id}]},{op:"remove",path:select(one.id)}));
    assert.deepEqual(updated.members.map(m=>m.value),[two.id]);
    const query=new URLSearchParams({filter:'displayName eq "sales" and externalId eq "org-02"',attributes:"members.value"});
    const hits=await call("GET","Groups?"+query,200);
    assert.deepEqual(hits.Resources,[{id:group.id,schemas:[groupSchema],members:[{value:two.id}]}]);
    const beyond=await call("GET","Groups?startIndex=2&count=1",200);
    assert.equal(beyond.startIndex,2);assert.equal(beyond.totalResults,1);assert.equal(beyond.itemsPerPage,0);
    assert.deepEqual(beyond.Resources,[]);
    const replaced=await call("PUT",path,200,profile("Replaced","org-03",[one.id]));assert.equal(replaced.displayName,"Replaced");
    await call("DELETE","Users/"+one.id,204);
    assert.deepEqual((await call("GET",path,200)).members,[]);
    await call("DELETE",path,204);await call("GET",path,404);
  }
  const a=client(await reference(t,go.databasePath)),b=client(go);
  const u=await b("POST","Users",201,makeUser("Third"));
  const v=await a("POST","Users",201,makeUser("Fourth"));
  const g=await b("POST","Groups",201,profile("Shared","org-04",[u.id]));const path="Groups/"+g.id;
  const before=await a("GET",path,200);assert.equal(before.members[0].display,"Third");
  await a("PATCH",path,200,patch({op:"add",path:"members",value:[{value:v.id}]}));
  const both=await b("GET",path+"?attributes=members.value",200);
  assert.deepEqual(both.members.map(m=>m.value).sort(),[u.id,v.id].sort());
  await b("PATCH",path,200,patch({op:"remove",path:select(u.id)}));
  assert.deepEqual((await a("GET",path,200)).members.map(m=>m.value),[v.id]);
  await a("DELETE",path,204);await b("GET",path,404);
  const fromRef=await a("POST","Groups",201,profile("Reused","org-04",[u.id]));
  assert.equal((await b("GET","Groups/"+fromRef.id,200)).members[0].value,u.id);
  await b("DELETE","Groups/"+fromRef.id,204);
  await a("GET","Groups/"+fromRef.id,404);
}
