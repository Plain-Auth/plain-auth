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
