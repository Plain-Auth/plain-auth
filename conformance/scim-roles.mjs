import assert from "node:assert/strict";

export async function directoryRoles(t, {goFixture, reference, client}) {
  const go = await goFixture(t, ["scim"]);
  const schema = "urn:ietf:params:scim:schemas:core:2.0:User";
  const patch = (...Operations) => ({schemas:["urn:ietf:params:scim:api:messages:2.0:PatchOp"],Operations});
  const login = {schemas:[schema],userName:"roles@example.test",externalId:"roles-fixture"};
  let discovery;
  for (const runtime of [await reference(t),go]) {
    const call = client(runtime);
    const descriptor = (await call("GET", "Schemas/"+schema, 200, undefined, false)).attributes.find(a=>a.name==="roles");
    assert.deepEqual(descriptor.subAttributes.map(s=>s.name), ["value","display","type","primary"]);
    if (discovery) assert.deepEqual(descriptor, discovery);
    discovery = descriptor;
    const user = await call("POST","Users",201,{...login,RoLes:[{VaLuE:" admin ",TyPe:" WORK ",pRiMaRy:"TRUE",Display:" Work "},{value:"member"},{value:"member"}]});
    const path = "Users/"+user.id;
    let expected = [{value:"admin",type:"work",primary:true,display:"Work"},{value:"member"},{value:"member"}];
    assert.deepEqual(user.roles, expected);
    assert.deepEqual((await call("GET",path,200)).roles,expected);
    assert.deepEqual((await call("GET","Users?attributes=roles.display",200)).Resources[0], {id:user.id,schemas:[schema],roles:[{display:"Work"}]});
    assert.deepEqual((await call("GET",path+"?excludedAttributes=roles.value",200)).roles,[{type:"work",primary:true,display:"Work"},{},{}]);
    const change = (...ops) => call("PATCH",path,200,patch(...ops));
    const select = 'roles[type eq "work"]';
    let changed = await change({op:"add",path:schema+':ROLES[type eq "other"]',value:{value:"support",primary:true}});
    assert.equal(changed.roles[0].primary,false);
    assert.deepEqual(changed.roles.at(-1),{value:"support",type:"other",primary:true});
    changed = await change({op:"replace",path:select,value:{display:null,value:"staff"}},{op:"replace",path:'roles[primary eq "true"].display',value:"Support"});
    assert.deepEqual(changed.roles[0],{value:"staff",type:"work",primary:false});
    assert.equal(changed.roles.at(-1).display,"Support");
    changed = await change({op:"remove",path:select+".primary"},{op:"add",path:'roles[type eq "new"].value',value:"new entry"},{op:"remove",path:'roles[type eq "absent"]'});
    assert.equal(changed.roles[0].primary,undefined);
    assert.deepEqual(changed.roles.at(-1),{type:"new",value:"new entry"});
    changed = await change({op:"replace",path:"roles.display",value:"Shared"},{op:"remove",path:'roles[primary eq true]'},{op:"replace",path:select+".display",value:null});
    assert.deepEqual(changed.roles[0],{value:"staff",type:"work"});
    assert.ok(changed.roles.slice(1).every(r=>r.display==="Shared"));
    changed = await change({op:"replace",path:'roles [type eq "new"] . primary',value:"TrUe"});
    assert.equal(changed.roles.find(r=>r.type==="new").primary,true);
    const before = changed.roles;
    const tooMany = Array.from({length:11}, (_,i)=>({value:"role-"+i}));
    for (const invalid of [tooMany, [{value:"same",type:"WORK"},{value:"other",type:" work "}],
      [{value:"one",primary:true},{value:"two",primary:true}], [{value:"bad",primary:"yes"}],
      [{value:"😀".repeat(1025)}], [{value:"v",type:"x".repeat(257)}], [{value:"v",display:"A".repeat(1025)}]]) {
      await call("PUT",path,400,{...login,roles:invalid});
    }
    const control = "\u0001".repeat(1024);
    const tooLarge = Array.from({length:10},()=>({value:control,display:control}));
    await call("PUT",path,400,{...login,roles:tooLarge});
    await call("PUT",path,400,{...login,roles:[{value:"kept"}],active:null});
    const bad = await call("PATCH",path,400,patch({op:"remove",path:select},{op:"replace",path:"roles",value:[{type:"a",value:"ok"},{type:"A",value:"duplicate"}]}));
    assert.equal(bad.scimType,"invalidValue");
    assert.deepEqual((await call("GET",path,200)).roles,before);
    const invalidPath = await call("PATCH",path,400,patch({op:"remove",path:'roles[value eq "staff"]'}));
    assert.equal(invalidPath.scimType,"invalidPath");
    // A body failing the PatchOp shape answers invalidValue.
    for (const op of [{op:"move",path:"title",value:"X"}, {op:5,path:"title",value:"X"}, {op:"replace",path:5,value:"X"}]) {
      assert.equal((await call("PATCH",path,400,patch(op))).scimType,"invalidValue");
    }
    const inactive = await change({op:"replace",path:"active",value:false});
    assert.equal(inactive.active,false);
    assert.deepEqual(inactive.roles,before);
    const reprovisioned = await call("POST","Users",201,{...login,roles:[{value:"new",type:"work"}]});
    assert.equal(reprovisioned.id,user.id);
    assert.deepEqual(reprovisioned.roles,[{value:"new",type:"work"}]);
    assert.deepEqual((await change({op:"replace",value:{roles:[]}})).roles,[]);
    assert.equal((await change({op:"replace",value:{roles:null}})).roles,undefined);
    assert.deepEqual((await change({op:"add",path:"roles",value:{value:"after clear"}})).roles,[{value:"after clear"}]);
    assert.equal((await call("PUT",path,200,login)).roles,undefined);
    await call("DELETE",path,204);
  }
  const shared=client(await reference(t, go.databasePath)), native=client(go);
  const user=await shared("POST","Users",201,{...login,roles:[{value:"from-js"}]});
  const path="Users/"+user.id;
  assert.deepEqual((await native("GET",path,200)).roles,[{value:"from-js"}]);
  // These strings fit the canonical bound with the JSON escaping used by both adapters.
  const html = "<&>".repeat(340);
  const literal = "\u2028x\u2029\\u2028";
  const longRoles = Array.from({length:10},()=>({value:html,display:html+literal.slice(0,4)}));
  await native("PUT",path,200,{...login,roles:longRoles});
  assert.deepEqual((await shared("GET",path,200)).roles,longRoles);
  await native("PATCH",path,200,patch({op:"replace",path:"roles",value:[{value:"from-go"}]}));
  assert.deepEqual((await shared("GET",path,200)).roles,[{value:"from-go"}]);
  await shared("PATCH",path,200,patch({op:"remove",path:"roles"}));
  assert.equal((await native("GET",path,200)).roles,undefined);
}
