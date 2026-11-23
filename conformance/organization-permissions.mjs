import assert from "node:assert/strict";
import { organization } from "better-auth/plugins";
import { organizationClient } from "better-auth/client/plugins";

export async function compareOrganizationPermissions(t, { reference, goFixture, instrument }) {
  const ref = await reference(t, [organization()], {rateLimit:{enabled:false}});
  const go = await goFixture(t, ["organization"]);
  for (const server of [ref,go]) {
    const connect = () => instrument(server,[organizationClient()]).client;
    const owner=connect(), admin=connect(), reader=connect();
    const ok = res => { assert.equal(res.error,null,JSON.stringify(res.error)); return res.data; };
    const query = (c,body) => c.$fetch("/organization/has-permission",{method:"POST",body});
    const denied = (res,status,code,message) => {
      assert.equal(res.error?.status,status,JSON.stringify(res));
      assert.equal(res.error.code,code);
      if (message !== undefined) assert.equal(res.error.message,message);
    };
    for (const body of [{},{permissions:[]},{permissions:{member:[3]}},{permission:{member:"update"}}]) {
      denied(await query(reader,body),400,"VALIDATION_ERROR","[body] Invalid input");
    }
    denied(await query(reader,{permission:{},permissions:{}}),400,"VALIDATION_ERROR","[body] Invalid input: more than one option matched");
    denied(await query(reader,{organizationId:null}),400,"VALIDATION_ERROR","[body.organizationId] Invalid input: expected string, received null; [body] Invalid input");
    denied(await query(reader,{permissions:{}}),401,"UNAUTHORIZED");
    for (const [caller,name] of [[owner,"owner"],[admin,"admin"],[reader,"reader"]]) {
      ok(await caller.signUp.email({name,email:name+"@example.test",password:"local-organization-permissions"}));
    }
    denied(await query(owner,{permissions:{}}),400,"NO_ACTIVE_ORGANIZATION");
    const group=ok(await owner.organization.create({name:"Studio",slug:"studio"}));
    const other=ok(await owner.organization.create({name:"Other",slug:"other"}));
    denied(await query(reader,{permissions:{},organizationId:group.id}),401,"USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION");
    denied(await query(owner,{permissions:{},organizationId:"missing"}),401,"USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION");
    for (const [caller,name,role] of [[admin,"admin",["admin","member"]],[reader,"reader","member"]]) {
      const inv=ok(await owner.organization.inviteMember({email:name+"@example.test",role,organizationId:group.id}));
      ok(await caller.organization.acceptInvitation({invitationId:inv.id}));
    }
    const expected = {
      organization:{update:[true,true,false],delete:[true,false,false]},
      member:{create:[true,true,false],update:[true,true,false],delete:[true,true,false]},
      invitation:{create:[true,true,false],cancel:[true,true,false]},
      team:{create:[true,true,false],update:[true,true,false],delete:[true,true,false]},
      ac:{create:[true,true,false],read:[true,true,true],update:[true,true,false],delete:[true,true,false]},
    };
    for (const [resource,actions] of Object.entries(expected)) {
      for (const [action,grants] of Object.entries(actions)) {
        for (const [i,caller] of [owner,admin,reader].entries()) {
          const decision=ok(await caller.organization.hasPermission({organizationId:group.id,permissions:{[resource]:[action]}}));
          assert.deepEqual(decision,{error:null,success:grants[i]},resource+"."+action);
        }
      }
    }
    for (const permissions of [{},{organization:[]},{unknown:["read"]},{member:["delete","unknown"]},{member:["create"],notGranted:["read"]}]) {
      assert.deepEqual(ok(await query(owner,{permissions})),{error:null,success:false});
    }
    assert.deepEqual(ok(await query(admin,{permissions:{member:["create","delete"],invitation:["cancel"]},organizationId:""})),{error:null,success:true});
    assert.deepEqual(ok(await query(owner,{permission:{organization:["delete"]}})),{error:null,success:false});
    assert.deepEqual(ok(await query(owner,{permission:3,permissions:{organization:["delete"]}})),{error:null,success:true});
    const self=ok(await owner.getSession());
    assert.equal(self.session.activeOrganizationId,other.id);
    const requested={organization:["delete"]};
    assert.deepEqual(ok(await query(reader,{role:"owner",userId:self.user.id,permissions:requested})),{error:null,success:false});
  }
}
