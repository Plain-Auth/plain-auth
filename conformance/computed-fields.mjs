import assert from "node:assert/strict";
import { inferAdditionalFields } from "better-auth/client/plugins";

export async function compareComputedFields(t, {reference, goFixture, instrument}) {
  const ref = await reference(t, [], {
    user:{additionalFields:{
      approval:{type:"string", required:true, input:false, defaultValue:() => "generated"},
      shade:{type:"string", required:false, defaultValue:() => "blue"},
    }},
    session:{additionalFields:{channel:{type:"string", required:true, defaultValue:() => "browser"}}},
  });
  const go = await goFixture(t, [], {CONFORMANCE_COMPUTED_FIELDS:"1"});
  for (const host of [ref, go]) {
    for (const [name, input, expected] of [["default", {}, "blue"], ["override", {shade:"red"}, "red"], ["nullable", {shade:null}, null]]) {
      const {client} = instrument(host, [inferAdditionalFields()]);
      const created = await client.signUp.email({
        name, password:"local fixture password", email:name+"@computed.test", ...input,
      });
      assert.equal(created.error, null);
      assert.equal(created.data.user.approval, "generated");
      assert.equal(created.data.user.shade, expected);
      const forbidden = await client.updateUser({approval:"untrusted"});
      assert.equal(forbidden.error?.code, "FIELD_NOT_ALLOWED");
      const initial = await client.getSession();
      assert.equal(initial.data.session.channel, "browser");
      const updated = await client.updateSession({channel:"native"});
      assert.equal(updated.error, null);
      assert.equal((await client.getSession()).data.session.channel, "native");
    }
  }
}
