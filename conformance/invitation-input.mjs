import assert from "node:assert/strict";
import { organization } from "better-auth/plugins";
import { organizationClient } from "better-auth/client/plugins";

export async function compareInvitationInput(t, { reference, goFixture, instrument }) {
  for (const teams of [false, true]) {
    const settings = { teams: { enabled: teams } };
    const ref = await reference(t, [organization(settings)]);
    const go = await goFixture(t, [teams ? "organization-teams" : "organization"]);
    for (const server of [ref, go]) {
      const connect = () => instrument(server, [organizationClient(settings)]).client;
      const owner = connect(), admin = connect();
      const ok = res => { assert.equal(res.error, null, JSON.stringify(res.error)); return res.data; };
      const issue = (client, values) => client.organization.inviteMember(values);
      const error = (res, status, code, message) => {
        assert.equal(res.error?.status, status, JSON.stringify(res));
        assert.equal(res.error.code, code);
        if (message !== undefined) assert.equal(res.error.message, message);
      };
      const email = "guest@example.test";
      error(await owner.$fetch("/organization/invite-member", { method: "POST", body: {} }), 400, "VALIDATION_ERROR", "[body.email] Invalid input: expected string, received undefined; [body.role] Invalid input");
      error(await issue(owner, { email: 42, role: [3], organizationId: null, resend: "yes", teamId: null }), 400, "VALIDATION_ERROR",
        "[body.email] Invalid input: expected string, received number; [body.role] Invalid input; [body.organizationId] Invalid input: expected string, received null; [body.resend] Invalid input: expected boolean, received string; [body.teamId] Invalid input");
      error(await issue(owner, { email: "bad", role: [] }), 401, "UNAUTHORIZED");
      for (const [client, name] of [[owner,"owner"], [admin,"admin"]]) {
        ok(await client.signUp.email({ name, email: name+"@example.test", password: "invitation-input-test" }));
      }
      error(await issue(owner, { email: "bad", role: "member" }), 400, "ORGANIZATION_NOT_FOUND");
      const group = ok(await owner.organization.create({name: "Studio", slug: "studio"}));
      const other = ok(await owner.organization.create({name: "Elsewhere", slug: "elsewhere"}));
      for (const organizationId of [group.id, "missing-org"]) {
        error(await issue(admin, { email, role: "member", organizationId }), 400, "MEMBER_NOT_FOUND");
      }
      for (const address of ["local@localhost", ".name@example.com", "a..b@example.test", "Display <guest@example.test>"]) {
        error(await issue(owner, { email: address, role: "member", organizationId: group.id }), 400, "INVALID_EMAIL", "Invalid email");
      }
      for (const role of ["", [], [" , ", " "]]) error(await issue(owner, { email, role }), 400, "ROLE_NOT_FOUND");
      error(await issue(owner, { email, role: ["visitor, ,unknown", "member"] }), 400, undefined, "ROLE_NOT_FOUND: visitor, unknown");
      const wide = ok(await issue(owner, { email: "GUEST+LIST@Example.Test", role: [" admin,member ", "", ", admin"], organizationId: "" }));
      assert.equal(wide.role, "admin,member,admin");
      assert.equal(wide.email, "guest+list@example.test");
      assert.equal(wide.organizationId, other.id);
      assert.equal("teamId" in wide, teams);
      if (teams) assert.equal(wide.teamId, null);
      const adminGrant = ok(await issue(owner, { email: "admin@example.test", role: "admin", organizationId: group.id }));
      ok(await admin.organization.acceptInvitation({ invitationId: adminGrant.id }));
      error(await issue(admin, { email, role: ["member, owner", "admin"] }), 403, "YOU_ARE_NOT_ALLOWED_TO_INVITE_USER_WITH_THIS_ROLE");
      const first = ok(await issue(owner, { email, role: " admin,  member ", organizationId: group.id }));
      const renewed = ok(await issue(admin, { email, role: ["member"], resend: true }));
      assert.equal(renewed.id, first.id);
      assert.equal(renewed.role, "admin,member");
      assert.equal(ok(await owner.getSession()).session.activeOrganizationId, other.id);
    }
  }
}
