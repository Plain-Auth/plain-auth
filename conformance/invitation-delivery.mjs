import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { organization } from "better-auth/plugins";
import { organizationClient } from "better-auth/client/plugins";

export async function compareInvitationDelivery(t, { reference, goFixture, instrument }) {
  const mail = [];
  const options = { teams: { enabled: true }, sendInvitationEmail: async (data, request) => {
    mail.push(structuredClone({ data, method: request.method, path: new URL(request.url).pathname, agent: request.headers.get("user-agent") }));
    if (data.email === "guest@example.test" && data.inviter.role === "owner") throw Error("private mail fixture failure");
  }};
  const ref = await reference(t, [organization(options)], { logger: { disabled: true }, user: { additionalFields: {
    locale: { type: "string", required: true, fieldName: "preferred_locale" },
    privateNote: { type: "string", required: false, returned: false }
  } } });
  const go = await goFixture(t, ["organization-teams"], { CONFORMANCE_INVITATION_DELIVERY: "1", CONFORMANCE_USER_FIELDS: "1" });
  for (const server of [ref, go]) {
    const mailbox = async () => server === ref ? mail : (await readFile(go.databasePath + ".invitation-mail", "utf8")).trim().split("\n").map(row => JSON.parse(row));
    const connect = () => instrument(server, [organizationClient({ teams: { enabled: true } })]).client;
    const owner = connect(), admin = connect(), outsider = connect();
    const ok = res => { assert.equal(res.error, null, JSON.stringify(res.error)); return res.data; };
    const signup = async (client, name) => ok(await client.signUp.email({name, email: name.toLowerCase()+"@example.test", password: "invitation-delivery-test", locale: name === "Admin" ? "fr" : "en", privateNote: "fixture-only" })).user;
    const host = await signup(owner, "Owner"), second = await signup(admin, "Admin");
    await signup(outsider, "Outsider");
    const group = ok(await owner.organization.create({ name: "Studio", slug: "studio", metadata: { region: "az" } }));
    const team = ok(await owner.organization.createTeam({ name: "Research", organizationId: group.id }));
    const invite = (client, email, role, extra = {}) => client.organization.inviteMember({ organizationId: group.id, email, role, ...extra });
    const grant = ok(await invite(owner, second.email, "admin"));
    const adminMember = ok(await admin.organization.acceptInvitation({ invitationId: grant.id })).member;
    const ownerMember = ok(await owner.organization.getActiveMember());
    ok(await admin.organization.create({ name: "Elsewhere", slug: "elsewhere" }));
    const original = ok(await invite(owner, "GUEST@example.test", "member", { teamId: team.id }));
    assert.equal(original.teamId, team.id);
    assert.equal(original.status, "pending");
    assert.ok((await invite(owner, "guest@example.test", "member")).error);
    assert.ok((await invite(outsider, "guest@example.test", "member", { resend: true })).error);
    const renewed = ok(await invite(admin, "guest@example.test", "admin", { resend: true }));
    assert.equal(renewed.id, original.id);
    const messages = await mailbox();
    assert.equal(messages.length, 3);
    for (const [index, member, user, grant] of [[1, ownerMember, host, original], [2, adminMember, second, renewed]]) {
      const { data, method, path, agent } = messages[index];
      assert.equal(data.email, "guest@example.test");
      assert.equal(data.invitation.id, grant.id);
      assert.equal(data.invitation.role, "member");
      assert.equal(data.invitation.teamId, team.id);
      assert.equal(data.invitation.inviterId, host.id);
      assert.equal(new Date(data.invitation.expiresAt).valueOf(), new Date(grant.expiresAt).valueOf());
      assert.equal(data.organization.id, group.id);
      assert.equal(data.organization.slug, group.slug);
      assert.equal(data.inviter.id, member.id);
      assert.equal(data.inviter.organizationId, group.id);
      assert.equal(data.inviter.role, member.role);
      assert.equal(data.inviter.userId, user.id);
      assert.equal(data.inviter.user.name, user.name);
      assert.equal(data.inviter.user.email, user.email);
      assert.equal(data.inviter.user.emailVerified, user.emailVerified);
      assert.equal(data.inviter.user.locale, user.locale);
      assert.equal("privateNote" in data.inviter.user, false);
      assert.deepEqual([method, path, agent], ["POST", "/api/auth/organization/invite-member", "authn-conformance"]);
      assert.equal("Request" in data || "request" in data, false);
    }
  }
}
