import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";
import { scim } from "@better-auth/scim";
import { NodeSqliteDialect } from "@better-auth/kysely-adapter/node-sqlite-dialect";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";

export async function managedCatalog(t, goFixture) {
  const go = await goFixture(t, ["scim-managed"]);
  const dir = await mkdtemp(join(tmpdir(), "scim-server-fixture-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const binary = join(dir, "scimfixture");
  execFileSync("go", ["build", "-o", binary, "./conformance/scimfixture"], {
    cwd: fileURLToPath(new URL("..", import.meta.url)),
  });

  const db = new DatabaseSync(go.databasePath);
  t.after(() => db.close());
  const options = {
    baseURL: "http://reference.localhost",
    secret: "local-conformance-0123456789-abcdefghijk",
    database: { dialect: new NodeSqliteDialect({ database: db }), type: "sqlite", transaction: true },
    plugins: [scim({ connections: [], managedConnections: {
      credentialHashSecret: "managed-local-fixture-credential-digest-secret", maxActiveCredentials: 3,
    } })],
    telemetry: { enabled: false },
  };
  await (await getMigrations(options)).runMigrations();
  const reference = betterAuth(options);
  const operations = {
    create: "createSCIMManagedConnection",
    rotate: "rotateSCIMManagedCredential",
    revoke: "revokeSCIMManagedCredential",
    get: "getSCIMManagedConnection",
    events: "listSCIMManagedConnectionEvents",
    list: "listSCIMManagedConnections",
  };
  const refAdmin = (op, body) => reference.api[operations[op]]({ body });
  const goAdmin = (op, body) => JSON.parse(execFileSync(binary, [go.databasePath], {
    input: JSON.stringify({ op, ...body }), encoding: "utf8",
  }));
  const runtimes = [
    { base: options.baseURL, send: request => reference.handler(request) },
    { base: go.baseURL, send: go.send },
  ];

  async function request(runtime, token, status) {
    const response = await runtime.send(new Request(runtime.base + "/api/auth/scim/v2/Users", {
      headers: { authorization: "Bearer " + token },
    }));
    assert.equal(response.status, status);
    assert.equal((await response.json()).status, status === 401 ? "401" : undefined);
  }

  for (const [i, [issuer, peer]] of [[goAdmin, refAdmin], [refAdmin, goAdmin]].entries()) {
    const domain = "catalog-domain-" + i;
    const actorId = "tenant-administrator";
    const policy = { actorId, scopes: ["scim.users.read"], expiresAt: new Date(Date.now() + 3600000) };
    const create = { ...policy, creationRequestId: "unique-catalog-request-" + i, provisioningDomainId: domain };
    const initial = await issuer("create", create);
    const owner = { connectionId: initial.connection.connectionId, provisioningDomainId: domain };
    assert.match(initial.token, /^ba_scim_credential_[A-Za-z0-9_-]{32}\.[A-Za-z0-9_-]{48}$/);
    for (const runtime of runtimes) await request(runtime, initial.token, 200);

    const state = await peer("get", owner);
    assert.equal(state.credentials[0].credentialId, initial.credential.credentialId);
    assert.ok(state.credentials[0].lastUsedAt);
    const duplicate = goAdmin("create", create);
    assert.equal(duplicate.status, 409);
    assert.equal(duplicate.token, undefined);

    const rotated = await peer("rotate", { ...owner, ...policy });
    assert.notEqual(initial.token, rotated.token);
    for (const runtime of runtimes) {
      await request(runtime, rotated.token, 200);
      await request(runtime, initial.token, 200);
    }

    const revoke = { ...owner, credentialId: rotated.credential.credentialId, actorId };
    await issuer("revoke", revoke);
    await peer("revoke", revoke);
    for (const runtime of runtimes) {
      await request(runtime, rotated.token, 401);
      await request(runtime, initial.token, 200);
    }
    const history = await peer("events", { ...owner, limit: 2, offset: 0 });
    assert.deepEqual(history.events.map(e => [e.sequence, e.type]), [[3, "credential.rotated"], [4, "credential.revoked"]]);
    assert.equal(history.total, 4);
    const list = await peer("list", { provisioningDomainId: domain });
    assert.deepEqual(list.connections.map(c => c.connectionId), [owner.connectionId]);
    assert.equal(goAdmin("get", { ...owner, provisioningDomainId: "foreign" }).status, 404);

    const row = db.prepare("SELECT tokenDigest FROM scimManagedCredential WHERE credentialId=?").get(initial.credential.credentialId);
    assert.equal(row.tokenDigest.length, 43);
    assert.ok(!JSON.stringify(state).includes(row.tokenDigest));
  }
}
