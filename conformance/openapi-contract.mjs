import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { DatabaseSync } from "node:sqlite";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { openAPI, username } from "better-auth/plugins";
import { buildCatalog } from "./openapi-catalog.mjs";

export async function compareOpenAPI(t, goFixture) {
  const generated = await buildCatalog();
  assert.equal(await readFile(new URL("../plugins/openapi/catalog.json",import.meta.url),"utf8"), generated);
  const go = await goFixture(t, ["username"], { CONFORMANCE_OPENAPI: "1" });
  const database = new DatabaseSync(":memory:");
  t.after(() => database.close());
  const config = {
    baseURL: "http://spec.localhost", basePath: "/identity", database, emailAndPassword: { enabled: true },
    secret: "local-reference-0123456789-abcdefghijk", telemetry: { enabled: false },
    plugins: [username(), openAPI({ path: "/manual", theme: "moon", nonce: "openAPI123" })],
  };
  await (await getMigrations(config)).runMigrations();
  const reference = betterAuth(config);
  const schemas = [];
  for (const host of [{ baseURL: "http://spec.localhost", send: request => reference.handler(request) }, go]) {
    const res = await host.send(new Request(host.baseURL + "/identity/open-api/generate-schema"));
    assert.equal(res.status,200);
    assert.match(res.headers.get("content-type"),/^application\/json/);
    const doc = await res.json();
    assert.equal(doc.openapi,"3.1.1");
    assert.equal(doc.servers[0].url,host.baseURL + "/identity");
    assert.equal(doc.paths["/manual"],undefined);
    assert.equal(doc.paths["/open-api/generate-schema"],undefined);
    assert.equal(doc.paths["/organization/list"],undefined);
    assert.ok(doc.paths["/sign-in/username"].post);
    const reset = doc.paths["/reset-password/{token}"].get;
    assert.ok(reset.parameters.some(p => p.in === "path" && p.name === "token" && p.required === true));
    assert.equal(doc.components.schemas.User.properties.createdAt.format,"date-time");
    const page = await host.send(new Request(host.baseURL + "/identity/manual"));
    assert.equal(page.status,200);
    assert.match(page.headers.get("content-type"),/^text\/html/);
    const html = await page.text();
    assert.ok(html.includes('nonce="openAPI123"'));
    assert.ok(html.includes("moon"));
    schemas.push(doc);
  }
  for (const [path, method] of [["/sign-up/email","post"],["/sign-in/email","post"],["/sign-in/username","post"],["/is-username-available","post"]]) {
    const [r,g] = schemas.map(doc=> doc.paths[path][method]);
    assert.equal(g.operationId, r.operationId ?? "post" + path.replaceAll("/","_"));
    const [a,b] = [r,g].map(op=> op.requestBody.content["application/json"].schema);
    assert.deepEqual(b.required,a.required);
    for (const key of Object.keys(a.properties)) assert.ok(key in b.properties, path + " missing " + key);
  }
}
