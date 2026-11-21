import assert from "node:assert/strict";
import { once } from "node:events";
import { createServer } from "node:http";
import { DatabaseSync } from "node:sqlite";
import { stripe } from "@better-auth/stripe";
import { stripeClient } from "@better-auth/stripe/client";
import Stripe from "stripe";

const webhookSecret = "whsec_offline_fixture";
const basicPrice = "price_basic";
const teamPrice = "price_team";
const annualTeamPrice = "price_team_annual";
const period = 2_592_000;

function subscription(owner) {
  const start = Math.floor(Date.now() / 1000) - 3600;
  return {
    id: "sub_" + owner, object: "subscription", customer: "cus_" + owner, status: "active",
    cancel_at_period_end: false, cancel_at: null, canceled_at: null, schedule: null,
    livemode: false, metadata: {},
    items: { object: "list", has_more: false, data: [{
      object: "subscription_item", id: "si_" + owner, quantity: 1,
      current_period_start: start, current_period_end: start + period,
      price: { id: basicPrice, object: "price", recurring: { interval: "month", interval_count: 1, usage_type: "licensed" } },
    }] },
  };
}

async function localStripe(t) {
  const subscriptions = new Map(["owner", "other"].map(name => ["sub_" + name, subscription(name)]));
  const calls = [];
  const server = createServer(async (req, res) => {
    const url = new URL(req.url, "http://127.0.0.1");
    const path = url.pathname;
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const form = new URLSearchParams(Buffer.concat(chunks).toString());
    calls.push({ method: req.method, path, form, query: url.searchParams });
    let result;
    let status = 200;
    const sub = subscriptions.get(path.split("/").at(-1));
    if (path === "/v1/subscriptions" && req.method === "GET") {
      const data = [...subscriptions.values()].filter(s => s.customer === url.searchParams.get("customer"));
      result = { object: "list", has_more: false, url: path, data };
    } else if (req.method === "GET" && [basicPrice, teamPrice, annualTeamPrice].some(id => path === "/v1/prices/" + id)) {
      const id = path.split("/").at(-1);
      result = { id, object: "price", active: true, type: "recurring", recurring: {
        interval: id === annualTeamPrice ? "year" : "month", interval_count: 1, usage_type: "licensed",
      } };
    } else if (sub && path === "/v1/subscriptions/" + sub.id && req.method === "GET") {
      result = sub;
    } else if (sub && path === "/v1/subscriptions/" + sub.id && req.method === "POST" && (form.get("cancel_at_period_end") === "false" || form.get("cancel_at") === "")) {
      if (form.has("cancel_at")) sub.cancel_at = null;
      else sub.cancel_at_period_end = false;
      result = sub;
    } else if (req.method === "POST" && path === "/v1/billing_portal/sessions") {
      result = {
        id: "bps_" + calls.length, object: "billing_portal.session", customer: form.get("customer"),
        url: "https://billing.example.test/" + ({ subscription_update_confirm: "confirm", subscription_cancel: "cancel" }[form.get("flow_data[type]")] ?? "portal"),
      };
    } else if (path === "/v1/subscription_schedules/sched_owner" && req.method === "GET") {
      result = { id: "sched_owner", object: "subscription_schedule", status: "active", customer: "cus_owner", subscription: "sub_owner" };
    } else if (path === "/v1/subscription_schedules/sched_owner/release" && req.method === "POST") {
      subscriptions.get("sub_owner").schedule = null;
      result = { id: "sched_owner", object: "subscription_schedule", status: "released", customer: "cus_owner", released_subscription: "sub_owner" };
    } else {
      status = 404;
      result = { error: { type: "invalid_request_error", code: "resource_missing", message: "Unexpected offline fixture request " + req.method + " " + path } };
    }
    res.writeHead(status, { "content-type": "application/json" });
    res.end(JSON.stringify(result));
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => new Promise(resolve => server.close(resolve)));
  const { port } = server.address();
  const api = new Stripe("sk_test_offline_fixture", {
    host: "127.0.0.1", port, protocol: "http", timeout: 5000, maxNetworkRetries: 0, telemetry: false,
  });
  return { url: "http://127.0.0.1:" + port, subscriptions, api, calls };
}

function ok(result) {
  assert.equal(result.error, null, JSON.stringify(result.error));
  return result.data;
}

async function signedUpdate(server, provider, eventID, sub) {
  const payload = JSON.stringify({
    object: "event", id: eventID, type: "customer.subscription.updated",
    api_version: Stripe.API_VERSION, livemode: false, created: Math.floor(Date.now() / 1000),
    data: { object: sub },
  });
  const signature = provider.api.webhooks.generateTestHeaderString({ payload, secret: webhookSecret });
  const result = await server.send(new Request(server.baseURL + "/api/auth/stripe/webhook", {
    method: "POST", headers: { "content-type": "application/json", "stripe-signature": signature }, body: payload,
  }));
  assert.equal(result.status, 200, await result.text());
}

function seed(database, id, sub) {
  database.prepare('UPDATE "user" SET "stripeCustomerId" = ? WHERE "id" = ?').run(sub.customer, id);
  database.prepare('INSERT INTO "subscription" ("id", "plan", "referenceId", "stripeCustomerId", "stripeSubscriptionId", "status", "seats", "cancelAtPeriodEnd") VALUES (?, ?, ?, ?, ?, ?, ?, ?)').run(
    "local_" + sub.id, "basic", id, sub.customer, sub.id, "active", 1, 0,
  );
}

async function exercise(t, runtime, { reference, goFixture, instrument }) {
  const provider = await localStripe(t);
  const server = runtime === "Go"
    ? await goFixture(t, ["stripe-subscriptions"], { CONFORMANCE_STRIPE_URL: provider.url })
    : await reference(t, [stripe({
      stripeClient: provider.api, stripeWebhookSecret: webhookSecret,
      subscription: { enabled: true, plans: [{ name: "basic", priceId: basicPrice }, { name: "team", priceId: teamPrice, annualDiscountPriceId: annualTeamPrice }] },
    })]);
  const database = server.database ?? new DatabaseSync(server.databasePath);
  if (!server.database) t.after(() => database.close());
  const browser = () => instrument(server, [stripeClient({ subscription: true })]).client;
  const owner = browser(), other = browser(), guest = browser();
  const ownerSub = provider.subscriptions.get("sub_owner");
  async function register(user, key) {
    const res = ok(await user.signUp.email({ email: key + "@example.test", name: key, password: "offline-billing-password" }));
    const before = provider.calls.length;
    const missing = await user.subscription.billingPortal({ disableRedirect: true });
    assert.deepEqual([missing.error.status, missing.error.code, missing.error.message],
      [404, "CUSTOMER_NOT_FOUND", "Stripe customer not found for this user"]);
    assert.equal(provider.calls.length, before);
    seed(database, res.user.id, provider.subscriptions.get("sub_" + key));
    return res.user.id;
  }
  const ownerID = await register(owner, "owner");
  const otherID = await register(other, "other");
  const list = async (user, id, subID) => {
    const rows = ok(await user.subscription.list());
    assert.equal(rows.length, 1);
    assert.equal(rows[0].referenceId, id);
    assert.equal(rows[0].stripeSubscriptionId, subID);
    return rows[0];
  };
  assert.equal((await list(owner, ownerID, ownerSub.id)).priceId, basicPrice);
  const explicit = ok(await owner.subscription.list({ query: { customerType: "user", referenceId: ownerID } }));
  assert.deepEqual(explicit.map(row => row.stripeSubscriptionId), [ownerSub.id]);
  const returnUrl = server.baseURL + "/account/billing";
  const own = { subscriptionId: ownerSub.id };
  const cancel = { ...own, returnUrl, disableRedirect: true };
  const portal = { returnUrl, disableRedirect: true, locale: "en" };

  const denied = [
    [() => other.subscription.cancel(cancel), 400, "SUBSCRIPTION_NOT_FOUND", "Subscription not found"],
    [() => other.subscription.restore(own), 400, "SUBSCRIPTION_NOT_FOUND", "Subscription not found"],
    [() => other.subscription.upgrade({ ...own, plan: "team" }), 400, "SUBSCRIPTION_NOT_FOUND", "Subscription not found"],
    [() => owner.subscription.upgrade({ plan: "missing" }), 400, "SUBSCRIPTION_PLAN_NOT_FOUND", "Subscription plan not found"],
    [() => guest.subscription.upgrade({ annual: false }), 400, "VALIDATION_ERROR", "[body.plan] Invalid input: expected string, received undefined"],
    [() => guest.subscription.cancel({ disableRedirect: true }), 400, "VALIDATION_ERROR", "[body.returnUrl] Invalid input: expected string, received undefined"],
    [() => guest.subscription.billingPortal({ locale: 11 }), 400, "VALIDATION_ERROR", "[body.locale] Invalid input"],
    [() => owner.subscription.cancel({ returnUrl: "https://foreign.example/return" }), 403, "INVALID_CALLBACK_URL", "Invalid callbackURL"],
    [() => owner.subscription.billingPortal({ returnUrl: "https://foreign.example/return" }), 403, "INVALID_CALLBACK_URL", "Invalid callbackURL"],
  ];
  for (const field of ["successUrl", "cancelUrl", "returnUrl"]) {
    denied.push([() => owner.subscription.upgrade({ plan: "missing", [field]: "https://foreign.example/return" }), 403, "INVALID_CALLBACK_URL", "Invalid callbackURL"]);
  }
  const operations = [
    ["body", (client, fields) => client.subscription.billingPortal({ ...portal, ...fields })],
    ["query", (client, fields) => client.subscription.list({ query: fields })],
    ["body", (client, fields) => client.subscription.cancel({ ...cancel, ...fields })],
    ["body", (client, fields) => client.subscription.restore({ ...own, ...fields })],
    ["body", (client, fields) => client.subscription.upgrade({ plan: "team", ...fields })],
  ];
  for (const [source, request] of operations) {
    const invalidType = "[" + source + '.customerType] Invalid option: expected one of "user"|"organization"';
    denied.push(
      [() => request(guest, {}), 401, "UNAUTHORIZED", "Unauthorized"],
      [() => request(other, { referenceId: ownerID }), 400, "REFERENCE_ID_NOT_ALLOWED", "Reference id is not allowed"],
      [() => request(other, { customerType: "organization", referenceId: ownerID }), 400, "ORGANIZATION_SUBSCRIPTION_NOT_ENABLED", "Organization subscription is not enabled"],
      [() => request(guest, { customerType: "invalid" }), 400, "VALIDATION_ERROR", invalidType],
      [() => request(owner, { customerType: "" }), 400, "VALIDATION_ERROR", invalidType],
    );
    if (source === "body") {
      denied.push(
        [() => request(guest, { customerType: null }), 400, "VALIDATION_ERROR", invalidType],
        [() => request(guest, { referenceId: 42, customerType: [] }), 400, "VALIDATION_ERROR",
          "[body.referenceId] Invalid input: expected string, received number; " + invalidType],
      );
    }
  }
  for (const [call, status, code, message] of denied) {
    const before = provider.calls.length;
    const result = await call();
    assert.equal(result.error?.status, status, JSON.stringify(result));
    assert.equal(result.error.code, code);
    assert.equal(result.error.message, message);
    assert.equal(provider.calls.length, before, "a denied operation contacted the provider");
  }
  const beforeDuplicate = provider.calls.length;
  for (const [query, message] of [
    ["customerType=invalid&customerType=user", '[query.customerType] Invalid option: expected one of "user"|"organization"'],
    ["referenceId=other&referenceId=owner", "[query.referenceId] Invalid input: expected string, received array"],
  ]) {
    const response = await server.send(new Request(server.baseURL + "/api/auth/subscription/list?" + query));
    assert.equal(response.status, 400);
    assert.deepEqual(await response.json(), { code: "VALIDATION_ERROR", message });
  }
  assert.equal(provider.calls.length, beforeDuplicate);

  const unavailablePrice = await owner.subscription.upgrade({ plan: "basic", annual: true });
  assert.equal(unavailablePrice.error.status, 400);
  assert.equal(unavailablePrice.error.message, "Price ID not found for the selected plan");
  assert.equal(Object.hasOwn(unavailablePrice.error, "code"), false);

  const samePlan = await owner.subscription.upgrade({ plan: "basic" });
  assert.equal(samePlan.error.status, 400);
  assert.equal(samePlan.error.code, "ALREADY_SUBSCRIBED_PLAN");
  assert.equal(samePlan.error.message, "You're already subscribed to this plan");
  const beforeConfirm = provider.calls.length;
  for (const [annual, selection, expectedPrice] of [[false, {}, teamPrice], [true, own, annualTeamPrice]]) {
    const change = ok(await owner.subscription.upgrade({
      ...selection, plan: "team", annual, returnUrl, disableRedirect: true,
    }));
    assert.deepEqual(change, { url: "https://billing.example.test/confirm", redirect: false });
    const confirm = provider.calls.at(-1);
    assert.equal(confirm.method, "POST");
    assert.equal(confirm.path, "/v1/billing_portal/sessions");
    assert.deepEqual(Object.fromEntries(confirm.form), {
      customer: ownerSub.customer, return_url: returnUrl,
      "flow_data[type]": "subscription_update_confirm",
      "flow_data[after_completion][type]": "redirect",
      "flow_data[after_completion][redirect][return_url]": returnUrl,
      "flow_data[subscription_update_confirm][subscription]": ownerSub.id,
      "flow_data[subscription_update_confirm][items][0][id]": ownerSub.items.data[0].id,
      "flow_data[subscription_update_confirm][items][0][quantity]": "1",
      "flow_data[subscription_update_confirm][items][0][price]": expectedPrice,
    });
    assert.equal((await list(owner, ownerID, ownerSub.id)).priceId, basicPrice);
  }
  assert.equal(provider.calls.slice(beforeConfirm).some(c => c.method === "POST" && c.path !== "/v1/billing_portal/sessions"), false);

  assert.deepEqual(ok(await owner.subscription.billingPortal(portal)), { url: "https://billing.example.test/portal", redirect: false });
  const portalCall = provider.calls.at(-1);
  assert.equal(portalCall.path, "/v1/billing_portal/sessions");
  assert.equal(portalCall.form.get("customer"), ownerSub.customer);
  assert.equal(portalCall.form.get("return_url"), returnUrl);
  assert.equal(portalCall.form.get("locale"), "en");

  assert.deepEqual(ok(await owner.subscription.cancel(cancel)), { url: "https://billing.example.test/cancel", redirect: false });
  const cancelCall = provider.calls.at(-1);
  assert.equal(cancelCall.path, "/v1/billing_portal/sessions");
  assert.equal(cancelCall.form.get("customer"), ownerSub.customer);
  assert.equal(cancelCall.form.get("return_url"), returnUrl);
  assert.equal(cancelCall.form.get("flow_data[type]"), "subscription_cancel");
  assert.equal(cancelCall.form.get("flow_data[subscription_cancel][subscription]"), ownerSub.id);
  assert.equal((await list(owner, ownerID, ownerSub.id)).cancelAtPeriodEnd, false);

  ownerSub.cancel_at_period_end = true;
  await signedUpdate(server, provider, "evt_cancel", ownerSub);
  assert.equal((await list(owner, ownerID, ownerSub.id)).cancelAtPeriodEnd, true);
  const restored = ok(await owner.subscription.restore(own));
  assert.equal(restored.id, ownerSub.id);
  const restoredWire = structuredClone(ownerSub);
  assert.equal(restored.cancel_at_period_end, false);
  assert.ok(provider.calls.some(c => c.method === "POST" && c.path === "/v1/subscriptions/" + ownerSub.id && c.form.get("cancel_at_period_end") === "false"));
  assert.equal((await list(owner, ownerID, ownerSub.id)).cancelAtPeriodEnd, false);
  assert.equal((await owner.subscription.restore(own)).error.code, "SUBSCRIPTION_NOT_PENDING_CHANGE");

  ownerSub.cancel_at = ownerSub.items.data[0].current_period_end;
  await signedUpdate(server, provider, "evt_cancel_at", ownerSub);
  assert.equal(Date.parse((await list(owner, ownerID, ownerSub.id)).cancelAt), ownerSub.cancel_at * 1000);
  assert.deepEqual(ok(await owner.subscription.restore(own)), ownerSub);
  assert.equal(ownerSub.cancel_at, null);
  assert.ok(provider.calls.some(c => c.method === "POST" && c.path === "/v1/subscriptions/" + ownerSub.id && c.form.get("cancel_at") === "" && !c.form.has("cancel_at_period_end")));
  assert.equal((await list(owner, ownerID, ownerSub.id)).cancelAt ?? null, null);

  ownerSub.schedule = "sched_owner";
  await signedUpdate(server, provider, "evt_schedule", ownerSub);
  assert.equal((await list(owner, ownerID, ownerSub.id)).stripeScheduleId, "sched_owner");
  const released = ok(await owner.subscription.restore(own));
  assert.equal(released.id, ownerSub.id);
  const releasedWire = structuredClone(ownerSub);
  assert.equal(released.schedule ?? null, null);
  assert.ok(provider.calls.some(c => c.method === "POST" && c.path === "/v1/subscription_schedules/sched_owner/release"));
  assert.equal((await list(owner, ownerID, ownerSub.id)).stripeScheduleId ?? null, null);

  const item = ownerSub.items.data[0];
  item.current_period_start = item.current_period_end;
  item.current_period_end += period;
  item.price.id = teamPrice;
  item.quantity = 3;
  await signedUpdate(server, provider, "evt_renew", ownerSub);
  const renewed = await list(owner, ownerID, ownerSub.id);
  assert.equal(renewed.plan, "team");
  assert.equal(renewed.priceId, teamPrice);
  assert.equal(renewed.status, "active");
  assert.equal(renewed.billingInterval, "month");
  assert.equal(renewed.seats, item.quantity);
  assert.equal(Date.parse(renewed.periodStart), item.current_period_start * 1000);
  assert.equal(Date.parse(renewed.periodEnd), item.current_period_end * 1000);
  const unchanged = await list(other, otherID, "sub_other");
  assert.equal(unchanged.plan, "basic");
  assert.equal(unchanged.seats, 1);
  for (const call of provider.calls) {
    assert.equal(call.path.includes("sub_other"), false);
    if (call.path === "/v1/subscriptions") assert.equal(call.query.get("customer"), ownerSub.customer);
    if (call.form.has("customer")) assert.equal(call.form.get("customer"), ownerSub.customer);
  }
  assert.deepEqual(restored, restoredWire, "period-end restore changed the Stripe wire object");
  assert.deepEqual(released, releasedWire, "schedule release changed the Stripe wire object");
}

export async function billingLifecycle(t, helpers) {
  for (const runtime of ["reference", "Go"]) {
    await t.test(runtime, t => exercise(t, runtime, helpers));
  }
}
