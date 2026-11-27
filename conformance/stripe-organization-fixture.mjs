import assert from "node:assert/strict";
import { once } from "node:events";
import { readFile } from "node:fs/promises";
import { createServer } from "node:http";
import { DatabaseSync } from "node:sqlite";
import { organization } from "better-auth/plugins";
import { organizationClient } from "better-auth/client/plugins";
import { stripe } from "@better-auth/stripe";
import { stripeClient } from "@better-auth/stripe/client";
import Stripe from "stripe";

const secret = "whsec_offline_fixture";
const checked = result => { assert.equal(result.error, null, JSON.stringify(result.error)); return result.data; };

const intervalOf = id => id.endsWith("_annual") ? "year" : "month";

async function provider(t, meteredIDs = []) {
  function price(id) {
    return { id, object: "price", active: true, recurring: {
      interval: intervalOf(id), interval_count: 1, usage_type: meteredIDs.includes(id) ? "metered" : "licensed",
    } };
  }
  const state = { calls: [], customer: null, checkout: null, subscription: null, seatUpdates: [] };
  const server = createServer(async (req, res) => {
    const url = new URL(req.url, "http://127.0.0.1");
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const form = new URLSearchParams(Buffer.concat(chunks).toString());
    const fields = prefix => Object.fromEntries([...form].filter(([k]) => k.startsWith(prefix)).map(([k, v]) => [k.slice(prefix.length, -1), v]));
    let result;
    state.calls.push([req.method, url.pathname]);
    if (url.pathname === "/v1/customers/search") result = { object: "search_result", has_more: false, data: [] };
    if (url.pathname === "/v1/customers" && req.method === "GET") result = { object: "list", has_more: false, data: [] };
    if (url.pathname === "/v1/customers" && req.method === "POST") {
      const metadata = fields("metadata[");
      result = { id: metadata.customerType === "organization" ? "cus_org" : "cus_user", object: "customer", name: form.get("name"), email: form.get("email"), metadata };
      if (result.id === "cus_org") state.customer = result;
      else state.userCustomer = result;
    }
    if (url.pathname === "/v1/subscriptions" && req.method === "GET") result = { object: "list", has_more: false, data: [] };
    if (url.pathname.startsWith("/v1/prices/")) {
      const id = url.pathname.split("/").at(-1);
      result = price(id);
    }
    if (url.pathname === "/v1/checkout/sessions" && req.method === "POST") {
      state.trialDays = form.get("subscription_data[trial_period_days]");
      const lines = [];
      for (let i = 0; form.has(`line_items[${i}][price]`); i++) {
        const line = { id: "li_" + i, price: price(form.get(`line_items[${i}][price]`)) };
        const quantity = form.get(`line_items[${i}][quantity]`);
        if (quantity !== null) line.quantity = Number(quantity);
        lines.push(line);
      }
      result = state.checkout = { id: "cs_org", object: "checkout.session", mode: form.get("mode"), customer: form.get("customer"), customer_email: form.get("customer_email"),
        url: "https://checkout.example.test/org", client_reference_id: form.get("client_reference_id"), metadata: fields("metadata["),
        subscription: "sub_org", status: "complete", payment_status: "paid", line_items: {object: "list", has_more: false, data: lines} };
      const start = Math.floor(Date.now() / 1000);
      state.subscription = { id: "sub_org", object: "subscription", customer: result.customer, status: "active",
        metadata: fields("subscription_data[metadata]["), livemode: false, items: { object: "list", has_more: false, data: lines.map((line, i) => ({
          id: ["si_org", "si_member"][i] ?? "si_addon_" + i, quantity: line.quantity, current_period_start: start,
          current_period_end: start + (intervalOf(line.price.id) === "year" ? 31_536_000 : 2_592_000), price: line.price,
        })) } };
      if (state.trialDays) {
        state.subscription.status = "trialing";
        state.subscription.trial_start = start;
        state.subscription.trial_end = start + Number(state.trialDays) * 86400;
      }
    }
    if (url.pathname === "/v1/checkout/sessions/cs_org" && req.method === "GET") result = state.checkout;
    if (url.pathname === "/v1/subscriptions/sub_org" && req.method === "GET") result = state.subscription;
    if (url.pathname === "/v1/subscriptions/sub_org" && req.method === "POST") {
      const item = form.get("items[0][id]");
      const quantity = Number(form.get("items[0][quantity]"));
      const proration = form.get("proration_behavior");
      const target = state.subscription?.items.data.find(row => row.id === item);
      if (target && Number.isInteger(quantity) && quantity >= 0) {
        state.seatUpdates.push({ item, quantity, proration });
        target.quantity = quantity;
        result = state.subscription;
      }
    }
    if (url.pathname === "/v1/billing_portal/sessions") result = { id: "bps_org", object: "billing_portal.session", customer: form.get("customer"), url: "https://billing.example.test/" + form.get("customer") };
    res.writeHead(result ? 200 : 404, { "content-type": "application/json" });
    res.end(JSON.stringify(result ?? { error: { type: "invalid_request_error", code: "resource_missing", message: "Unsupported fixture operation" } }));
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => new Promise(resolve => server.close(resolve)));
  const port = server.address().port;
  const api = new Stripe("sk_test_offline_fixture", { host: "127.0.0.1", port, protocol: "http", maxNetworkRetries: 0, telemetry: false });
  return { state, api, url: "http://127.0.0.1:" + port };
}

async function organizationBillingPolicy({ user, referenceId }, ctx) {
  const member = await ctx.context.adapter.findOne({ model: "member", where: [
    { field: "organizationId", value: referenceId }, { field: "userId", value: user.id },
  ] });
  return member?.role === "owner" || member?.role === "admin";
}

export async function organizationBilling(t, { reference, goFixture, instrument }, { automatic = false, separate = false, annual = false } = {}) {
  for (const runtime of ["reference", "Go"]) await t.test(runtime, async t => {
    const remote = await provider(t);
    const basicPlan = { name: "basic", priceId: "price_basic" };
    if (automatic) basicPlan.seatPriceId = separate ? "price_member" : basicPlan.priceId;
    let fixturePricing = separate ? "1" : "";
    if (annual) {
      basicPlan.annualDiscountPriceId = "price_basic_annual";
      basicPlan.seatPriceId = separate ? "price_member_annual" : basicPlan.annualDiscountPriceId;
      // The reference identifies a seat-only plan by its default price.
      if (!separate) basicPlan.priceId = basicPlan.seatPriceId;
      fixturePricing = separate ? "annual" : "annual-seat-only";
    }
    const server = runtime === "Go"
      ? await goFixture(t, ["organization", "stripe-organization"], { CONFORMANCE_STRIPE_URL: remote.url, CONFORMANCE_STRIPE_AUTO_SEATS: automatic ? "1" : "", CONFORMANCE_STRIPE_SEPARATE_PRICE: fixturePricing })
      : await reference(t, [organization(), stripe({
        stripeClient: remote.api, stripeWebhookSecret: secret, organization: { enabled: true },
        subscription: { enabled: true, plans: [basicPlan, { name: "team", priceId: "price_team", annualDiscountPriceId: "price_team_annual" }],
          authorizeReference: organizationBillingPolicy },
      })]);
    const browser = () => instrument(server, [organizationClient(), stripeClient({ subscription: true })]).client;
    const owner = browser(), peer = browser();
    const account = checked(await owner.signUp.email({ email: "org-buyer@example.test", name: "Owner", password: "test-password-123" }));
    checked(await peer.signUp.email({ email: "outside@example.test", name: "Peer", password: "test-password-123" }));
    const selector = { customerType: "organization" };
    assert.equal((await owner.subscription.list({ query: selector })).error.code, "ORGANIZATION_REFERENCE_ID_REQUIRED");
    assert.equal((await owner.subscription.upgrade({ ...selector, plan: "basic", disableRedirect: true })).error.code, "ORGANIZATION_REFERENCE_ID_REQUIRED");
    assert.equal(remote.state.calls.length, 0);
    const group = checked(await owner.organization.create({ name: "Fixture Group", slug: "fixture-group" }));
    const explicit = { ...selector, referenceId: group.id };
    const denied = await peer.subscription.upgrade({ ...explicit, plan: "basic" });
    assert.equal(denied.error.status, 401);
    assert.equal(denied.error.code, "UNAUTHORIZED");
    assert.equal(remote.state.calls.length, 0);
    if (automatic) {
      await automaticSeats({ browser, owner, peer, group, remote, deliver, separate, annual });
      return;
    }
    const purchase = checked(await owner.subscription.upgrade({ ...selector, plan: "basic", seats: 5, disableRedirect: true }));
    assert.equal(purchase.url, "https://checkout.example.test/org");
    assert.equal(purchase.redirect, false);
    assert.deepEqual(purchase, { ...JSON.parse(JSON.stringify(remote.state.checkout)), redirect: false });
    assert.deepEqual(remote.state.customer.metadata, { organizationId: group.id, customerType: "organization" });
    assert.equal(remote.state.customer.name, group.name);
    assert.equal(remote.state.checkout.client_reference_id, group.id);
    assert.equal(remote.state.subscription.items.data[0].quantity, 5);
    assert.equal(remote.state.checkout.customer, "cus_org");
    assert.equal(remote.state.checkout.metadata.referenceId, group.id);
    assert.equal(remote.state.checkout.metadata.userId, account.user.id);
    assert.equal(remote.state.customer.email ?? null, null);
    assert.equal(remote.state.checkout.customer_email ?? null, null);
    assert.deepEqual(checked(await owner.subscription.list()), []);
    assert.deepEqual(checked(await owner.subscription.list({ query: explicit })), []);
    async function deliver(id, type, object) {
      const payload = JSON.stringify({ id, type, object: "event", api_version: Stripe.API_VERSION, created: Math.floor(Date.now() / 1000), livemode: false, data: { object } });
      const signature = remote.api.webhooks.generateTestHeaderString({ payload, secret });
      const resp = await server.send(new Request(server.baseURL + "/api/auth/stripe/webhook", { method: "POST", headers: { "content-type": "application/json", "stripe-signature": signature }, body: payload }));
      assert.equal(resp.status, 200, await resp.text());
    }
    assert.equal(remote.state.checkout.line_items.data[0].quantity, 5);
    remote.state.subscription.items.data[0].quantity = 8;
    await deliver("evt_checkout_org", "checkout.session.completed", remote.state.checkout);
    const rows = checked(await owner.subscription.list({ query: selector }));
    assert.equal(rows.length, 1);
    assert.equal(rows[0].referenceId, group.id);
    assert.equal(rows[0].seats, 8);
    assert.equal(rows[0].stripeCustomerId, "cus_org");
    assert.equal(rows[0].stripeSubscriptionId, "sub_org");
    assert.equal(rows[0].priceId, "price_basic");
    assert.equal(checked(await owner.subscription.billingPortal({ ...explicit, returnUrl: "/billing", disableRedirect: true })).url, "https://billing.example.test/cus_org");
    assert.equal((await peer.subscription.billingPortal({ ...explicit })).error.code, "UNAUTHORIZED");
    remote.state.subscription.items.data[0].price = { id: "price_team_annual", recurring: { interval: "year", interval_count: 1, usage_type: "licensed" } };
    await deliver("evt_org_renew", "customer.subscription.updated", remote.state.subscription);
    const updated = checked(await owner.subscription.list({ query: explicit }));
    assert.equal(updated[0].plan, "team");
    assert.equal(updated[0].priceId, "price_team_annual");
    assert.deepEqual(checked(await owner.subscription.list()), []);
    assert.deepEqual(checked(await peer.subscription.list()), []);
    // An explicit reference lists that organization rather than the active
    // one, and a purchase without a customer type stays the user's own.
    checked(await owner.organization.create({ name: "Second Group", slug: "second-group" }));
    assert.deepEqual(checked(await owner.subscription.list({ query: selector })), []);
    assert.deepEqual(checked(await owner.subscription.list({ query: explicit })).map(row => [row.referenceId, row.plan, row.priceId]), [[group.id, "team", "price_team_annual"]]);
    assert.equal((await peer.subscription.list({ query: explicit })).error.code, "UNAUTHORIZED");
    checked(await owner.subscription.upgrade({ plan: "team", disableRedirect: true }));
    assert.deepEqual(remote.state.userCustomer.metadata, { userId: account.user.id, customerType: "user" });
    assert.equal(remote.state.checkout.client_reference_id, account.user.id);
    assert.equal(remote.state.checkout.metadata.referenceId, account.user.id);
    assert.equal(remote.state.checkout.customer, "cus_user");
    assert.equal(remote.state.calls.some(([method, path]) => method === "POST" && path.startsWith("/v1/customers/")), false);
  });
}

async function automaticSeats({ browser, owner, peer, group, remote, deliver, separate, annual }) {
  const invite = async (client, email) => {
    const invitation = checked(await owner.organization.inviteMember({ organizationId: group.id, email, role: "member" }));
    checked(await client.organization.acceptInvitation({ invitationId: invitation.id }));
  };
  await invite(peer, "outside@example.test");
  const selector = { customerType: "organization", referenceId: group.id };
  const managedCheckout = checked(await owner.subscription.upgrade({ ...selector, plan: "basic", annual, seats: 99, disableRedirect: true }));
  assert.equal(managedCheckout.url, "https://checkout.example.test/org");
  if (annual && !separate) {
    assert.deepEqual(remote.state.checkout.line_items.data.map(line => [line.price.id, line.quantity]), [["price_basic_annual", 2]]);
  } else if (annual) {
    assert.deepEqual(remote.state.checkout.line_items.data.map(line => [line.price.id, line.quantity]), [["price_basic_annual", 1], ["price_member_annual", 2]]);
  } else if (separate) {
    assert.deepEqual(remote.state.checkout.line_items.data.map(line => [line.price.id, line.quantity]), [["price_basic", 1], ["price_member", 2]]);
  } else {
    assert.equal(remote.state.checkout.line_items.data[0].quantity, 2);
  }
  const seatID = separate ? "si_member" : "si_org";
  assert.equal(remote.state.checkout.customer, "cus_org");
  await deliver("evt_managed_checkout", "checkout.session.completed", remote.state.checkout);
  const member = browser();
  checked(await member.signUp.email({ email: "third@example.test", name: "Third", password: "test-password-123" }));
  async function observe(expected) {
    const deadline = Date.now() + 5_000;
    do {
      const rows = checked(await owner.subscription.list({ query: selector }));
      if (rows.length === 1 && rows[0].priceId === (annual ? "price_basic_annual" : "price_basic") && rows[0].billingInterval === (annual ? "year" : "month") && rows[0].seats === expected && remote.state.subscription.items.data.find(item => item.id === seatID)?.quantity === expected) return;
      await new Promise(resolve => setTimeout(resolve, 25));
    } while (Date.now() < deadline);
    assert.fail("Membership quantity did not reach " + expected);
  }
  await invite(member, "third@example.test");
  await observe(3);
  checked(await owner.organization.removeMember({ organizationId: group.id, memberIdOrEmail: "third@example.test" }));
  await observe(2);
  if (separate) assert.equal(remote.state.subscription.items.data.find(item => item.id === "si_org").quantity, 1);
  assert.deepEqual(remote.state.seatUpdates, [
    { item: seatID, quantity: 3, proration: "create_prorations" },
    { item: seatID, quantity: 2, proration: "create_prorations" },
  ]);
  assert.deepEqual(checked(await owner.subscription.list()), []);
}

export async function meteredCheckout(t, { reference, goFixture, instrument }, isOrganization, withAddons = false) {
  const priceID = "price_team_annual";
  for (const runtime of ["reference", "Go"]) await t.test(runtime, async t => {
    const addonIDs = ["price_storage_annual", "price_requests_annual"];
    const plan = { name: "team", priceId: "price_team", annualDiscountPriceId: priceID };
    if (withAddons) plan.lineItems = addonIDs.map(price => ({ price }));
    const remote = await provider(t, withAddons ? addonIDs : [priceID]);
    const profile = isOrganization ? ["organization", "stripe-organization"] : ["stripe-subscriptions"];
    const server = runtime === "Go"
      ? await goFixture(t, profile, { CONFORMANCE_STRIPE_URL: remote.url, CONFORMANCE_STRIPE_METERED_ADDONS: withAddons ? "1" : "" })
      : await reference(t, [organization(), stripe({
        stripeClient: remote.api, stripeWebhookSecret: secret, organization: { enabled: true },
        subscription: { enabled: true, authorizeReference: organizationBillingPolicy,
          plans: [plan] },
      })]);
    const browser = () => instrument(server, [organizationClient(), stripeClient({ subscription: true })]).client;
    const owner = browser(), other = browser();
    const signup = (client, name) => client.signUp.email({ name, email: name + "@example.test", password: "meter-fixture-password" });
    const account = checked(await signup(owner, "buyer"));
    checked(await signup(other, "peer"));
    let referenceId = account.user.id;
    let selection = {};
    if (isOrganization) {
      const group = checked(await owner.organization.create({ name: "Metered org", slug: "metered" }));
      referenceId = group.id;
      selection = { referenceId, customerType: "organization" };
      const denied = await other.subscription.upgrade({ ...selection, plan: "team", annual: true });
      assert.equal(denied.error.status, 401);
      assert.equal(remote.state.calls.length, 0);
    }
    const checkout = checked(await owner.subscription.upgrade({ ...selection, plan: "team", annual: true, seats: 9, disableRedirect: true }));
    assert.equal(checkout.redirect, false);
    assert.equal(checkout.url, remote.state.checkout.url);
    assert.equal(remote.state.checkout.client_reference_id, referenceId);
    const [line] = remote.state.checkout.line_items.data;
    assert.equal(line.price.id, priceID);
    if (withAddons) {
      const lines = remote.state.checkout.line_items.data;
      assert.deepEqual(lines.map(l => [l.price.id, Object.hasOwn(l, "quantity")]), [[priceID, true], ...addonIDs.map(id => [id, false])]);
      assert.equal(line.quantity, 9);
      const base = remote.state.subscription.items.data[0];
      base.quantity = 12;
      remote.state.subscription.items.data.reverse();
    } else {
      assert.equal(Object.hasOwn(line, "quantity"), false);
    }
    const list = () => owner.subscription.list({ query: selection });
    assert.deepEqual(checked(await list()), []);
    // An event may identify the bought price without expanding its recurring details.
    const receipt = structuredClone(remote.state.checkout);
    receipt.line_items.data[0].price = priceID;
    for (const [type, object] of [["checkout.session.completed", receipt], ["customer.subscription.updated", remote.state.subscription]]) {
      const payload = JSON.stringify({ id: "evt_" + type, type, object: "event", api_version: Stripe.API_VERSION,
        created: Math.floor(Date.now() / 1000), livemode: false, data: { object } });
      const signature = remote.api.webhooks.generateTestHeaderString({ payload, secret });
      const reply = await server.send(new Request(server.baseURL + "/api/auth/stripe/webhook", {
        method: "POST", headers: { "content-type": "application/json", "stripe-signature": signature }, body: payload,
      }));
      assert.equal(reply.status, 200, await reply.text());
      const [row] = checked(await list());
      if (withAddons) {
        assert.deepEqual([row.referenceId, row.priceId, row.billingInterval, row.seats], [referenceId, priceID, "year", 12]);
      } else {
        assert.deepEqual([row.referenceId, row.plan, row.priceId, row.billingInterval, row.seats], [referenceId, "team", priceID, "year", 1]);
      }
      assert.deepEqual(checked(await other.subscription.list()), []);
      if (isOrganization) assert.deepEqual(checked(await owner.subscription.list()), []);
    }
  });
}

export async function checkoutCompletionObserver(t, { reference, goFixture, instrument }, groupBilling) {
  for (const runtime of ["reference", "Go"]) await t.test(runtime, async t => {
    const remote = await provider(t);
    const calls = [];
    const profiles = groupBilling ? ["organization", "stripe-organization"] : ["stripe-subscriptions"];
    const server = runtime === "Go"
      ? await goFixture(t, profiles, { CONFORMANCE_STRIPE_URL: remote.url, CONFORMANCE_STRIPE_COMPLETION_OBSERVER: "1" })
      : await reference(t, [organization(), stripe({
        stripeClient: remote.api,
        stripeWebhookSecret: secret,
        organization: { enabled: true },
        subscription: {
          enabled: true,
          plans: [{ name: "basic", priceId: "price_basic" }, { name: "team", priceId: "price_team" }],
          authorizeReference: organizationBillingPolicy,
          onSubscriptionComplete: async (p, ctx) => calls.push([
            "complete", p.event.id, p.stripeSubscription.id, p.subscription.referenceId,
            p.subscription.status, p.plan.name, new URL(ctx.request.url).pathname,
          ]),
        },
        onEvent: async event => calls.push(["event", event.id]),
      })]);
    const client = instrument(server, [organizationClient(), stripeClient({ subscription: true })]).client;
    const { user } = checked(await client.signUp.email({
      name: "Buyer", email: "complete@example.test", password: "complete-fixture-password",
    }));
    let selection = {};
    let referenceID = user.id;
    if (groupBilling) {
      const group = checked(await client.organization.create({ name: "Billing group", slug: "checkout-complete" }));
      selection = { referenceId: group.id, customerType: "organization" };
      referenceID = group.id;
    }
    const purchase = checked(await client.subscription.upgrade({ ...selection, plan: "basic", seats: 3, disableRedirect: true }));
    assert.equal(purchase.url, remote.state.checkout.url);

    const expected = [];
    async function deliver(id, type, object, plan) {
      const body = JSON.stringify({ id, type, object: "event", api_version: Stripe.API_VERSION,
        created: 1712345678, livemode: false, data: { object } });
      const signature = remote.api.webhooks.generateTestHeaderString({ payload: body, secret });
      const result = await server.send(new Request(server.baseURL + "/api/auth/stripe/webhook", {
        method: "POST", headers: { "content-type": "application/json", "stripe-signature": signature }, body,
      }));
      assert.equal(result.status, 200, await result.text());
      if (plan) {
        expected.push(["complete", id, remote.state.subscription.id, referenceID, remote.state.subscription.status, plan, "/api/auth/stripe/webhook"]);
      }
      expected.push(["event", id]);
      const actual = runtime === "Go"
        ? (await readFile(server.databasePath + ".stripe-updates", "utf8")).trim().split("\n").map(JSON.parse)
        : calls;
      assert.deepEqual(actual, expected);
    }
    await deliver("evt_before_checkout", "customer.subscription.created", remote.state.subscription);
    const signedCheckout = structuredClone(remote.state.checkout);
    await deliver("evt_completed", "checkout.session.completed", signedCheckout, "basic");
    // Stripe changed the live subscription between deliveries of the identical Checkout event.
    remote.state.subscription.status = "trialing";
    const [item] = remote.state.subscription.items.data;
    item.price = { ...item.price, id: "price_team" };
    item.quantity = 7;
    await deliver("evt_completed", "checkout.session.completed", signedCheckout, "team");
    item.price = { ...item.price, id: "price_unconfigured" };
    await deliver("evt_completed", "checkout.session.completed", signedCheckout);
    const [row] = checked(await client.subscription.list({ query: selection }));
    assert.equal(row.referenceId, referenceID);
    assert.equal(row.stripeSubscriptionId, remote.state.subscription.id);
    assert.deepEqual([row.plan, row.status, row.seats], ["team", "trialing", 7]);
  });
}

export async function trialEligibility(t, { reference, goFixture, instrument }, groupBilling, priorTrial) {
  const remote = await provider(t);
  for (const runtime of ["reference", "Go"]) await t.test(runtime, async t => {
    const server = runtime === "Go"
      ? await goFixture(t, groupBilling ? ["organization", "stripe-organization"] : ["stripe-subscriptions"],
        { CONFORMANCE_STRIPE_URL: remote.url, CONFORMANCE_STRIPE_FREE_TRIAL: "1" })
      : await reference(t, [organization(), stripe({
        stripeClient: remote.api, stripeWebhookSecret: secret, organization: { enabled: true },
        subscription: { enabled: true, plans: [{ name: "basic", priceId: "price_basic", freeTrial: { days: 14 } }],
          authorizeReference: organizationBillingPolicy },
      })]);
    const db = server.database ?? new DatabaseSync(server.databasePath);
    if (!server.database) t.after(() => db.close());
    const client = instrument(server, [organizationClient(), stripeClient({ subscription: true })]).client;
    const { user } = checked(await client.signUp.email({
      name: "Trial buyer", email: "trial@example.test", password: "trial-fixture-password",
    }));
    let referenceID = user.id;
    let selection = {};
    if (groupBilling) {
      const group = checked(await client.organization.create({ name: "Trial group", slug: "trial-group" }));
      referenceID = group.id;
      selection = { referenceId: group.id, customerType: "organization" };
    }
    if (priorTrial) {
      db.prepare('INSERT INTO "subscription" ("id","plan","referenceId","status","trialEnd") VALUES(?,?,?,?,?)')
        .run("original", "older-plan", referenceID, "canceled", new Date("2025-01-02").toISOString());
    }
    // Only the configured plan and the selected reference's persisted history determine the term.
    const result = checked(await client.subscription.upgrade({ ...selection, plan: "basic", disableRedirect: true }));
    assert.equal(result.url, remote.state.checkout.url);
    assert.equal(remote.state.trialDays, priorTrial ? null : "14");
    const body = JSON.stringify({ id: "evt_trial_receipt", type: "checkout.session.completed", object: "event",
      api_version: Stripe.API_VERSION, livemode: false, data: { object: remote.state.checkout } });
    const signature = remote.api.webhooks.generateTestHeaderString({ payload: body, secret });
    const reply = await server.send(new Request(server.baseURL + "/api/auth/stripe/webhook", {
      method: "POST", headers: { "content-type": "application/json", "stripe-signature": signature }, body,
    }));
    assert.equal(reply.status, 200, await reply.text());
    const [row] = checked(await client.subscription.list({ query: selection }));
    assert.equal(row.referenceId, referenceID);
    assert.equal(row.status, priorTrial ? "active" : "trialing");
    if (!priorTrial) assert.equal(Date.parse(row.trialEnd) - Date.parse(row.trialStart), 14 * 86400000);
  });
}

export async function trialCallbacks(t, { reference, goFixture, instrument }, target, standalone = false) {
  for (const runtime of ["reference", "Go"]) await t.test(runtime, async t => {
    const remote = await provider(t);
    const calls = [];
    const server = runtime === "Go"
      ? await goFixture(t, ["stripe-subscriptions"], { CONFORMANCE_STRIPE_URL: remote.url, CONFORMANCE_STRIPE_TRIAL_CALLBACKS: standalone ? "solo" : "1" })
      : await reference(t, [stripe({
        stripeClient: remote.api, stripeWebhookSecret: secret,
        subscription: {
          enabled: true, plans: [{ name: "basic", priceId: "price_basic", freeTrial: {
            days: 14,
            onTrialStart: async s => calls.push(["start", s.referenceId, s.status]),
            onTrialEnd: async ({ subscription }, ctx) =>
              calls.push(["end", subscription.referenceId, subscription.status, new URL(ctx.request.url).pathname]),
            onTrialExpired: async (s, ctx) => calls.push(["expired", s.referenceId, s.status, new URL(ctx.request.url).pathname]),
          } }],
          onSubscriptionComplete: standalone ? undefined : async ({ event }) => calls.push(["complete", event.id]),
          onSubscriptionUpdate: standalone ? undefined : async ({ event }) => calls.push(["update", event.id]),
        },
        onEvent: async event => calls.push(["event", event.id]),
      })]);
    const client = instrument(server, [stripeClient({ subscription: true })]).client;
    const { user } = checked(await client.signUp.email({
      name: "Trial buyer", email: "callbacks@example.test", password: "trial-callback-fixture",
    }));
    checked(await client.subscription.upgrade({ plan: "basic", disableRedirect: true }));
    const expected = [];
    async function deliver(id, type, object, ...order) {
      const body = JSON.stringify({ id, type, object: "event", api_version: Stripe.API_VERSION,
        livemode: false, data: { object } });
      const signature = remote.api.webhooks.generateTestHeaderString({ payload: body, secret });
      const reply = await server.send(new Request(server.baseURL + "/api/auth/stripe/webhook", {
        method: "POST", headers: { "content-type": "application/json", "stripe-signature": signature }, body,
      }));
      assert.equal(reply.status, 200, await reply.text());
      for (const operation of order) {
        if (operation === "start") expected.push(["start", user.id, "trialing"]);
        else if (operation === "end" || operation === "expired") expected.push([operation, user.id, target, "/api/auth/stripe/webhook"]);
        else if (!standalone) expected.push([operation, id]);
      }
      expected.push(["event", id]);
      const actual = runtime === "Go"
        ? (await readFile(server.databasePath + ".stripe-updates", "utf8")).trim().split("\n").map(JSON.parse)
        : calls;
      assert.deepEqual(actual, expected);
    }
    for (let attempt = 0; attempt < 2; attempt++) {
      await deliver("evt_trial_checkout", "checkout.session.completed", remote.state.checkout, "start", "complete");
    }
    remote.state.subscription.status = target;
    if (target === "active") {
      await deliver("evt_trial_change", "customer.subscription.updated", remote.state.subscription, "update", "end");
    } else {
      await deliver("evt_trial_change", "customer.subscription.updated", remote.state.subscription, "update", "expired");
    }
    await deliver("evt_trial_change", "customer.subscription.updated", remote.state.subscription, "update");
  });
}
