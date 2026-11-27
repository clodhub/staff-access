import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import test from "node:test";
import {
  ATTEMPTS_COLLECTION, DEFAULT_SETTINGS, MINIMUM_PIN_LENGTH, MINIMUM_SECRET_LENGTH, ROLES, createStaffAccess, installedSettings, parseCookies, serialiseCookie,
  settingsFrom, type StaffAccessOptions,
} from "../implementation/server/index.ts";
import { sameBytes } from "../implementation/server/access.ts";
import { staffRoutes } from "../examples/consumer.ts";
import { createStore } from "./fixtures/records.ts";
import { importRendered, placeholders } from "./render.ts";

const template = new URL("../implementation/server/settings.ts", import.meta.url);
const env = { ADMIN_PIN: "admin-4821-pin", STAFF_PIN: "246813", STAFF_SESSION_SECRET: "k".repeat(24) + "-0123456789abcdef" };
const pair = (setCookie: string) => setCookie.split(";")[0];
const attributes = (setCookie: string) => setCookie.split("; ").slice(1);
// A staff access over its own store; the store's clock is the access's.
function make(options: Omit<StaffAccessOptions, "records"> & { records?: StaffAccessOptions["records"] } = {}) {
  const records = options.records ?? createStore({ now: options.now });
  return createStaffAccess({ env, ...options, records });
}
const bearer = (token: string) => new Request("https://studio.example.com/api/v1/staff/members/X", { headers: { authorization: `Bearer ${token}` } });

test("the settings template names only plain settings and renders to the defaults", async () => {
  assert.deepEqual(placeholders(template).sort(),
    ["adminCookie", "adminPinVariable", "attemptWindowMinutes", "maximumAttempts", "sessionDays", "sessionSecretVariable", "staffCookie", "staffPinVariable"]);
  // The defaults declared in authoring/spec.json collect.
  const rendered = await importRendered<{ rawSettings: Record<string, string> }>(template, {
    adminPinVariable: "ADMIN_PIN", staffPinVariable: "STAFF_PIN", sessionSecretVariable: "STAFF_SESSION_SECRET", adminCookie: "shop_admin", staffCookie: "shop_staff",
    sessionDays: 7, maximumAttempts: 5, attemptWindowMinutes: 15,
  });
  assert.deepEqual(settingsFrom(rendered.rawSettings), DEFAULT_SETTINGS);
  assert.deepEqual(installedSettings(), DEFAULT_SETTINGS);
  assert.deepEqual(ROLES, ["admin", "staff"]);
  assert.deepEqual([ATTEMPTS_COLLECTION, MINIMUM_PIN_LENGTH, MINIMUM_SECRET_LENGTH], ["staffAttempts", 6, 32]);
});

test("settingsFrom converts rendered text and refuses what is not of a setting's form", () => {
  assert.deepEqual(settingsFrom({ adminPinVariable: "SHOP_OWNER_PIN", sessionDays: "30", maximumAttempts: "3", attemptWindowMinutes: "60" }),
    { ...DEFAULT_SETTINGS, adminPinVariable: "SHOP_OWNER_PIN", sessionDays: 30, maximumAttempts: 3, attemptWindowMinutes: 60 });
  for (const bad of [{ adminPinVariable: "admin_pin" }, { staffPinVariable: "1PIN" }, { sessionSecretVariable: "secret" }, { adminCookie: "shop-admin" },
    { staffCookie: "" }, { sessionDays: "0" }, { sessionDays: "366" }, { sessionDays: 2.5 }, { sessionDays: "seven" }, { maximumAttempts: "0" },
    { maximumAttempts: "101" }, { attemptWindowMinutes: "0" }, { attemptWindowMinutes: "1441" }, { adminCookie: "same", staffCookie: "same" },
    { sessionSecretVariable: "ADMIN_PIN" }]) {
    assert.throws(() => settingsFrom(bad), RangeError, JSON.stringify(bad));
  }
});

test("each PIN signs in its role with the source's cookie attributes and the session's token and end, and an admin passes staff checks (api/special-pricing/lookup)", async () => {
  const at = Date.parse("2026-05-04T09:00:00Z");
  const access = make({ now: () => new Date(at) });
  const admin = await access.login("admin", env.ADMIN_PIN);
  assert.ok(admin.ok);
  assert.match(admin.token, /^\d+\.[A-Za-z0-9_-]{43}$/);
  assert.equal(admin.expiresAt.getTime(), at + 7 * 86_400_000);
  assert.equal(pair(admin.setCookie), `shop_admin=${admin.token}`);
  // HttpOnly, Secure in production, SameSite Lax, seven days, path /.
  assert.deepEqual(attributes(admin.setCookie), ["Max-Age=604800", "Path=/", "HttpOnly", "Secure", "SameSite=Lax"]);
  const staff = await access.login("staff", env.STAFF_PIN);
  assert.ok(staff.ok);
  assert.match(staff.setCookie, /^shop_staff=/);
  assert.equal(await access.role(pair(admin.setCookie)), "admin");
  assert.equal(await access.role(pair(staff.setCookie)), "staff");
  assert.equal(await access.allows(pair(admin.setCookie), "staff"), true);
  assert.equal(await access.allows(pair(staff.setCookie), "admin"), false);
  assert.equal(await access.allows(`${pair(staff.setCookie)}; ${pair(admin.setCookie)}`, "admin"), true);
});

test("the token is also a bearer token: Authorization decides alone, other requests by their cookies", async () => {
  const access = make();
  const admin = await access.login("admin", env.ADMIN_PIN);
  const staff = await access.login("staff", env.STAFF_PIN);
  assert.ok(admin.ok && staff.ok);
  assert.equal(await access.requestRole(bearer(admin.token)), "admin");
  assert.equal(await access.requestRole(bearer(staff.token)), "staff");
  assert.equal(await access.requestAllows(bearer(staff.token), "staff"), true);
  assert.equal(await access.requestAllows(bearer(staff.token), "admin"), false);
  assert.equal(await access.requestAllows(bearer(admin.token), "staff"), true);
  const both = new Request("https://studio.example.com/", { headers: { authorization: `bearer  ${staff.token}`, cookie: pair(admin.setCookie) } });
  assert.equal(await access.requestRole(both), "staff");
  assert.equal(await access.requestRole(bearer("not-a-token")), null);
  assert.equal(await access.requestRole(new Request("https://studio.example.com/", { headers: { authorization: `Bearer ${admin.token}x`, cookie: pair(admin.setCookie) } })), null);
  // A password the host asks for (Basic) leaves the cookies to decide.
  const behindPassword = new Request("https://studio.example.com/", { headers: { authorization: "Basic b3duZXI6cGFzcw==", cookie: pair(admin.setCookie) } });
  assert.equal(await access.requestRole(behindPassword), "admin");
  assert.equal(await access.requestRole({ headers: new Headers({ cookie: pair(staff.setCookie) }) }), "staff");
  assert.equal(await access.requestRole(new Request("https://studio.example.com/")), null);
});

test("a wrong PIN, a missing one and one of another type all give 401 INVALID_PIN", async () => {
  const access = make({ settings: { maximumAttempts: 100 } });
  for (const pin of ["246814", "", undefined, null, 246813, true, ["246813"], "246813\n"]) {
    assert.deepEqual(await access.login("staff", pin), { ok: false, status: 401, code: "INVALID_PIN" }, String(pin));
  }
});

test("five wrong PINs from one client in fifteen minutes refuse that role and client with TOO_MANY_ATTEMPTS and the seconds to wait", async () => {
  let clock = Date.parse("2026-05-04T09:00:00Z");
  const now = () => new Date(clock);
  const records = createStore({ now });
  const access = make({ records, now });
  const desk = { client: "198.51.100.7" };
  for (let attempt = 0; attempt < 5; attempt++) {
    assert.equal((await access.login("staff", "975310", desk)).ok, false);
    clock += 60_000;
  }
  // The right PIN too: the limit stops guessing, whatever the guess.
  assert.deepEqual(await access.login("staff", env.STAFF_PIN, desk), { ok: false, status: 429, code: "TOO_MANY_ATTEMPTS", retryAfter: 10 * 60 });
  clock += 4 * 60_000 + 30_000;
  assert.deepEqual(await access.login("staff", env.STAFF_PIN, desk), { ok: false, status: 429, code: "TOO_MANY_ATTEMPTS", retryAfter: 5 * 60 + 30 });
  // Another client, and another role from the same client, are not held back.
  assert.equal((await access.login("staff", env.STAFF_PIN, { client: "198.51.100.8" })).ok, true);
  assert.equal((await access.login("admin", env.ADMIN_PIN, desk)).ok, true);
  // Another server process over the same store holds it back too.
  assert.equal((await make({ records, now }).login("staff", env.STAFF_PIN, desk)).ok, false);
  // The window ends fifteen minutes after its first failure.
  clock = Date.parse("2026-05-04T09:15:00Z");
  assert.equal((await access.login("staff", env.STAFF_PIN, desk)).ok, true);
  const kept = await records.collection(ATTEMPTS_COLLECTION).find({});
  assert.equal(kept.some((item) => JSON.stringify(item).includes("198.51.100")), false, "no client address is stored");
  const indexes = await records.collection(ATTEMPTS_COLLECTION).listIndexes();
  assert.ok(indexes.some((index) => index.key.expiresAt === 1 && index.expireAfterSeconds === 0));
});

test("a right PIN clears the client's failures, and requests without an address share one count", async () => {
  let clock = Date.parse("2026-05-04T09:00:00Z");
  const now = () => new Date(clock);
  const access = make({ now, settings: { maximumAttempts: 3, attemptWindowMinutes: 5 } });
  for (let attempt = 0; attempt < 2; attempt++) await access.login("admin", "wrong-pin", { client: "203.0.113.9" });
  assert.equal((await access.login("admin", env.ADMIN_PIN, { client: "203.0.113.9" })).ok, true);
  for (let attempt = 0; attempt < 2; attempt++) assert.equal((await access.login("admin", "wrong-pin", { client: "203.0.113.9" })).ok, false);
  assert.equal((await access.login("admin", env.ADMIN_PIN, { client: "203.0.113.9" })).ok, true);
  for (let attempt = 0; attempt < 3; attempt++) await access.login("admin", "wrong-pin");
  assert.deepEqual(await access.login("admin", env.ADMIN_PIN, { client: " " }), { ok: false, status: 429, code: "TOO_MANY_ATTEMPTS", retryAfter: 300 });
  clock += 5 * 60_000;
  assert.equal((await access.login("admin", env.ADMIN_PIN)).ok, true);
});

test("a role without a PIN, or a server without the session secret, fails closed: 503 NOT_CONFIGURED and no cookie accepted", async () => {
  const access = make({ env: { STAFF_PIN: "246813", STAFF_SESSION_SECRET: env.STAFF_SESSION_SECRET } });
  assert.equal(access.configured("admin"), false);
  assert.equal(access.configured("staff"), true);
  assert.deepEqual(await access.login("admin", "975310"), { ok: false, status: 503, code: "NOT_CONFIGURED" });
  assert.equal(await access.role(`shop_admin=${"a".repeat(32)}`), null);
  assert.equal(make({ env: { ADMIN_PIN: " \t", STAFF_PIN: "", STAFF_SESSION_SECRET: env.STAFF_SESSION_SECRET } }).configured("admin"), false);
  const signed = await make().login("staff", env.STAFF_PIN);
  assert.ok(signed.ok);
  const noSecret = make({ env: { ADMIN_PIN: env.ADMIN_PIN, STAFF_PIN: env.STAFF_PIN } });
  assert.deepEqual([noSecret.configured("admin"), noSecret.configured("staff")], [false, false]);
  assert.deepEqual(await noSecret.login("staff", env.STAFF_PIN), { ok: false, status: 503, code: "NOT_CONFIGURED" });
  assert.equal(await noSecret.role(pair(signed.setCookie)), null);
});

test("PINs shorter than six characters and secrets shorter than 32 are refused when the access is created", () => {
  assert.throws(() => make({ env: { ...env, STAFF_PIN: "2468" } }), /STAFF_PIN holds a PIN of 4 characters; it needs at least 6/);
  assert.throws(() => make({ env: { ...env, ADMIN_PIN: " 12345 " } }), /ADMIN_PIN holds a PIN of 5 characters/);
  assert.throws(() => make({ env: { ...env, STAFF_SESSION_SECRET: "s".repeat(31) } }), /STAFF_SESSION_SECRET holds a secret of 31 characters; it needs at least 32/);
  assert.throws(() => createStaffAccess({ env } as never), TypeError);
  assert.equal(make({ env: { ...env, STAFF_PIN: "123456" } }).configured("staff"), true);
});

test("a PIN read from a secret store with a line end around it is the PIN without it", async () => {
  const access = make({ env: { ...env, ADMIN_PIN: "admin-4821-pin\n" } });
  assert.equal((await access.login("admin", "admin-4821-pin")).ok, true);
  assert.equal((await access.login("admin", "admin-4821-pin\n")).ok, false);
});

test("sessions end after sessionDays, when sessionDays shrinks, when the PIN changes and when the secret changes", async () => {
  let clock = Date.parse("2026-05-04T09:00:00Z");
  const now = () => new Date(clock);
  const access = make({ now, settings: { sessionDays: 2 } });
  const cookie = pair(((await access.login("admin", env.ADMIN_PIN)) as { setCookie: string }).setCookie);
  clock += 2 * 86_400_000 - 1000;
  assert.equal(await access.role(cookie), "admin");
  clock += 2000;
  assert.equal(await access.role(cookie), null);
  clock = Date.parse("2026-05-04T09:00:00Z");
  assert.equal(await make({ now, settings: { sessionDays: 1 } }).role(cookie), null);
  assert.equal(await make({ env: { ...env, ADMIN_PIN: "changed-pin" }, now, settings: { sessionDays: 2 } }).role(cookie), null);
  assert.equal(await make({ env: { ...env, STAFF_SESSION_SECRET: "n".repeat(40) }, now, settings: { sessionDays: 2 } }).role(cookie), null);
  assert.equal(await make({ now, settings: { sessionDays: 2 } }).role(cookie), "admin");
});

test("altered, borrowed and malformed cookies give no role, and a token says nothing about the PIN without the server's secret", async () => {
  const access = make();
  const admin = pair(((await access.login("admin", env.ADMIN_PIN)) as { setCookie: string }).setCookie).split("=")[1];
  const [expires, mac] = admin.split(".");
  const flipped = mac.slice(0, 20) + (mac[20] === "A" ? "B" : "A") + mac.slice(21);
  for (const value of [`${expires}.${flipped}`, `${Number(expires) + 1}.${mac}`, `${expires}.${mac}x`, `${expires}${mac}`, "%E0%A4%A", "x".repeat(4000)]) {
    assert.equal(await access.role(`shop_admin=${value}`), null, value);
  }
  assert.equal(await access.role(`shop_staff=${admin}`), null);
  const otherShop = make({ env: { ADMIN_PIN: "someone-else", STAFF_PIN: "135791", STAFF_SESSION_SECRET: "o".repeat(40) } });
  assert.equal(await otherShop.role(`shop_admin=${admin}`), null);
  // Keyed by the PIN alone, as sessions were signed before the server's secret, the right PIN no longer reproduces the token.
  assert.notEqual(createHmac("sha256", env.ADMIN_PIN).update(`admin.${expires}`).digest("base64url"), mac);
});

test("custom variable and cookie names, the server environment by default, and logout", async () => {
  process.env.STAFF_ACCESS_TEST_OWNER_PIN = "owner-pin-9";
  process.env.STAFF_SESSION_SECRET = env.STAFF_SESSION_SECRET;
  try {
    const access = createStaffAccess({ records: createStore(), settings: { adminPinVariable: "STAFF_ACCESS_TEST_OWNER_PIN", adminCookie: "owner", staffCookie: "team" }, secure: false });
    const result = await access.login("admin", "owner-pin-9");
    assert.ok(result.ok);
    assert.match(result.setCookie, /^owner=/);
    assert.equal(result.setCookie.includes("Secure"), false);
    assert.equal(access.logout("staff"), "team=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax");
  } finally {
    delete process.env.STAFF_ACCESS_TEST_OWNER_PIN;
    delete process.env.STAFF_SESSION_SECRET;
  }
  const access = make();
  await assert.rejects(access.login("owner" as "admin", "x"), RangeError);
  await assert.rejects(access.requestAllows(new Request("https://studio.example.com/"), "owner" as "admin"), RangeError);
  assert.throws(() => access.configured("manager" as "staff"), RangeError);
});

test("sameBytes compares whole byte strings", () => {
  assert.equal(sameBytes(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3])), true);
  assert.equal(sameBytes(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 4])), false);
  assert.equal(sameBytes(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2])), false);
  assert.equal(sameBytes(new Uint8Array([]), new Uint8Array([])), true);
});

test("parseCookies and serialiseCookie", () => {
  assert.deepEqual(parseCookies('a=1; b="two words"; c=%E2%82%AC; c=later; d; =e; __proto__=x; f=%E0%A4%A'), { a: "1", b: "two words", c: "\u20ac", f: "%E0%A4%A" });
  assert.deepEqual(parseCookies(undefined), {});
  assert.equal(serialiseCookie("shop_admin", "a b", { maxAge: 10, domain: "example.com", path: "/admin" }), "shop_admin=a%20b; Max-Age=10; Domain=example.com; Path=/admin");
  assert.equal(serialiseCookie("x", "", { sameSite: "None", secure: true }), "x=; Path=/; Secure; SameSite=None");
  for (const [name, options] of [["bad name", {}], ["x", { maxAge: 1.5 }], ["x", { domain: "bad domain" }], ["x", { path: "no-slash" }], ["x", { path: "/a;b" }],
    ["x", { sameSite: "None" }], ["x", { sameSite: "lax" }]] as const) {
    assert.throws(() => serialiseCookie(name, "v", options as never), RangeError, `${name} ${JSON.stringify(options)}`);
  }
});

test("the example routes sign the owner in, guard admin and staff routes by cookie or bearer token, and hold back a guessing client", async () => {
  const routes = staffRoutes(env, createStore());
  const signIn = (pin: string, client = "192.0.2.1") =>
    routes.signIn(new Request("https://example.com/api/admin/login", { method: "POST", headers: { "x-forwarded-for": client }, body: JSON.stringify({ pin }) }));
  const refused = await signIn("111111");
  assert.equal(refused.status, 401);
  assert.deepEqual(await refused.json(), { error: "INVALID_PIN" });
  assert.equal((await routes.signIn(new Request("https://example.com/api/admin/login", { method: "POST", body: "not json" }))).status, 401);
  const signedIn = await signIn(env.ADMIN_PIN);
  assert.equal(signedIn.status, 200);
  const { token } = (await signedIn.json()) as { token: string };
  const cookie = pair(signedIn.headers.get("set-cookie") ?? "");
  assert.equal((await routes.promotions(new Request("https://example.com/api/promotions"))).status, 401);
  assert.equal((await routes.promotions(new Request("https://example.com/api/promotions", { headers: { cookie } }))).status, 200);
  assert.equal((await routes.promotions(new Request("https://example.com/api/promotions", { headers: { authorization: `Bearer ${token}` } }))).status, 200);
  const lookup = await routes.lookup(new Request("https://example.com/api/lookup?code=ABCD-EFGH-JKMN", { headers: { cookie } }));
  assert.deepEqual(await lookup.json(), { code: "ABCD-EFGH-JKMN" });
  assert.match(routes.signOut().headers.get("set-cookie") ?? "", /^shop_admin=; Max-Age=0/);
  for (let attempt = 0; attempt < 5; attempt++) await signIn("975310", "192.0.2.66");
  const held = await signIn(env.ADMIN_PIN, "192.0.2.66");
  assert.deepEqual([held.status, held.headers.get("retry-after"), await held.json()], [429, "900", { error: "TOO_MANY_ATTEMPTS" }]);
  const closed = staffRoutes({}, createStore());
  assert.equal((await closed.signIn(new Request("https://example.com/api/admin/login", { method: "POST", body: JSON.stringify({ pin: "x" }) }))).status, 503);
});
