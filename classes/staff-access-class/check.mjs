import { assert, load } from './runtime.mjs';
import { createStore } from './records.ts';

const m = await load('server/index.ts');
let clock = Date.parse('2026-03-02T10:00:00.000Z');
const now = () => new Date(clock);
// PINs and the session secret are read from ADMIN_PIN, STAFF_PIN and STAFF_SESSION_SECRET unless the settings name other variables.
const env = { ADMIN_PIN: 'admin-4821-pin', STAFF_PIN: '246813', STAFF_SESSION_SECRET: 'c'.repeat(20) + '-session-secret-for-checks' };
const settings = { adminCookie: 'class_admin', staffCookie: 'class_staff', sessionDays: 2 };
const pair = (setCookie) => setCookie.split(';')[0];
const attributes = (setCookie) => new Set(setCookie.split(';').slice(1).map((part) => part.trim().toLowerCase()));
const store = createStore({ now });
const make = (options = {}) => m.createStaffAccess({ records: store, env, settings, now, ...options });
const request = (headers) => new Request('https://studio.example.com/api/v1/staff/gift-cards/X', { headers });

// Settings: defaults, unrendered placeholders, rendered text and refusals.
const defaults = m.settingsFrom({});
assert.match(defaults.adminCookie, /^[A-Za-z][A-Za-z0-9_]{0,63}$/);
assert.match(defaults.staffCookie, /^[A-Za-z][A-Za-z0-9_]{0,63}$/);
assert.notEqual(defaults.adminCookie, defaults.staffCookie);
assert.ok(Number.isInteger(defaults.sessionDays) && defaults.sessionDays >= 1);
assert.deepEqual([defaults.maximumAttempts, defaults.attemptWindowMinutes], [5, 15]);
assert.deepEqual(m.settingsFrom({ adminCookie: '{{adminCookie}}', staffCookie: '{{staffCookie}}', sessionDays: '{{sessionDays}}', maximumAttempts: '{{maximumAttempts}}',
  attemptWindowMinutes: '{{attemptWindowMinutes}}' }), defaults);
assert.equal(m.settingsFrom({ sessionDays: '3' }).sessionDays, 3);
assert.deepEqual([m.settingsFrom({ maximumAttempts: '3', attemptWindowMinutes: '30' }).maximumAttempts, m.settingsFrom({ attemptWindowMinutes: '30' }).attemptWindowMinutes], [3, 30]);
for (const bad of [{ sessionDays: '0' }, { sessionDays: 'week' }, { sessionDays: 1.5 }, { adminCookie: 'has space' }, { adminCookie: 'same', staffCookie: 'same' },
  { maximumAttempts: '0' }, { attemptWindowMinutes: 'soon' }]) {
  assert.throws(() => m.settingsFrom(bad), RangeError, JSON.stringify(bad));
}
const installed = m.installedSettings();
assert.deepEqual(m.settingsFrom(installed), installed);
assert.equal(m.ATTEMPTS_COLLECTION, 'staffAttempts');

// The access needs a records store; PINs under six characters and a secret under 32 are refused when it is created.
assert.throws(() => m.createStaffAccess({ env, settings, now }), TypeError);
assert.throws(() => make({ env: { ...env, STAFF_PIN: '2468' } }), RangeError);
assert.throws(() => make({ env: { ...env, STAFF_SESSION_SECRET: 'too-short' } }), RangeError);
const access = make({ secure: true });
assert.equal(access.configured('admin'), true);
assert.equal(access.configured('staff'), true);
await access.ensureIndexes();
const indexes = await store.collection(m.ATTEMPTS_COLLECTION).listIndexes();
assert.ok(indexes.some((index) => index.key.expiresAt === 1 && index.expireAfterSeconds === 0));

// The right PIN gives a signed session that lasts sessionDays, as a cookie and a token; an admin passes every staff check, staff
// pass staff checks only.
const admin = await access.login('admin', env.ADMIN_PIN);
assert.equal(admin.ok, true);
assert.match(admin.token, /^[0-9]{1,12}\.[A-Za-z0-9_-]{43}$/);
assert.equal(admin.expiresAt.getTime(), clock + 2 * 86400 * 1000);
assert.equal(pair(admin.setCookie), `class_admin=${admin.token}`);
for (const attribute of ['httponly', 'secure', 'samesite=lax', 'path=/', `max-age=${2 * 86400}`]) assert.ok(attributes(admin.setCookie).has(attribute), attribute);
const adminCookie = pair(admin.setCookie);
assert.equal(await access.role(adminCookie), 'admin');
assert.equal(await access.allows(adminCookie, 'admin'), true);
assert.equal(await access.allows(adminCookie, 'staff'), true);
const staff = await access.login('staff', env.STAFF_PIN);
assert.equal(staff.ok, true);
assert.match(staff.setCookie, /^class_staff=[^;]+/);
const staffCookie = pair(staff.setCookie);
assert.equal(await access.role(staffCookie), 'staff');
assert.equal(await access.allows(staffCookie, 'staff'), true);
assert.equal(await access.allows(staffCookie, 'admin'), false);
assert.equal(await access.role(`theme=dark; ${staffCookie}; ${adminCookie}`), 'admin');

// The token as a bearer token: it decides alone; without one, the cookies do.
assert.equal(await access.requestRole(request({ authorization: `Bearer ${staff.token}` })), 'staff');
assert.equal(await access.requestRole(request({ authorization: `Bearer ${admin.token}` })), 'admin');
assert.equal(await access.requestAllows(request({ authorization: `Bearer ${staff.token}` }), 'admin'), false);
assert.equal(await access.requestAllows(request({ authorization: `Bearer ${admin.token}` }), 'staff'), true);
assert.equal(await access.requestRole(request({ authorization: `Bearer ${staff.token}`, cookie: adminCookie })), 'staff');
assert.equal(await access.requestRole(request({ authorization: 'Bearer forged.token', cookie: adminCookie })), null);
assert.equal(await access.requestRole(request({ cookie: staffCookie })), 'staff');
assert.equal(await access.requestRole(request({})), null);

// A wrong PIN and a missing or non-text one give the same answer.
const invalid = { ok: false, status: 401, code: 'INVALID_PIN' };
const generous = make({ settings: { ...settings, maximumAttempts: 100 } });
for (const pin of ['975310', '', undefined, null, 246813, ['246813'], { pin: '246813' }, ' 246813', '246813 ', env.ADMIN_PIN]) {
  assert.deepEqual(await generous.login('staff', pin, { client: 'check-wrong-pins' }), invalid, JSON.stringify(pin));
}
assert.deepEqual(await generous.login('admin', env.STAFF_PIN, { client: 'check-wrong-pins' }), invalid);

// maximumAttempts wrong PINs from one client within the window hold back that role for that client, right PIN or not, with the
// seconds left; other clients and the other role are not held back; the window ends attemptWindowMinutes after its first failure.
const guessing = { client: '198.51.100.23' };
const started = clock;
for (let attempt = 0; attempt < 5; attempt++) {
  assert.deepEqual(await access.login('staff', `wrong-${attempt}`, guessing), invalid);
  clock += 60 * 1000;
}
const held = await access.login('staff', env.STAFF_PIN, guessing);
assert.deepEqual(held, { ok: false, status: 429, code: 'TOO_MANY_ATTEMPTS', retryAfter: 10 * 60 });
assert.equal((await make().login('staff', env.STAFF_PIN, guessing)).code, 'TOO_MANY_ATTEMPTS');
assert.equal((await access.login('staff', env.STAFF_PIN, { client: '198.51.100.24' })).ok, true);
assert.equal((await access.login('admin', env.ADMIN_PIN, guessing)).ok, true);
clock = started + 15 * 60 * 1000;
assert.equal((await access.login('staff', env.STAFF_PIN, guessing)).ok, true);
// A right PIN clears the count.
for (let attempt = 0; attempt < 4; attempt++) await access.login('admin', 'wrong-pin', guessing);
assert.equal((await access.login('admin', env.ADMIN_PIN, guessing)).ok, true);
for (let attempt = 0; attempt < 4; attempt++) assert.deepEqual(await access.login('admin', 'wrong-pin', guessing), invalid);
clock = started;

// Fail closed: no cookie, a malformed or altered one, one under the other role's name, one signed before the PIN or the secret
// changed, an expired one.
for (const header of [null, '', 'class_admin=', 'class_admin=garbage', 'class_staff=garbage; class_admin=1.2']) assert.equal(await access.role(header), null, header);
const [adminName, adminValue] = adminCookie.split('=');
const at = Math.floor(adminValue.length * 2 / 3);
const altered = adminValue.slice(0, at) + (adminValue[at] === 'A' ? 'B' : 'A') + adminValue.slice(at + 1);
assert.equal(await access.role(`${adminName}=${altered}`), null);
assert.equal(await access.role(`class_staff=${adminValue}`), null);
assert.equal(await access.role(`class_admin=${staffCookie.split('=')[1]}`), null);
assert.equal(await make({ env: { ...env, ADMIN_PIN: 'a-new-pin-77' } }).role(adminCookie), null);
assert.equal(await make({ env: { ...env, STAFF_SESSION_SECRET: 'd'.repeat(40) } }).role(adminCookie), null);
const signedAt = clock;
clock += 2 * 86400 * 1000 + 1000;
assert.equal(await access.role(adminCookie), null);
assert.equal(await access.role(staffCookie), null);
assert.equal(await access.requestRole(request({ authorization: `Bearer ${admin.token}` })), null);
clock = signedAt;

// A role without a PIN, or a server without its session secret, cannot be signed in to and is never granted.
const closed = make({ env: { STAFF_PIN: env.STAFF_PIN, STAFF_SESSION_SECRET: env.STAFF_SESSION_SECRET } });
assert.equal(closed.configured('admin'), false);
for (const pin of ['', 'anything', undefined]) assert.deepEqual(await closed.login('admin', pin), { ok: false, status: 503, code: 'NOT_CONFIGURED' });
assert.equal(await closed.role(adminCookie), null);
assert.equal(await closed.allows(adminCookie, 'staff'), false);
assert.equal(await closed.role(staffCookie), 'staff');
const blank = make({ env: { ADMIN_PIN: '   ', STAFF_PIN: '', STAFF_SESSION_SECRET: env.STAFF_SESSION_SECRET } });
assert.equal(blank.configured('admin'), false);
assert.equal(blank.configured('staff'), false);
const secretless = make({ env: { ADMIN_PIN: env.ADMIN_PIN, STAFF_PIN: env.STAFF_PIN } });
assert.deepEqual([secretless.configured('admin'), secretless.configured('staff')], [false, false]);
assert.deepEqual(await secretless.login('admin', env.ADMIN_PIN), { ok: false, status: 503, code: 'NOT_CONFIGURED' });
assert.equal(await secretless.allows(adminCookie, 'staff'), false);
assert.equal(await make({ env: {} }).allows(`${adminCookie}; ${staffCookie}`, 'staff'), false);

// Logout removes the cookie; secure false leaves Secure off for http://localhost.
const out = access.logout('admin');
assert.match(out, /^class_admin=;/);
assert.ok(attributes(out).has('max-age=0'));
const local = await make({ secure: false }).login('staff', env.STAFF_PIN, { client: 'local' });
assert.equal(attributes(local.setCookie).has('secure'), false);

// An unknown role is a programmer error.
await assert.rejects(access.login('owner', 'x'), RangeError);
await assert.rejects(access.allows(adminCookie, 'owner'), RangeError);
await assert.rejects(access.requestAllows(request({}), 'owner'), RangeError);
assert.throws(() => access.logout('owner'), RangeError);
assert.throws(() => access.configured('owner'), RangeError);

// Cookie helpers.
assert.deepEqual(m.parseCookies('a=1; b=%20two; a=3; broken; =x'), { a: '1', b: ' two' });
assert.deepEqual(m.parseCookies(null), {});
const written = m.serialiseCookie('n', 'v w;', { maxAge: 60, secure: true, httpOnly: true, sameSite: 'Strict' });
assert.equal(pair(written), 'n=v%20w%3B');
assert.deepEqual(attributes(written), new Set(['max-age=60', 'path=/', 'httponly', 'secure', 'samesite=strict']));
assert.deepEqual(m.parseCookies(pair(written)), { n: 'v w;' });
assert.throws(() => m.serialiseCookie('bad name', 'v'), RangeError);
assert.throws(() => m.serialiseCookie('n', 'v', { sameSite: 'None' }), RangeError);
console.log('staff access class: all checks passed');
