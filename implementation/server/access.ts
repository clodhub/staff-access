import { parseCookies, serialiseCookie } from "./cookies.ts";
import { rawSettings } from "./settings.ts";

export type Role = "admin" | "staff";
export const ROLES: readonly Role[] = ["admin", "staff"];
export const ATTEMPTS_COLLECTION = "staffAttempts";
export const MINIMUM_PIN_LENGTH = 6;
export const MINIMUM_SECRET_LENGTH = 32;

export type StaffAccessSettings = {
  adminPinVariable: string;
  staffPinVariable: string;
  sessionSecretVariable: string;
  adminCookie: string;
  staffCookie: string;
  sessionDays: number;
  maximumAttempts: number;
  attemptWindowMinutes: number;
};

export const DEFAULT_SETTINGS: StaffAccessSettings = {
  adminPinVariable: "ADMIN_PIN",
  staffPinVariable: "STAFF_PIN",
  sessionSecretVariable: "STAFF_SESSION_SECRET",
  adminCookie: "shop_admin",
  staffCookie: "shop_staff",
  sessionDays: 7,
  maximumAttempts: 5,
  attemptWindowMinutes: 15,
};

type RawSettings = { [K in keyof StaffAccessSettings]?: unknown };

// A value still in its {{name}} form (the source, before installation renders it) takes the default.
const unrendered = (value: unknown) => typeof value === "string" && /^\{\{[A-Za-z][A-Za-z0-9_.-]*\}\}$/.test(value);
const ENVIRONMENT = /^[A-Z][A-Z0-9_]{0,63}$/;
const IDENTIFIER = /^[A-Za-z][A-Za-z0-9_]{0,63}$/;

export function settingsFrom(raw: RawSettings): StaffAccessSettings {
  const value = (key: keyof StaffAccessSettings): unknown => (raw[key] === undefined || unrendered(raw[key]) ? DEFAULT_SETTINGS[key] : raw[key]);
  const text = (key: "adminPinVariable" | "staffPinVariable" | "sessionSecretVariable" | "adminCookie" | "staffCookie", pattern: RegExp, what: string): string => {
    const found = value(key);
    if (typeof found !== "string" || !pattern.test(found)) throw new RangeError(`${key} is ${what}`);
    return found;
  };
  const whole = (key: "sessionDays" | "maximumAttempts" | "attemptWindowMinutes", low: number, high: number): number => {
    const found = value(key);
    const number = typeof found === "string" && /^[0-9]{1,5}$/.test(found) ? Number(found) : found;
    if (typeof number !== "number" || !Number.isInteger(number) || number < low || number > high) throw new RangeError(`${key} is a whole number from ${low} to ${high}`);
    return number;
  };
  const variable = "an environment variable name: upper-case letters, digits and underscores, starting with a letter";
  const cookie = "a cookie name: letters, digits and underscores, starting with a letter";
  const settings: StaffAccessSettings = {
    adminPinVariable: text("adminPinVariable", ENVIRONMENT, variable),
    staffPinVariable: text("staffPinVariable", ENVIRONMENT, variable),
    sessionSecretVariable: text("sessionSecretVariable", ENVIRONMENT, variable),
    adminCookie: text("adminCookie", IDENTIFIER, cookie),
    staffCookie: text("staffCookie", IDENTIFIER, cookie),
    sessionDays: whole("sessionDays", 1, 365),
    maximumAttempts: whole("maximumAttempts", 1, 100),
    attemptWindowMinutes: whole("attemptWindowMinutes", 1, 1440),
  };
  if (settings.adminCookie === settings.staffCookie) throw new RangeError("adminCookie and staffCookie must differ");
  if (new Set([settings.adminPinVariable, settings.staffPinVariable, settings.sessionSecretVariable]).size < 3) {
    throw new RangeError("adminPinVariable, staffPinVariable and sessionSecretVariable must differ");
  }
  return settings;
}

export const installedSettings = (): StaffAccessSettings => settingsFrom(rawSettings);

export type LoginResult =
  | { ok: true; token: string; expiresAt: Date; setCookie: string }
  | { ok: false; status: 401 | 503; code: "INVALID_PIN" | "NOT_CONFIGURED" }
  | { ok: false; status: 429; code: "TOO_MANY_ATTEMPTS"; retryAfter: number };

// A request as route handlers get it: a Fetch Request, or anything with its headers.
export type RequestLike = { headers: { get(name: string): string | null } };

export type StaffAccess = {
  readonly settings: StaffAccessSettings;
  ensureIndexes(): Promise<void>;
  login(role: Role, pin: unknown, options?: { client?: string }): Promise<LoginResult>;
  role(cookieHeader: string | null | undefined): Promise<Role | null>;
  allows(cookieHeader: string | null | undefined, needed: Role): Promise<boolean>;
  requestRole(request: RequestLike): Promise<Role | null>;
  requestAllows(request: RequestLike, needed: Role): Promise<boolean>;
  logout(role: Role): string;
  configured(role: Role): boolean;
};

// The parts of the records store the attempt limits use.
export type AttemptDocument = { _id: string; role: Role; failures: number; startedAt: Date; expiresAt: Date };
type AttemptCollection = {
  findOne(filter: Record<string, unknown>): Promise<AttemptDocument | null>;
  findOneAndUpdate(filter: Record<string, unknown>, update: { $inc: Record<string, number> }, options: { returnDocument: "after" }): Promise<AttemptDocument | null>;
  updateOne(filter: Record<string, unknown>, update: { $set: Record<string, unknown> }, options: { upsert: boolean }): Promise<unknown>;
  deleteOne(filter: Record<string, unknown>): Promise<unknown>;
  createIndexes(indexes: Array<{ key: Record<string, 1 | -1>; expireAfterSeconds?: number }>): Promise<void>;
};
export type RecordsLike = { collection(name: string): unknown };

export type StaffAccessOptions = {
  records: RecordsLike;
  env?: Record<string, string | undefined>;
  settings?: Partial<StaffAccessSettings>;
  secure?: boolean;
  now?: () => Date;
};

const DAY_SECONDS = 86_400;
// <expiry in Unix seconds>.<HMAC-SHA-256 of "<role>.<expiry>", base64url without padding>, the same as cookie value and bearer token.
const TOKEN = /^([0-9]{1,12})\.([A-Za-z0-9_-]{43})$/;
const BEARER = /^Bearer\s+(\S+)$/i;
const HMAC = { name: "HMAC", hash: "SHA-256" } as const;
const encoder = new TextEncoder();

function checkRole(role: unknown): Role {
  if (role !== "admin" && role !== "staff") throw new RangeError(`a role is admin or staff, not ${JSON.stringify(role)}`);
  return role;
}

// Byte strings of one length compared without an early exit, so the time taken does not depend on where they differ.
export function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let index = 0; index < a.length; index++) difference |= a[index] ^ b[index];
  return difference === 0;
}

const sha256 = async (text: string) => new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(text)));
const hex = (bytes: Uint8Array) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");

function base64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64url(text: string): Uint8Array {
  return Uint8Array.from(atob(text.replace(/-/g, "+").replace(/_/g, "/")), (char) => char.charCodeAt(0));
}

// A value is any text that is not blank, without the spaces and line ends secret stores leave around it; an unset or blank
// variable leaves what it opens closed. A value shorter than its minimum is refused when the access is created.
function valueIn(env: Record<string, string | undefined>, variable: string, minimum: number, what: string): string | null {
  const found = env[variable];
  if (typeof found !== "string" || found.trim() === "") return null;
  const value = found.trim();
  if (value.length < minimum) throw new RangeError(`${variable} holds a ${what} of ${value.length} characters; it needs at least ${minimum}`);
  return value;
}

const isDuplicateKey = (error: unknown) => typeof error === "object" && error !== null && (error as { code?: unknown }).code === "duplicate-key";

const IPV4 = /^((?:\d{1,3}\.){3}\d{1,3})(?::\d{1,5})?$/;

// What a client's wrong PINs are counted under: an IPv4 address, also written as an IPv4-mapped IPv6 address or with a port; an
// IPv6 address by its /64 network, since one subscriber is given a whole /64 and can use any address in it; other text as given.
export function clientKey(client: string): string {
  let text = client.trim().toLowerCase();
  const bracketed = /^\[([^\]]+)\](?::\d{1,5})?$/.exec(text);
  if (bracketed) text = bracketed[1];
  text = text.replace(/%[0-9a-z._~-]+$/, "");
  const mapped = /^::ffff:(.+)$/.exec(text);
  const v4 = IPV4.exec(mapped ? mapped[1] : text);
  if (v4) {
    const octets = v4[1].split(".").map(Number);
    return octets.every((octet) => octet <= 255) ? octets.join(".") : text;
  }
  if (!text.includes(":") || !/^[0-9a-f:]+$/.test(text)) return text;
  const halves = text.split("::");
  if (halves.length > 2) return text;
  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const missing = 8 - head.length - tail.length;
  if (halves.length === 1 ? missing !== 0 : missing < 1) return text;
  const groups = [...head, ...Array<string>(missing).fill("0"), ...tail];
  if (groups.some((group) => !/^[0-9a-f]{1,4}$/.test(group))) return text;
  const values = groups.map((group) => parseInt(group, 16));
  if (values.slice(0, 5).every((value) => value === 0) && values[5] === 0xffff) {
    return [values[6] >> 8, values[6] & 255, values[7] >> 8, values[7] & 255].join(".");
  }
  return `${values.slice(0, 4).map((value) => value.toString(16)).join(":")}::/64`;
}

export function createStaffAccess(options: StaffAccessOptions): StaffAccess {
  if (typeof options?.records?.collection !== "function") throw new TypeError("createStaffAccess needs records: a records store for the sign-in attempts");
  const settings = settingsFrom({ ...installedSettings(), ...options.settings });
  const env = options.env ?? process.env;
  const now = options.now ?? (() => new Date());
  const secure = options.secure ?? true;
  const lifetime = settings.sessionDays * DAY_SECONDS;
  const windowMs = settings.attemptWindowMinutes * 60_000;
  const pins: Record<Role, string | null> = {
    admin: valueIn(env, settings.adminPinVariable, MINIMUM_PIN_LENGTH, "PIN"),
    staff: valueIn(env, settings.staffPinVariable, MINIMUM_PIN_LENGTH, "PIN"),
  };
  const secret = valueIn(env, settings.sessionSecretVariable, MINIMUM_SECRET_LENGTH, "secret");
  const attempts = options.records.collection(ATTEMPTS_COLLECTION) as AttemptCollection;

  // Each role's signing key is derived from the server's secret and the role's PIN: a token proves nothing without the secret,
  // and a changed PIN or secret ends every session it signed.
  const keys: Partial<Record<Role, Promise<CryptoKey>>> = {};
  const keyOf = (role: Role) => (keys[role] ??= (async () => {
    const base = await crypto.subtle.importKey("raw", encoder.encode(secret ?? ""), HMAC, false, ["sign"]);
    const derived = await crypto.subtle.sign("HMAC", base, encoder.encode(`clodhub staff-access session key\n${role}\n${pins[role] ?? ""}`));
    return crypto.subtle.importKey("raw", derived, HMAC, false, ["sign"]);
  })());
  const sign = async (role: Role, expires: number) => new Uint8Array(await crypto.subtle.sign("HMAC", await keyOf(role), encoder.encode(`${role}.${expires}`)));
  const seconds = () => Math.floor(now().getTime() / 1000);
  const cookieOf = (role: Role) => (role === "admin" ? settings.adminCookie : settings.staffCookie);
  const open = (role: Role) => pins[role] !== null && secret !== null;

  let indexed: Promise<void> | null = null;
  function ensureIndexes(): Promise<void> {
    indexed ??= attempts.createIndexes([{ key: { expiresAt: 1 }, expireAfterSeconds: 0 }]).catch((error: unknown) => {
      indexed = null;
      throw error;
    });
    return indexed;
  }

  async function holds(role: Role, token: string | undefined): Promise<boolean> {
    if (!open(role) || typeof token !== "string") return false;
    const match = TOKEN.exec(token);
    if (!match) return false;
    const expires = Number(match[1]);
    const signed = sameBytes(await sign(role, expires), fromBase64url(match[2]));
    const left = expires - seconds();
    return signed && left > 0 && left <= lifetime;
  }

  async function tokenRole(token: string | undefined): Promise<Role | null> {
    if (await holds("admin", token)) return "admin";
    if (await holds("staff", token)) return "staff";
    return null;
  }

  async function roleOf(cookieHeader: string | null | undefined): Promise<Role | null> {
    const cookies = parseCookies(cookieHeader);
    if (await holds("admin", cookies[settings.adminCookie])) return "admin";
    if (await holds("staff", cookies[settings.staffCookie])) return "staff";
    return null;
  }

  // A bearer token decides alone; any other request (a browser, or one behind a password the host asks for) by its cookies.
  async function requestRole(request: RequestLike): Promise<Role | null> {
    const bearer = BEARER.exec(request.headers.get("authorization")?.trim() ?? "");
    return bearer ? tokenRole(bearer[1]) : roleOf(request.headers.get("cookie"));
  }

  const passes = (held: Role | null, needed: Role) => held === "admin" || (held === "staff" && needed === "staff");

  // Failures counted per role and client in a window that starts with the first; the id is a digest, so no address is stored.
  async function attemptId(role: Role, client: string): Promise<string> {
    return hex(await sha256(`${role}\n${client}`));
  }

  // One more try in the client's window, or the first try of a new window: the document as counted.
  async function countTry(id: string, role: Role, at: Date): Promise<AttemptDocument> {
    const live = { _id: id, expiresAt: { $gt: at } };
    const counted = await attempts.findOneAndUpdate(live, { $inc: { failures: 1 } }, { returnDocument: "after" });
    if (counted) return counted;
    const fresh = { role, failures: 1, startedAt: at, expiresAt: new Date(at.getTime() + windowMs) };
    try {
      // Only an ended window is replaced: while another try opens this one, the insert meets its _id.
      await attempts.updateOne({ _id: id, expiresAt: { $lte: at } }, { $set: fresh }, { upsert: true });
      return { _id: id, ...fresh };
    } catch (error) {
      if (!isDuplicateKey(error)) throw error;
      return (await attempts.findOneAndUpdate(live, { $inc: { failures: 1 } }, { returnDocument: "after" })) ?? { _id: id, ...fresh };
    }
  }

  const tooMany = (held: AttemptDocument, at: Date): LoginResult =>
    ({ ok: false, status: 429, code: "TOO_MANY_ATTEMPTS", retryAfter: Math.max(1, Math.ceil((new Date(held.expiresAt).getTime() - at.getTime()) / 1000)) });

  return {
    settings,
    ensureIndexes,

    async login(role, pin, loginOptions = {}) {
      checkRole(role);
      if (!open(role)) return { ok: false, status: 503, code: "NOT_CONFIGURED" };
      const client = typeof loginOptions.client === "string" && loginOptions.client.trim() !== "" ? loginOptions.client : "unknown";
      const id = await attemptId(role, clientKey(client));
      await ensureIndexes();
      const at = now();
      const held = await attempts.findOne({ _id: id, expiresAt: { $gt: at } });
      if (held && held.failures >= settings.maximumAttempts) return tooMany(held, at);
      // Every try is counted before its PIN is compared, so tries sent together cannot slip past the limit between the check and
      // the count; a right PIN then clears the count.
      const counted = await countTry(id, role, at);
      if (counted.failures > settings.maximumAttempts) return tooMany(counted, at);
      // A missing, empty or non-text PIN takes the same path as a wrong one.
      const [given, expected] = await Promise.all([sha256(typeof pin === "string" ? pin : ""), sha256(pins[role] ?? "")]);
      if (!sameBytes(given, expected)) return { ok: false, status: 401, code: "INVALID_PIN" };
      await attempts.deleteOne({ _id: id });
      const expires = seconds() + lifetime;
      const token = `${expires}.${base64url(await sign(role, expires))}`;
      const setCookie = serialiseCookie(cookieOf(role), token, { maxAge: lifetime, httpOnly: true, secure, sameSite: "Lax", path: "/" });
      return { ok: true, token, expiresAt: new Date(expires * 1000), setCookie };
    },
    role: roleOf,
    async allows(cookieHeader, needed) {
      checkRole(needed);
      return passes(await roleOf(cookieHeader), needed);
    },
    requestRole,
    async requestAllows(request, needed) {
      checkRole(needed);
      return passes(await requestRole(request), needed);
    },
    logout(role) {
      checkRole(role);
      return serialiseCookie(cookieOf(role), "", { maxAge: 0, httpOnly: true, secure, sameSite: "Lax", path: "/" });
    },
    configured(role) {
      return open(checkRole(role));
    },
  };
}
