export type CookieOptions = {
  maxAge?: number;
  secure?: boolean;
  httpOnly?: boolean;
  sameSite?: "Lax" | "Strict" | "None";
  path?: string;
  domain?: string;
};

// A cookie name is an HTTP token (RFC 6265 section 4.1.1).
const NAME = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const DOMAIN = /^\.?[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*$/;
const PATH = /^\/[^\u0000-\u001f\u007f;]*$/;

function decode(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

// The cookies of a Cookie request header by name; the first of two cookies with one name wins, values are percent-decoded.
export function parseCookies(header: string | null | undefined): Record<string, string> {
  const cookies: Record<string, string> = {};
  if (typeof header !== "string") return cookies;
  for (const part of header.split(";")) {
    const at = part.indexOf("=");
    if (at <= 0) continue;
    const name = part.slice(0, at).trim();
    if (!NAME.test(name) || name === "__proto__" || Object.hasOwn(cookies, name)) continue;
    let value = part.slice(at + 1).trim();
    if (value.length >= 2 && value.startsWith('"') && value.endsWith('"')) value = value.slice(1, -1);
    cookies[name] = decode(value);
  }
  return cookies;
}

// A Set-Cookie header value. The value is percent-encoded; Path is "/" unless given.
export function serialiseCookie(name: string, value: string, options: CookieOptions = {}): string {
  if (typeof name !== "string" || !NAME.test(name)) throw new RangeError(`cookie name ${JSON.stringify(name)} is not an HTTP token`);
  if (typeof value !== "string") throw new RangeError("a cookie value is text");
  const parts = [`${name}=${encodeURIComponent(value)}`];
  if (options.maxAge !== undefined) {
    if (!Number.isInteger(options.maxAge)) throw new RangeError("maxAge is a whole number of seconds");
    parts.push(`Max-Age=${options.maxAge}`);
  }
  if (options.domain !== undefined) {
    if (!DOMAIN.test(options.domain)) throw new RangeError(`cookie domain ${JSON.stringify(options.domain)} is not a host name`);
    parts.push(`Domain=${options.domain}`);
  }
  const path = options.path ?? "/";
  if (!PATH.test(path)) throw new RangeError(`cookie path ${JSON.stringify(path)} must start with / and hold no ; or control characters`);
  parts.push(`Path=${path}`);
  if (options.httpOnly) parts.push("HttpOnly");
  if (options.secure) parts.push("Secure");
  if (options.sameSite !== undefined) {
    if (!["Lax", "Strict", "None"].includes(options.sameSite)) throw new RangeError("sameSite is Lax, Strict or None");
    if (options.sameSite === "None" && !options.secure) throw new RangeError("browsers refuse SameSite=None without Secure");
    parts.push(`SameSite=${options.sameSite}`);
  }
  return parts.join("; ");
}
