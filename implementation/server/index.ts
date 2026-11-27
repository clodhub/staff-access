// The entry module of staff-access's server code: everything code outside the component may use.
export {
  ATTEMPTS_COLLECTION, DEFAULT_SETTINGS, MINIMUM_PIN_LENGTH, MINIMUM_SECRET_LENGTH, ROLES, createStaffAccess, installedSettings, settingsFrom,
} from "./access.ts";
export type { AttemptDocument, LoginResult, RecordsLike, RequestLike, Role, StaffAccess, StaffAccessOptions, StaffAccessSettings } from "./access.ts";
export { parseCookies, serialiseCookie } from "./cookies.ts";
export type { CookieOptions } from "./cookies.ts";
