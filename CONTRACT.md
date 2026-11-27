# Staff access component

## Purpose and facilities
A shop's management pages (promotions, member pricing, gift cards, the schedule) belong to the owner, and the code lookup to the staff at the desk, on the website and in the shop's apps. This component signs them in with a PIN and recognises them on later requests by a signed session: the website keeps it in a cookie, an app sends it as `Authorization: Bearer <token>`. There are two roles, `admin` and `staff`, and an admin passes every staff check. Every check fails closed: a role whose PIN is not set, or a server without its session secret, cannot be signed in to (503 `NOT_CONFIGURED`), and a missing, altered, expired or foreign session gives no role. A session holds its expiry and an HMAC-SHA-256 of the role and expiry keyed by a key made from the server's secret and the role's PIN (WebCrypto), compared in constant time: a stolen session lets nobody test PINs without the secret, and changing a PIN or the secret ends every session it signed. Wrong PINs are counted per role and client in the records store, so they hold across server instances: an IPv6 client is counted by its /64 network and an IPv4 address however it is written, and every try is counted before its PIN is compared, so tries sent together cannot pass the limit. After `maximumAttempts` within `attemptWindowMinutes`, that client is refused (429 `TOO_MANY_ATTEMPTS`, with the seconds to wait). PINs shorter than six characters and secrets shorter than 32 are refused when the access is created.

Facilities: `staff-access` (Sign-in with a PIN for the admin and staff roles, signed sessions that prove the role on later requests as a cookie or a bearer token, a limit on wrong PINs, and the checks route handlers make).

## User inputs
`adminPinVariable` and `staffPinVariable` name the environment variables that hold the PINs (`ADMIN_PIN` and `STAFF_PIN`), and `sessionSecretVariable` the one that holds the server's signing secret (`STAFF_SESSION_SECRET`, at least 32 characters, such as the output of `openssl rand -base64 32`); `adminPin`, `staffPin` and `sessionSecret` are the references to those secrets, supplied by the deployment and never by value. `adminCookie` and `staffCookie` name the two cookies; `sessionDays` is how long a sign-in lasts; `maximumAttempts` (5) wrong PINs from one client within `attemptWindowMinutes` (15) hold that client back for the rest of the window.

- `adminPinVariable` (string, environment; optional; default `ADMIN_PIN`)
- `staffPinVariable` (string, environment; optional; default `STAFF_PIN`)
- `sessionSecretVariable` (string, environment; optional; default `STAFF_SESSION_SECRET`)
- `adminCookie` (string, identifier; optional; default `shop_admin`)
- `staffCookie` (string, identifier; optional; default `shop_staff`)
- `sessionDays` (integer; optional; default `7`)
- `maximumAttempts` (integer; optional; default `5`)
- `attemptWindowMinutes` (integer; optional; default `15`)
- `adminPin` (string, identifier; optional; secret, supplied only by reference)
- `staffPin` (string, identifier; optional; secret, supplied only by reference)
- `sessionSecret` (string, identifier; optional; secret, supplied only by reference)

## Artefacts and dependencies
`component.json` maps every `implementation/` source into `components/staff-access/`:

- `implementation/server/access.ts` -> `components/staff-access/server/access.ts`
- `implementation/server/cookies.ts` -> `components/staff-access/server/cookies.ts`
- `implementation/server/index.ts` -> `components/staff-access/server/index.ts`
- `implementation/server/settings.ts` -> `components/staff-access/server/settings.ts`

Dependencies: none.
`tools.lock.json` pins verification tools: node 26.5. Licence: `Apache-2.0` (`LICENCE`, `NOTICE`).

## Provided interfaces
- `interfaces/staff-access.json` defines `staff-access` (com.clodhub/staff-access) version 1.0.0.

## Required interfaces
- `records` (com.clodhub/records) version 1.0.0, supplied by the recipe or application.

## Integration
Create one `createStaffAccess({ records })` per server process, with the shop's records store. A sign-in route passes the posted PIN and the client's address to `login(role, pin, { client })` and answers with the result's `setCookie` as the `Set-Cookie` header (a browser) or its `token` and `expiresAt` (an app), or with its `status` and `code`, and a `Retry-After` header of `retryAfter` seconds for `TOO_MANY_ATTEMPTS`. Every protected route handler calls `requestAllows(request, "admin")` (or `"staff"`) first and answers 401 when it is false: a request with `Authorization: Bearer <token>` is judged by that token alone, any other by its cookies. `requestRole(request)` gives the role itself, for a handler that answers 401 without one and 403 for the wrong one, and `allows(cookieHeader, needed)` judges cookies alone. A page that shows management links asks `role(cookieHeader)` on the server. `logout(role)` gives the header that removes the cookie, and `configured(role)` lets a sign-in page say that a role is closed. The first `login` creates the time-to-live index of the wrong PINs; `ensureIndexes()` creates it at start instead. Server only: no client sees a PIN, the secret or a signing key. The client address is the application's to give: the one the host itself writes (Netlify's `x-nf-client-connection-ip`, Vercel's `x-real-ip`, or the entry the owner's own TLS proxy adds to `X-Forwarded-For`), never an entry the client could have written.

## Visual definition and connected examples
`visual/definition.json` maps its ports to the provided and required interfaces. `visual/examples/connected.json` connects the component to an illustrative application consumer. Both image formats and a text description are retained under `visual/output/`.

## Infrastructure
No service or account. The PINs and the session secret live in the host's environment variables: the hosting provider's dashboard, or the service file on the owner's machine. Wrong PINs are kept in the records store's `staffAttempts` collection for at most `attemptWindowMinutes`, under a digest of the role and the client address (no address is stored).

## Verification
`tests/web.test.ts` checks the settings template and its defaults, sign-in for both roles with the source's cookie attributes and the session's token and end, the token as a bearer token beside the cookie, an admin passing staff checks, wrong, missing and non-text PINs giving one answer, the limit on wrong PINs per role and client (held back with the seconds left, across instances over one store, cleared by a right PIN, no address stored, the time-to-live index, tries sent together counted before their PINs are compared, an IPv6 client counted by its /64 and an IPv4 address however it is written), a role without a PIN or a server without its secret failing closed, short PINs and secrets refused at start, expiry, a shorter `sessionDays` and a changed PIN or secret ending sessions, altered and borrowed cookies, custom names, the cookie helpers and the example routes. The class suite (`classes/staff-access-class/check.mjs`) checks the shared contract on any implementation.

- `node --test tests/web.test.ts` (web, required-local; tools: node 26.5)

## Scenarios and presentation
The owner signs in at the admin page with the admin PIN and manages promotions and gift cards for a week without signing in again. A receptionist signs in on the shop's iPad app with the staff PIN, and the app keeps the bearer token until it ends to look up member vouchers; the admin pages stay closed to her. Someone guessing the staff PIN is held back after five wrong tries for fifteen minutes. A shop installed without an admin PIN shows its sign-in page as closed instead of accepting a default PIN.

## Updates and removal
Patch updates replace the files only. The records store keeps only open windows of wrong PINs, which its time-to-live index removes. A change of PIN signs that role out everywhere, and a change of the session secret signs everyone out. Removing the component removes the sign-in; the cookies expire on their own, and the `staffAttempts` collection can be dropped.
