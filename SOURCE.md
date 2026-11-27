# Source mapping

Reference revision: `219d7dc979278f850fe0efd83c5e11eee26c3217` of `george-mcintyre/totalsculpt` (the totalsculpt.com web monorepo). Paths below are relative to that repository's root.

The source checks two PINs in about a dozen places. This component keeps the two roles and the cookie sign-in in one implementation.

- `implementation/server/access.ts` <-
  - the admin sign-in that refuses to mint a cookie without a configured PIN (503) and answers a wrong PIN with 401: `web/apps/beauty-center/src/app/api/promotions/auth/route.ts:11-36`; its status check: `:38-51`;
  - the staff sign-in and status check: `web/apps/beauty-center/src/app/api/auth/route.ts:1-40`;
  - the admin check shared by the gift card and schedule routes: `web/apps/beauty-center/src/lib/admin-auth.ts:12-24`, used at `web/apps/beauty-center/src/app/api/gift-cards/admin-create/route.ts:22` and `web/apps/beauty-center/src/app/api/schedule/route.ts:7`;
  - the per-route copies of the admin check: `web/apps/beauty-center/src/app/api/promotions/route.ts:21-28`, `web/apps/beauty-center/src/app/api/special-pricing/route.ts:7-14`, `special-pricing/inscribe/route.ts:7-14`, `special-pricing/approve/route.ts:7-14`, `special-pricing/vouchers/route.ts:7-14`, `special-pricing/de-inscribe/route.ts:6-13`, `special-pricing/resend/route.ts:6-13`, `special-pricing/resend-all/route.ts:6-13`;
  - the one check that accepted either cookie, which becomes "an admin passes every staff check": `web/apps/beauty-center/src/app/api/special-pricing/lookup/route.ts:4-22`;
  - the header that shows the management links only to a signed-in admin, which becomes `role(cookieHeader)`: `web/apps/beauty-center/src/app/[locale]/page-header.tsx:16-49`.
  - Generalised: one implementation for both roles; the environment variable names, cookie names and session length are settings (the source's were `PROMO_PIN`, `STAFF_PIN`, `ts_promo_auth`, `ts_staff_auth` and seven days); the cookie attributes are the source's (HttpOnly, SameSite Lax, path /, Secure unless the caller serves http://localhost).
  - Also: a role without a PIN, or a server without its session secret, cannot be signed in to and accepts no session. The cookie is the expiry and an HMAC-SHA-256 of the role and the expiry keyed by a key made from the server's secret and the PIN (WebCrypto), so it ends after `sessionDays` and when the PIN or the secret changes. Comparisons are constant-time, and PINs are compared through their SHA-256 digests.
  - Also: the session as a bearer token for the shop's apps (`requestRole`, `requestAllows`; the website's API adapter read it before), the session's end in the sign-in result, the limit on wrong PINs per role and client address kept in the records store's `staffAttempts` collection with a time-to-live index, and PINs under six characters and secrets under 32 refused at start.
  - Left behind: the JSON bodies of the source's routes (`{ success: true }`, `{ error: 'Invalid PIN' }`), which the application writes from the result.
- `implementation/server/cookies.ts` <- the cookie reading and writing that Next.js did for the source (`request.cookies.get` and `response.cookies.set` in the routes above). New code, so the component works on any server with a Cookie header.
- `implementation/server/settings.ts`: new; the settings template clod renders at install.
- `implementation/server/index.ts`: new; the entry module.
- `tests/web.test.ts`: new; names the source behaviours kept in its test names, and checks the sign-in above.
- `tests/fixtures/records.ts`: a byte copy of memory-records' `implementation/server/engine.ts`, the records store the tests count wrong PINs in.
- `examples/consumer.ts`: new.
