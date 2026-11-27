# Staff access instructions

## For the agent
Select this component for the staff-access slot of every web shop. Leave the variable and cookie names at their defaults unless another application on the same domain uses them. Set `adminPin`, `staffPin` and `sessionSecret` from the recipe's PIN and signing secret reference questions, and leave `staffPin` unset when the shop has no staff role (staff checks then pass for the admin only). The deployment must expose the referenced secrets under the environment variable names `adminPinVariable`, `staffPinVariable` and `sessionSecretVariable` give. Connect `records` to the shop's records store, and the provided `staff-access` to the application.

- Select package `pkg:clod/com.clodhub/staff-access` version `0.2.0`.
- Settings to configure:
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
- Connect the provided `staff-access` (com.clodhub/staff-access 1.0.0) to the consumer that needs it.
- Supply `records` (com.clodhub/records 1.0.0) from the component that provides it.
- Secrets are given by reference (`secretRef`) only, never by value.

## For the developer
Supply the PINs and the session secret as environment variables (`ADMIN_PIN`, `STAFF_PIN` and `STAFF_SESSION_SECRET` by default) in the host's settings, never in the repository. A PIN needs at least 6 characters; give the admin PIN at least 12. Make the secret with `openssl rand -base64 32`. Pass `secure: false` only when serving over http://localhost. Give `login` the client address the host itself writes (Netlify: `x-nf-client-connection-ip`; Vercel: `x-real-ip`; your own TLS proxy: the entry it adds to `X-Forwarded-For`, with the application reachable only through that proxy), never the first `X-Forwarded-For` entry, which any client can write; IPv6 addresses are counted by their /64. To check: sign in on the admin page, open a protected page, then change the PIN and see the session end.

## How to check
From the component directory:

- `node --test tests/web.test.ts` (web, required-local; tools: node 26.5)
- `python3 -m clod review <digest> --store STORE --policy POLICY --trusted --allow-network` runs the packaged checks.
