# jay-ai server API contract — danauth email auth (v2, IMPLEMENTED)

Base: `https://jayai.danjaye.lol`. All JSON. Errors: `{ "error": "..." }`.
Server working copy: `src/server/server.js` in the app generator (and this folder).

## Live now (unchanged — do not change shapes)

- `GET /api/search?q=...&count=1..10[&key=...]`
  → `{ results: [{ title, url, snippet }], provider }`
- `GET /api/fetch?url=...&mode=auto|raw|js&maxChars=N[&key=...]`
  → `{ url, finalUrl, title, text, chars, truncated, renderedWith }`
- CORS `*`, `Authorization` header allowed. Shared 30 req/min per IP.
  Key via `?key=` or `Authorization: Bearer ...` (only enforced if the server
  operator sets `SEARCH_SECRET`).

## Auth endpoints (v2 email flow — IMPLEMENTED)

The login generator holds ZERO secrets: only form POSTs to these endpoints.
Never log, cache, or persist passwords/codes/tokens beyond the immediate flow.

- `POST /api/auth/register` `{ username, email, password }`
  → `200 { username, pendingVerification: true }` + 6-digit verify email sent.
  → `400 { error }` on bad shape; `409 { error: "username taken" }` /
  `{ error: "email already registered" }`; `503` if email is down.
- `POST /api/auth/verify` `{ username, code }`
  → `200 { code }` (one-time handoff code, marks email verified).
  → `401 { error }` on bad/expired/over-attempted code.
- `POST /api/auth/resend` `{ username }`
  → always `200 { ok: true }` (sends a fresh code only if an unverified
  account with that username exists — no enumeration).
- `POST /api/auth/login` `{ username, password }`
  → `200 { code }`; `401 { error: "invalid credentials" }` (generic);
  `403 { error: "email not verified", needsVerification: true }` when the
  password is right but the email isn't verified yet (a fresh code is sent).
- `POST /api/auth/recover` `{ email }`
  → always `200 { ok: true }` (sends a reset code only if the email exists).
- `POST /api/auth/reset` `{ email, code, newPassword }`
  → `200 { ok: true, code }` (password set + immediate handoff code).
  → `401 { error }` on bad code; `400` on bad password shape.
- `POST /api/auth/exchange` `{ code }`
  → `200 { token, username }`; `401`/`410 { error }` on bad/expired/used code.
  Codes are single-use, ~60s expiry.
- `GET /api/auth/me` (`Authorization: Bearer <token>`)
  → `200 { username, email, createdAt }`; `401` on bad token.
- `POST /api/auth/logout` (Bearer) → `200 { ok: true }` (revokes token).

Rules (enforced server-side; mirror client-side for UX):
- username: 3–20 chars, `a-z 0-9 _ -` (lowercase).
- password: minimum 10 chars, maximum 512. Scrypt-hashed, never stored plain.
- email: trimmed + lowercased, basic RFC shape check.
- verify/reset codes: 6 digits, 10-min expiry, max 5 attempts, peppered hash
  at rest, single-use (a new code invalidates the previous one).
- login codes: opaque 256-bit, single-use, ~60s expiry.
- tokens: opaque 256-bit, Bearer, `TOKEN_DAYS` lifetime (default 30), revocable.
- rate limits: register 5/hr per IP; login 10/min per IP AND per username +
  15-min cool-down after 10 fails; verify/reset/exchange 30/min per IP;
  recover 10/hr per IP + 5/hr per email; resend 5/hr per username+IP.

## Login → app handoff flow (v2)

1. App links to the login generator (fixed app URL constant).
2. Register → user checks email for the 6-digit code → verify screen →
   one-time `code`. Login (verified) → `code` directly. Login (unverified)
   → resends code, client shows the verify screen. Recover → email code →
   reset screen (email + code + new password) → one-time `code`.
3. Login page redirects to `<app-url>#code=<code>` — fragment, NOT query
   (fragments never reach any server, keeping the code out of logs).
4. App boot: if `#code=` present → `POST /api/auth/exchange` → store token →
   `history.replaceState` to wipe the fragment → `GET /api/auth/me`.
5. App stores: `localStorage["jay-ai-auth-token"]`,
   `localStorage["jay-ai-username"]`.

## Screens the login generator needs

login (username → password) · register · verify-code (shared:
registration + login-unverified) · recover-email · reset-new-password ·
authorize (handoff). The verify-code screen serves both flows.
