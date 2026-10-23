# jay-ai server API contract — danauth email auth (v2.3, IMPLEMENTED)

Base: `https://jayai.danjaye.lol`. All JSON. Errors: `{ "error": "..." }`.
Server source of truth: https://github.com/danjaye/jayai-server
(working copy in the app generator's `src/server/` may lag — the repo wins).

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
- `POST /api/auth/check` `{ username }`
  → `200 { available: true/false }`; `400` on bad shape; `429` past
  120/min per IP. For live keystroke validation (debounced + aborted
  client-side). No new enumeration: register already reveals taken usernames.
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
  → `200 { username, email, verified, createdAt }`; `401` on bad token.
  (`verified` added in v2.3; old clients ignore it.)
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

## Profile settings endpoints (v2.3 — IMPLEMENTED)

Used by the **jay-ai settings UI**, which holds the Bearer token in
`localStorage["jay-ai-auth-token"]` (the login generator never sees tokens,
so settings live in the app, not in danauth). All endpoints require
`Authorization: Bearer <token>` → `401 { error: "unauthorized" }` on a
bad/expired/revoked token. All JSON, CORS `*`.

- `POST /api/auth/password/change` `{ currentPassword, newPassword }`
  → `200 { ok: true }`. Verifies the current password, sets the new one
  (same 10–512 rule), and revokes all OTHER tokens — this device stays
  signed in, other devices are signed out.
  → `400` bad shape; `401` wrong current password; `429` past 10/hr.
- `POST /api/auth/email/request` `{ newEmail, currentPassword }`
  → `200 { ok: true }` + 6-digit confirmation code sent to the NEW address
  (nothing changes yet; a new request invalidates any previous pending one).
  → `400` bad shape / same-as-current; `401` wrong current password;
  `409 { error: "email already registered" }`; `429` past 5/hr;
  `502/503` if the confirmation email can't be sent.
- `POST /api/auth/email/confirm` `{ code }`
  → `200 { ok: true, email }` (swaps to the pending address, marks the
  account verified — the new address proved deliverable).
  → `400` missing code; `401` bad/expired/over-attempted code (6 digits,
  10 min, 5 attempts, single-use, peppered hash — same as verify/reset);
  `409` if the address got taken meanwhile (pending is dropped);
  `429` past 30/min per IP.
- `POST /api/auth/username/change` `{ newUsername, currentPassword }`
  → `200 { ok: true, username }`. Same `a-z 0-9 _ -` 3–20 rule, must be
  unused. Server keys everything by `user_id`, so blobs/tokens survive —
  but the app MUST update `localStorage["jay-ai-username"]` after this call.
  → `400` bad shape; `401` wrong current password;
  `409 { error: "username taken" }`; `429` past 5/hr.
- `POST /api/auth/delete` `{ password }`
  → `200 { ok: true }`. Verifies the password, then deletes the user row —
  blobs, tokens, codes, and pending email changes cascade (irreversible).
  The client MUST wipe `localStorage` (token + username + sync state) after.
  → `400` missing password; `401` wrong password; `429` past 5/hr.

Rate limits (v2.3 additions): password change 10/hr per user; email request
5/hr per user; email confirm 30/min per IP (shared `verify` bucket);
username change 5/hr per user; account delete 5/hr per user.

Client wiring (jay-ai settings screen):
```js
const API = "https://jayai.danjaye.lol";
const token = localStorage.getItem("jay-ai-auth-token");
const auth = (body) => fetch(API + "/api/auth/password/change", {
  method: "POST",
  headers: { "Content-Type": "application/json", "Authorization": "Bearer " + token },
  body: JSON.stringify(body),
}).then((r) => r.json().then((d) => ({ status: r.status, data: d })));
// same shape for /email/request, /email/confirm, /username/change, /delete.
// After a username change: localStorage.setItem("jay-ai-username", data.username).
// After delete: localStorage.removeItem("jay-ai-auth-token");
//   localStorage.removeItem("jay-ai-username"); (+ sync state) → signed-out UI.
```

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
Profile settings live in the APP (jay-ai), not here — see above.
