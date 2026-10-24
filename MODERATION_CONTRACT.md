# jay-ai trust & safety — MODERATION_CONTRACT (v2.5)

Goal: detect abusive content, attribute it, and let a human admin review and
ban. The scanner is heuristic and FLAG-ONLY: it never blocks, throttles, or
bans. A person (currently just the box owner) decides every ban.

## What is scanned

- `PUT /api/sync/chats/:id` — user-role messages only (last 25 user messages,
  capped at `MOD_SCAN_MAXCHARS` chars). Assistant messages are the AI's own
  output, not user conduct. Memories/settings blobs are private files and are
  NEVER scanned.
- A score at/over `MOD_FLAG_THRESHOLD` (default 35) writes one row to
  `mod_flags` with: user, IP, /24 (or /64) range, chat id, per-category
  scores, and a ~160-char excerpt around the strongest hit. The sync response
  is unaffected — scanning cannot fail or slow down sync (bounded input,
  wrapped in try/catch).

## Categories (heuristic wordlists, `lib/moderate.js` WORDLISTS)

sexual (incl. child-safety patterns weighted to always flag), hate,
violent (incl. school-violence and self-harm patterns for review/care),
spam/scam. Expect false positives (games, romance RP, medical talk) — that is
what the review queue is for. Tune via `MOD_FLAG_THRESHOLD` env (1-100).

## Enforcement

On every `/api/auth/*` (register/login/exchange/me + all Bearer endpoints)
and `/api/sync/*` request the box checks, in order: user id → exact IP →
network range, skipping revoked/expired bans. A hit returns:

`403 { "banned": true, "reason": "<admin-written reason>" }`

The client must show `You are banned: <reason>` and lock features. Banned
users cannot log in, register from a banned IP, exchange codes, or sync.
Creating a user ban revokes all of that user's tokens immediately (instant
kick on every device) and emails the ban notice (best-effort; the ban stands
even if email fails).

Honest limits: IP bans are weak (VPNs) and range bans can hit innocents
(CGNAT, dorms) — user-ID bans are the real lever; IP is a speed bump and
ranges are manual-only. `/api/search` + `/api/fetch` use a shared key, not
user identity, so they are rate-limited only, not ban-gated.

## Admin API (Bearer + `ADMIN_USERNAMES`)

- `GET /api/admin/flags?status=open|dismissed|all&category=&limit=50`
  → `{ items: [{ id, username, user_id, ip, ip_range, chat_id, categories,
  score, excerpt, status, createdAt }] }`
- `POST /api/admin/flags/:id/dismiss` → `{ ok:true }`
- `GET /api/admin/bans` → `{ items: [{ id, target_type, target, user_id,
  reason, created_by, created_at, expires_at, revoked }] }`
- `POST /api/admin/bans { target_type: "user"|"ip"|"range", target, reason, days? }`
  → `{ ok:true, id }`. `target` is a username (resolved to id), an IP, or a
  `a.b.c.d/24` range. `reason` is REQUIRED (shown to the banned user).
  `days` optional expiry. Banning a username in `ADMIN_USERNAMES` is refused.
- `POST /api/admin/bans/:id/revoke` → `{ ok:true }`
- Non-admins get plain `403 { error:"forbidden" }` (never the banned shape).

## Email

Ban notices reuse the Zoho SMTP mailer: subject "Your danauth account has
been banned", body states the reason, the lockout scope, and that replying
appeals. Appeals land in the mailbox — no separate workflow v1.

## Setup

1. Add to `.env`: `ADMIN_USERNAMES=danjaye` (lowercase, comma-separated).
2. Deploy v2.5. Tables create themselves on boot (`mod_flags`, `mod_bans`).
3. In the generator (signed in as the admin user), Settings → Moderation.
4. Optional: `TRUST_PROXY=1` behind a reverse proxy, `MOD_FLAG_THRESHOLD`.

## Data retention

Flags live until dismissed (kept as dismissed for audit); bans live until
revoked/expired. Deleting a user (`ON DELETE CASCADE`) wipes their flags and
nulls their ban rows' user_id (target text kept for audit).
