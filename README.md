# jay-ai dedicated server

Source of truth: https://github.com/danjaye/jayai-server (clone it on the
box; deploy with `git pull` + restart — no build step).
Live at `https://jayai.danjaye.lol`. Entry: `server.js` (thin boot +
routing); logic lives in `lib/` (`config`, `util`, `browser`, `search`,
`fetchPage`, `crypto`, `mailer`, `db`, `auth`, `sync`, `routes`, `cleanup`).
When a one-line deploy file is needed, bundle the entry (e.g.
`npx esbuild server.js --bundle --platform=node --minify > server.one-line.js`)
and send that separately — never edit a one-liner directly.

## Endpoints

- `GET /` — health check (plain text).
- `GET /api/search?q=...&count=1..10[&key=...]` — web search.
  `{ results: [{ title, url, snippet }], provider }`. DDG static first,
  headless-Bing fallback (same as before).
- `GET /api/fetch?url=...&mode=auto|raw|js&maxChars=N[&key=...]` — **new.**
  Full page fetch as clean text, JS-rendered when needed.
  `{ url, finalUrl, title, text, chars, truncated, renderedWith }`.
  - `mode=auto` (default): static fetch first, headless Chromium only when the
    HTML looks like an unhydrated JS shell (thin text / app-mount markers).
  - `mode=raw`: static only. `mode=js`: always render.
  - `maxChars` default 12000, clamped to 500–50000.
- `POST|GET /api/auth/*` — danauth email auth (v2) + profile settings
  (v2.3: password/email/username change, account delete — Bearer-authed,
  for the jay-ai settings UI). Full shapes, rules, and the login→app
  handoff flow: see `AUTH_CONTRACT.md`.
- `GET|PUT|DELETE /api/sync/*` — cross-device blob sync for chats, memories,
  settings (v1). Full shapes, merge rules, caps: see `SYNC_CONTRACT.md`.

## Setup (first time on the box)

```bash
git clone https://github.com/danjaye/jayai-server.git
cd jayai-server
npm install
npx playwright install chromium --with-deps   # needs root for --with-deps
cp .env.example .env   # then fill in AUTH_PEPPER + SMTP_PASS (see below)
```

Generate the pepper (any long random hex — never reuse the SMTP password):

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

`.env` holds the real secrets and is NEVER committed/shared. Real
environment variables override `.env`, so either mechanism works. The server
serves no static files, so `.env` is not reachable over HTTP — still, keep it
`chmod 600` and out of backups/repos.

## Deploy

```bash
cd jayai-server
git pull
npm install   # only needed when package.json changed
node server.js
```

(`.env` in the working dir covers `PORT`/`SEARCH_SECRET`/mail config;
explicit env vars win, e.g. `PORT=3000 node server.js`.)
If Node complains that `node:sqlite` needs `--experimental-sqlite`, start
with `node --experimental-sqlite server.js` instead — harmless on versions
where the flag is no longer needed. Existing deploy keeps working unchanged:
`/api/search` behavior is identical, and old clients without `/api/fetch`
fall back to `superFetch`.

Upgrading to v2.3 from v2.2: just `git pull` + restart. The new
`email_changes` table is created automatically (`CREATE TABLE IF NOT
EXISTS`); no manual DB migration. v2.3 is backward-compatible: old
search/fetch/auth/sync clients see identical shapes (`/api/auth/me` only
gains an additive `verified` field).

Auth storage is a single SQLite file (`AUTH_DB_PATH`, default
`./danauth.sqlite`, WAL mode). Back it up like any database; tokens and
codes are hashed, passwords are scrypt-hashed.

## Smoke tests (run from any machine; replace BASE + values)

```bash
BASE=https://jayai.danjaye.lol
# 0. availability check (used by live keystroke validation + login gate)
curl -s -X POST $BASE/api/auth/check -H 'Content-Type: application/json' \
  -d '{"username":"alice"}'
# 1. register (sends the 6-digit code to the email)
curl -s -X POST $BASE/api/auth/register -H 'Content-Type: application/json' \
  -d '{"username":"alice","email":"alice@example.com","password":"correct-horse-10"}'
# 2. verify (code from the email) -> one-time handoff {code}
curl -s -X POST $BASE/api/auth/verify -H 'Content-Type: application/json' \
  -d '{"username":"alice","code":"123456"}'
# 3. exchange handoff code -> {token, username}
curl -s -X POST $BASE/api/auth/exchange -H 'Content-Type: application/json' \
  -d '{"code":"PASTE_CODE"}'
# 4. me + logout
curl -s $BASE/api/auth/me -H "Authorization: Bearer PASTE_TOKEN"
curl -s -X POST $BASE/api/auth/logout -H "Authorization: Bearer PASTE_TOKEN"
# 5. recovery round-trip
curl -s -X POST $BASE/api/auth/recover -H 'Content-Type: application/json' \
  -d '{"email":"alice@example.com"}'
curl -s -X POST $BASE/api/auth/reset -H 'Content-Type: application/json' \
  -d '{"email":"alice@example.com","code":"123456","newPassword":"new-correct-horse-11"}'
```

To test end-to-end without sending mail, set `ALLOW_NO_SMTP=1` in `.env`
(dev only): email codes are logged to the server console instead of sent.

## Profile settings smoke tests (v2.3; needs a Bearer TOKEN)

```bash
TOKEN=PASTE_TOKEN
# me now includes verified
curl -s $BASE/api/auth/me -H "Authorization: Bearer $TOKEN"
# password change (other devices are signed out, this token stays valid)
curl -s -X POST $BASE/api/auth/password/change -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"currentPassword":"correct-horse-10","newPassword":"new-correct-horse-11"}'
# email change: request (code goes to the NEW address) then confirm
curl -s -X POST $BASE/api/auth/email/request -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"newEmail":"alice-new@example.com","currentPassword":"new-correct-horse-11"}'
curl -s -X POST $BASE/api/auth/email/confirm -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"code":"123456"}'
# username change (update localStorage["jay-ai-username"] afterwards)
curl -s -X POST $BASE/api/auth/username/change -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"newUsername":"alice2","currentPassword":"new-correct-horse-11"}'
# delete account (irreversible; wipe localStorage after)
# curl -s -X POST $BASE/api/auth/delete -H "Authorization: Bearer $TOKEN" \
#   -H 'Content-Type: application/json' \
#   -d '{"password":"new-correct-horse-11"}'
```

## Sync smoke tests (needs a Bearer TOKEN from the auth smoke tests above)

```bash
TOKEN=PASTE_TOKEN
# manifest (empty on a fresh account)
curl -s $BASE/api/sync/chats -H "Authorization: Bearer $TOKEN"
# push a settings blob -> { id: "main", rev: 1 }
curl -s -X PUT $BASE/api/sync/settings/main -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"updatedAt": 1760000000000, "data": {"userName": "Al", "version": 1, "updatedAt": 1760000000000}}'
# blind re-push -> rev bumps, no conflict
curl -s -X PUT $BASE/api/sync/settings/main -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"updatedAt": 1760000000001, "data": {"userName": "Al2", "version": 2, "updatedAt": 1760000000001}}'
# stale baseRev -> still writes, but conflict: true + server rev
curl -s -X PUT $BASE/api/sync/settings/main -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"updatedAt": 1760000000002, "baseRev": 1, "data": {"userName": "Al3", "version": 3, "updatedAt": 1760000000002}}'
# memories round-trip + tombstone
curl -s -X PUT $BASE/api/sync/memories/foo-bar -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"updatedAt": 1760000000000, "data": {"path": "memories/foo-bar.md", "content": "hi", "updatedAt": 1760000000000}}'
curl -s -X DELETE $BASE/api/sync/memories/foo-bar -H "Authorization: Bearer $TOKEN"
# cross-user isolation: a second account's token must see empty manifests
```

## Safety

- SSRF guards: http(s) only, no credentials in URL, literal + DNS-resolved
  IPs checked against private/reserved ranges (10/8, 172.16/12, 192.168/16,
  127/8, 169.254/16, 0/8, ::1, fc00::/7, fe80::/10, v4-mapped). Redirect
  targets re-checked. DNS failures refused.
- 30 req/min per IP (shared search+fetch bucket), 10-min caches (500 entries
  max), 15s static timeout, 5MB download cap, non-text content refused (415).
- Optional shared key via `SEARCH_SECRET` (covers search+fetch). Client
  sends `?key=` or `Authorization: Bearer`.
- Auth: scrypt password hashes; peppered 6-digit email codes (10 min, 5
  attempts, single-use); 60s single-use handoff codes; 30-day revocable
  Bearer tokens; per-IP + per-account rate limits (see AUTH_CONTRACT.md).
  Generic error messages (no user enumeration beyond what register reveals).
  Profile changes require the current password; password change revokes
  other tokens; account delete wipes the whole user row (cascade).

## Troubleshooting

- `mode=js` returns `browser unavailable: Executable doesn't exist ...`:
  install the browser on the box: `npx playwright install chromium --with-deps`
  (needs root for `--with-deps`), then restart the server.
- `FATAL: node:sqlite unavailable` → use Node >= 22 and/or add the
  `--experimental-sqlite` flag (see Deploy).
- `smtp verify failed` at boot → wrong host/port/credentials or blocked
  outbound 465. Check `.env`, Zoho app password, and firewall. Sends are
  retried per request, so fixing config + retry works without a restart…
  except a config change needs a restart to be re-read (restart the server).
- `503 email unavailable` on register/recover → SMTP not configured and
  `ALLOW_NO_SMTP` is off. Expected until `.env` is filled in.
- Any handler error is answered as JSON (500 `internal: ...`), never a dropped
  socket — if a request still gets a connection reset, the process is being
  killed from outside (OOM killer: check `dmesg`, give the box more RAM).

## Client wiring

`src/js/tools.js` `fetchPage` tries this server's `/api/fetch` first
(endpoint override via `localStorage["jay-ai-fetch-endpoint"]`, key via
`localStorage["jay-ai-search-key"]`) and falls back to `superFetch` when the
server is missing/old, denies, or fails. Same tool, same args — a tool
implementation fix, not a new version (see `src/VERSIONING.md`).

Settings UI (jay-ai generator) talks to `/api/auth/*` with the stored
Bearer token — see the `AUTH_CONTRACT.md` "Profile settings" section for
the exact shapes (password/email/username change, delete, and the
`localStorage` updates each one needs).
