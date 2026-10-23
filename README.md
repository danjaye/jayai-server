# jay-ai dedicated server

Working copy of what runs at `https://jayai.danjaye.lol`. `server.js` is the
prettified source of truth — never edit a minified one-liner directly. When a
one-line deploy file is needed, minify this file (e.g. `npx esbuild
server.js --minify > server.one-line.js`) and send that separately.

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
- `POST|GET /api/auth/*` — danauth email auth (v2). Full shapes, rules, and
  the login→app handoff flow: see `AUTH_CONTRACT.md`.

## Setup (first time on the box)

```bash
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
PORT=3000 SEARCH_SECRET=... ALLOWED_ORIGIN=* node server.js
```

(`.env` in the working dir covers all of the above; explicit env vars win.)
If Node complains that `node:sqlite` needs `--experimental-sqlite`, start
with `node --experimental-sqlite server.js` instead — harmless on versions
where the flag is no longer needed. Existing deploy keeps working unchanged:
`/api/search` behavior is identical, and old clients without `/api/fetch`
fall back to `superFetch`.

Auth storage is a single SQLite file (`AUTH_DB_PATH`, default
`./danauth.sqlite`, WAL mode). Back it up like any database; tokens and
codes are hashed, passwords are scrypt-hashed.

## Smoke tests (run from any machine; replace BASE + values)

```bash
BASE=https://jayai.danjaye.lol
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
