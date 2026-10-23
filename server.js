// jay-ai dedicated server: web search + full page fetch (incl. JS pages) + danauth email auth.
//
// Multi-file layout (v2.3+): this file is the thin entry — env/boot + routing.
// Logic lives in lib/: config, util, browser, search, fetchPage, crypto,
// mailer, db, auth (incl. profile settings), sync, routes, cleanup.
//
// Endpoints:
//   GET /                                                        health check (plain text)
//   GET /api/search?q=...&count=1..10[&key=...]                  web search
//     -> { results: [{ title, url, snippet }], provider: "ddg-fetch" | "bing-playwright" }
//   GET /api/fetch?url=...&mode=auto|raw|js&maxChars=N[&key=...] full page fetch as text
//     -> { url, finalUrl, title, text, chars, truncated, renderedWith: "raw" | "js" }
//   POST /api/auth/register {username, email, password}          -> { username, pendingVerification } + verify email
//   POST /api/auth/verify {username, code}                       -> { code } (one-time handoff)
//   POST /api/auth/resend {username}                             -> { ok } (always; sends only if needed)
//   POST /api/auth/login {username, password}                    -> { code } | 403 { needsVerification }
//   POST /api/auth/recover {email}                               -> { ok } (always; sends reset code if known)
//   POST /api/auth/reset {email, code, newPassword}              -> { ok, code } (auto handoff)
//   POST /api/auth/exchange {code}                               -> { token, username }
//   GET  /api/auth/me  (Bearer)                                  -> { username, email, verified, createdAt }
//   POST /api/auth/logout (Bearer)                               -> { ok }
//   POST /api/auth/password/change (Bearer) {currentPassword, newPassword} -> { ok }
//   POST /api/auth/email/request (Bearer) {newEmail, currentPassword}      -> { ok }
//   POST /api/auth/email/confirm (Bearer) {code}                            -> { ok, email }
//   POST /api/auth/username/change (Bearer) {newUsername, currentPassword}  -> { ok, username }
//   POST /api/auth/delete (Bearer) {password}                               -> { ok }
//   Full shapes + rules: AUTH_CONTRACT.md.
//   POST /api/auth/check {username}                                    -> { available } (live availability)
//   GET /api/sync/:collection                                     -> { items: [{ id, rev, updatedAt, bytes, deleted? }] }
//   GET /api/sync/:collection/:id                                -> { id, rev, updatedAt, data }
//   PUT /api/sync/:collection/:id { updatedAt, data, baseRev? }   -> { id, rev } (+ conflict flag)
//   DELETE /api/sync/:collection/:id (memories only)             -> { id, rev, deleted }
//   Full shapes + rules: SYNC_CONTRACT.md.
//
// Env (or .env file — see .env.example; process.env wins):
//   PORT            default 3000
//   SEARCH_SECRET   optional shared key (applies to /api/search AND /api/fetch).
//                   client sends ?key= or Authorization: Bearer <key>.
//   ALLOWED_ORIGIN  CORS origin, default "*"
//   AUTH_DB_PATH    SQLite file, default "./danauth.sqlite"
//   AUTH_PEPPER     long random hex (email-code hashes rely on it) — REQUIRED for auth
//   TOKEN_DAYS      token lifetime in days, default 30 (clamped 1..365)
//   SMTP_HOST       default "smtp.zoho.com"   SMTP_PORT default 465 (implicit TLS)
//   SMTP_USER       e.g. "noreply@danjaye.lol"   SMTP_PASS Zoho app password — REQUIRED to send mail
//   MAIL_FROM       default "danauth <noreply@danjaye.lol>"
//   ALLOW_NO_SMTP=1 dev only: log codes to console instead of sending email
//
// Deps: playwright (system chromium via `npx playwright install chromium`) +
// nodemailer (Zoho SMTP). No web framework: plain node:http + global fetch.

const http = require("http");
const config = require("./lib/config");
const db = require("./lib/db");
const mailer = require("./lib/mailer");
const browserLib = require("./lib/browser");
const routes = require("./lib/routes");
const cleanupLib = require("./lib/cleanup");
const util = require("./lib/util");

process.on("SIGTERM", async () => {
  try {
    await browserLib.closeBrowser();
  } catch (e) {}
  process.exit(0);
});

const server = http.createServer(function (req, res) {
  // Never let a handler rejection kill the process (Node's default on
  // unhandled rejection): always answer, so one bad render can't drop the socket.
  routes.handleRequest(req, res).catch(function (err) {
    try {
      util.send(res, 500, { error: "internal: " + String((err && err.message) || err).slice(0, 200) });
    } catch (e2) {
      try { res.destroy(); } catch (e3) {}
    }
  });
});

db.openAuthDb();
if (mailer.smtpReady()) {
  mailer.getMailer().verify().then(
    function () { console.log("danauth smtp ok (" + config.SMTP_HOST + ":" + config.SMTP_PORT + " as " + config.SMTP_USER + ")"); },
    function (err) { console.warn("danauth smtp verify failed (will retry per send): " + String((err && err.message) || err).slice(0, 160)); }
  );
} else if (!config.ALLOW_NO_SMTP) {
  console.warn("danauth email NOT configured (set SMTP_USER/SMTP_PASS in .env, or ALLOW_NO_SMTP=1 for dev) — register/recover will answer 503 until configured.");
}
if (!config.AUTH_PEPPER) console.warn("danauth AUTH_PEPPER is empty — set a long random value in .env (email-code hashes rely on it).");
const __cleanupTimer = setInterval(cleanupLib.cleanupAuth, 10 * 60 * 1000);
if (__cleanupTimer.unref) __cleanupTimer.unref();

server.listen(config.PORT, function () {
  console.log("jay-ai server on :" + config.PORT);
});
