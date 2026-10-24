// danauth email auth (v2 email flow + v2.3 profile settings).
// Users + codes + tokens in SQLite. Email via Zoho SMTP.
// Secrets ONLY from env/.env — never in code, logs, or responses.
const config = require("./config");
const util = require("./util");
const cryptoLib = require("./crypto");
const db = require("./db");
const mailer = require("./mailer");
const moderateLib = require("./moderate");

// --- tiny fixed-window rate limiters (in-memory; pruned by lib/cleanup.js) ---
const rlLoginIp = util.makeLimiter(), rlLoginUser = util.makeLimiter(), rlLoginFail = util.makeLimiter();
const rlRegister = util.makeLimiter(), rlVerify = util.makeLimiter(), rlExchange = util.makeLimiter();
const rlRecoverIp = util.makeLimiter(), rlRecoverEmail = util.makeLimiter(), rlResend = util.makeLimiter();
const rlCheck = util.makeLimiter();
// Profile settings (all Bearer-authed): per-user buckets so one account can't
// starve others, plus a shared IP bucket on the code-confirm step.
const rlProfilePw = util.makeLimiter();
const rlProfileEmailReq = util.makeLimiter();
const rlProfileUser = util.makeLimiter();
const rlProfileDelete = util.makeLimiter();

function noteLoginFail(username) { util.allow(rlLoginFail, "f:" + username, Infinity, 15 * 60 * 1000); }
function loginFailCount(username) {
  const now = Date.now();
  return (rlLoginFail.get("f:" + username) || []).filter(function (t) { return now - t < 15 * 60 * 1000; }).length;
}

async function handleAuth(req, res, url) {
  try {
    const p = url.pathname;
    if (p === "/api/auth/me") {
      if (req.method !== "GET") return util.send(res, 405, { error: "method not allowed" });
      const u = db.getBearerUser(req);
      if (!u) return util.send(res, 401, { error: "unauthorized" });
      const banMe = moderateLib.banCheck(u.id, moderateLib.clientIp(req));
      if (banMe) return moderateLib.bannedRes(res, banMe);
      return util.send(res, 200, {
        username: u.username, email: u.email,
        verified: !!u.verified,
        createdAt: new Date(u.created_at).toISOString(),
        isAdmin: moderateLib.isAdminName(u.username),
      });
    }
    if (p === "/api/auth/logout") {
      if (req.method !== "POST") return util.send(res, 405, { error: "method not allowed" });
      const u = db.getBearerUser(req);
      if (!u) return util.send(res, 401, { error: "unauthorized" });
      const h = req.headers.authorization || "";
      const m = /^Bearer (.+)$/.exec(h);
      if (m) db.getDb().prepare("UPDATE tokens SET revoked=1 WHERE token_hash=?").run(cryptoLib.sha256hex(m[1].trim()));
      return util.send(res, 200, { ok: true });
    }
    if (req.method !== "POST") return util.send(res, 405, { error: "method not allowed" });
    const body = await util.readJsonBody(req);
    if (p === "/api/auth/register") return await authRegister(res, body, req);
    if (p === "/api/auth/verify") return await authVerify(res, body, req);
    if (p === "/api/auth/resend") return await authResend(res, body, req);
    if (p === "/api/auth/login") return await authLogin(res, body, req);
    if (p === "/api/auth/recover") return await authRecover(res, body, req);
    if (p === "/api/auth/reset") return await authReset(res, body, req);
    if (p === "/api/auth/exchange") return await authExchange(res, body, req);
    if (p === "/api/auth/check") return await authCheck(res, body, req);
    // v2.3 profile settings (Bearer; used by the jay-ai settings UI, which
    // holds the token in localStorage — the login generator never sees it).
    if (p === "/api/auth/password/change") return await authPasswordChange(res, body, req);
    if (p === "/api/auth/email/request") return await authEmailRequest(res, body, req);
    if (p === "/api/auth/email/confirm") return await authEmailConfirm(res, body, req);
    if (p === "/api/auth/username/change") return await authUsernameChange(res, body, req);
    if (p === "/api/auth/delete") return await authDelete(res, body, req);
    return util.send(res, 404, { error: "not found" });
  } catch (e) {
    return util.send(res, (e && e.status) || 500, {
      error: (e && e.status) ? String(e.message).slice(0, 200) : "internal",
    });
  }
}

async function authRegister(res, body, req) {
  const ip = req.socket.remoteAddress || "x";
  if (!util.allow(rlRegister, ip, 5, 3600000)) return util.send(res, 429, { error: "too many registrations, try again later" });
  const banIp = moderateLib.banCheck(null, ip);
  if (banIp) return moderateLib.bannedRes(res, banIp);
  const username = String(body.username || "").trim().toLowerCase();
  const email = String(body.email || "").trim().toLowerCase();
  if (!cryptoLib.validUsername(username)) return util.send(res, 400, { error: "bad username (3-20 chars: a-z 0-9 _ -)" });
  if (!cryptoLib.validEmail(email)) return util.send(res, 400, { error: "bad email" });
  if (!cryptoLib.validPassword(body.password)) return util.send(res, 400, { error: "bad password (minimum 10 characters)" });
  if (db.dbGetUserByUsername(username)) return util.send(res, 409, { error: "username taken" });
  if (db.dbGetUserByEmail(email)) return util.send(res, 409, { error: "email already registered" });
  const now = Date.now();
  db.dbTx(function () {
    db.getDb().prepare("INSERT INTO users(username, email, pass_hash, verified, created_at) VALUES(?,?,?,?,?)")
      .run(username, email, cryptoLib.scryptHash(body.password), 0, now);
  });
  const created = db.getDb().prepare("SELECT id FROM users WHERE username=?").get(username);
  const code = db.issueEmailCode(created.id, "verify");
  try { await mailer.sendCodeEmail(email, "verify", code); }
  catch (e) { return util.send(res, (e && e.status) || 502, { error: "could not send verification email" }); }
  return util.send(res, 200, { username, pendingVerification: true });
}

async function authVerify(res, body, req) {
  const ip = req.socket.remoteAddress || "x";
  if (!util.allow(rlVerify, ip, 30, 60000)) return util.send(res, 429, { error: "rate limited" });
  const username = String(body.username || "").trim().toLowerCase();
  const u = db.dbGetUserByUsername(username);
  if (!u || !db.checkEmailCode(u.id, "verify", body.code)) {
    return util.send(res, 401, { error: "invalid or expired code" });
  }
  db.getDb().prepare("UPDATE users SET verified=1 WHERE id=?").run(u.id);
  return util.send(res, 200, { code: db.issueLoginCode(u.id) });
}

async function authCheck(res, body, req) {
  const ip = req.socket.remoteAddress || "x";
  if (!util.allow(rlCheck, ip, 120, 60000)) return util.send(res, 429, { error: "rate limited" });
  const username = String(body.username || "").trim().toLowerCase();
  if (!cryptoLib.validUsername(username)) return util.send(res, 400, { error: "bad username (3-20 chars: a-z 0-9 _ -)" });
  return util.send(res, 200, { available: !db.dbGetUserByUsername(username) });
}

async function authResend(res, body, req) {
  const ip = req.socket.remoteAddress || "x";
  const username = String(body.username || "").trim().toLowerCase();
  if (!util.allow(rlResend, ip + "|" + username, 5, 3600000)) return util.send(res, 429, { error: "rate limited" });
  const u = db.dbGetUserByUsername(username);
  if (u && !u.verified) {
    const code = db.issueEmailCode(u.id, "verify");
    try { await mailer.sendCodeEmail(u.email, "verify", code); } catch (e) { /* still ok:true; verify/login will surface 503 */ }
  }
  return util.send(res, 200, { ok: true });
}

async function authLogin(res, body, req) {
  const ip = req.socket.remoteAddress || "x";
  if (!util.allow(rlLoginIp, ip, 10, 60000)) return util.send(res, 429, { error: "rate limited" });
  const username = String(body.username || "").trim().toLowerCase();
  if (!cryptoLib.validUsername(username)) return util.send(res, 401, { error: "invalid credentials" });
  if (!util.allow(rlLoginUser, "u:" + username, 10, 60000) || loginFailCount(username) >= 10) {
    return util.send(res, 429, { error: "too many attempts, try again later" });
  }
  const u = db.dbGetUserByUsername(username);
  if (u) {
    const banU = moderateLib.banCheck(u.id, ip);
    if (banU) return moderateLib.bannedRes(res, banU);
  }
  const okPw = u ? cryptoLib.scryptVerify(u.pass_hash, body.password) : cryptoLib.scryptVerify(cryptoLib.DUMMY_PASS_HASH, "dummy");
  if (!u || !okPw) { noteLoginFail(username); return util.send(res, 401, { error: "invalid credentials" }); }
  rlLoginFail.delete("f:" + username);
  if (!u.verified) {
    const code = db.issueEmailCode(u.id, "verify");
    try { await mailer.sendCodeEmail(u.email, "verify", code); } catch (e) { /* 403 still tells client to verify; resend surfaces errors */ }
    return util.send(res, 403, { error: "email not verified", needsVerification: true });
  }
  return util.send(res, 200, { code: db.issueLoginCode(u.id) });
}

async function authRecover(res, body, req) {
  const ip = req.socket.remoteAddress || "x";
  const email = String(body.email || "").trim().toLowerCase();
  if (!util.allow(rlRecoverIp, ip, 10, 3600000)) return util.send(res, 429, { error: "rate limited" });
  if (email && cryptoLib.validEmail(email)) {
    if (!util.allow(rlRecoverEmail, email, 5, 3600000)) return util.send(res, 429, { error: "rate limited" });
    const u = db.dbGetUserByEmail(email);
    if (u) {
      const code = db.issueEmailCode(u.id, "reset");
      try { await mailer.sendCodeEmail(email, "reset", code); } catch (e) { /* always ok:true; reset surfaces errors */ }
    }
  }
  return util.send(res, 200, { ok: true }); // never reveal whether the email exists
}

async function authReset(res, body, req) {
  const ip = req.socket.remoteAddress || "x";
  if (!util.allow(rlVerify, ip, 30, 60000)) return util.send(res, 429, { error: "rate limited" });
  const email = String(body.email || "").trim().toLowerCase();
  if (!cryptoLib.validEmail(email)) return util.send(res, 400, { error: "bad email" });
  if (!cryptoLib.validPassword(body.newPassword)) return util.send(res, 400, { error: "bad password (minimum 10 characters)" });
  const u = db.dbGetUserByEmail(email);
  if (!u || !db.checkEmailCode(u.id, "reset", body.code)) {
    return util.send(res, 401, { error: "invalid or expired code" });
  }
  db.getDb().prepare("UPDATE users SET pass_hash=? WHERE id=?").run(cryptoLib.scryptHash(body.newPassword), u.id);
  return util.send(res, 200, { ok: true, code: db.issueLoginCode(u.id) }); // straight into the app
}

async function authExchange(res, body, req) {
  const ip = req.socket.remoteAddress || "x";
  if (!util.allow(rlExchange, ip, 30, 60000)) return util.send(res, 429, { error: "rate limited" });
  if (typeof body.code !== "string" || !body.code) return util.send(res, 400, { error: "missing code" });
  const u = db.consumeLoginCode(body.code);
  const banEx = moderateLib.banCheck(u.id, ip);
  if (banEx) return moderateLib.bannedRes(res, banEx);
  return util.send(res, 200, { token: db.issueToken(u.id), username: u.username });
}

// ---- v2.3 profile settings (all Bearer-authed) ----

function requireUser(req, res) {
  const u = db.getBearerUser(req);
  if (!u) { util.send(res, 401, { error: "unauthorized" }); return null; }
  const ban = moderateLib.banCheck(u.id, moderateLib.clientIp(req));
  if (ban) { moderateLib.bannedRes(res, ban); return null; }
  return u;
}

// POST /api/auth/password/change { currentPassword, newPassword } -> { ok:true }
// Verifies the current password, sets the new one, and revokes all OTHER
// tokens (this device stays signed in; other devices are signed out).
async function authPasswordChange(res, body, req) {
  const u = requireUser(req, res);
  if (!u) return;
  if (!util.allow(rlProfilePw, "pw:" + u.id, 10, 3600000)) return util.send(res, 429, { error: "rate limited" });
  if (typeof body.currentPassword !== "string" || !body.currentPassword) {
    return util.send(res, 400, { error: "missing currentPassword" });
  }
  if (!cryptoLib.validPassword(body.newPassword)) {
    return util.send(res, 400, { error: "bad password (minimum 10 characters)" });
  }
  const fresh = db.dbGetUserByUsername(u.username);
  if (!fresh || !cryptoLib.scryptVerify(fresh.pass_hash, body.currentPassword)) {
    return util.send(res, 401, { error: "invalid current password" });
  }
  db.getDb().prepare("UPDATE users SET pass_hash=? WHERE id=?").run(cryptoLib.scryptHash(body.newPassword), u.id);
  db.revokeOtherTokens(u.id, db.bearerTokenFromHeader(req));
  return util.send(res, 200, { ok: true });
}

// POST /api/auth/email/request { newEmail, currentPassword } -> { ok:true }
// Sends a 6-digit confirmation code to the NEW address (nothing changes yet).
// A new request invalidates any previous pending one.
async function authEmailRequest(res, body, req) {
  const u = requireUser(req, res);
  if (!u) return;
  if (!util.allow(rlProfileEmailReq, "er:" + u.id, 5, 3600000)) return util.send(res, 429, { error: "rate limited" });
  const newEmail = String(body.newEmail || "").trim().toLowerCase();
  if (!cryptoLib.validEmail(newEmail)) return util.send(res, 400, { error: "bad email" });
  if (typeof body.currentPassword !== "string" || !body.currentPassword) {
    return util.send(res, 400, { error: "missing currentPassword" });
  }
  const fresh = db.dbGetUserByUsername(u.username);
  if (!fresh || !cryptoLib.scryptVerify(fresh.pass_hash, body.currentPassword)) {
    return util.send(res, 401, { error: "invalid current password" });
  }
  if (newEmail === fresh.email) return util.send(res, 400, { error: "new email is the same as the current one" });
  if (db.dbGetUserByEmail(newEmail)) return util.send(res, 409, { error: "email already registered" });
  const code = db.issueEmailChangeCode(u.id, newEmail);
  try { await mailer.sendCodeEmail(newEmail, "email_change", code); }
  catch (e) { return util.send(res, (e && e.status) || 502, { error: "could not send confirmation email" }); }
  return util.send(res, 200, { ok: true });
}

// POST /api/auth/email/confirm { code } -> { ok:true, email }
// Swaps users.email to the pending address and marks the account verified
// (the new address proved deliverable by receiving the code).
async function authEmailConfirm(res, body, req) {
  const u = requireUser(req, res);
  if (!u) return;
  const ip = req.socket.remoteAddress || "x";
  if (!util.allow(rlVerify, ip, 30, 60000)) return util.send(res, 429, { error: "rate limited" });
  if (typeof body.code !== "string" || !body.code) return util.send(res, 400, { error: "missing code" });
  const pending = db.getPendingEmailChange(u.id);
  if (!pending) return util.send(res, 401, { error: "invalid or expired code" });
  if (db.dbGetUserByEmail(pending.new_email)) {
    db.getDb().prepare("DELETE FROM email_changes WHERE user_id=?").run(u.id);
    return util.send(res, 409, { error: "email already registered" });
  }
  const confirmed = db.checkEmailChangeCode(u.id, body.code);
  if (!confirmed) return util.send(res, 401, { error: "invalid or expired code" });
  db.dbTx(function () {
    db.getDb().prepare("UPDATE users SET email=?, verified=1 WHERE id=?").run(confirmed, u.id);
    db.getDb().prepare("DELETE FROM email_changes WHERE user_id=?").run(u.id);
  });
  return util.send(res, 200, { ok: true, email: confirmed });
}

// POST /api/auth/username/change { newUsername, currentPassword } -> { ok:true, username }
// Identity change only (server keys everything by user_id, so blobs/tokens
// survive). The app must update its stored username after this call.
async function authUsernameChange(res, body, req) {
  const u = requireUser(req, res);
  if (!u) return;
  if (!util.allow(rlProfileUser, "un:" + u.id, 5, 3600000)) return util.send(res, 429, { error: "rate limited" });
  const newUsername = String(body.newUsername || "").trim().toLowerCase();
  if (!cryptoLib.validUsername(newUsername)) return util.send(res, 400, { error: "bad username (3-20 chars: a-z 0-9 _ -)" });
  if (typeof body.currentPassword !== "string" || !body.currentPassword) {
    return util.send(res, 400, { error: "missing currentPassword" });
  }
  const fresh = db.dbGetUserByUsername(u.username);
  if (!fresh || !cryptoLib.scryptVerify(fresh.pass_hash, body.currentPassword)) {
    return util.send(res, 401, { error: "invalid current password" });
  }
  if (newUsername === fresh.username) return util.send(res, 200, { ok: true, username: fresh.username });
  if (db.dbGetUserByUsername(newUsername)) return util.send(res, 409, { error: "username taken" });
  db.getDb().prepare("UPDATE users SET username=? WHERE id=?").run(newUsername, u.id);
  return util.send(res, 200, { ok: true, username: newUsername });
}

// POST /api/auth/delete { password } -> { ok:true }
// Irreversible: deletes the user row; blobs/tokens/codes/pending email
// changes cascade. The client must wipe localStorage (token + username +
// sync state) after this call.
async function authDelete(res, body, req) {
  const u = requireUser(req, res);
  if (!u) return;
  if (!util.allow(rlProfileDelete, "del:" + u.id, 5, 3600000)) return util.send(res, 429, { error: "rate limited" });
  if (typeof body.password !== "string" || !body.password) {
    return util.send(res, 400, { error: "missing password" });
  }
  const fresh = db.dbGetUserByUsername(u.username);
  if (!fresh || !cryptoLib.scryptVerify(fresh.pass_hash, body.password)) {
    return util.send(res, 401, { error: "invalid password" });
  }
  db.getDb().prepare("DELETE FROM users WHERE id=?").run(u.id);
  return util.send(res, 200, { ok: true });
}

module.exports = { handleAuth };
