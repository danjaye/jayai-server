// SQLite store: users + codes + tokens + blobs (+ pending email changes).
// Single file (AUTH_DB_PATH, WAL mode). All profile/auth/sync rows hang off users(id)
// with ON DELETE CASCADE, so deleting a user wipes their server state.
const crypto = require("crypto");
const config = require("./config");
const util = require("./util");
const cryptoLib = require("./crypto");

let sqliteLib = null;
try { sqliteLib = require("node:sqlite"); } catch (e) { sqliteLib = null; }
let authDb = null;

function openAuthDb() {
  if (!sqliteLib) {
    console.error("FATAL: node:sqlite unavailable. Use Node >= 22 (you have it) and if needed start with `node --experimental-sqlite server.js`.");
    process.exit(1);
  }
  authDb = new sqliteLib.DatabaseSync(config.AUTH_DB_PATH);
  authDb.exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;");
  authDb.exec(
    "CREATE TABLE IF NOT EXISTS users(" +
    "id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE, email TEXT NOT NULL UNIQUE, " +
    "pass_hash TEXT NOT NULL, verified INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL);" +
    "CREATE TABLE IF NOT EXISTS email_codes(" +
    "id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, " +
    "purpose TEXT NOT NULL, code_hash TEXT NOT NULL, expires_at INTEGER NOT NULL, " +
    "attempts INTEGER NOT NULL DEFAULT 0, used INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL);" +
    "CREATE INDEX IF NOT EXISTS idx_email_codes_user ON email_codes(user_id, purpose);" +
    "CREATE TABLE IF NOT EXISTS login_codes(" +
    "id INTEGER PRIMARY KEY, code_hash TEXT NOT NULL UNIQUE, user_id INTEGER NOT NULL " +
    "REFERENCES users(id) ON DELETE CASCADE, expires_at INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0, " +
    "created_at INTEGER NOT NULL);" +
    "CREATE TABLE IF NOT EXISTS tokens(" +
    "id INTEGER PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE, user_id INTEGER NOT NULL " +
    "REFERENCES users(id) ON DELETE CASCADE, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, " +
    "revoked INTEGER NOT NULL DEFAULT 0);" +
    "CREATE TABLE IF NOT EXISTS blobs(" +
    "id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, " +
    "collection TEXT NOT NULL, blob_id TEXT NOT NULL, rev INTEGER NOT NULL DEFAULT 1, " +
    "updated_at INTEGER NOT NULL, bytes INTEGER NOT NULL, data TEXT NOT NULL, " +
    "deleted INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL, " +
    "UNIQUE(user_id, collection, blob_id));" +
    "CREATE INDEX IF NOT EXISTS idx_blobs_user ON blobs(user_id, collection);" +
    // Pending verified-new-email changes (profile settings). One row per user;
    // a new request invalidates the previous one. Same 10-min / 5-attempt /
    // single-use semantics as verify/reset codes.
    "CREATE TABLE IF NOT EXISTS email_changes(" +
    "id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE, " +
    "new_email TEXT NOT NULL, code_hash TEXT NOT NULL, expires_at INTEGER NOT NULL, " +
    "attempts INTEGER NOT NULL DEFAULT 0, used INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL);" +
    "CREATE INDEX IF NOT EXISTS idx_email_changes_user ON email_changes(user_id);"
  );
}

function getDb() { return authDb; }

function dbTx(fn) {
  authDb.exec("BEGIN IMMEDIATE");
  try { const out = fn(); authDb.exec("COMMIT"); return out; }
  catch (e) { try { authDb.exec("ROLLBACK"); } catch (e2) {} throw e; }
}
function dbGetUserByUsername(username) {
  return authDb.prepare("SELECT * FROM users WHERE username=?").get(username) || null;
}
function dbGetUserByEmail(email) {
  return authDb.prepare("SELECT * FROM users WHERE email=?").get(email) || null;
}
function issueEmailCode(userId, purpose) {
  const code = cryptoLib.newEmailCode();
  const now = Date.now();
  dbTx(function () {
    authDb.prepare("UPDATE email_codes SET used=1 WHERE user_id=? AND purpose=? AND used=0").run(userId, purpose);
    authDb.prepare("INSERT INTO email_codes(user_id, purpose, code_hash, expires_at, created_at) VALUES(?,?,?,?,?)")
      .run(userId, purpose, cryptoLib.pepperHash(purpose, code), now + config.EMAIL_CODE_MS, now);
  });
  return code;
}
function checkEmailCode(userId, purpose, code) {
  const row = authDb.prepare("SELECT * FROM email_codes WHERE user_id=? AND purpose=? AND used=0 ORDER BY id DESC LIMIT 1").get(userId, purpose);
  if (!row) return false;
  if (Date.now() > row.expires_at || row.attempts >= config.EMAIL_CODE_MAX_ATTEMPTS) return false;
  authDb.prepare("UPDATE email_codes SET attempts=attempts+1 WHERE id=?").run(row.id);
  const want = Buffer.from(String(row.code_hash), "hex");
  const got = Buffer.from(cryptoLib.pepperHash(purpose, String(code || "")), "hex");
  if (want.length !== got.length || !crypto.timingSafeEqual(want, got)) return false;
  authDb.prepare("UPDATE email_codes SET used=1 WHERE id=?").run(row.id);
  return true;
}
function issueLoginCode(userId) {
  const code = cryptoLib.newOpaque();
  const now = Date.now();
  authDb.prepare("INSERT INTO login_codes(code_hash, user_id, expires_at, created_at) VALUES(?,?,?,?)")
    .run(cryptoLib.sha256hex(code), userId, now + config.LOGIN_CODE_MS, now);
  return code;
}
function consumeLoginCode(code) {
  const h = cryptoLib.sha256hex(String(code || ""));
  return dbTx(function () {
    const row = authDb.prepare("SELECT * FROM login_codes WHERE code_hash=? AND used=0").get(h);
    if (!row) throw util.fail(401, "invalid code");
    authDb.prepare("UPDATE login_codes SET used=1 WHERE id=?").run(row.id);
    if (Date.now() > row.expires_at) throw util.fail(410, "code expired");
    const u = authDb.prepare("SELECT * FROM users WHERE id=?").get(row.user_id);
    if (!u) throw util.fail(401, "invalid code");
    return u;
  });
}
function issueToken(userId) {
  const token = cryptoLib.newOpaque();
  const now = Date.now();
  authDb.prepare("INSERT INTO tokens(token_hash, user_id, created_at, expires_at) VALUES(?,?,?,?)")
    .run(cryptoLib.sha256hex(token), userId, now, now + config.TOKEN_DAYS * 86400 * 1000);
  return token;
}
function bearerTokenFromHeader(req) {
  try {
    const h = req.headers.authorization || "";
    const m = /^Bearer (.+)$/.exec(h);
    return m ? m[1].trim() : null;
  } catch (e) { return null; }
}
function getBearerUser(req) {
  try {
    const token = bearerTokenFromHeader(req);
    if (!token) return null;
    return authDb.prepare(
      "SELECT u.* FROM tokens t JOIN users u ON u.id=t.user_id " +
      "WHERE t.token_hash=? AND t.revoked=0 AND t.expires_at>?").get(cryptoLib.sha256hex(token), Date.now()) || null;
  } catch (e) { return null; }
}
function revokeOtherTokens(userId, keepToken) {
  authDb.prepare("UPDATE tokens SET revoked=1 WHERE user_id=? AND token_hash != ?")
    .run(userId, cryptoLib.sha256hex(String(keepToken || "")));
}

// --- pending email-change helpers (profile settings) ---
function issueEmailChangeCode(userId, newEmail) {
  const code = cryptoLib.newEmailCode();
  const now = Date.now();
  dbTx(function () {
    authDb.prepare("DELETE FROM email_changes WHERE user_id=?").run(userId);
    authDb.prepare("INSERT INTO email_changes(user_id, new_email, code_hash, expires_at, created_at) VALUES(?,?,?,?,?)")
      .run(userId, newEmail, cryptoLib.pepperHash("email_change", code), now + config.EMAIL_CODE_MS, now);
  });
  return code;
}
function getPendingEmailChange(userId) {
  return authDb.prepare("SELECT * FROM email_changes WHERE user_id=? AND used=0").get(userId) || null;
}
// Returns the confirmed new_email on success, or null on bad/expired/over-attempted code.
// Marks the row used (single-use); the caller swaps users.email + verified in the same flow.
function checkEmailChangeCode(userId, code) {
  const row = getPendingEmailChange(userId);
  if (!row) return null;
  if (Date.now() > row.expires_at || row.attempts >= config.EMAIL_CODE_MAX_ATTEMPTS) return null;
  authDb.prepare("UPDATE email_changes SET attempts=attempts+1 WHERE id=?").run(row.id);
  const want = Buffer.from(String(row.code_hash), "hex");
  const got = Buffer.from(cryptoLib.pepperHash("email_change", String(code || "")), "hex");
  const ok = want.length === got.length && crypto.timingSafeEqual(want, got);
  if (!ok) return null;
  authDb.prepare("UPDATE email_changes SET used=1 WHERE id=?").run(row.id);
  return row.new_email;
}

function syncQuotaUsed(userId) {
  const row = authDb.prepare("SELECT COALESCE(SUM(bytes),0) AS total FROM blobs WHERE user_id=?").get(userId);
  return (row && row.total) || 0;
}

module.exports = {
  openAuthDb, getDb, dbTx,
  dbGetUserByUsername, dbGetUserByEmail,
  issueEmailCode, checkEmailCode, issueLoginCode, consumeLoginCode,
  issueToken, bearerTokenFromHeader, getBearerUser, revokeOtherTokens,
  issueEmailChangeCode, getPendingEmailChange, checkEmailChangeCode,
  syncQuotaUsed,
};
