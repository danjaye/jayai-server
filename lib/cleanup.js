// Periodic cleanup: expired codes/tokens + pruned rate-limit maps.
// (Also prunes the shared search/fetch `hits` map, which was previously unbounded.)
const db = require("./db");
const util = require("./util");
const config = require("./config");

function cleanupAuth() {
  try {
    const authDb = db.getDb();
    if (authDb) {
      const now = Date.now();
      authDb.prepare("DELETE FROM login_codes WHERE expires_at < ?").run(now);
      authDb.prepare("DELETE FROM email_codes WHERE expires_at < ?").run(now);
      authDb.prepare("DELETE FROM tokens WHERE expires_at < ?").run(now);
      authDb.prepare("DELETE FROM blobs WHERE deleted=1 AND updated_at < ?").run(now - config.TOMBSTONE_GC_MS);
      // Pending email changes: drop expired rows and consumed rows older than an hour.
      try {
        authDb.prepare("DELETE FROM email_changes WHERE expires_at < ?").run(now);
        authDb.prepare("DELETE FROM email_changes WHERE used=1 AND created_at < ?").run(now - 3600000);
      } catch (e) { /* table exists since v2.3; ignore on older DBs mid-migration */ }
    }
    util.pruneLimiters(Date.now());
    util.pruneHits(Date.now());
  } catch (e) { console.warn("cleanup:", String((e && e.message) || e).slice(0, 120)); }
}

module.exports = { cleanupAuth };
