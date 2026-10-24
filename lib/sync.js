// jay-ai cross-device sync (v1 + v8 server-authoritative; contract: SYNC_CONTRACT.md)
// Blob sync for chats / memories / settings behind the existing Bearer tokens.
// The server is the authority (ChatGPT/Claude-style): per-blob revs, server-assigned
// timestamps, baseRev conflict flags, last-write-wins. Deletes propagate via tombstones.
// Merge rules themselves run client-side. Strict per-user isolation on every query.
const config = require("./config");
const util = require("./util");
const db = require("./db");

const SYNC_COLLECTIONS = {
  chats: { maxBytes: 5 * 1024 * 1024 },
  memories: { maxBytes: 200 * 1024 },
  settings: { maxBytes: 100 * 1024 },
};
const SYNC_ID_RE = /^[A-Za-z0-9_-]{1,128}$/;
const rlSyncRead = util.makeLimiter(), rlSyncWrite = util.makeLimiter();

function parseSyncPath(pathname) {
  const parts = pathname.split("/").filter(function (s) { return s.length; });
  // ["api","sync"] | ["api","sync",collection] | ["api","sync",collection,id]
  if (parts.length < 2 || parts[0] !== "api" || parts[1] !== "sync") return null;
  if (parts.length === 2) return { collection: null, id: null };
  if (parts.length === 3) return { collection: parts[2], id: null };
  let id;
  try { id = decodeURIComponent(parts.slice(3).join("/")); } catch (e) { return { collection: parts[2], id: "" }; }
  return { collection: parts[2], id: id };
}

async function handleSync(req, res, url) {
  try {
    const u = db.getBearerUser(req);
    if (!u) return util.send(res, 401, { error: "unauthorized" });
    const p = parseSyncPath(url.pathname);
    if (!p || !(p.collection in SYNC_COLLECTIONS)) return util.send(res, 404, { error: "unknown collection" });
    if (p.id !== null && !SYNC_ID_RE.test(p.id)) return util.send(res, 400, { error: "bad id" });
    if (p.collection === "settings" && p.id !== null && p.id !== "main") {
      return util.send(res, 400, { error: 'settings id must be "main"' });
    }
    if (req.method === "GET" && p.id === null) {
      if (!util.allow(rlSyncRead, "sr:" + u.id, 60, 60000)) return util.send(res, 429, { error: "rate limited" });
      const rows = db.getDb().prepare(
        "SELECT blob_id AS id, rev, updated_at AS updatedAt, bytes, deleted FROM blobs " +
        "WHERE user_id=? AND collection=? ORDER BY blob_id").all(u.id, p.collection);
      return util.send(res, 200, { items: rows.map(function (r) {
        const it = { id: r.id, rev: r.rev, updatedAt: r.updatedAt, bytes: r.bytes };
        if (r.deleted) it.deleted = true;
        return it;
      }) });
    }
    if (req.method === "GET") {
      if (!util.allow(rlSyncRead, "sr:" + u.id, 60, 60000)) return util.send(res, 429, { error: "rate limited" });
      const row = db.getDb().prepare("SELECT * FROM blobs WHERE user_id=? AND collection=? AND blob_id=?")
        .get(u.id, p.collection, p.id);
      if (!row) return util.send(res, 404, { error: "not found" });
      let data;
      try { data = JSON.parse(row.data); } catch (e) { return util.send(res, 500, { error: "internal" }); }
      const out = { id: row.blob_id, rev: row.rev, updatedAt: row.updated_at, data: data };
      if (row.deleted) out.deleted = true;
      return util.send(res, 200, out);
    }
    if (req.method === "PUT" && p.id !== null) {
      if (!util.allow(rlSyncWrite, "sw:" + u.id, 20, 60000)) return util.send(res, 429, { error: "rate limited" });
      const cap = SYNC_COLLECTIONS[p.collection].maxBytes;
      const body = await util.readJsonBody(req, cap + 65536);
      // v8: client-sent updatedAt is still required (back-compat with old
      // clients) but the server clock is authoritative — stored and returned
      // timestamps are server time, so device clock skew can never win LWW.
      if (typeof body.updatedAt !== "number" || !(body.updatedAt > 0)) {
        return util.send(res, 400, { error: "bad updatedAt" });
      }
      if (!body.data || typeof body.data !== "object" || Array.isArray(body.data)) {
        return util.send(res, 400, { error: "bad data" });
      }
      const raw = JSON.stringify(body.data);
      const bytes = Buffer.byteLength(raw);
      if (bytes > cap) return util.send(res, 409, { error: "blob too large" });
      const baseRev = (body.baseRev === undefined || body.baseRev === null) ? null : body.baseRev;
      if (baseRev !== null && (!Number.isInteger(baseRev) || baseRev < 1)) {
        return util.send(res, 400, { error: "bad baseRev" });
      }
      const now = Date.now();
      const out = db.dbTx(function () {
        const existing = db.getDb().prepare("SELECT * FROM blobs WHERE user_id=? AND collection=? AND blob_id=?")
          .get(u.id, p.collection, p.id);
        const oldBytes = existing ? existing.bytes : 0;
        if (db.syncQuotaUsed(u.id) - oldBytes + bytes > config.SYNC_QUOTA_BYTES) throw util.fail(413, "quota exceeded");
        const rev = existing ? existing.rev + 1 : 1;
        if (existing) {
          db.getDb().prepare("UPDATE blobs SET rev=?, updated_at=?, bytes=?, data=?, deleted=0 WHERE id=?")
            .run(rev, now, bytes, raw, existing.id);
        } else {
          db.getDb().prepare("INSERT INTO blobs(user_id, collection, blob_id, rev, updated_at, bytes, data, deleted, created_at) VALUES(?,?,?,?,?,?,?,0,?)")
            .run(u.id, p.collection, p.id, rev, now, bytes, raw, Date.now());
        }
        const result = { id: p.id, rev: rev, updatedAt: now };
        if (baseRev !== null && existing && baseRev !== existing.rev) {
          result.conflict = true;
          result.server = { rev: rev, updatedAt: now };
        }
        return result;
      });
      return util.send(res, 200, out);
    }
    if (req.method === "DELETE" && p.id !== null) {
      if (!util.allow(rlSyncWrite, "sw:" + u.id, 20, 60000)) return util.send(res, 429, { error: "rate limited" });
      // v8: chats are tombstoned like memories so deletes propagate to every
      // device. settings is still never deleted by the client.
      if (p.collection !== "memories" && p.collection !== "chats") {
        return util.send(res, 400, { error: "client never deletes " + p.collection });
      }
      const now = Date.now();
      const out = db.dbTx(function () {
        const existing = db.getDb().prepare("SELECT * FROM blobs WHERE user_id=? AND collection=? AND blob_id=?")
          .get(u.id, p.collection, p.id);
        if (!existing) throw util.fail(404, "not found");
        const rev = existing.rev + 1;
        // PUT on a tombstoned id resurrects it (UPDATE path sets deleted=0).
        const tomb = (p.collection === "chats")
          ? JSON.stringify({ deleted: true, updatedAt: now })
          : JSON.stringify({ path: "memories/" + p.id + ".md", deleted: true, updatedAt: now });
        db.getDb().prepare("UPDATE blobs SET rev=?, updated_at=?, bytes=?, data=?, deleted=1 WHERE id=?")
          .run(rev, now, Buffer.byteLength(tomb), tomb, existing.id);
        return { id: p.id, rev: rev, updatedAt: now, deleted: true };
      });
      return util.send(res, 200, out);
    }
    return util.send(res, 405, { error: "method not allowed" });
  } catch (e) {
    return util.send(res, (e && e.status) || 500, {
      error: (e && e.status) ? String(e.message).slice(0, 200) : "internal",
    });
  }
}

module.exports = { handleSync, SYNC_COLLECTIONS };
