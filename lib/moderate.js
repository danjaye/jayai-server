// Trust & safety (v2.5): heuristic content flagging + bans + admin review.
//
// FLAG-ONLY by design: the scanner never blocks, throttles, or bans. A chat
// PUT that scores over threshold writes one row to mod_flags (excerpt +
// categories + score) for human review in the admin portal. A person decides.
//
// Scan scope: chats only (user-role messages). Memories/settings blobs are
// private files and are never scanned. Assistant-role messages are the AI's
// own output, not user conduct, and are never scanned.
//
// Heuristic caveat: wordlists have false positives (TF2 "kill", romance RP,
// medical talk). Thresholds are tunable in config; when in doubt the admin
// dismisses the flag. The scanner interface is one function (scanMessages)
// so an external moderation API can replace the wordlists later without
// touching the pipeline, enforcement, or UI.
const config = require("./config");
const db = require("./db");
const util = require("./util");
const mailer = require("./mailer");

// ---- identity helpers ----

function clientIp(req) {
  try {
    if (config.TRUST_PROXY) {
      const xff = req.headers["x-forwarded-for"] || req.headers["X-Forwarded-For"] || "";
      const first = String(xff).split(",")[0].trim();
      if (first) return normIp(first);
    }
    return normIp((req.socket && req.socket.remoteAddress) || "x");
  } catch (e) { return "x"; }
}
function normIp(ip) {
  ip = String(ip || "").trim();
  if (ip.indexOf("::ffff:") === 0) ip = ip.slice(7);
  return ip || "x";
}
// Coarse network bucket for range bans: /24 (v4) or /64 (v6). Stored on every
// flag so a banned range stays meaningful even for logged-out abuse.
function rangeOf(ip) {
  ip = normIp(ip);
  if (/^\d+\.\d+\.\d+\.\d+$/.test(ip)) return ip.split(".").slice(0, 3).join(".") + ".0/24";
  if (ip.indexOf(":") >= 0) {
    const head = ip.split(":").slice(0, 4).join(":");
    return head + "::/64";
  }
  return ip;
}

// ---- heuristic scanner ----
// [patternSource, weight]. Scores add, capped at 100 per category.
// Weights: ~5 = weak signal alone, 15-25 = strong term, 40+ = extreme
// (a single extreme hit always clears the flag threshold).

var WORDLISTS = {
  sexual: [
    ["\\bporn(ography)?\\b", 12], ["\\bxxx\\b", 12], ["\\bhentai\\b", 12],
    ["\\bnude(s)?\\b", 8], ["\\bexplicit\\s+(pics?|photos?|images?|content)\\b", 15],
    ["\\bnaked\\s+(pics?|photos?|teens?|kids?|girls?|boys?)\\b", 40],
    ["\\bchild\\s*(porn|sex|nude|naked)\\b", 100], ["\\bkiddie\\s*(porn)?\\b", 100],
    ["\\bteen\\s*porn\\b", 100], ["\\bpreteen\\b", 100], ["\\bcp\\b.{0,10}\\b(video|pics?|trade)\\b", 90],
    ["\\b(lolita|shota)\\b", 60], ["\\bincest\\b", 25], ["\\bbestiality\\b", 60],
    ["\\b(ma|ra)pe\\s+(porn|fantasy|roleplay|story)\\b", 40], ["\\bnon-?con\\b", 40],
    ["\\b(erotic|steamy)\\s+(story|roleplay|rp)\\b.{0,40}\\b(child|kid|minor|teen|young)\\b", 90],
    ["\\b(onlyfans|escort)\\b", 10], ["\\bsext(ing)?\\b.{0,30}\\b(minor|child|kid|teen)\\b", 90],
  ],
  hate: [
    ["\\bnigg(er|a)\\b", 40], ["\\bfagg?ot\\b", 35], ["\\bkike\\b", 35],
    ["\\bspic\\b", 30], ["\\bchink\\b", 30], ["\\btranny\\b", 25],
    ["\\bretard(ed)?\\b", 10], ["\\bgas\\s+the\\s+jews\\b", 60],
    ["\\bwhite\\s+power\\b", 40], ["\\bkill\\s+all\\s+(muslims|jews|blacks|gays)\\b", 70],
    ["\\bgo\\s+back\\s+to\\s+(africa|mexico|china)\\b", 30],
  ],
  violent: [
    ["\\bschool\\s+shoot(er|ing)\\b", 100], ["\\bshoot\\s+up\\s+(a|the|my)\\s+school\\b", 100],
    ["\\bhow\\s+to\\s+make\\s+(a\\s+)?bomb\\b", 45], ["\\bpipe\\s+bomb\\b", 45],
    ["\\bmurder\\b", 12], ["\\bmass\\s+murder\\b", 40], ["\\bserial\\s+killer\\b", 15],
    ["\\bkidnap\\b", 15], ["\\btorture\\b", 12], ["\\bbehead\\b", 30],
    ["\\bkill\\s+myself\\b", 25], ["\\bcommit\\s+suicide\\b", 25], ["\\bhow\\s+to\\s+hang\\s+myself\\b", 45],
    ["\\bassassinat(e|ion)\\b", 25], ["\\bhire\\s+(a\\s+)?hitman\\b", 50],
    ["\\bkill\\b", 4], ["\\bgun\\b.{0,20}\\bschool\\b", 30],
  ],
  spam: [
    ["\\bviagra\\b", 18], ["\\bcialis\\b", 18], ["\\bcrypto\\b.{0,30}\\bdouble\\b", 25],
    ["\\bsend\\s+[\\d.]+\\s*(btc|eth)\\b", 30], ["\\bguaranteed\\s+returns\\b", 15],
    ["\\bwork\\s+from\\s+home\\b.{0,30}\\b\\$\\d", 12], ["\\blottery\\s+(winner|claim)\\b", 15],
    ["\\bclick\\s+(here|below).{0,30}http", 8],
  ],
};
var COMPILED = null;
function compiled() {
  if (COMPILED) return COMPILED;
  COMPILED = {};
  for (const cat in WORDLISTS) {
    COMPILED[cat] = WORDLISTS[cat].map(function (e) {
      return { re: new RegExp(e[0], "i"), w: e[1], src: e[0] };
    });
  }
  return COMPILED;
}

// Returns null (clean) or { score, cats, excerpt }. score = top category score.
function scanText(text) {
  text = String(text || "").slice(0, config.MOD_SCAN_MAXCHARS);
  if (!text) return null;
  const lists = compiled();
  const cats = {};
  let best = null;
  for (const cat in lists) {
    let s = 0;
    for (const p of lists[cat]) {
      if (p.re.test(text)) {
        s = Math.min(100, s + p.w);
        if (!best || p.w > best.w) {
          const m = p.re.exec(text);
          best = { w: p.w, idx: m ? m.index : 0, len: m ? m[0].length : 0 };
        }
      }
    }
    if (s > 0) cats[cat] = s;
  }
  let top = 0;
  for (const cat in cats) if (cats[cat] > top) top = cats[cat];
  if (top < config.MOD_FLAG_THRESHOLD) return null;
  let excerpt = text.slice(0, 220);
  if (best) {
    const a = Math.max(0, best.idx - 80), b = Math.min(text.length, best.idx + best.len + 80);
    excerpt = (a > 0 ? "…" : "") + text.slice(a, b) + (b < text.length ? "…" : "");
  }
  return { score: top, cats: cats, excerpt: excerpt };
}

// Scan one synced chat blob. Only user-role messages count (assistant output
// is the AI's, not user conduct). Returns the flag row id or null.
function maybeFlagChat(userId, ip, chatId, data) {
  try {
    const msgs = data && Array.isArray(data.messages) ? data.messages : null;
    if (!msgs || !msgs.length) return null;
    const bits = [];
    for (const m of msgs) {
      if (!m || m.role !== "user") continue;
      const t = typeof m.content === "string" ? m.content : (typeof m.text === "string" ? m.text : "");
      if (t) bits.push(t);
    }
    if (!bits.length) return null;
    const found = scanText(bits.slice(-25).join("\n---\n"));
    if (!found) return null;
    const now = Date.now();
    const r = db.getDb().prepare(
      "INSERT INTO mod_flags(user_id, ip, ip_range, chat_id, categories, score, excerpt, status, created_at) " +
      "VALUES(?,?,?,?,?,?,?,'open',?)"
    ).run(userId, normIp(ip), rangeOf(ip), String(chatId || ""),
      JSON.stringify(found.cats), found.score, found.excerpt.slice(0, 600), now);
    return Number(r.lastInsertRowid) || null;
  } catch (e) { return null; } // scanning must never break sync
}

// ---- bans ----

function activeBanWhere() {
  return "(revoked=0 AND (expires_at IS NULL OR expires_at>?))";
}
// Returns { reason, target } or null. Checks user id, exact IP, then range.
function banCheck(userId, ip) {
  try {
    const now = Date.now();
    const q = "SELECT * FROM mod_bans WHERE target_type=? AND target=? AND " + activeBanWhere() + " ORDER BY id DESC LIMIT 1";
    const byUser = userId ? db.getDb().prepare(q).get("user", String(userId), now) : null;
    if (byUser) return { reason: byUser.reason || "terms violation", target: "user:" + byUser.target };
    const nip = normIp(ip);
    const byIp = db.getDb().prepare(q).get("ip", nip, now);
    if (byIp) return { reason: byIp.reason || "terms violation", target: "ip:" + byIp.target };
    const byRange = db.getDb().prepare(q).get("range", rangeOf(nip), now);
    if (byRange) return { reason: byRange.reason || "terms violation", target: "range:" + byRange.target };
    return null;
  } catch (e) { return null; } // fail open on DB trouble; bans are checked again next request
}
function bannedRes(res, ban) {
  return util.send(res, 403, { banned: true, reason: (ban && ban.reason) || "terms violation" });
}

function isAdminName(username) {
  try {
    return config.ADMIN_USERS.indexOf(String(username || "").toLowerCase()) >= 0;
  } catch (e) { return false; }
}

// ---- admin API ----

async function handleAdmin(req, res, url) {
  try {
    const me = db.getBearerUser(req);
    if (!me || !isAdminName(me.username)) return util.send(res, 403, { error: "forbidden" });
    const parts = url.pathname.split("/").filter(Boolean); // ["api","admin",...]
    // GET /api/admin/flags?status=open&category=&limit=50
    if (req.method === "GET" && parts.length === 3 && parts[2] === "flags") {
      const status = url.searchParams.get("status") || "open";
      const category = url.searchParams.get("category") || "";
      const limit = Math.min(Math.max(parseInt(url.searchParams.get("limit") || "50", 10) || 50, 1), 200);
      let sql = "SELECT f.*, u.username FROM mod_flags f LEFT JOIN users u ON u.id=f.user_id WHERE 1=1";
      const args = [];
      if (status && status !== "all") { sql += " AND f.status=?"; args.push(status); }
      if (category) { sql += " AND f.categories LIKE ?"; args.push("%\"" + category + "\"%"); }
      sql += " ORDER BY f.created_at DESC LIMIT ?";
      args.push(limit);
      const rows = db.getDb().prepare(sql).all(...args);
      return util.send(res, 200, { items: rows.map(flagShape) });
    }
    // POST /api/admin/flags/:id/dismiss
    if (req.method === "POST" && parts.length === 5 && parts[2] === "flags" && parts[4] === "dismiss") {
      const id = parseInt(parts[3], 10);
      if (!id) return util.send(res, 400, { error: "bad id" });
      db.getDb().prepare("UPDATE mod_flags SET status='dismissed' WHERE id=?").run(id);
      return util.send(res, 200, { ok: true });
    }
    // GET /api/admin/bans
    if (req.method === "GET" && parts.length === 3 && parts[2] === "bans") {
      const rows = db.getDb().prepare("SELECT * FROM mod_bans ORDER BY created_at DESC LIMIT 200").all();
      return util.send(res, 200, { items: rows });
    }
    // POST /api/admin/bans { target_type: user|ip|range, target, reason, days? }
    if (req.method === "POST" && parts.length === 3 && parts[2] === "bans") {
      const body = await util.readJsonBody(req);
      const t = String(body.target_type || "");
      const target = String(body.target || "").trim();
      const reason = String(body.reason || "").trim().slice(0, 300);
      if (["user", "ip", "range"].indexOf(t) < 0 || !target) return util.send(res, 400, { error: "bad target" });
      if (!reason) return util.send(res, 400, { error: "reason required" });
      if (t === "user" && isAdminName(target)) return util.send(res, 400, { error: "cannot ban an admin" });
      const days = body.days === undefined || body.days === null ? null : Math.max(1, Math.min(3650, parseInt(body.days, 10) || 0)) || null;
      const now = Date.now();
      let uid = null, email = null;
      if (t === "user") {
        const u = db.dbGetUserByUsername(target.toLowerCase());
        if (!u) return util.send(res, 404, { error: "no such user" });
        uid = u.id; email = u.email;
      }
      const targetNorm = t === "user" ? String(uid) : (t === "range" ? normRangeInput(target) : normIp(target));
      if (!targetNorm) return util.send(res, 400, { error: "bad target" });
      const r = db.getDb().prepare(
        "INSERT INTO mod_bans(target_type, target, user_id, reason, created_by, created_at, expires_at, revoked) VALUES(?,?,?,?,?,?,?,0)"
      ).run(t, targetNorm, uid, reason, me.username, now, days ? now + days * 86400000 : null);
      // Immediate kick: revoke every token so the next request (any device) 403s.
      if (uid) {
        try { db.getDb().prepare("UPDATE tokens SET revoked=1 WHERE user_id=?").run(uid); } catch (e) {}
        try { if (email) await mailer.sendBanNotice(email, reason); } catch (e) { /* ban stands; email is best-effort */ }
      }
      return util.send(res, 200, { ok: true, id: Number(r.lastInsertRowid) || null });
    }
    // POST /api/admin/bans/:id/revoke
    if (req.method === "POST" && parts.length === 5 && parts[2] === "bans" && parts[4] === "revoke") {
      const id = parseInt(parts[3], 10);
      if (!id) return util.send(res, 400, { error: "bad id" });
      db.getDb().prepare("UPDATE mod_bans SET revoked=1 WHERE id=?").run(id);
      return util.send(res, 200, { ok: true });
    }
    return util.send(res, 404, { error: "not found" });
  } catch (e) {
    return util.send(res, (e && e.status) || 500, {
      error: (e && e.status) ? String(e.message).slice(0, 200) : "internal",
    });
  }
}
function normRangeInput(s) {
  s = String(s || "").trim();
  if (/^\d+\.\d+\.\d+\.\d+\/24$/.test(s)) return s;
  if (/^\d+\.\d+\.\d+\.\d+$/.test(s)) return rangeOf(s);
  return "";
}
function flagShape(f) {
  let cats = {};
  try { cats = JSON.parse(f.categories || "{}"); } catch (e) {}
  return {
    id: f.id, username: f.username || null, user_id: f.user_id,
    ip: f.ip, ip_range: f.ip_range, chat_id: f.chat_id,
    categories: cats, score: f.score, excerpt: f.excerpt,
    status: f.status, createdAt: f.created_at,
  };
}

module.exports = {
  clientIp, normIp, rangeOf,
  scanText, maybeFlagChat,
  banCheck, bannedRes, isAdminName,
  handleAdmin,
};
