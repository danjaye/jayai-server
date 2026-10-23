// Shared plumbing: errors, JSON responses, bodies, rate limiters, caches.
const config = require("./config");

function fail(status, message) {
  return Object.assign(new Error(message), { status });
}

function send(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": config.ORIGIN,
    "Access-Control-Allow-Headers": "Authorization, Content-Type",
    "Content-Length": Buffer.byteLength(body),
  });
  res.end(body);
}

function readJsonBody(req, maxBytes) {
  return new Promise(function (resolve, reject) {
    const chunks = [];
    let bytes = 0, tooBig = false;
    req.on("data", function (c) { bytes += c.length; if (bytes > (maxBytes || 16384)) tooBig = true; else chunks.push(c); });
    req.on("end", function () {
      if (tooBig) return reject(fail(413, "body too large"));
      const text = Buffer.concat(chunks).toString("utf8");
      if (!text) return resolve({});
      try {
        const v = JSON.parse(text);
        resolve(v && typeof v === "object" ? v : {});
      } catch (e) { reject(fail(400, "invalid json")); }
    });
    req.on("error", reject);
  });
}

// --- tiny fixed-window rate limiters (in-memory; pruned by lib/cleanup.js) ---
const rlMaps = [];
function makeLimiter() { const m = new Map(); rlMaps.push(m); return m; }
function allow(map, key, limit, windowMs) {
  const now = Date.now();
  let arr = map.get(key) || [];
  arr = arr.filter(function (t) { return now - t < windowMs; });
  if (arr.length >= limit) { map.set(key, arr); return false; }
  arr.push(now);
  map.set(key, arr);
  return true;
}
function pruneLimiters(now) {
  for (const m of rlMaps) {
    for (const entry of m) {
      const fresh = entry[1].filter(function (t) { return now - t < 3600000; });
      if (fresh.length) m.set(entry[0], fresh); else m.delete(entry[0]);
    }
  }
}

// --- shared search/fetch IP bucket (30 req/min per IP) ---
const hits = new Map(); // ip -> [timestamps]
function checkRateLimit(req) {
  const now = Date.now();
  const ip = req.socket.remoteAddress || "x";
  const arr = (hits.get(ip) || []).filter(function (t) { return now - t < 60000; });
  if (arr.length >= 30) return false;
  arr.push(now);
  hits.set(ip, arr);
  return true;
}
function pruneHits(now) {
  for (const entry of hits) {
    const fresh = entry[1].filter(function (t) { return now - t < 60000; });
    if (fresh.length) hits.set(entry[0], fresh); else hits.delete(entry[0]);
  }
}

function checkAuth(req, params) {
  if (!config.SECRET) return true;
  const given = params.get("key") || (req.headers.authorization || "").replace(/^Bearer /i, "");
  return given === config.SECRET;
}

function cachePut(map, key, data) {
  map.set(key, { at: Date.now(), data });
  if (map.size > config.MAX_CACHE_ENTRIES) {
    const oldest = map.keys().next().value;
    map.delete(oldest);
  }
}

module.exports = {
  fail, send, readJsonBody,
  rlMaps, makeLimiter, allow, pruneLimiters,
  hits, checkRateLimit, pruneHits, checkAuth,
  cachePut,
};
