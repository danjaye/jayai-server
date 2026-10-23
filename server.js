// jay-ai dedicated server: web search + full page fetch (incl. JS pages) + danauth email auth.
//
// Prettified working copy of the deployed server. Search/fetch behavior is
// preserved exactly; danauth auth (v2, email flow) is the addition.
// When the maintainer asks for the deploy file, ship a minified one-line
// build of THIS file (never edit the one-liner directly).
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
//   GET  /api/auth/me  (Bearer)                                  -> { username, email, createdAt }
//   POST /api/auth/logout (Bearer)                               -> { ok }
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
const dns = require("dns").promises;
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { chromium } = require("playwright");

// .env file (same dir, or ENV_FILE path) — real secrets live there, never in code.
// process.env always wins over .env, so a real environment overrides the file.
(function loadDotEnv() {
  try {
    const file = process.env.ENV_FILE || path.join(process.cwd(), ".env");
    const text = fs.readFileSync(file, "utf8");
    for (const rawLine of text.split("\n")) {
      const line = rawLine.trim();
      if (!line || line[0] === "#") continue;
      const eq = line.indexOf("=");
      if (eq < 0) continue;
      const key = line.slice(0, eq).trim();
      let val = line.slice(eq + 1).trim();
      if (val.length >= 2 && ((val[0] === '"' && val[val.length - 1] === '"') || (val[0] === "'" && val[val.length - 1] === "'"))) {
        val = val.slice(1, -1);
      }
      if (key && !(key in process.env)) process.env[key] = val;
    }
  } catch (e) { /* no .env — env vars only */ }
})();

const PORT = process.env.PORT || 3000;
const SECRET = process.env.SEARCH_SECRET || "";
const ORIGIN = process.env.ALLOWED_ORIGIN || "*";

const CACHE_MS = 600000;
const FETCH_CACHE_MS = 600000;
const FETCH_MAX_BYTES = 5 * 1024 * 1024; // max raw download per fetch
const FETCH_TEXT_DEFAULT = 12000; // server-side text cap default
const FETCH_TEXT_MAX = 50000; // server-side text cap ceiling
const MAX_CACHE_ENTRIES = 500;

const cache = new Map(); // search cache: "q#count" -> { at, data }
const fetchCache = new Map(); // fetch cache: "fetch:mode:maxChars:url" -> { at, data }
const hits = new Map(); // rate limit: ip -> [timestamps]

let browser = null;
async function getBrowser() {
  if (!browser) {
    browser = await chromium.launch({
      headless: true,
      args: ["--no-sandbox", "--disable-dev-shm-usage", "--disable-blink-features=AutomationControlled"],
    });
  }
  return browser;
}

function htmlClean(e) {
  return String(e)
    .replace(/<[^>]+>/g, "")
    .replace(/&amp;/g, "&")
    .replace(/&quot;/g, '"')
    .replace(/&#x27;/g, "'")
    .replace(/&#39;/g, "'")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .trim();
}

function unwrapDdg(e) {
  e = String(e).replace(/&amp;/g, "&");
  const t = /[?&]uddg=([^&]+)/.exec(e);
  if (t) {
    try {
      return decodeURIComponent(t[1]);
    } catch (e) {}
  }
  return 0 === e.indexOf("//") ? "https:" + e : e;
}

async function ddgFetch(e, t) {
  const r = await fetch("https://html.duckduckgo.com/html/?q=" + encodeURIComponent(e), {
    headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" },
  });
  if (!r.ok) throw new Error("DDG " + r.status);
  const n = await r.text(),
    o = [],
    a = /<a rel="nofollow" class="result__a" href="([^"]+)">([\s\S]*?)<\/a>/g;
  let s;
  for (; (s = a.exec(n)) && o.length < t; ) {
    const e = unwrapDdg(s[1]),
      t = htmlClean(s[2]);
    t && /^https?:\/\//.test(e) && o.push({ title: t, url: e });
  }
  const i = [],
    c = /<a class="result__snippet"[^>]*>([\s\S]*?)<\/a>/g;
  let l;
  for (; (l = c.exec(n)) && i.length < t; ) i.push(htmlClean(l[1]));
  return o.map(function (e, t) {
    return { title: e.title, url: e.url, snippet: i[t] || "" };
  });
}

async function bingPlaywright(e, t) {
  const r = await getBrowser(),
    n = await r.newContext({
      userAgent:
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
      viewport: { width: 1280, height: 900 },
      locale: "en-US",
    });
  try {
    const r = await n.newPage();
    await r.route(/\.(png|jpg|jpeg|gif|svg|woff2?)(\?|$)/, function (e) {
      return e.abort();
    }),
      await r.goto("https://www.bing.com/search?q=" + encodeURIComponent(e), {
        waitUntil: "domcontentloaded",
        timeout: 20000,
      }),
      await r.waitForSelector("li.b_algo h2 a", { timeout: 15000 });
    return (
      await r.$$eval(
        "li.b_algo",
        function (e, t) {
          return e.slice(0, t).map(function (e) {
            const t = e.querySelector("h2 a"),
              r = e.querySelector("p, .b_caption p");
            return {
              title: (t ? t.innerText : "").trim(),
              url: t ? t.href : "",
              snippet: (r ? r.innerText : "").trim(),
            };
          });
        },
        t
      )
    ).filter(function (e) {
      return e.title && /^https?:\/\//.test(e.url);
    });
  } finally {
    await n.close();
  }
}

// ---- full page fetch (new) ----

function fail(status, message) {
  return Object.assign(new Error(message), { status });
}

// True for IP literals (v4, v6, v4-mapped v6) in private/reserved ranges.
function isBlockedIp(addr) {
  const a = String(addr).split("%")[0].toLowerCase().replace(/^\[(.*)\]$/, "$1");
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(a);
  const v4 = mapped ? mapped[1] : /^[0-9.]+$/.test(a) && a.indexOf(":") < 0 ? a : null;
  if (v4) {
    const p = v4.split(".").map(Number);
    if (p.length !== 4 || p.some(function (n) { return !(n >= 0 && n <= 255); })) return true;
    if (p[0] === 10) return true; // 10/8
    if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true; // 172.16/12
    if (p[0] === 192 && p[1] === 168) return true; // 192.168/16
    if (p[0] === 127) return true; // loopback
    if (p[0] === 169 && p[1] === 254) return true; // link-local / cloud metadata
    if (p[0] === 0) return true; // 0/8
    return false;
  }
  if (a.indexOf(":") < 0) return true; // not an IP at all -> caller resolves via DNS
  if (a === "::1" || a === "::") return true;
  const hextet = parseInt(a.split(":")[0] || "0", 16);
  if (!isNaN(hextet)) {
    if ((hextet & 0xfe00) === 0xfc00) return true; // fc00::/7 unique local
    if ((hextet & 0xffc0) === 0xfe80) return true; // fe80::/10 link local
  }
  return false;
}

function hostBlocked(hostname) {
  const h = String(hostname || "").toLowerCase().replace(/\.$/, "");
  if (!h || h === "localhost") return true;
  if (/^[0-9.]+$/.test(h) || h.indexOf(":") >= 0) return isBlockedIp(h); // literal
  return false;
}

// Parse + SSRF-guard a URL: http(s) only, no credentials, host + resolved
// IPs must be public. Throws fail(status, msg).
async function assertSafeUrl(urlStr) {
  let u;
  try {
    u = new URL(urlStr);
  } catch (e) {
    throw fail(400, "invalid url");
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") throw fail(400, "only http(s) allowed");
  if (u.username || u.password) throw fail(400, "credentials in url not allowed");
  if (hostBlocked(u.hostname)) throw fail(403, "blocked host");
  let addrs;
  try {
    addrs = await dns.lookup(u.hostname, { all: true });
  } catch (e) {
    throw fail(502, "dns failed for host");
  }
  if (!addrs.length) throw fail(502, "dns failed for host");
  for (const a of addrs) {
    if (isBlockedIp(a.address)) throw fail(403, "blocked host");
  }
  return u;
}

// Static fetch with timeout, size cap, and content-type gating.
// Returns { finalUrl, contentType, buf, isHtml }.
async function rawFetch(urlStr) {
  const ctrl = new AbortController();
  const timer = setTimeout(function () { ctrl.abort(); }, 15000);
  try {
    const r = await fetch(urlStr, {
      signal: ctrl.signal,
      redirect: "follow",
      headers: {
        "User-Agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,text/plain;q=0.8,*/*;q=0.5",
        "Accept-Language": "en-US,en;q=0.9",
      },
    });
    try {
      const fin = new URL(r.url || urlStr);
      if (hostBlocked(fin.hostname)) throw fail(403, "blocked host after redirect");
      await assertSafeUrl(fin.href); // re-check resolved IPs post-redirect
    } catch (e) {
      if (e && e.status) throw e;
    }
    if (!r.ok) throw fail(502, "fetch " + r.status);
    const ctype = (r.headers.get("content-type") || "").toLowerCase();
    const texty = /text\/|html|xml|json|javascript/.test(ctype) || ctype === "";
    if (!texty) throw fail(415, "unsupported content type: " + (ctype.split(";")[0] || "unknown"));
    const reader = r.body.getReader();
    const chunks = [];
    let bytes = 0;
    for (;;) {
      const part = await reader.read();
      if (part.done) break;
      bytes += part.value.length;
      if (bytes > FETCH_MAX_BYTES) {
        try { await reader.cancel(); } catch (e) {}
        break;
      }
      chunks.push(part.value);
    }
    const buf = Buffer.concat(chunks.map(function (c) { return Buffer.from(c); }));
    const head = buf.slice(0, 2000).toString("utf8");
    const isHtml = /html|xml/.test(ctype) || /^\s*</.test(head);
    return { finalUrl: r.url || urlStr, contentType: ctype, buf, isHtml };
  } catch (e) {
    if (e && e.name === "AbortError") throw fail(502, "fetch timed out");
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

function decodeEntities(s) {
  return String(s)
    .replace(/&#x([0-9a-fA-F]+);/g, function (_, h) {
      try { return String.fromCodePoint(parseInt(h, 16)); } catch (e) { return ""; }
    })
    .replace(/&#(\d+);/g, function (_, d) {
      try { return String.fromCodePoint(parseInt(d, 10)); } catch (e) { return ""; }
    })
    .replace(/&amp;/g, "&")
    .replace(/&quot;/g, '"')
    .replace(/&#x27;/g, "'")
    .replace(/&#39;/g, "'")
    .replace(/&apos;/g, "'")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&nbsp;/g, " ");
}

function cleanText(s) {
  return String(s).replace(/[ \t\x0B\f\r]+/g, " ").replace(/\n{3,}/g, "\n\n").trim();
}

function htmlToText(html) {
  const h = String(html);
  const titleM = /<title[^>]*>([\s\S]*?)<\/title>/i.exec(h);
  const title = titleM ? cleanText(decodeEntities(titleM[1].replace(/<[^>]+>/g, ""))).slice(0, 300) : "";
  const bodyM = /<body[^>]*>([\s\S]*?)<\/body>/i.exec(h);
  const body = bodyM ? bodyM[1] : h;
  const text = cleanText(
    decodeEntities(
      body
        .replace(/<(script|style|noscript|template|svg|canvas|head)[^>]*>[\s\S]*?<\/\1>/gi, " ")
        .replace(/<!--[\s\S]*?-->/g, " ")
        .replace(/<[^>]+>/g, " ")
    )
  );
  return { title, text };
}

// Static HTML that is probably an unhydrated JS shell: too little text,
// or app-mount markers with thin content.
function looksLikeJsShell(html, text) {
  if (!text || text.length < 800) return true;
  if (/(requires?|enable) javascript|__NEXT_DATA__|id=["']?(__next|root|app)["']?/i.test(html || "") && text.length < 2000)
    return true;
  if (/^(loading\.\.\.|just a moment|checking your browser)/i.test(text) && text.length < 500) return true;
  return false;
}

// Full render in headless Chromium (shared browser singleton).
// Returns { finalUrl, title, text }.
async function renderWithBrowser(urlStr) {
  let b;
  try {
    b = await getBrowser();
  } catch (e) {
    throw fail(503, "browser unavailable: " + String((e && e.message) || e).slice(0, 160));
  }
  const ctx = await b.newContext({
    userAgent:
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    viewport: { width: 1280, height: 900 },
    locale: "en-US",
  });
  try {
    const page = await ctx.newPage();
    await page.route(/\.(png|jpg|jpeg|gif|svg|webp|woff2?|ttf|mp4|webm)(\?|$)/, function (r) {
      return r.abort();
    });
    await page.goto(urlStr, { waitUntil: "domcontentloaded", timeout: 25000 });
    try {
      await page.waitForLoadState("networkidle", { timeout: 8000 });
    } catch (e) {}
    await page.waitForTimeout(1800);
    try {
      await page.evaluate(function () {
        window.scrollTo(0, document.body ? document.body.scrollHeight : 0);
      });
      await page.waitForTimeout(700);
    } catch (e) {}
    const finalUrl = page.url();
    let title = "";
    try {
      title = (await page.title()).trim().slice(0, 300);
    } catch (e) {}
    let text = "";
    try {
      text = await page.evaluate(function () {
        const el = document.body || document.documentElement;
        return (el ? el.innerText : "") || "";
      });
    } catch (e) {}
    return { finalUrl, title, text: cleanText(text) };
  } finally {
    await ctx.close();
  }
}

function cachePut(map, key, data) {
  map.set(key, { at: Date.now(), data });
  if (map.size > MAX_CACHE_ENTRIES) {
    const oldest = map.keys().next().value;
    map.delete(oldest);
  }
}

async function handleFetch(req, res, params) {
  const raw = String(params.get("url") || "").trim();
  if (!raw) return send(res, 400, { error: "missing ?url=" });
  if (raw.length > 2000) return send(res, 400, { error: "url too long" });
  let mode = String(params.get("mode") || "auto").toLowerCase();
  if (["auto", "raw", "js"].indexOf(mode) < 0) mode = "auto";
  let maxChars = parseInt(params.get("maxChars") || String(FETCH_TEXT_DEFAULT), 10);
  if (isNaN(maxChars)) maxChars = FETCH_TEXT_DEFAULT;
  maxChars = Math.min(Math.max(maxChars, 500), FETCH_TEXT_MAX);

  try {
    await assertSafeUrl(raw);
  } catch (e) {
    return send(res, (e && e.status) || 400, { error: String((e && e.message) || e).slice(0, 200) });
  }

  const cacheKey = "fetch:" + mode + ":" + maxChars + ":" + raw;
  const hit = fetchCache.get(cacheKey);
  if (hit && Date.now() - hit.at < FETCH_CACHE_MS) return send(res, 200, hit.data);

  try {
    let title = "",
      text = "",
      finalUrl = raw,
      renderedWith = "raw",
      rawHtml = "";

    if (mode !== "js") {
      const r = await rawFetch(raw);
      finalUrl = r.finalUrl;
      if (r.isHtml) {
        rawHtml = r.buf.toString("utf8");
        const t = htmlToText(rawHtml);
        title = t.title;
        text = t.text;
      } else {
        text = cleanText(r.buf.toString("utf8"));
      }
    }

    if (mode === "js" || (mode === "auto" && looksLikeJsShell(rawHtml, text))) {
      try {
        const rendered = await renderWithBrowser(finalUrl);
        try {
          await assertSafeUrl(rendered.finalUrl);
          finalUrl = rendered.finalUrl;
        } catch (e) {
          // Landed somewhere unsafe (shouldn't happen) — keep the raw URL.
        }
        if (rendered.title && (!title || (rendered.text || "").length >= text.length)) title = rendered.title;
        if (rendered.text && (mode === "js" || rendered.text.length > text.length)) {
          text = rendered.text;
          renderedWith = "js";
        }
      } catch (e) {
        if (mode === "js" && !text) throw e; // explicit js with nothing to fall back to
        // auto: keep the raw text on render failure
      }
    }

    if (!text) return send(res, 502, { error: "page was empty" });
    const truncated = text.length > maxChars;
    const out = {
      url: raw,
      finalUrl,
      title,
      text: truncated ? text.slice(0, maxChars) : text,
      chars: text.length,
      truncated,
      renderedWith,
    };
    cachePut(fetchCache, cacheKey, out);
    return send(res, 200, out);
  } catch (e) {
    return send(res, (e && e.status) || 502, {
      error: "fetch failed: " + String((e && e.message) || e).slice(0, 200),
    });
  }
}

// ---- danauth email auth (v2; contract: AUTH_CONTRACT.md) ----
// Users + codes + tokens in SQLite (node:sqlite). Email via Zoho SMTP.
// Secrets ONLY from env/.env — never in code, logs, or responses.

const AUTH_DB_PATH = process.env.AUTH_DB_PATH || "./danauth.sqlite";
const AUTH_PEPPER = process.env.AUTH_PEPPER || "";
const SMTP_HOST = process.env.SMTP_HOST || "smtp.zoho.com";
const SMTP_PORT = parseInt(process.env.SMTP_PORT || "465", 10) || 465;
const SMTP_USER = process.env.SMTP_USER || "";
const SMTP_PASS = process.env.SMTP_PASS || "";
const MAIL_FROM = process.env.MAIL_FROM || "danauth <noreply@danjaye.lol>";
const ALLOW_NO_SMTP = process.env.ALLOW_NO_SMTP === "1";
const TOKEN_DAYS = Math.min(Math.max(parseInt(process.env.TOKEN_DAYS || "30", 10) || 30, 1), 365);

const EMAIL_CODE_MS = 10 * 60 * 1000; // verify + reset codes live 10 min
const LOGIN_CODE_MS = 60 * 1000; // handoff codes live 60s, single-use
const EMAIL_CODE_MAX_ATTEMPTS = 5;

let sqliteLib = null;
try { sqliteLib = require("node:sqlite"); } catch (e) { sqliteLib = null; }
let nodemailerLib = null;
try { nodemailerLib = require("nodemailer"); } catch (e) { nodemailerLib = null; }
let authDb = null;
let mailTransport = null;

// --- password hashing: scrypt (node:crypto, no deps) ---
function scryptHash(password) {
  const salt = crypto.randomBytes(16);
  const key = crypto.scryptSync(String(password), salt, 64, { N: 16384, r: 8, p: 1 });
  return "scrypt$16384$8$1$" + salt.toString("hex") + "$" + key.toString("hex");
}
function scryptVerify(stored, password) {
  try {
    const parts = String(stored).split("$");
    if (parts.length !== 6 || parts[0] !== "scrypt") return false;
    const N = parseInt(parts[1], 10), r = parseInt(parts[2], 10), p = parseInt(parts[3], 10);
    if (!(N > 0 && r > 0 && p > 0)) return false;
    const salt = Buffer.from(parts[4], "hex");
    const expect = Buffer.from(parts[5], "hex");
    const key = crypto.scryptSync(String(password), salt, expect.length, { N, r, p });
    return key.length === expect.length && crypto.timingSafeEqual(key, expect);
  } catch (e) { return false; }
}
// Parsed like a real hash so unknown-user logins cost the same work (timing).
const DUMMY_PASS_HASH = scryptHash("danauth-dummy-" + crypto.randomBytes(8).toString("hex"));

// --- misc crypto helpers ---
function sha256hex(s) { return crypto.createHash("sha256").update(String(s), "utf8").digest("hex"); }
// Short email codes get a server-side pepper so a DB leak alone can't brute-force 6 digits.
function pepperHash(purpose, code) { return sha256hex(AUTH_PEPPER + "|" + purpose + "|" + String(code)); }
function newOpaque() { return crypto.randomBytes(32).toString("base64url"); }
function newEmailCode() { return String(crypto.randomInt(0, 1000000)).padStart(6, "0"); }

// --- input validation (mirrored client-side for UX; enforced here) ---
function validUsername(v) { return typeof v === "string" && /^[a-z0-9_-]{3,20}$/.test(v); }
function validEmail(v) { return typeof v === "string" && v.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(v); }
function validPassword(v) { return typeof v === "string" && v.length >= 10 && v.length <= 512; }

// --- tiny fixed-window rate limiters (in-memory; pruned by cleanupAuth) ---
const rlMaps = [];
function makeLimiter() { const m = new Map(); rlMaps.push(m); return m; }
const rlLoginIp = makeLimiter(), rlLoginUser = makeLimiter(), rlLoginFail = makeLimiter();
const rlRegister = makeLimiter(), rlVerify = makeLimiter(), rlExchange = makeLimiter();
const rlRecoverIp = makeLimiter(), rlRecoverEmail = makeLimiter(), rlResend = makeLimiter();
const rlCheck = makeLimiter();
function allow(map, key, limit, windowMs) {
  const now = Date.now();
  let arr = map.get(key) || [];
  arr = arr.filter(function (t) { return now - t < windowMs; });
  if (arr.length >= limit) { map.set(key, arr); return false; }
  arr.push(now);
  map.set(key, arr);
  return true;
}
function noteLoginFail(username) { allow(rlLoginFail, "f:" + username, Infinity, 15 * 60 * 1000); }
function loginFailCount(username) {
  const now = Date.now();
  return (rlLoginFail.get("f:" + username) || []).filter(function (t) { return now - t < 15 * 60 * 1000; }).length;
}

// --- SQLite store ---
function openAuthDb() {
  if (!sqliteLib) {
    console.error("FATAL: node:sqlite unavailable. Use Node >= 22 (you have it) and if needed start with `node --experimental-sqlite server.js`.");
    process.exit(1);
  }
  authDb = new sqliteLib.DatabaseSync(AUTH_DB_PATH);
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
    "CREATE INDEX IF NOT EXISTS idx_blobs_user ON blobs(user_id, collection);"
  );
}
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
  const code = newEmailCode();
  const now = Date.now();
  dbTx(function () {
    authDb.prepare("UPDATE email_codes SET used=1 WHERE user_id=? AND purpose=? AND used=0").run(userId, purpose);
    authDb.prepare("INSERT INTO email_codes(user_id, purpose, code_hash, expires_at, created_at) VALUES(?,?,?,?,?)")
      .run(userId, purpose, pepperHash(purpose, code), now + EMAIL_CODE_MS, now);
  });
  return code;
}
function checkEmailCode(userId, purpose, code) {
  const row = authDb.prepare("SELECT * FROM email_codes WHERE user_id=? AND purpose=? AND used=0 ORDER BY id DESC LIMIT 1").get(userId, purpose);
  if (!row) return false;
  if (Date.now() > row.expires_at || row.attempts >= EMAIL_CODE_MAX_ATTEMPTS) return false;
  authDb.prepare("UPDATE email_codes SET attempts=attempts+1 WHERE id=?").run(row.id);
  const want = Buffer.from(String(row.code_hash), "hex");
  const got = Buffer.from(pepperHash(purpose, String(code || "")), "hex");
  if (want.length !== got.length || !crypto.timingSafeEqual(want, got)) return false;
  authDb.prepare("UPDATE email_codes SET used=1 WHERE id=?").run(row.id);
  return true;
}
function issueLoginCode(userId) {
  const code = newOpaque();
  const now = Date.now();
  authDb.prepare("INSERT INTO login_codes(code_hash, user_id, expires_at, created_at) VALUES(?,?,?,?)")
    .run(sha256hex(code), userId, now + LOGIN_CODE_MS, now);
  return code;
}
function consumeLoginCode(code) {
  const h = sha256hex(String(code || ""));
  return dbTx(function () {
    const row = authDb.prepare("SELECT * FROM login_codes WHERE code_hash=? AND used=0").get(h);
    if (!row) throw fail(401, "invalid code");
    authDb.prepare("UPDATE login_codes SET used=1 WHERE id=?").run(row.id);
    if (Date.now() > row.expires_at) throw fail(410, "code expired");
    const u = authDb.prepare("SELECT * FROM users WHERE id=?").get(row.user_id);
    if (!u) throw fail(401, "invalid code");
    return u;
  });
}
function issueToken(userId) {
  const token = newOpaque();
  const now = Date.now();
  authDb.prepare("INSERT INTO tokens(token_hash, user_id, created_at, expires_at) VALUES(?,?,?,?)")
    .run(sha256hex(token), userId, now, now + TOKEN_DAYS * 86400 * 1000);
  return token;
}
function getBearerUser(req) {
  try {
    const h = req.headers.authorization || "";
    const m = /^Bearer (.+)$/.exec(h);
    if (!m) return null;
    return authDb.prepare(
      "SELECT u.* FROM tokens t JOIN users u ON u.id=t.user_id " +
      "WHERE t.token_hash=? AND t.revoked=0 AND t.expires_at>?").get(sha256hex(m[1].trim()), Date.now()) || null;
  } catch (e) { return null; }
}

// --- email (Zoho SMTP; dev fallback logs codes — never returns them in responses) ---
function smtpReady() { return !!(SMTP_USER && SMTP_PASS && nodemailerLib); }
function getMailer() {
  if (mailTransport) return mailTransport;
  mailTransport = nodemailerLib.createTransport({
    host: SMTP_HOST, port: SMTP_PORT, secure: SMTP_PORT === 465,
    auth: { user: SMTP_USER, pass: SMTP_PASS },
    connectionTimeout: 15000, greetingTimeout: 10000, socketTimeout: 20000,
  });
  return mailTransport;
}
async function sendCodeEmail(to, purpose, code) {
  if (!smtpReady()) {
    if (ALLOW_NO_SMTP) { console.log("[auth:dev] " + purpose + " code for " + to + ": " + code); return; }
    throw fail(503, "email unavailable");
  }
  const what = purpose === "verify" ? "verifying your danauth account" : "resetting your danauth password";
  const subject = purpose === "verify" ? "Verify your danauth email" : "Reset your danauth password";
  await getMailer().sendMail({
    from: MAIL_FROM, to, subject,
    text: "Your danauth code: " + code + "\n\nUse this code for " + what + ". It expires in 10 minutes.\nIf you didn't request this, you can safely ignore this email.",
  });
}

// --- request plumbing for auth routes ---
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

async function handleAuth(req, res, url) {
  try {
    const p = url.pathname;
    if (p === "/api/auth/me") {
      if (req.method !== "GET") return send(res, 405, { error: "method not allowed" });
      const u = getBearerUser(req);
      if (!u) return send(res, 401, { error: "unauthorized" });
      return send(res, 200, { username: u.username, email: u.email, createdAt: new Date(u.created_at).toISOString() });
    }
    if (p === "/api/auth/logout") {
      if (req.method !== "POST") return send(res, 405, { error: "method not allowed" });
      const u = getBearerUser(req);
      if (!u) return send(res, 401, { error: "unauthorized" });
      const h = req.headers.authorization || "";
      authDb.prepare("UPDATE tokens SET revoked=1 WHERE token_hash=?").run(sha256hex(/^Bearer (.+)$/.exec(h)[1].trim()));
      return send(res, 200, { ok: true });
    }
    if (req.method !== "POST") return send(res, 405, { error: "method not allowed" });
    const body = await readJsonBody(req);
    if (p === "/api/auth/register") return await authRegister(res, body, req);
    if (p === "/api/auth/verify") return await authVerify(res, body, req);
    if (p === "/api/auth/resend") return await authResend(res, body, req);
    if (p === "/api/auth/login") return await authLogin(res, body, req);
    if (p === "/api/auth/recover") return await authRecover(res, body, req);
    if (p === "/api/auth/reset") return await authReset(res, body, req);
    if (p === "/api/auth/exchange") return await authExchange(res, body, req);
    if (p === "/api/auth/check") return await authCheck(res, body, req);
    return send(res, 404, { error: "not found" });
  } catch (e) {
    return send(res, (e && e.status) || 500, {
      error: (e && e.status) ? String(e.message).slice(0, 200) : "internal",
    });
  }
}

async function authRegister(res, body, req) {
  const ip = req.socket.remoteAddress || "x";
  if (!allow(rlRegister, ip, 5, 3600000)) return send(res, 429, { error: "too many registrations, try again later" });
  const username = String(body.username || "").trim().toLowerCase();
  const email = String(body.email || "").trim().toLowerCase();
  if (!validUsername(username)) return send(res, 400, { error: "bad username (3-20 chars: a-z 0-9 _ -)" });
  if (!validEmail(email)) return send(res, 400, { error: "bad email" });
  if (!validPassword(body.password)) return send(res, 400, { error: "bad password (minimum 10 characters)" });
  if (dbGetUserByUsername(username)) return send(res, 409, { error: "username taken" });
  if (dbGetUserByEmail(email)) return send(res, 409, { error: "email already registered" });
  const now = Date.now();
  dbTx(function () {
    authDb.prepare("INSERT INTO users(username, email, pass_hash, verified, created_at) VALUES(?,?,?,?,?)")
      .run(username, email, scryptHash(body.password), 0, now);
  });
  const created = authDb.prepare("SELECT id FROM users WHERE username=?").get(username);
  const code = issueEmailCode(created.id, "verify");
  try { await sendCodeEmail(email, "verify", code); }
  catch (e) { return send(res, (e && e.status) || 502, { error: "could not send verification email" }); }
  return send(res, 200, { username, pendingVerification: true });
}

async function authVerify(res, body, req) {
  const ip = req.socket.remoteAddress || "x";
  if (!allow(rlVerify, ip, 30, 60000)) return send(res, 429, { error: "rate limited" });
  const username = String(body.username || "").trim().toLowerCase();
  const u = dbGetUserByUsername(username);
  if (!u || !checkEmailCode(u.id, "verify", body.code)) {
    return send(res, 401, { error: "invalid or expired code" });
  }
  authDb.prepare("UPDATE users SET verified=1 WHERE id=?").run(u.id);
  return send(res, 200, { code: issueLoginCode(u.id) });
}

async function authCheck(res, body, req) {
  const ip = req.socket.remoteAddress || "x";
  if (!allow(rlCheck, ip, 120, 60000)) return send(res, 429, { error: "rate limited" });
  const username = String(body.username || "").trim().toLowerCase();
  if (!validUsername(username)) return send(res, 400, { error: "bad username (3-20 chars: a-z 0-9 _ -)" });
  return send(res, 200, { available: !dbGetUserByUsername(username) });
}

async function authResend(res, body, req) {
  const ip = req.socket.remoteAddress || "x";
  const username = String(body.username || "").trim().toLowerCase();
  if (!allow(rlResend, ip + "|" + username, 5, 3600000)) return send(res, 429, { error: "rate limited" });
  const u = dbGetUserByUsername(username);
  if (u && !u.verified) {
    const code = issueEmailCode(u.id, "verify");
    try { await sendCodeEmail(u.email, "verify", code); } catch (e) { /* still ok:true; verify/login will surface 503 */ }
  }
  return send(res, 200, { ok: true });
}

async function authLogin(res, body, req) {
  const ip = req.socket.remoteAddress || "x";
  if (!allow(rlLoginIp, ip, 10, 60000)) return send(res, 429, { error: "rate limited" });
  const username = String(body.username || "").trim().toLowerCase();
  if (!validUsername(username)) return send(res, 401, { error: "invalid credentials" });
  if (!allow(rlLoginUser, "u:" + username, 10, 60000) || loginFailCount(username) >= 10) {
    return send(res, 429, { error: "too many attempts, try again later" });
  }
  const u = dbGetUserByUsername(username);
  const okPw = u ? scryptVerify(u.pass_hash, body.password) : scryptVerify(DUMMY_PASS_HASH, "dummy");
  if (!u || !okPw) { noteLoginFail(username); return send(res, 401, { error: "invalid credentials" }); }
  rlLoginFail.delete("f:" + username);
  if (!u.verified) {
    const code = issueEmailCode(u.id, "verify");
    try { await sendCodeEmail(u.email, "verify", code); } catch (e) { /* 403 still tells client to verify; resend surfaces errors */ }
    return send(res, 403, { error: "email not verified", needsVerification: true });
  }
  return send(res, 200, { code: issueLoginCode(u.id) });
}

async function authRecover(res, body, req) {
  const ip = req.socket.remoteAddress || "x";
  const email = String(body.email || "").trim().toLowerCase();
  if (!allow(rlRecoverIp, ip, 10, 3600000)) return send(res, 429, { error: "rate limited" });
  if (email && validEmail(email)) {
    if (!allow(rlRecoverEmail, email, 5, 3600000)) return send(res, 429, { error: "rate limited" });
    const u = dbGetUserByEmail(email);
    if (u) {
      const code = issueEmailCode(u.id, "reset");
      try { await sendCodeEmail(email, "reset", code); } catch (e) { /* always ok:true; reset surfaces errors */ }
    }
  }
  return send(res, 200, { ok: true }); // never reveal whether the email exists
}

async function authReset(res, body, req) {
  const ip = req.socket.remoteAddress || "x";
  if (!allow(rlVerify, ip, 30, 60000)) return send(res, 429, { error: "rate limited" });
  const email = String(body.email || "").trim().toLowerCase();
  if (!validEmail(email)) return send(res, 400, { error: "bad email" });
  if (!validPassword(body.newPassword)) return send(res, 400, { error: "bad password (minimum 10 characters)" });
  const u = dbGetUserByEmail(email);
  if (!u || !checkEmailCode(u.id, "reset", body.code)) {
    return send(res, 401, { error: "invalid or expired code" });
  }
  authDb.prepare("UPDATE users SET pass_hash=? WHERE id=?").run(scryptHash(body.newPassword), u.id);
  return send(res, 200, { ok: true, code: issueLoginCode(u.id) }); // straight into the app
}

async function authExchange(res, body, req) {
  const ip = req.socket.remoteAddress || "x";
  if (!allow(rlExchange, ip, 30, 60000)) return send(res, 429, { error: "rate limited" });
  if (typeof body.code !== "string" || !body.code) return send(res, 400, { error: "missing code" });
  const u = consumeLoginCode(body.code);
  return send(res, 200, { token: issueToken(u.id), username: u.username });
}

// ---- jay-ai cross-device sync (v1; contract: SYNC_CONTRACT.md) ----
// Blob sync for chats / memories / settings behind the existing Bearer tokens.
// Server is the backup + relay: per-blob revs, baseRev conflict flags, last-write-wins.
// Merge rules themselves run client-side. Strict per-user isolation on every query.

const SYNC_COLLECTIONS = {
  chats: { maxBytes: 5 * 1024 * 1024 },
  memories: { maxBytes: 200 * 1024 },
  settings: { maxBytes: 100 * 1024 },
};
const SYNC_QUOTA_BYTES = (parseInt(process.env.SYNC_QUOTA_MB || "50", 10) || 50) * 1024 * 1024;
const TOMBSTONE_GC_MS = 30 * 86400 * 1000;
const SYNC_ID_RE = /^[A-Za-z0-9_-]{1,128}$/;
const rlSyncRead = makeLimiter(), rlSyncWrite = makeLimiter();

function syncQuotaUsed(userId) {
  const row = authDb.prepare("SELECT COALESCE(SUM(bytes),0) AS total FROM blobs WHERE user_id=?").get(userId);
  return (row && row.total) || 0;
}

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
    const u = getBearerUser(req);
    if (!u) return send(res, 401, { error: "unauthorized" });
    const p = parseSyncPath(url.pathname);
    if (!p || !(p.collection in SYNC_COLLECTIONS)) return send(res, 404, { error: "unknown collection" });
    if (p.id !== null && !SYNC_ID_RE.test(p.id)) return send(res, 400, { error: "bad id" });
    if (p.collection === "settings" && p.id !== null && p.id !== "main") {
      return send(res, 400, { error: 'settings id must be "main"' });
    }
    if (req.method === "GET" && p.id === null) {
      if (!allow(rlSyncRead, "sr:" + u.id, 60, 60000)) return send(res, 429, { error: "rate limited" });
      const rows = authDb.prepare(
        "SELECT blob_id AS id, rev, updated_at AS updatedAt, bytes, deleted FROM blobs " +
        "WHERE user_id=? AND collection=? ORDER BY blob_id").all(u.id, p.collection);
      return send(res, 200, { items: rows.map(function (r) {
        const it = { id: r.id, rev: r.rev, updatedAt: r.updatedAt, bytes: r.bytes };
        if (r.deleted) it.deleted = true;
        return it;
      }) });
    }
    if (req.method === "GET") {
      if (!allow(rlSyncRead, "sr:" + u.id, 60, 60000)) return send(res, 429, { error: "rate limited" });
      const row = authDb.prepare("SELECT * FROM blobs WHERE user_id=? AND collection=? AND blob_id=?")
        .get(u.id, p.collection, p.id);
      if (!row) return send(res, 404, { error: "not found" });
      let data;
      try { data = JSON.parse(row.data); } catch (e) { return send(res, 500, { error: "internal" }); }
      const out = { id: row.blob_id, rev: row.rev, updatedAt: row.updated_at, data: data };
      if (row.deleted) out.deleted = true;
      return send(res, 200, out);
    }
    if (req.method === "PUT" && p.id !== null) {
      if (!allow(rlSyncWrite, "sw:" + u.id, 20, 60000)) return send(res, 429, { error: "rate limited" });
      const cap = SYNC_COLLECTIONS[p.collection].maxBytes;
      const body = await readJsonBody(req, cap + 65536);
      if (typeof body.updatedAt !== "number" || !(body.updatedAt > 0)) {
        return send(res, 400, { error: "bad updatedAt" });
      }
      if (!body.data || typeof body.data !== "object" || Array.isArray(body.data)) {
        return send(res, 400, { error: "bad data" });
      }
      const raw = JSON.stringify(body.data);
      const bytes = Buffer.byteLength(raw);
      if (bytes > cap) return send(res, 409, { error: "blob too large" });
      const baseRev = (body.baseRev === undefined || body.baseRev === null) ? null : body.baseRev;
      if (baseRev !== null && (!Number.isInteger(baseRev) || baseRev < 1)) {
        return send(res, 400, { error: "bad baseRev" });
      }
      const out = dbTx(function () {
        const existing = authDb.prepare("SELECT * FROM blobs WHERE user_id=? AND collection=? AND blob_id=?")
          .get(u.id, p.collection, p.id);
        const oldBytes = existing ? existing.bytes : 0;
        if (syncQuotaUsed(u.id) - oldBytes + bytes > SYNC_QUOTA_BYTES) throw fail(413, "quota exceeded");
        const rev = existing ? existing.rev + 1 : 1;
        if (existing) {
          authDb.prepare("UPDATE blobs SET rev=?, updated_at=?, bytes=?, data=?, deleted=0 WHERE id=?")
            .run(rev, body.updatedAt, bytes, raw, existing.id);
        } else {
          authDb.prepare("INSERT INTO blobs(user_id, collection, blob_id, rev, updated_at, bytes, data, deleted, created_at) VALUES(?,?,?,?,?,?,?,0,?)")
            .run(u.id, p.collection, p.id, rev, body.updatedAt, bytes, raw, Date.now());
        }
        const result = { id: p.id, rev: rev };
        if (baseRev !== null && existing && baseRev !== existing.rev) {
          result.conflict = true;
          result.server = { rev: rev, updatedAt: body.updatedAt };
        }
        return result;
      });
      return send(res, 200, out);
    }
    if (req.method === "DELETE" && p.id !== null) {
      if (!allow(rlSyncWrite, "sw:" + u.id, 20, 60000)) return send(res, 429, { error: "rate limited" });
      if (p.collection !== "memories") {
        return send(res, 400, { error: "client never deletes " + p.collection + " in v1" });
      }
      const now = Date.now();
      const out = dbTx(function () {
        const existing = authDb.prepare("SELECT * FROM blobs WHERE user_id=? AND collection=? AND blob_id=?")
          .get(u.id, p.collection, p.id);
        if (!existing) throw fail(404, "not found");
        const rev = existing.rev + 1;
        const tomb = JSON.stringify({ path: "memories/" + p.id + ".md", deleted: true, updatedAt: now });
        authDb.prepare("UPDATE blobs SET rev=?, updated_at=?, bytes=?, data=?, deleted=1 WHERE id=?")
          .run(rev, now, Buffer.byteLength(tomb), tomb, existing.id);
        return { id: p.id, rev: rev, deleted: true };
      });
      return send(res, 200, out);
    }
    return send(res, 405, { error: "method not allowed" });
  } catch (e) {
    return send(res, (e && e.status) || 500, {
      error: (e && e.status) ? String(e.message).slice(0, 200) : "internal",
    });
  }
}

// Periodic cleanup: expired codes/tokens + pruned rate-limit maps.
// (Also prunes the shared search/fetch `hits` map, which was previously unbounded.)
function cleanupAuth() {
  try {
    if (authDb) {
      const now = Date.now();
      authDb.prepare("DELETE FROM login_codes WHERE expires_at < ?").run(now);
      authDb.prepare("DELETE FROM email_codes WHERE expires_at < ?").run(now);
      authDb.prepare("DELETE FROM tokens WHERE expires_at < ?").run(now);
      authDb.prepare("DELETE FROM blobs WHERE deleted=1 AND updated_at < ?").run(now - TOMBSTONE_GC_MS);
    }
    for (const m of rlMaps) {
      const now = Date.now();
      for (const entry of m) {
        const fresh = entry[1].filter(function (t) { return now - t < 3600000; });
        if (fresh.length) m.set(entry[0], fresh); else m.delete(entry[0]);
      }
    }
    const now2 = Date.now();
    for (const entry of hits) {
      const fresh = entry[1].filter(function (t) { return now2 - t < 60000; });
      if (fresh.length) hits.set(entry[0], fresh); else hits.delete(entry[0]);
    }
  } catch (e) { console.warn("cleanup:", String((e && e.message) || e).slice(0, 120)); }
}

// ---- shared plumbing ----

function checkRateLimit(req) {
  const now = Date.now();
  const ip = req.socket.remoteAddress || "x";
  const arr = (hits.get(ip) || []).filter(function (t) {
    return now - t < 60000;
  });
  if (arr.length >= 30) return false;
  arr.push(now);
  hits.set(ip, arr);
  return true;
}

function checkAuth(req, params) {
  if (!SECRET) return true;
  const given = params.get("key") || (req.headers.authorization || "").replace(/^Bearer /i, "");
  return given === SECRET;
}

function send(e, t, r) {
  const n = JSON.stringify(r);
  e.writeHead(t, {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": ORIGIN,
    "Access-Control-Allow-Headers": "Authorization, Content-Type",
    "Content-Length": Buffer.byteLength(n),
  }),
    e.end(n);
}

process.on("SIGTERM", async () => {
  try {
    browser && (await browser.close());
  } catch (e) {}
  process.exit(0);
});

const server = http.createServer(function (e, t) {
  // Never let a handler rejection kill the process (Node's default on
  // unhandled rejection): always answer, so one bad render can't drop the socket.
  handleRequest(e, t).catch(function (err) {
    try {
      send(t, 500, { error: "internal: " + String((err && err.message) || err).slice(0, 200) });
    } catch (e2) {
      try { t.destroy(); } catch (e3) {}
    }
  });
});

async function handleRequest(e, t) {
  if ("OPTIONS" === e.method)
    return (
      t.writeHead(204, {
        "Access-Control-Allow-Origin": ORIGIN,
        "Access-Control-Allow-Headers": "Authorization, Content-Type",
        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
      }),
      t.end()
    );
  const r = new URL(e.url, "http://x");
  if (r.pathname === "/api/sync" || r.pathname.indexOf("/api/sync/") === 0) return handleSync(e, t, r);
  if (r.pathname.indexOf("/api/auth/") === 0) return handleAuth(e, t, r);
  if ("/" === r.pathname)
    return (
      t.writeHead(200, { "Content-Type": "text/plain", "Access-Control-Allow-Origin": ORIGIN }),
      t.end("jay-ai search proxy ok - try /api/search?q=hello")
    );
  if ("/api/fetch" === r.pathname || "/api/search" === r.pathname) {
    if (!checkRateLimit(e)) return send(t, 429, { error: "rate limited" });
    if (!checkAuth(e, r.searchParams)) return send(t, 401, { error: "bad key" });
    if ("/api/fetch" === r.pathname) return handleFetch(e, t, r.searchParams);
    // ---- /api/search (unchanged behavior) ----
    const s = String(r.searchParams.get("q") || "").trim().slice(0, 300);
    let i = parseInt(r.searchParams.get("count") || "5", 10);
    if (!(i >= 1)) i = 5;
    if (i > 10) i = 10;
    if (!s) return send(t, 400, { error: "missing ?q=" });
    const n = Date.now(),
      c = s.toLowerCase() + "#" + i,
      l = cache.get(c);
    if (l && n - l.at < CACHE_MS) return send(t, 200, l.data);
    try {
      let e = [],
        r = "ddg-fetch";
      try {
        e = await ddgFetch(s, i);
      } catch (t) {
        e = [];
      }
      if (!e.length) {
        e = await bingPlaywright(s, i);
        r = "bing-playwright";
      }
      const o = { results: e.slice(0, i), provider: r };
      cachePut(cache, c, o);
      return send(t, 200, o);
    } catch (e) {
      return send(t, 502, { error: "search failed: " + String((e && e.message) || e).slice(0, 200) });
    }
  }
  return t.writeHead(404, { "Access-Control-Allow-Origin": ORIGIN }), t.end("not found");
}

openAuthDb();
if (smtpReady()) {
  getMailer().verify().then(
    function () { console.log("danauth smtp ok (" + SMTP_HOST + ":" + SMTP_PORT + " as " + SMTP_USER + ")"); },
    function (err) { console.warn("danauth smtp verify failed (will retry per send): " + String((err && err.message) || err).slice(0, 160)); }
  );
} else if (!ALLOW_NO_SMTP) {
  console.warn("danauth email NOT configured (set SMTP_USER/SMTP_PASS in .env, or ALLOW_NO_SMTP=1 for dev) — register/recover will answer 503 until configured.");
}
if (!AUTH_PEPPER) console.warn("danauth AUTH_PEPPER is empty — set a long random value in .env (email-code hashes rely on it).");
const __cleanupTimer = setInterval(cleanupAuth, 10 * 60 * 1000);
if (__cleanupTimer.unref) __cleanupTimer.unref();

server.listen(PORT, function () {
  console.log("jay-ai server on :" + PORT);
});
