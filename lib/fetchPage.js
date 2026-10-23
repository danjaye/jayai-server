// Full page fetch as clean text, JS-rendered when needed (behavior unchanged).
const dns = require("dns").promises;
const browserLib = require("./browser");
const config = require("./config");
const util = require("./util");

const fetchCache = new Map(); // fetch cache: "fetch:mode:maxChars:url" -> { at, data }

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
    throw util.fail(400, "invalid url");
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") throw util.fail(400, "only http(s) allowed");
  if (u.username || u.password) throw util.fail(400, "credentials in url not allowed");
  if (hostBlocked(u.hostname)) throw util.fail(403, "blocked host");
  let addrs;
  try {
    addrs = await dns.lookup(u.hostname, { all: true });
  } catch (e) {
    throw util.fail(502, "dns failed for host");
  }
  if (!addrs.length) throw util.fail(502, "dns failed for host");
  for (const a of addrs) {
    if (isBlockedIp(a.address)) throw util.fail(403, "blocked host");
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
      if (hostBlocked(fin.hostname)) throw util.fail(403, "blocked host after redirect");
      await assertSafeUrl(fin.href); // re-check resolved IPs post-redirect
    } catch (e) {
      if (e && e.status) throw e;
    }
    if (!r.ok) throw util.fail(502, "fetch " + r.status);
    const ctype = (r.headers.get("content-type") || "").toLowerCase();
    const texty = /text\/|html|xml|json|javascript/.test(ctype) || ctype === "";
    if (!texty) throw util.fail(415, "unsupported content type: " + (ctype.split(";")[0] || "unknown"));
    const reader = r.body.getReader();
    const chunks = [];
    let bytes = 0;
    for (;;) {
      const part = await reader.read();
      if (part.done) break;
      bytes += part.value.length;
      if (bytes > config.FETCH_MAX_BYTES) {
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
    if (e && e.name === "AbortError") throw util.fail(502, "fetch timed out");
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
    b = await browserLib.getBrowser();
  } catch (e) {
    throw util.fail(503, "browser unavailable: " + String((e && e.message) || e).slice(0, 160));
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

async function handleFetch(req, res, params) {
  const raw = String(params.get("url") || "").trim();
  if (!raw) return util.send(res, 400, { error: "missing ?url=" });
  if (raw.length > 2000) return util.send(res, 400, { error: "url too long" });
  let mode = String(params.get("mode") || "auto").toLowerCase();
  if (["auto", "raw", "js"].indexOf(mode) < 0) mode = "auto";
  let maxChars = parseInt(params.get("maxChars") || String(config.FETCH_TEXT_DEFAULT), 10);
  if (isNaN(maxChars)) maxChars = config.FETCH_TEXT_DEFAULT;
  maxChars = Math.min(Math.max(maxChars, 500), config.FETCH_TEXT_MAX);

  try {
    await assertSafeUrl(raw);
  } catch (e) {
    return util.send(res, (e && e.status) || 400, { error: String((e && e.message) || e).slice(0, 200) });
  }

  const cacheKey = "fetch:" + mode + ":" + maxChars + ":" + raw;
  const hit = fetchCache.get(cacheKey);
  if (hit && Date.now() - hit.at < config.FETCH_CACHE_MS) return util.send(res, 200, hit.data);

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

    if (!text) return util.send(res, 502, { error: "page was empty" });
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
    util.cachePut(fetchCache, cacheKey, out);
    return util.send(res, 200, out);
  } catch (e) {
    return util.send(res, (e && e.status) || 502, {
      error: "fetch failed: " + String((e && e.message) || e).slice(0, 200),
    });
  }
}

module.exports = { handleFetch, assertSafeUrl };
