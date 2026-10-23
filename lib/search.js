// Web search: DDG static first, headless-Bing fallback (behavior unchanged).
const browserLib = require("./browser");
const config = require("./config");
const util = require("./util");

const cache = new Map(); // search cache: "q#count" -> { at, data }

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
  const r = await browserLib.getBrowser(),
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

async function handleSearch(req, res, params) {
  const q = String(params.get("q") || "").trim().slice(0, 300);
  let count = parseInt(params.get("count") || "5", 10);
  if (!(count >= 1)) count = 5;
  if (count > 10) count = 10;
  if (!q) return util.send(res, 400, { error: "missing ?q=" });
  const now = Date.now(),
    key = q.toLowerCase() + "#" + count,
    hit = cache.get(key);
  if (hit && now - hit.at < config.CACHE_MS) return util.send(res, 200, hit.data);
  try {
    let results = [],
      provider = "ddg-fetch";
    try {
      results = await ddgFetch(q, count);
    } catch (e) {
      results = [];
    }
    if (!results.length) {
      results = await bingPlaywright(q, count);
      provider = "bing-playwright";
    }
    const out = { results: results.slice(0, count), provider };
    util.cachePut(cache, key, out);
    return util.send(res, 200, out);
  } catch (e) {
    return util.send(res, 502, { error: "search failed: " + String((e && e.message) || e).slice(0, 200) });
  }
}

module.exports = { handleSearch, ddgFetch, bingPlaywright };
