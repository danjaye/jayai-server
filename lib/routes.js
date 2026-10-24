// HTTP routing: OPTIONS/CORS + health + search/fetch (key-gated) + auth + sync.
const config = require("./config");
const util = require("./util");
const searchLib = require("./search");
const fetchLib = require("./fetchPage");
const authLib = require("./auth");
const syncLib = require("./sync");
const moderateLib = require("./moderate");

async function handleRequest(req, res) {
  if ("OPTIONS" === req.method)
    return (
      res.writeHead(204, {
        "Access-Control-Allow-Origin": config.ORIGIN,
        "Access-Control-Allow-Headers": "Authorization, Content-Type",
        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
      }),
      res.end()
    );
  const url = new URL(req.url, "http://x");
  if (url.pathname === "/api/admin" || url.pathname.indexOf("/api/admin/") === 0) return moderateLib.handleAdmin(req, res, url);
  if (url.pathname === "/api/sync" || url.pathname.indexOf("/api/sync/") === 0) return syncLib.handleSync(req, res, url);
  if (url.pathname.indexOf("/api/auth/") === 0) return authLib.handleAuth(req, res, url);
  if ("/" === url.pathname)
    return (
      res.writeHead(200, { "Content-Type": "text/plain", "Access-Control-Allow-Origin": config.ORIGIN }),
      res.end("jay-ai search proxy ok - try /api/search?q=hello")
    );
  if ("/api/fetch" === url.pathname || "/api/search" === url.pathname) {
    if (!util.checkRateLimit(req)) return util.send(res, 429, { error: "rate limited" });
    if (!util.checkAuth(req, url.searchParams)) return util.send(res, 401, { error: "bad key" });
    if ("/api/fetch" === url.pathname) return fetchLib.handleFetch(req, res, url.searchParams);
    return searchLib.handleSearch(req, res, url.searchParams);
  }
  return res.writeHead(404, { "Access-Control-Allow-Origin": config.ORIGIN }), res.end("not found");
}

module.exports = { handleRequest };
