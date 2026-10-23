// Shared env + tunables. Real secrets live in .env / environment, never in code.
// process.env always wins over .env.
const fs = require("fs");
const path = require("path");

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

// ---- danauth email auth ----
const AUTH_DB_PATH = process.env.AUTH_DB_PATH || "./danauth.sqlite";
const AUTH_PEPPER = process.env.AUTH_PEPPER || "";
const SMTP_HOST = process.env.SMTP_HOST || "smtp.zoho.com";
const SMTP_PORT = parseInt(process.env.SMTP_PORT || "465", 10) || 465;
const SMTP_USER = process.env.SMTP_USER || "";
const SMTP_PASS = process.env.SMTP_PASS || "";
const MAIL_FROM = process.env.MAIL_FROM || "danauth <noreply@danjaye.lol>";
const ALLOW_NO_SMTP = process.env.ALLOW_NO_SMTP === "1";
const TOKEN_DAYS = Math.min(Math.max(parseInt(process.env.TOKEN_DAYS || "30", 10) || 30, 1), 365);

const EMAIL_CODE_MS = 10 * 60 * 1000; // verify + reset + email-change codes live 10 min
const LOGIN_CODE_MS = 60 * 1000; // handoff codes live 60s, single-use
const EMAIL_CODE_MAX_ATTEMPTS = 5;

// ---- sync ----
const SYNC_QUOTA_BYTES = (parseInt(process.env.SYNC_QUOTA_MB || "50", 10) || 50) * 1024 * 1024;
const TOMBSTONE_GC_MS = 30 * 86400 * 1000;

module.exports = {
  PORT, SECRET, ORIGIN,
  CACHE_MS, FETCH_CACHE_MS, FETCH_MAX_BYTES, FETCH_TEXT_DEFAULT, FETCH_TEXT_MAX, MAX_CACHE_ENTRIES,
  AUTH_DB_PATH, AUTH_PEPPER, SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, MAIL_FROM,
  ALLOW_NO_SMTP, TOKEN_DAYS, EMAIL_CODE_MS, LOGIN_CODE_MS, EMAIL_CODE_MAX_ATTEMPTS,
  SYNC_QUOTA_BYTES, TOMBSTONE_GC_MS,
};
