// Password hashing + opaque tokens/codes + input validation.
// No DB access here — pure crypto + shapes.
const crypto = require("crypto");
const config = require("./config");

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
function pepperHash(purpose, code) { return sha256hex(config.AUTH_PEPPER + "|" + purpose + "|" + String(code)); }
function newOpaque() { return crypto.randomBytes(32).toString("base64url"); }
function newEmailCode() { return String(crypto.randomInt(0, 1000000)).padStart(6, "0"); }

// --- input validation (mirrored client-side for UX; enforced here) ---
function validUsername(v) { return typeof v === "string" && /^[a-z0-9_-]{3,20}$/.test(v); }
function validEmail(v) { return typeof v === "string" && v.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(v); }
function validPassword(v) { return typeof v === "string" && v.length >= 10 && v.length <= 512; }

module.exports = {
  scryptHash, scryptVerify, DUMMY_PASS_HASH,
  sha256hex, pepperHash, newOpaque, newEmailCode,
  validUsername, validEmail, validPassword,
};
