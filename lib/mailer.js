// Outbound email (Zoho SMTP; dev fallback logs codes — never returns them in responses).
const config = require("./config");

let nodemailerLib = null;
try { nodemailerLib = require("nodemailer"); } catch (e) { nodemailerLib = null; }
let mailTransport = null;

function smtpReady() { return !!(config.SMTP_USER && config.SMTP_PASS && nodemailerLib); }
function getMailer() {
  if (mailTransport) return mailTransport;
  mailTransport = nodemailerLib.createTransport({
    host: config.SMTP_HOST, port: config.SMTP_PORT, secure: config.SMTP_PORT === 465,
    auth: { user: config.SMTP_USER, pass: config.SMTP_PASS },
    connectionTimeout: 15000, greetingTimeout: 10000, socketTimeout: 20000,
  });
  return mailTransport;
}
async function sendCodeEmail(to, purpose, code) {
  if (!smtpReady()) {
    if (config.ALLOW_NO_SMTP) { console.log("[auth:dev] " + purpose + " code for " + to + ": " + code); return; }
    throw Object.assign(new Error("email unavailable"), { status: 503 });
  }
  let subject, what;
  if (purpose === "verify") {
    subject = "Verify your danauth email";
    what = "verifying your danauth account";
  } else if (purpose === "email_change") {
    subject = "Confirm your new danauth email";
    what = "changing your danauth account email (enter this code in your settings to confirm the new address)";
  } else {
    subject = "Reset your danauth password";
    what = "resetting your danauth password";
  }
  await getMailer().sendMail({
    from: config.MAIL_FROM, to, subject,
    text: "Your danauth code: " + code + "\n\nUse this code for " + what + ". It expires in 10 minutes.\nIf you didn't request this, you can safely ignore this email.",
  });
}

module.exports = { smtpReady, getMailer, sendCodeEmail };
