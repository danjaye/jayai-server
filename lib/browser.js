// Shared headless-Chromium singleton (search fallback + JS page renders).
const { chromium } = require("playwright");

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
async function closeBrowser() {
  try { if (browser) await browser.close(); } catch (e) {}
  browser = null;
}

module.exports = { getBrowser, closeBrowser };
