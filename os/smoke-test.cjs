const { chromium } = require("playwright");
const path = require("node:path");
(async () => {
  const browser = await chromium.launch({ headless: true });
  try {
    const page = await browser.newPage();
    await page.goto("file://" + path.resolve("os/index.html"));
    await page.getByRole("button", { name: "Test Lab" }).click();
    await page.getByRole("button", { name: "Run all tests" }).click();
    await page.getByText("4/4 tests passed.", { exact: false }).waitFor({ timeout: 5000 });
    const summary = await page.locator("#testSummary").textContent();
    if (!summary || !summary.startsWith("4/4 tests passed")) throw new Error("Unexpected test summary: " + summary);
    process.stdout.write("AntiOS browser self-tests passed: " + summary + "\n");
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error); process.exit(1); });
