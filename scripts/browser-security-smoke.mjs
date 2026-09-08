import assert from "node:assert/strict";
import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";

const { chromium } = await import(process.env.PLAYWRIGHT_MODULE || "playwright");
process.env.MOCK_GITHUB_SCAN = "1";
const { handleApiRequest } = await import("../server.mjs");
const response = await handleApiRequest({ path: "/api/github/scan", method: "POST", trustedClientAddress: "browser-fixture", body: JSON.stringify({ url: "https://github.com/fixture/public" }) });
const complete = JSON.parse(response.body);
assert.equal(complete.status, "complete");
const output = resolve(".deploy/browser-checks");
await mkdir(output, { recursive: true });
const base = process.env.TEST_BASE_URL || "http://127.0.0.1:5173";
const browser = await chromium.launch({ headless: true });
const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
const errors = [];
page.on("pageerror", (error) => errors.push(error.message));
let scan = complete, githubWrites = 0, decisions = [], rejectWorker = false;
page.on("dialog", async (dialog) => {
  const accept = decisions.length ? decisions.shift() : true;
  if (accept) await dialog.accept(); else await dialog.dismiss();
});
// No browser test may contact GitHub or another external service.
await page.route("**/*", async (route) => {
  const url = new URL(route.request().url());
  if (url.hostname === "api.github.com") {
    if (route.request().method() === "POST") { githubWrites++; return route.fulfill({ json: { number: 43, html_url: "https://github.com/fixture/public/issues/43" } }); }
    return route.fulfill({ json: { items: [{ number: 42, state: "closed", title: "CVE-2024-0001 previous version", html_url: "https://github.com/fixture/public/issues/42" }] } });
  }
  if (url.origin !== new URL(base).origin) return route.abort();
  if (url.pathname === "/generated/sbom-worker.js" && rejectWorker) return route.abort();
  if (url.pathname === "/api/github/scan") return route.fulfill({ json: scan });
  if (url.pathname === "/api/health") return route.fulfill({ json: { status: "ok", sources: [] } });
  if (url.pathname.startsWith("/api/")) return route.fulfill({ status: 503, json: { message: "Offline browser fixture" } });
  return route.continue();
});

try {
  await page.goto(base);
  await page.locator("#content .empty-panel").waitFor();
  const cve = "CVE-2026-900001";
  const bom = {
    bomFormat: "CycloneDX", specVersion: "1.5",
    components: ["safe", "exposed"].map((name) => ({ name, version: "1.0.0", "bom-ref": name, purl: "pkg:npm/" + name + "@1.0.0" })),
    vulnerabilities: [{ id: cve, affects: [{ ref: "safe" }], analysis: { state: "not_affected" } }, { id: cve, affects: [{ ref: "exposed" }] }]
  };
  const second = { ...bom, vulnerabilities: [{ id: cve, affects: [{ ref: "safe" }] }] };
  await page.locator("#sbomInput").setInputFiles([bom, second].map((data) => ({ name: "same.json", mimeType: "application/json", buffer: Buffer.from(JSON.stringify(data)) })));
  await page.getByRole("heading", { name: "Affected Packages for " + cve }).waitFor();
  const packageTable = page.locator("table").filter({ has: page.getByRole("columnheader", { name: "Package", exact: true }) });
  const rows = await packageTable.locator("tbody tr").allTextContents();
  assert.equal(rows.length, 3);
  assert(rows.find((row) => row.includes("safe")).includes("Needs verification"));
  assert(rows.find((row) => row.includes("exposed")).includes("Unreviewed"));
  await page.screenshot({ path: resolve(output, "sbom-desktop.png"), fullPage: true });
  await page.locator("#sbomInput").setInputFiles({ name: "invalid.json", mimeType: "application/json", buffer: Buffer.from("{invalid") });
  await page.locator("#toast").filter({ hasText: /JSON|property|parse|position/i }).waitFor();
  assert.equal(await page.locator("#sbomList [data-action='open-sbom']").count(), 1);
  assert.deepEqual(await packageTable.locator("tbody tr").allTextContents(), rows);

  rejectWorker = true;
  await page.locator("#sbomInput").setInputFiles({ name: "worker-failure.json", mimeType: "application/json", buffer: Buffer.from(JSON.stringify(bom)) });
  await page.locator("#toast").filter({ hasText: "SBOM worker failed" }).waitFor();
  assert.equal(await page.locator("#sbomList [data-action='open-sbom']").count(), 1);
  rejectWorker = false;
  const xml = '<bom xmlns="http://cyclonedx.org/schema/bom/1.5"><components><component bom-ref="xml" type="library"><name>xml-package</name><version>1.0.0</version></component></components></bom>';
  await page.locator("#sbomInput").setInputFiles({ name: "inventory.xml", mimeType: "application/xml", buffer: Buffer.from(xml) });
  await page.locator("#sbomList [data-action='open-sbom']").filter({ hasText: "inventory" }).waitFor();
  assert.equal(await page.locator("#sbomList [data-action='open-sbom']").count(), 2);
  assert((await page.locator("#content").innerText()).includes("xml-package"));
  console.log("PASS browser worker JSON/XML, scoped VEX, duplicate files and fail-closed recovery");

  await page.locator("[data-action='open-github-scan']").first().click();
  await page.locator("#githubRepositoryUrl").fill("https://github.com/fixture/public");
  await page.getByRole("button", { name: "Scan repository", exact: true }).click();
  await page.getByText("Scan complete", { exact: true }).waitFor();
  await page.locator("[data-github-cve]").check();
  await page.locator("[data-action='review-github-issues']").click();
  await page.locator(".issue-draft-body > summary").first().click();
  assert((await page.locator(".issue-body-preview").innerText()).includes("CVE-2024-0001"));
  await page.screenshot({ path: resolve(output, "issue-review-desktop.png"), fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), "Issue review overflow on mobile");
  assert(await page.locator(".issue-body-preview").evaluate((element) => element.scrollWidth <= element.clientWidth + 1), "Issue body should wrap without horizontal scrolling");
  await page.screenshot({ path: resolve(output, "issue-review-mobile.png"), fullPage: true });
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.locator("#githubIssueToken").fill("offline-token-not-a-real-credential");
  await page.locator("#githubIssueConsent").check();
  decisions = [true, false, false];
  await page.locator("[data-action='publish-github-issues']").click();
  await page.getByText("Analyst cancelled publication for this CVE.", { exact: true }).waitFor();
  assert.equal(githubWrites, 0);
  assert.equal(await page.locator("#githubIssueToken").inputValue(), "");
  assert.equal(await page.evaluate(() => Object.values(localStorage).some((value) => value.includes("offline-token"))), false);
  console.log("PASS browser full issue preview and cancellation without a GitHub write or token persistence");

  await page.locator("[data-action='back-github-results']").click();
  await page.locator("[data-action='reset-github-scan']").click();
  scan = { ...complete, status: "failed", packageCount: 0, vulnerabilityCount: null, packages: [], truncated: true, coverage: { checkedPackageCount: 0, reasons: ["OSV lookup failed; no package was checked."], unresolvedAdvisoryIds: [] } };
  await page.locator("#githubRepositoryUrl").fill("https://github.com/fixture/public");
  await page.getByRole("button", { name: "Scan repository", exact: true }).click();
  await page.getByText("Scan failed", { exact: true }).waitFor();
  assert.equal(await page.locator(".metric-value").filter({ hasText: "Unknown" }).count(), 2);
  assert((await page.locator("#content").innerText()).includes("No CVE conclusion available"));
  await page.screenshot({ path: resolve(output, "failed-scan-desktop.png"), fullPage: true });
  for (const width of [390, 768, 1440]) {
    await page.setViewportSize({ width, height: 900 });
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), "Viewport overflow at " + width);
    await page.screenshot({ path: resolve(output, "coverage-" + width + ".png"), fullPage: true });
  }
  assert.deepEqual(errors, []);
  console.log("PASS browser failed coverage states, desktop/tablet/mobile layout and no uncaught page errors");
  console.log("Browser screenshots: " + output);
} finally { await browser.close(); }
