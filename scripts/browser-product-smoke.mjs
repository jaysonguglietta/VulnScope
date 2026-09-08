import assert from "node:assert/strict";
import { mkdir, readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { chromium } from "playwright";

process.env.MOCK_RESEARCH = "1";
process.env.MOCK_GITHUB_SCAN = "1";
const { handleApiRequest } = await import("../server.mjs");
const base = process.env.TEST_BASE_URL;
const id = "CVE-2024-0001";
const research = JSON.parse((await handleApiRequest({ path: "/api/research", query: new URLSearchParams({ cve: id }), trustedClientAddress: "fixture" })).body);
research.sourceResults = ["cve", "nvd", "kev", "epss", "github"].map((id) => ({ id, label: id, status: "ok" }));
research.metrics.kev = { listed: true }; research.metrics.epss = { epss: 0 };
research.claims = [{ id: "claim-1", title: "Vendor advisory narrative", body: "Full vendor text\nVerify the affected branch", url: "https://example.com/advisory", authority: "Publisher statement", review: "Unreviewed" }];
const scan = JSON.parse((await handleApiRequest({ path: "/api/github/scan", method: "POST", body: JSON.stringify({ url: "https://github.com/fixture/public" }), trustedClientAddress: "fixture" })).body);
const browser = await chromium.launch();
const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, acceptDownloads: true });
const errors = [];
let githubWrites = 0;
context.on("page", (page) => { page.on("pageerror", (e) => errors.push(e.message)); page.on("dialog", (dialog) => dialog.accept()); });
await context.route("**/*", async (route) => {
  const request = route.request(), url = new URL(request.url());
  if (url.hostname === "api.github.com") {
    if (request.method() === "POST") { githubWrites++; return route.abort("failed"); }
    return route.fulfill({ json: { items: [] } });
  }
  if (url.origin !== new URL(base).origin) return route.abort();
  if (url.pathname === "/api/research") {
    if (url.searchParams.get("cve") === "CVE-2024-0002") await new Promise((r) => setTimeout(r, 350));
    return route.fulfill({ json: { ...research, id: url.searchParams.get("cve"), title: "Fixture " + url.searchParams.get("cve"), generatedAt: new Date().toISOString() } }).catch(() => {});
  }
  if (url.pathname === "/api/github/scan") return route.fulfill({ json: scan });
  if (url.pathname === "/api/enrich") {
    const { packages } = request.postDataJSON();
    return route.fulfill({ json: { generatedAt: new Date().toISOString(), status: "complete", packageCount: packages.length, vulnerabilityCount: 1, sourceResults: [], coverage: { checkedPackageCount: packages.length, reasons: [], unresolvedAdvisoryIds: [] }, packages: packages.map((p) => ({ ...p, checkStatus: "complete", vulnerabilities: [{ id, cves: [id], aliases: [id], severity: "HIGH", detailStatus: "complete", summary: "Fixture advisory", fixedVersions: ["2.0.0"], references: [] }] })) } });
  }
  if (url.pathname === "/api/health") return route.fulfill({ json: { status: "ok", sources: [] } });
  if (url.pathname.startsWith("/api/")) return route.fulfill({ status: 503, json: { message: "Offline fixture" } });
  return route.continue();
});
const page = await context.newPage();
const output = resolve(".deploy/browser-checks"); await mkdir(output, { recursive: true });
async function search(cve) { await page.locator("#cveInput").fill(cve); await page.locator("#searchForm").dispatchEvent("submit"); await page.getByRole("heading", { name: "Fixture " + cve, exact: true }).waitFor(); }
async function workspace() { await page.locator('[data-action="tab"][data-value="workspace"]').click(); }
async function cases() { return page.evaluate(() => new Promise((resolve, reject) => { const req = indexedDB.open("vulnscope-workspace", 1); req.onerror = () => reject(req.error); req.onsuccess = () => { const db = req.result; const tx = db.transaction("records"), result = tx.objectStore("records").index("collection").getAll("cases"); result.onsuccess = () => resolve(result.result.map((r) => r.value)); tx.oncomplete = () => db.close(); }; })); }
try {
  await page.goto(base);
  await page.locator("#content .empty-panel").waitFor();
  await search(id); await workspace();
  await page.locator('[data-case-field="notes"]').fill("Persisted analyst notes");
  await page.locator('[data-action="open-tools"]').first().click();
  await page.getByRole("dialog", { name: "Unsaved case changes" }).getByRole("button", { name: "Stay here" }).click();
  assert.equal(await page.locator('[data-case-field="notes"]').inputValue(), "Persisted analyst notes");
  await page.locator('[data-action="save"]').first().click();
  await page.locator("#toast").filter({ hasText: /Saved|saved/ }).waitFor();
  assert.equal((await cases())[0].investigation.caseDraft.notes, "Persisted analyst notes");
  await page.reload();
  await page.locator('[data-action="open-case"]').filter({ hasText: id }).click(); await workspace();
  assert.equal(await page.locator('[data-case-field="notes"]').inputValue(), "Persisted analyst notes");

  await page.evaluate(() => { window.originalPut = IDBObjectStore.prototype.put; IDBObjectStore.prototype.put = function(value, ...args) { if (value.collection === "cases") throw new DOMException("Fixture quota exceeded", "QuotaExceededError"); return window.originalPut.call(this, value, ...args); }; });
  await page.locator('[data-case-field="notes"]').fill("Unsaved quota draft");
  await page.locator('[data-action="save"]').first().click();
  await page.locator("#toast").filter({ hasText: /quota|failed/i }).waitFor();
  assert.equal((await cases())[0].investigation.caseDraft.notes, "Persisted analyst notes");
  assert.equal(await page.locator('[data-case-field="notes"]').inputValue(), "Unsaved quota draft");
  await page.evaluate(() => { IDBObjectStore.prototype.put = window.originalPut; });
  await page.locator('[data-action="save"]').first().click();
  await page.locator("#toast").filter({ hasText: /Saved|saved/ }).waitFor();
  console.log("PASS browser durable save/reload, unsaved guard and quota failure with retained draft");

  const second = await context.newPage(); await second.goto(base);
  await second.locator('[data-action="open-case"]').filter({ hasText: id }).click();
  await second.locator('[data-action="tab"][data-value="workspace"]').click();
  await second.locator('[data-case-field="notes"]').fill("Second tab revision");
  await second.locator('[data-action="save"]').first().click();
  await second.locator("#toast").filter({ hasText: /Saved|saved/ }).waitFor();
  await page.locator('[data-case-field="notes"]').fill("Stale competing draft");
  await page.locator('[data-action="save"]').first().click();
  await page.locator("#toast").filter({ hasText: "another tab" }).waitFor();
  assert.equal((await cases())[0].investigation.caseDraft.notes, "Second tab revision");
  await page.locator('[data-action="open-tools"]').first().click();
  await page.getByRole("dialog").getByRole("button", { name: "Discard draft" }).click();
  await second.close();

  const downloadEvent = page.waitForEvent("download");
  await page.locator('[data-action="backup"]').click();
  await page.getByRole("dialog").getByRole("button", { name: "Export backup" }).click();
  const backup = await downloadEvent;
  const backupText = await readFile(await backup.path(), "utf8");
  assert(!JSON.parse(backupText).inventory);
  await page.locator("#restoreInput").setInputFiles({ name: "backup.json", mimeType: "application/json", buffer: Buffer.from(backupText) });
  await page.getByRole("dialog", { name: "Restore preview" }).getByRole("button", { name: "Merge new IDs" }).click();
  await page.locator("#toast").filter({ hasText: "Backup restored" }).waitFor();
  console.log("PASS browser cross-tab conflict, backup export and restore preview/merge");

  await page.locator("#cveInput").fill("CVE-2024-0002"); await page.locator("#searchForm").dispatchEvent("submit");
  await search("CVE-2024-0003");
  await page.waitForTimeout(500);
  assert.equal(await page.getByRole("heading", { name: "Fixture CVE-2024-0003", exact: true }).count(), 1);
  await page.locator('[data-action="open-exposures"]').first().click();
  assert((await page.locator("#content").innerText()).includes("CVE-2024-0003"));
  console.log("PASS browser latest-search-wins and researched CVEs remain in unlinked triage");

  const bom = { bomFormat: "CycloneDX", specVersion: "1.5", components: [{ name: "fixture", version: "1.0.0", purl: "pkg:npm/fixture@1.0.0", "bom-ref": "fixture" }] };
  await page.locator("#sbomInput").setInputFiles({ name: "inventory.json", mimeType: "application/json", buffer: Buffer.from(JSON.stringify(bom)) });
  await page.locator('[data-action="enrich-sbom"]').waitFor();
  await page.locator('[data-action="enrich-sbom"]').click();
  await page.getByText("Scan complete", { exact: true }).waitFor();
  await search(id);
  await page.locator('[data-action="open-sbom-cve-report"]').first().waitFor();
  await page.locator('[data-action="open-sbom-cve-report"]').first().click();
  await page.getByRole("heading", { name: "Affected Packages for " + id }).waitFor();
  await page.locator('[data-action="open-exposures"]').first().click();
  assert((await page.locator("#content").innerText()).includes("fixture"));
  await page.locator('[data-action="decide-exposure"]').first().click();
  const decision = page.getByRole("dialog", { name: "Target decision" });
  await decision.getByLabel("Disposition").selectOption("Not affected");
  await decision.getByLabel("Review by").fill("2099-01-01");
  await decision.getByLabel("Rationale", { exact: true }).fill("Fixture scope reviewed");
  await decision.getByLabel("Verification evidence / source links").fill("https://example.com/verification");
  await decision.getByRole("button", { name: "Save scoped decision" }).click();
  await page.locator('[data-action="open-tools"]').first().click();
  await page.locator('[data-action="revoke-decision"]').click();
  await page.getByText("Needs verification", { exact: true }).waitFor();
  console.log("PASS browser OSV enrichment joins exact-CVE drilldown and scoped decision revocation");

  await search(id);
  await page.locator(".claim-record summary").click();
  await page.locator('[data-action="review-claim"]').click();
  await page.getByRole("dialog").getByLabel("Reason and supporting source").fill("Confirmed against vendor narrative");
  await page.getByRole("dialog").getByRole("button", { name: "Save", exact: true }).click();
  await page.locator('[data-action="tab"][data-value="remediation"]').click();
  await page.getByLabel("Target package or asset").fill("pkg:npm/fixture@1.0.0");
  await page.getByLabel("Remediation steps", { exact: true }).fill("Upgrade fixture to 2.0.0 and redeploy");
  await page.locator('[data-action="save-plan"]').click();
  await page.locator("#toast").filter({ hasText: "Scoped plan saved" }).waitFor();
  assert.equal((await cases())[0].investigation.caseDraft.plan.steps, "Upgrade fixture to 2.0.0 and redeploy");
  for (const width of [390, 768, 1440]) {
    await page.setViewportSize({ width, height: 900 });
    await page.evaluate(() => window.scrollTo(0, 0));
    await page.waitForTimeout(100);
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), `Remediation overflow at ${width}`);
    await page.screenshot({ path: resolve(output, `product-plan-${width}.png`), fullPage: true });
    await page.screenshot({ path: resolve(output, `product-viewport-${width}.png`) });
  }
  await page.setViewportSize({ width: 390, height: 900 });
  await page.locator('.mobile-workspaces [data-action="open-tools"]').click();
  await page.goBack();
  await page.getByLabel("Target package or asset").waitFor();
  console.log("PASS browser claim review, scoped plan persistence, mobile navigation and browser back");

  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.locator('[data-action="open-github-scan"]').first().click();
  await page.locator("#githubRepositoryUrl").fill("https://github.com/fixture/public");
  await page.getByRole("button", { name: "Scan repository", exact: true }).click();
  await page.getByText("Scan complete", { exact: true }).waitFor();
  await page.locator('[data-github-cve]').check();
  await page.locator('[data-action="review-github-issues"]').click();
  for (let attempt = 0; attempt < 2; attempt++) {
    await page.locator("#githubIssueToken").fill("offline-product-fixture-no-credential");
    await page.locator("#githubIssueConsent").check();
    await page.locator('[data-action="publish-github-issues"]').click();
    await page.getByRole("button", { name: "Publish 1 issue", exact: true }).waitFor();
    await page.locator("#toast").filter({ hasText: "GitHub issue publishing complete" }).waitFor();
    if (attempt === 0) assert((await page.locator("#content").innerText()).includes("Unknown"));
  }
  assert.equal(githubWrites, 1, "Unknown write must reconcile before any repeat POST");
  assert((await page.locator("#content").innerText()).includes("Previous filing outcome is unknown"));
  assert.equal(await page.locator("#githubIssueToken").inputValue(), "");
  assert.deepEqual(errors, []);
  console.log("PASS browser durable unknown filing receipt blocks repeat issue POST; no uncaught errors");
} catch (error) {
  console.error("Page errors:", errors);
  console.error("Last toast:", await page.locator("#toast").textContent());
  console.error("Content:", (await page.locator("#content").innerText()).slice(-2500));
  await page.screenshot({ path: resolve(output, "product-failure.png"), fullPage: true });
  throw error;
} finally { await context.close(); await browser.close(); }
