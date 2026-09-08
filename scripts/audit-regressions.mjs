import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import vm from "node:vm";
import { buildExposureRows } from "../public/modules/workspace.js";
import { buildRepositoryCveFindings } from "../public/modules/github.js";
import { buildSbomReport, applySbomVexDecisions } from "../public/modules/sbom-report.js";
import { parseSbomPayload } from "../public/modules/sbom-worker-core.js";
import { createSbomBudget } from "../public/modules/sbom-budget.js";
import { createMonitorHandler } from "../monitor.mjs";

// Each fixture replaces transport; no real GitHub or AWS calls are made.
process.env.GITHUB_TOKEN = "audit-private-capable-token";
process.env.TRUST_PROXY = "1";
delete process.env.ORIGIN_VERIFY_SECRET;
delete process.env.MOCK_RESEARCH;
delete process.env.MOCK_GITHUB_SCAN;
globalThis.fetch = async () => { throw new Error("Unexpected offline fixture request"); };
const server = await import("../server.mjs");
const json = (data, status = 200) => new Response(JSON.stringify(data), { status });
const cve = "CVE-2026-900001";
let checks = 0;
function passed(name) { checks++; console.log("PASS " + name); }

const requests = [];
globalThis.fetch = async (value, options = {}) => {
  const url = new URL(value);
  if (url.hostname === "api.github.com") {
    requests.push({ url, headers: options.headers });
    if (url.pathname === "/search/repositories") return json({ total_count: 2, items: [
      { private: true, full_name: "SECRET-REPO", description: "SECRET-TEXT" },
      { private: false, full_name: "fixture/public", html_url: "https://github.com/fixture/public" }
    ] });
    if (url.pathname === "/search/issues") return json({ items: [{ title: "SECRET-INCIDENT", repository_url: "https://api.github.com/repos/fixture/private" }] });
    if (url.pathname === "/repos/fixture/private") return json({ private: true });
    return json([]);
  }
  if (url.hostname === "cveawg.mitre.org") return json({ cveMetadata: { cveId: cve }, containers: {} });
  throw new Error("Offline source unavailable");
};
const privateProbe = await server.handleApiRequest({ path: "/api/research", query: new URLSearchParams({ cve }), trustedClientAddress: "privacy" });
assert(!privateProbe.body.includes("SECRET-"));
assert(requests.every((item) => !item.headers.authorization));
assert(requests.filter((item) => item.url.pathname.startsWith("/search/")).every((item) => item.url.searchParams.get("q").includes("is:public")));
const cached = await server.handleApiRequest({ path: "/api/research", query: new URLSearchParams({ cve }), trustedClientAddress: "other-client" });
assert(!cached.body.includes("SECRET-"));
passed("F01 private search results cannot cross public API or cache");

const metadata = { private: false, owner: { login: "fixture" }, name: "public", full_name: "fixture/public", default_branch: "main" };
let mode = "batch-failure";
globalThis.fetch = async (value, options = {}) => {
  assert(!options.headers?.authorization);
  const url = new URL(value);
  if (url.pathname === "/repos/fixture/public") return json(metadata);
  if (url.pathname.endsWith("/generate-report")) return json({ sbom_url: "https://api.github.com/repos/fixture/public/dependency-graph/sbom/fetch-report/11111111-1111-1111-1111-111111111111" }, 201);
  if (url.pathname.includes("/fetch-report/")) return json({ sbom: { packages: [{ name: "fixture-package", versionInfo: "1.0.0", externalRefs: [{ referenceLocator: "pkg:npm/fixture-package@1.0.0" }] }] } });
  if (url.pathname === "/v1/querybatch") {
    if (mode === "batch-failure") return json({}, 503);
    if (mode === "pagination") return json({ results: [{ next_page_token: "next" }] });
    if (mode === "clean") return json({ results: [{}] });
    if (mode === "malformed") return json({ results: [{ vulns: [{}] }] });
    return json({ results: [{ vulns: [{ id: mode === "native-cve" ? cve : "GHSA-test-detail" }] }] });
  }
  if (mode === "native-cve") return json({ id: cve, affected: [] });
  return json({}, 503);
};
for (const value of ["batch-failure", "detail-failure", "pagination", "native-cve", "clean", "malformed"]) {
  mode = value;
  const response = await server.handleApiRequest({ path: "/api/github/scan", method: "POST", trustedClientAddress: value, body: JSON.stringify({ url: "https://github.com/fixture/public" }) });
  assert.equal(response.statusCode, 200);
  const result = JSON.parse(response.body);
  if (["native-cve", "clean"].includes(mode)) assert.equal(result.status, "complete");
  else { assert.notEqual(result.status, "complete"); assert(result.truncated); }
  if (mode === "batch-failure") assert.equal(result.coverage.checkedPackageCount, 0);
  if (mode === "detail-failure") assert.deepEqual(result.coverage.unresolvedAdvisoryIds, ["GHSA-test-detail"]);
  if (mode === "native-cve") assert.equal(buildRepositoryCveFindings(result)[0].cve, cve);
}
passed("F03 failed, partial and checked-clean scans are distinct");
passed("F04 primary CVE IDs survive OSV normalization and grouping");

process.env.MOCK_RESEARCH = "1";
const statuses = [];
for (let i = 0; i < 35; i++) statuses.push((await server.handleApiRequest({ path: "/api/research", remoteAddress: "127.0.0.1", headers: { "x-forwarded-for": "192.0.2." + i + ", 198.51.100.1" }, query: new URLSearchParams({ cve: "CVE-2026-900002" }) })).statusCode);
assert.equal(statuses.at(-1), 429);
for (const forwarded of ["fe80::1%eth0", ["192.0.2.1", "192.0.2.2"], "not-an-address"]) {
  assert.equal((await server.handleApiRequest({ path: "/api/research", remoteAddress: "127.0.0.1", headers: { "x-forwarded-for": forwarded }, query: new URLSearchParams({ cve: "CVE-2026-900002" }) })).statusCode, 429);
}
passed("F05 rotating untrusted XFF prefixes cannot reset application quotas");

const source = {
  bomFormat: "CycloneDX", specVersion: "1.5",
  components: [{ name: "safe", version: "1.0.0", "bom-ref": "safe", purl: "pkg:npm/safe@1.0.0" }, { name: "exposed", version: "1.0.0", "bom-ref": "exposed", purl: "pkg:npm/exposed@1.0.0" }],
  vulnerabilities: [{ id: cve, affects: [{ ref: "safe" }], analysis: { state: "not_affected" } }, { id: cve, affects: [{ ref: "exposed" }] }]
};
const parsed = parseSbomPayload({ name: "same.json" }, JSON.stringify(source)).parsed;
const second = parseSbomPayload({ name: "same.json" }, JSON.stringify({ ...source, vulnerabilities: [{ id: cve, affects: [{ ref: "safe" }] }] })).parsed;
const report = buildSbomReport([parsed, second]);
const firstSafe = report.cves[0].affectedPackages.find((pkg) => pkg.name === "safe" && pkg.vexClaims.length);
firstSafe.vexClaims[0].trusted = true;
applySbomVexDecisions(report);
const exposures = buildExposureRows({ sbomReports: [report] });
assert.equal(exposures.filter((row) => row.vexStatus === "Not affected").length, 1);
assert(exposures.filter((row) => row.packageName === "exposed").every((row) => row.vexStatus !== "Not affected"));
assert.equal(exposures.length, 3, "same-named files must remain distinct");
firstSafe.vexClaims.push({ ...firstSafe.vexClaims[0], status: "Affected" });
applySbomVexDecisions(report);
assert.equal(firstSafe.vexStatus, "Needs verification");
const nameOnlyVex = { vulnerability: cve, aliases: [], products: ["exposed"], status: "Not affected", trusted: true };
assert(buildExposureRows({ sbomReports: [report], evidenceReports: [{ vexStatements: [nameOnlyVex] }] }).filter((row) => row.packageName === "exposed").every((row) => row.vexStatus !== "Not affected"));
passed("F02 VEX approval isolates package/file scope and conflicting claims");

const xml = '<bom xmlns="http://cyclonedx.org/schema/bom/1.5"><components><component bom-ref="one" type="library"><name>example</name><version>1.0.0</version><purl>pkg:npm/example@1.0.0</purl></component></components><vulnerabilities><vulnerability><id>' + cve + '</id><affects><target ref="one"/></affects></vulnerability></vulnerabilities></bom>';
assert.equal(parseSbomPayload({ name: "bom.xml" }, xml).parsed.components.length, 1);
assert.throws(() => parseSbomPayload({ name: "bad.xml" }, '<!DOCTYPE bom [<!ENTITY x "x">]><bom>&x;</bom>'), /DTD/);
assert.throws(() => parseSbomPayload({ name: "bad.json" }, "{bad"));
assert.throws(() => parseSbomPayload({ name: "huge.json" }, JSON.stringify({ components: Array.from({ length: 101 }, () => ({ name: "a" })) }), createSbomBudget({ maxRecords: 100 })), /limit/);
assert.throws(() => buildSbomReport([parsed], [], createSbomBudget({ maxRecords: 1 })), /limit/);
passed("F06 XML, malformed data and aggregate processing budgets are bounded");

const appSource = await readFile(new URL("../public/app.js", import.meta.url), "utf8");
const app = vm.createContext({ crypto: globalThis.crypto, URL, Date, console, window: { confirm: () => false }, applySbomVexDecisions });
vm.runInContext(appSource.slice(appSource.indexOf("async function research(")), app);
let terminated = false;
app.Worker = class { addEventListener() {} postMessage() {} terminate() { terminated = true; } };
app.setTimeout = (fn) => { queueMicrotask(fn); return 1; };
app.clearTimeout = () => {};
await assert.rejects(app.parseSbomsInBackground([{ file: { name: "timeout.json", size: 2 }, text: "{}" }]), /timed out/);
assert(terminated);
assert(!appSource.includes("function parseSbomFile("));
assert(!appSource.includes("new DOMParser("));
assert(!app.renderGitHubFindingTable([], { status: "failed" }).includes("No CVE matches in checked"));
passed("F06 worker timeout fails closed with no main-thread parser");

const padded = Object.fromEntries(Array.from({ length: 20000 }, (_, i) => ["padding-" + i, {}]));
padded["node_modules/real"] = { version: "1.0.0" };
assert(server.extractGitHubLockfilePackages("package-lock.json", JSON.stringify({ packages: padded })).truncated);
assert.equal(server.extractGitHubLockfilePackages("requirements.txt", "example==1.*\n").packages.length, 0);
assert(server.extractGitHubLockfilePackages("package-lock.json", "[]").parseError);
const versionedInventory = server.extractGitHubSbomPackages({ sbom: { packages: ["1.0.0", "2.0.0"].map((versionInfo) => ({ name: "shared", versionInfo, externalRefs: [{ referenceLocator: "pkg:npm/shared" }] })) } });
assert.equal(versionedInventory.packages.length, 2, "versionless PURLs must not collapse installed versions");
assert.throws(() => server.extractGitHubSbomPackages({ sbom: {} }), /invalid/);
passed("F07 row caps, unsupported versions and invalid schemas cannot appear complete");

process.env.MONITORED_CVES = cve;
process.env.MONITOR_TABLE_NAME = "offline";
process.env.MONITOR_TOPIC_ARN = "offline";
let state = { snapshot: { riskLevel: "Low", kev: false }, pending: null, revision: 0 };
let publishAttempts = 0, publishedId;
const monitor = createMonitorHandler({
  research: async () => ({ id: cve, risk: { level: "High" }, metrics: { kev: { listed: true } }, sourceResults: ["cve", "kev", "epss"].map((id) => ({ id, status: "ok" })) }),
  load: async () => structuredClone(state),
  save: async (_table, _cve, next, revision) => { assert.equal(revision, state.revision); state = { ...structuredClone(next), revision: revision + 1 }; },
  publish: async (message) => { publishAttempts++; publishedId = state.pending.eventId; assert(message.Message.includes(publishedId)); if (publishAttempts === 1) throw new Error("SNS failure"); }
});
await assert.rejects(monitor(), /SNS failure/);
assert(state.pending && !state.snapshot.kev);
const id = state.pending.eventId;
assert.equal((await monitor()).changed, 1);
assert.equal(publishedId, id);
assert.equal(state.pending, null);
assert(state.snapshot.kev);
const failedResearch = createMonitorHandler({ load: async () => structuredClone(state), research: async () => ({ sourceResults: [] }), save: async () => assert.fail("Must not save failed research") });
await assert.rejects(failedResearch(), /incomplete/);
passed("F09 pending notifications survive delivery failure; failed research preserves baselines");

app.githubApiRequest = async () => ({ items: [{ title: cve + "0 unrelated", state: "closed" }] });
assert.equal(await app.findExistingGitHubIssue({ fullName: "fixture/public" }, cve, "offline"), null);
assert(appSource.includes("Reuse this issue?"));
assert(appSource.includes("escapeHtml(draft.body)"));
app.state = { githubScan: { repository: { ...metadata, owner: "fixture", fullName: "fixture/public", issuesEnabled: true } }, githubPublishing: false, receipts: [] };
app.TextEncoder = TextEncoder;
app.changes = null;
app.store = { list: async () => app.state.receipts, put: async (_collection, record, revision = 0) => ({ ...record, revision: revision + 1 }) };
app.document = { querySelector: (selector) => selector.includes("Consent") ? { checked: true } : { value: "offline-token-not-a-real-credential" } };
app.selectedGitHubIssueDrafts = () => [{ cve, title: cve, body: "Reviewed body" }];
app.renderGitHubRepositoryWorkspace = () => {};
app.showToast = () => {};
app.delay = async () => {};
app.findExistingGitHubIssue = async () => ({ number: 42, state: "closed", title: cve, html_url: "https://github.com/fixture/public/issues/42" });
let writes = 0;
app.githubApiRequest = async () => { writes++; return { number: 43, html_url: "https://github.com/fixture/public/issues/43" }; };
app.safeExternalUrl = (url) => url;
for (const [decisions, expectedStatus, expectedWrites] of [[[true, true], "Reused", 0], [[true, false, false], "Skipped", 0], [[true, false, true], "Created", 1]]) {
  const answers = [...decisions];
  app.window.confirm = () => answers.shift();
  writes = 0;
  app.state.receipts = [];
  await app.publishGitHubIssues();
  assert.equal(app.state.githubIssueResults[0].status, expectedStatus);
  assert.equal(writes, expectedWrites);
}
passed("F10 exact CVE candidates require explicit reuse with full draft review");

for (const [url, provider] of [
  ["https://evil.invalid/?x=https://aws.amazon.com/security/security-bulletins/", "AWS"],
  ["https://msrc.microsoft.com.evil.invalid/x", "Azure"],
  ["https://github.com/microsoft-other/repo", "Azure"],
  ["https://user@alas.aws.amazon.com/x", "AWS"]
]) assert.equal(server.officialCloudReference(url, provider), false);
assert(server.officialCloudReference("https://aws.amazon.com/security/security-bulletins/", "AWS"));
assert(server.officialCloudReference("https://msrc.microsoft.com/update-guide/", "Azure"));
passed("F11 official cloud references require exact URL authority");
console.log(checks + " adversarial regression groups passed");
