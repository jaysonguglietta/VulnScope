import { spawn, spawnSync } from "node:child_process";
import { once } from "node:events";
import { createServer } from "node:net";
import { buildOsvQuery, extractGitHubLockfilePackages, extractGitHubSbomPackages, handleApiRequest, normalizeGitHubRepositoryUrl, normalizeOsvVulnerability } from "../server.mjs";
import { buildGitHubIssueDraft, buildRepositoryCveFindings } from "../public/modules/github.js";

const normalizedRepository = normalizeGitHubRepositoryUrl("https://github.com/openai/openai-node.git/");
assert(normalizedRepository?.fullName === "openai/openai-node", "canonical public GitHub repository URLs should normalize");
for (const rejectedUrl of [
  "http://github.com/openai/openai-node",
  "https://github.com.evil.example/openai/openai-node",
  "https://user:token@github.com/openai/openai-node",
  "https://github.com/openai/openai-node/issues",
  "https://github.com/openai/openai-node?tab=readme"
]) {
  assert(normalizeGitHubRepositoryUrl(rejectedUrl) === null, `unsafe repository URL must be rejected: ${rejectedUrl}`);
}

const githubSbomInventory = extractGitHubSbomPackages({ sbom: {
  name: "openai/example",
  packages: [
    { SPDXID: "SPDXRef-Repository", name: "example", versionInfo: "main", externalRefs: [{ referenceLocator: "pkg:github/openai/example@main" }] },
    { SPDXID: "SPDXRef-a", name: "alpha", versionInfo: "1.0.0", externalRefs: [{ referenceLocator: "pkg:npm/alpha@1.0.0" }] },
    { SPDXID: "SPDXRef-b", name: "beta", versionInfo: "2.0.0", externalRefs: [{ referenceLocator: "pkg:npm/beta@2.0.0" }] },
    { SPDXID: "SPDXRef-no-version", name: "unversioned", externalRefs: [{ referenceLocator: "pkg:npm/unversioned" }] }
  ]
}}, 1);
assert(githubSbomInventory.discoveredPackageCount === 3, "repository root package must be excluded from dependency count");
assert(githubSbomInventory.packages.length === 1 && githubSbomInventory.truncated, "GitHub SBOM package queries must honor the configured cap");
assert(githubSbomInventory.skippedWithoutVersion === 1, "unversioned packages must not generate broad OSV queries");

const npmLockInventory = extractGitHubLockfilePackages("package-lock.json", JSON.stringify({
  lockfileVersion: 3,
  packages: {
    "": { name: "root", version: "1.0.0" },
    "node_modules/@scope/alpha": { version: "1.2.3" },
    "node_modules/beta": { version: "2.0.0" },
    "node_modules/unversioned": {}
  }
}), 10);
assert(npmLockInventory.packages.some((pkg) => pkg.purl === "pkg:npm/%40scope/alpha@1.2.3"), "npm lockfile fallback should preserve scoped package identity");
assert(npmLockInventory.packages.some((pkg) => pkg.purl === "pkg:npm/beta@2.0.0"), "npm lockfile fallback should extract exact versions");
assert(npmLockInventory.skippedWithoutVersion === 1, "lockfile fallback should skip packages without exact versions");

const requirementsInventory = extractGitHubLockfilePackages("requirements.txt", "Django==5.0.1\nrequests>=2.0\nflask==3.0.0; python_version > '3.9'\n", 10);
assert(requirementsInventory.packages.length === 2, "requirements fallback should accept exact pins and reject ranges");
assert(extractGitHubLockfilePackages("go.sum", "golang.org/x/text v0.3.0 h1:test\ngolang.org/x/text v0.3.0/go.mod h1:test\n", 10).packages.length === 1, "Go fallback should ignore go.mod checksum rows");
assert(extractGitHubLockfilePackages("Cargo.lock", '[[package]]\nname = "serde"\nversion = "1.0.0"\n', 10).packages[0]?.purl === "pkg:cargo/serde@1.0.0", "Cargo fallback should extract package blocks");
assert(extractGitHubLockfilePackages("Gemfile.lock", "GEM\n  specs:\n    rack (3.0.0)\n", 10).packages[0]?.purl === "pkg:gem/rack@3.0.0", "Gemfile fallback should extract locked gems");
assert(extractGitHubLockfilePackages("composer.lock", JSON.stringify({ packages: [{ name: "vendor/package", version: "1.0.0" }] }), 10).packages[0]?.purl === "pkg:composer/vendor/package@1.0.0", "Composer fallback should extract locked packages");
assert(extractGitHubLockfilePackages("package-lock.json", "{not json", 10).parseError, "malformed lockfiles must fail closed");

const groupedFindings = buildRepositoryCveFindings({ packages: [{
  purl: "pkg:npm/alpha@1.0.0",
  name: "alpha|injected\nrow",
  version: "1.0.0",
  vulnerabilities: [{
    id: "GHSA-test",
    cves: ["CVE-2024-12345"],
    aliases: ["CVE-2024-12345"],
    severity: "HIGH",
    fixedVersions: ["1.0.1"],
    references: [{ url: "https://osv.dev/vulnerability/GHSA-test" }, { url: "javascript:alert(1)" }]
  }]
}] });
assert(groupedFindings.length === 1 && groupedFindings[0].packages.length === 1, "repository findings should group duplicate aliases by CVE and package");
const issueDraft = buildGitHubIssueDraft({
  ...groupedFindings[0],
  packages: groupedFindings[0].packages.map((pkg) => ({ ...pkg, purl: "" }))
}, { fullName: "openai/example", url: "https://github.com/openai/example" }, "2026-08-11T00:00:00Z");
assert(issueDraft.title.startsWith("[Security] CVE-2024-12345"), "issue draft title should identify the confirmed CVE");
assert(!issueDraft.body.includes("javascript:"), "unsafe advisory references must not enter issue bodies");
assert(issueDraft.body.includes("alpha\\|injected row"), "package text must not inject Markdown table rows");

process.env.MOCK_GITHUB_SCAN = "1";
const mockGitHubScan = await handleApiRequest({
  path: "/api/github/scan",
  method: "POST",
  headers: { "content-type": "application/json" },
  trustedClientAddress: "github-scan-test",
  body: JSON.stringify({ url: "https://github.com/openai/example" })
});
assert(mockGitHubScan.statusCode === 200, "valid public repository scans should return 200");
assert(JSON.parse(mockGitHubScan.body).packages[0].vulnerabilities[0].cves[0] === "CVE-2024-0001", "repository scan should return package-specific CVE matches");
delete process.env.MOCK_GITHUB_SCAN;

const versionedPurlQuery = buildOsvQuery({
  purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
  version: "2.14.1"
});
assert(!Object.hasOwn(versionedPurlQuery, "version"), "versioned PURLs must not duplicate the OSV version field");
const unversionedPurlQuery = buildOsvQuery({ purl: "pkg:maven/org.example/library", version: "1.2.3" });
assert(unversionedPurlQuery.version === "1.2.3", "unversioned PURLs should retain an explicit OSV version");

const multiPackageOsv = {
  id: "GHSA-test",
  affected: [
    {
      package: { ecosystem: "npm", name: "alpha", purl: "pkg:npm/alpha" },
      ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "2.0.0" }] }]
    },
    {
      package: { ecosystem: "npm", name: "beta", purl: "pkg:npm/beta" },
      ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "9.0.0" }] }]
    }
  ]
};
const alphaOsv = normalizeOsvVulnerability(multiPackageOsv, {}, { purl: "pkg:npm/alpha@1.0.0", ecosystem: "npm", name: "alpha" });
assert(JSON.stringify(alphaOsv.fixedVersions) === JSON.stringify(["2.0.0"]), "OSV fixes must come only from the matching package entry");
assert(alphaOsv.affected.length === 1, "only one matching affected entry should remain");
assert(alphaOsv.affected[0].package.name === "alpha", "the matching affected package should be alpha");
assert(alphaOsv.fixProvenance[0].package === "pkg:npm/alpha", "fix provenance should retain the matched PURL");
const missingOsv = normalizeOsvVulnerability(multiPackageOsv, {}, { purl: "pkg:npm/gamma@1.0.0", ecosystem: "npm", name: "gamma" });
assert(missingOsv.fixedVersions.length === 0, "unmatched packages must not inherit another package's fix");

process.env.ORIGIN_VERIFY_SECRET = "test-origin-secret-that-is-at-least-32-bytes";
const deniedOrigin = await handleApiRequest({ path: "/api/health", method: "GET", headers: {} });
assert(deniedOrigin.statusCode === 403, "configured origin verification should reject direct API requests");
const acceptedOrigin = await handleApiRequest({
  path: "/api/health",
  method: "GET",
  headers: { "x-origin-verify": process.env.ORIGIN_VERIFY_SECRET }
});
assert(acceptedOrigin.statusCode === 200, "configured origin verification should accept the trusted origin header");
delete process.env.ORIGIN_VERIFY_SECRET;

let child;
const rootUrl = await startTestServer();

try {
  const index = request("/");
  assert(index.status === 200, `expected / to return 200, got ${index.status}`);
  assert(index.headers["content-security-policy"]?.includes("frame-ancestors 'none'"), "missing CSP frame protection");
  assert(index.headers["x-content-type-options"] === "nosniff", "missing nosniff header");
  assert(index.body.includes("VulnScope"), "index should include VulnScope brand");
  assert(index.body.includes("sbomInput"), "index should include SBOM upload input");

  const health = request("/api/health");
  assert(health.status === 200, `expected /api/health to return 200, got ${health.status}`);
  const healthJson = JSON.parse(health.body);
  assert(Array.isArray(healthJson.sources) && healthJson.sources.length >= 10, "health should return source catalog");
  assert(!Object.hasOwn(healthJson.sources[0], "configured"), "health should not expose token configuration state");
  assert(healthJson.sources.every((source) => ["unknown", "optional", "ok", "error", "skipped"].includes(source.status)), "health should return truthful source state");

  const methodRejected = request("/api/research?cve=CVE-2023-22527", { method: "POST" });
  assert(methodRejected.status === 405, `expected POST research to return 405, got ${methodRejected.status}`);
  assert(methodRejected.headers.allow === "GET", "method rejection should identify the allowed method");

  const invalidEnrichment = request("/api/enrich", {
    method: "POST",
    body: JSON.stringify({ packages: [{ name: "missing-version" }] }),
    headers: ["content-type: application/json"]
  });
  assert(invalidEnrichment.status === 400, `expected invalid enrichment to return 400, got ${invalidEnrichment.status}`);

  const invalid = request("/api/research?cve=not-a-cve");
  assert(invalid.status === 400, `expected invalid CVE to return 400, got ${invalid.status}`);
  assert(JSON.parse(invalid.body).message.includes("CVE-YYYY-NNNN"), "invalid CVE should return a safe validation message");

  const traversal = request("/%2e%2e/%2e%2e/etc/passwd");
  assert(traversal.status !== 200, "path traversal probe must not return 200");
  assert(traversal.headers["content-security-policy"], "error responses should keep security headers");

  const first = request("/api/research?cve=CVE-2023-22527");
  const second = request("/api/research?cve=CVE-2023-22527");
  const third = request("/api/research?cve=CVE-2023-22527");
  assert(first.status === 200, `expected first research request to return 200, got ${first.status}`);
  assert(JSON.parse(first.body).id === "CVE-2023-22527", "research response should include requested CVE");
  assert(second.status === 200, `expected second research request to return 200, got ${second.status}`);
  assert(JSON.parse(second.body).cached === true, "second research response should come from cache");
  assert(third.status === 429, `expected third research request to return 429, got ${third.status}`);
  assert(third.headers["retry-after"], "rate limited response should include retry-after");

  console.log("security smoke tests passed");
} finally {
  stopTestServer();
}

async function startTestServer() {
  const port = await getFreePort();
  child = spawn(process.execPath, ["server.mjs"], {
    cwd: new URL("..", import.meta.url),
    env: {
      ...process.env,
      HOST: "127.0.0.1",
      PORT: String(port),
      MOCK_RESEARCH: "1",
      RATE_LIMIT_MAX: "2",
      REFRESH_RATE_LIMIT_MAX: "1",
      RATE_LIMIT_WINDOW_MS: "60000"
    },
    stdio: ["ignore", "pipe", "pipe"]
  });

  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (chunk) => {
    stdout += chunk.toString();
  });
  child.stderr.on("data", (chunk) => {
    stderr += chunk.toString();
  });

  const deadline = Date.now() + 8000;
  while (!stdout.includes(`http://127.0.0.1:${port}`)) {
    if (child.exitCode !== null) {
      throw new Error(`test server exited early\nstdout:\n${stdout}\nstderr:\n${stderr}`);
    }
    if (Date.now() > deadline) {
      throw new Error(`test server did not start\nstdout:\n${stdout}\nstderr:\n${stderr}`);
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }

  return `http://127.0.0.1:${port}`;
}

async function getFreePort() {
  const server = createServer();
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  const port = address.port;
  server.close();
  await once(server, "close");
  return port;
}

function request(pathname, options = {}) {
  const args = ["-sS", "-D", "-", "-X", options.method || "GET"];
  for (const header of options.headers || []) args.push("-H", header);
  if (options.body !== undefined) args.push("--data-binary", options.body);
  args.push(`${rootUrl}${pathname}`);
  const result = spawnSync("curl", args, {
    encoding: "utf8",
    maxBuffer: 1024 * 1024
  });
  if (result.status !== 0) {
    throw new Error(`curl failed for ${pathname}: ${result.stderr || result.stdout}`);
  }
  return parseHttp(result.stdout);
}

function parseHttp(raw) {
  const parts = raw.split(/\r?\n\r?\n/).filter(Boolean);
  const headerBlock = parts.shift() || "";
  const body = parts.join("\n\n");
  const headerLines = headerBlock.split(/\r?\n/);
  const status = Number(headerLines[0]?.match(/\s(\d{3})\s/)?.[1] || 0);
  const headers = {};
  for (const line of headerLines.slice(1)) {
    const separator = line.indexOf(":");
    if (separator === -1) continue;
    headers[line.slice(0, separator).trim().toLowerCase()] = line.slice(separator + 1).trim();
  }
  return { status, headers, body };
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function stopTestServer() {
  if (!child || child.exitCode !== null) return;
  child.kill("SIGTERM");
}
