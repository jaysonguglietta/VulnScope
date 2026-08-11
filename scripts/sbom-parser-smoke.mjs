import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { parseSbomPayload } from "../public/modules/sbom-worker-core.js";
import { buildExposureRows, parseEvidenceFile, summarizeExposureRows } from "../public/modules/workspace.js";

const sampleText = await readFile(new URL("fixtures/sample-cyclonedx.json", import.meta.url), "utf8");
const result = parseSbomPayload({ name: "sample-cyclonedx.json", size: sampleText.length }, sampleText);
assert.equal(result.handled, true, "CycloneDX JSON should be handled in the background parser");
assert.equal(result.parsed.format, "CycloneDX 1.5");
assert.equal(result.parsed.components.length, 1);
assert(result.parsed.vulnerabilities.some((item) => item.cve === "CVE-2021-44228"));
assert(result.parsed.vulnerabilities.some((item) => item.components.some((component) => component.includes("log4j-core"))));

const openVex = JSON.stringify({
  "@context": "https://openvex.dev/ns/v0.2.0",
  statements: [{
    vulnerability: { name: "CVE-2021-44228" },
    products: [{ "@id": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" }],
    status: "not_affected",
    justification: "vulnerable_code_not_in_execute_path"
  }]
});
const vexReport = parseEvidenceFile({ name: "status.openvex.json", size: openVex.length }, openVex);
assert.equal(vexReport.format, "OpenVEX");
assert.equal(vexReport.vexStatements[0].status, "Not affected");
assert.equal(vexReport.vexStatements[0].trusted, false);

const sbomReport = {
  title: "production-api",
  cves: [{
    id: "CVE-2021-44228",
    severity: "Critical",
    files: ["sample-cyclonedx.json"],
    affectedPackages: [{
      name: "org.apache.logging.log4j/log4j-core",
      version: "2.14.1",
      purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
      fileName: "sample-cyclonedx.json"
    }]
  }]
};
const exposureRows = buildExposureRows({ sbomReports: [sbomReport], evidenceReports: [vexReport] });
assert.equal(exposureRows.length, 1);
assert.equal(exposureRows[0].vulnerability, "CVE-2021-44228");
assert.equal(exposureRows[0].vexStatus, "Needs verification");
assert.notEqual(exposureRows[0].priorityScore, 0);
assert.equal(summarizeExposureRows(exposureRows).notAffected, 0);

vexReport.vexStatements[0].trusted = true;
vexReport.vexStatements[0].trustReason = "Analyst approved during import.";
const approvedExposureRows = buildExposureRows({ sbomReports: [sbomReport], evidenceReports: [vexReport] });
assert.equal(approvedExposureRows[0].vexStatus, "Not affected");
assert.equal(approvedExposureRows[0].priorityScore, 0);

const isolatedProducts = buildExposureRows({
  evidenceReports: [{
    findings: [
      { vulnerability: "CVE-2021-44228", packageName: "log4j-core", purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" },
      { vulnerability: "CVE-2021-44228", packageName: "unrelated-package", purl: "pkg:npm/unrelated-package@1.0.0" }
    ],
    vexStatements: [{
      vulnerability: "CVE-2021-44228",
      aliases: [],
      products: ["pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"],
      status: "Not affected",
      justification: "Component is unreachable.",
      trusted: true,
      trustReason: "Analyst approved during import."
    }]
  }]
});
assert.equal(isolatedProducts.find((row) => row.packageName === "log4j-core").vexStatus, "Not affected");
assert.equal(isolatedProducts.find((row) => row.packageName === "unrelated-package").vexStatus, "Unknown");

const substringProducts = buildExposureRows({
  evidenceReports: [{
    findings: [{ vulnerability: "CVE-2024-1234", packageName: "catalog" }],
    vexStatements: [{
      vulnerability: "CVE-2024-1234",
      aliases: [],
      products: ["log"],
      status: "Not affected",
      trusted: true
    }]
  }]
});
assert.equal(substringProducts[0].vexStatus, "Unknown", "substring product identities must not match");

const inspector = JSON.stringify({
  findings: [{
    title: "Log4j finding",
    severity: "CRITICAL",
    resources: [{ id: "arn:aws:ecr:us-east-1:123456789012:repository/api", type: "AWS_ECR_CONTAINER_IMAGE", region: "us-east-1" }],
    packageVulnerabilityDetails: {
      vulnerabilityId: "CVE-2021-44228",
      vulnerablePackages: [{ name: "log4j-core", version: "2.14.1", fixedInVersion: "2.17.1", packageManager: "MAVEN" }]
    }
  }]
});
const inspectorReport = parseEvidenceFile({ name: "inspector.json", size: inspector.length }, inspector);
assert.equal(inspectorReport.format, "Amazon Inspector findings");
assert.equal(inspectorReport.findings[0].provider, "AWS");
assert.equal(inspectorReport.findings[0].fixedVersion, "2.17.1");

console.log("sbom, VEX, cloud evidence, and exposure tests passed");
