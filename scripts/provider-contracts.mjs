import assert from "node:assert/strict";
import { getAsyncSbom } from "../lib/github-sbom.mjs";

const signal = AbortSignal.timeout(15000);
async function read(response) {
  const reader = response.body.getReader(); let size = 0; const chunks = [];
  try { for (;;) { const { done, value } = await reader.read(); if (done) break; size += value.length; if (size > 8 * 1024 * 1024) throw new Error("Provider response exceeds contract limit"); chunks.push(value); } }
  finally { await reader.cancel(); }
  return Buffer.concat(chunks).toString("utf8");
}
async function json(url, options = {}) {
  const response = await fetch(url, { ...options, signal, redirect: "error" });
  if (!response.ok) { await response.body?.cancel(); throw new Error(`Provider HTTP ${response.status}`); }
  return JSON.parse(await read(response));
}
const outcomes = [];
try {
  const report = await getAsyncSbom({ owner: "jaysonguglietta", name: "VulnScope" }, { json, read, signal });
  assert(report.pending ? report.jobId : Array.isArray(report.payload?.sbom?.packages));
  outcomes.push({ provider: "GitHub asynchronous SBOM", state: report.pending ? "pending contract accepted; readiness unverified" : "download schema verified" });
} catch (error) { outcomes.push({ provider: "GitHub asynchronous SBOM", state: "unverified/degraded", message: error.message }); process.exitCode = 1; }
try {
  const result = await json("https://api.osv.dev/v1/querybatch", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ queries: [{ package: { purl: "pkg:npm/lodash@4.17.20" } }] }) });
  assert(Array.isArray(result.results) && result.results.length === 1);
  outcomes.push({ provider: "OSV querybatch", state: "schema verified", count: result.results[0].vulns?.length || 0 });
} catch (error) { outcomes.push({ provider: "OSV querybatch", state: "unverified/degraded", message: error.message }); process.exitCode = 1; }
console.log(JSON.stringify({ checkedAt: new Date().toISOString(), anonymousPublicReadsOnly: true, outcomes }, null, 2));
