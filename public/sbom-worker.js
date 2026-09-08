import { parseSbomPayload } from "./modules/sbom-worker-core.js";
import { createSbomBudget } from "./modules/sbom-budget.js";
import { buildSbomReport } from "./modules/sbom-report.js";

self.addEventListener("message", (event) => {
  const { id, files } = event.data || {};
  if (!id || !Array.isArray(files)) return;
  try {
    if (files.length > 10 || files.reduce((sum, file) => sum + new TextEncoder().encode(file.text).byteLength, 0) > 40 * 1024 * 1024) throw new Error("SBOM batch exceeds upload limits.");
    const budget = createSbomBudget();
    const parsed = files.map((file) => parseSbomPayload(file, file.text, budget).parsed);
    const report = buildSbomReport(parsed, [], budget);
    self.postMessage({ id, ok: true, report });
  } catch (error) {
    self.postMessage({ id, ok: false, message: "SBOM import rejected: " + String(error.message || "processing failed").slice(0, 240) });
  }
});
