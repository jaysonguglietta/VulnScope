import { parseEvidenceFile } from "./modules/workspace.js";

const MAX_BATCH_RECORDS = 50000;

self.addEventListener("message", (event) => {
  const { id, files } = event.data || {};
  if (!id || !Array.isArray(files)) return;
  try {
    const results = [];
    let remainingRecords = MAX_BATCH_RECORDS;
    for (const file of files) {
      if (remainingRecords <= 0) break;
      const report = parseEvidenceFile(file, file.text, { maxOutputRecords: remainingRecords });
      results.push(report);
      remainingRecords -= report.findings.length + report.assets.length + report.vexStatements.length;
    }
    self.postMessage({
      id,
      ok: true,
      results,
      truncated: results.length < files.length || remainingRecords <= 0
    });
  } catch {
    self.postMessage({ id, ok: false, message: "Evidence parsing failed within the browser safety limits." });
  }
});
