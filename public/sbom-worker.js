import { parseSbomPayload } from "./modules/sbom-worker-core.js";

self.addEventListener("message", (event) => {
  const { id, files } = event.data || {};
  if (!id || !Array.isArray(files)) return;
  try {
    const results = files.map((file) => ({
      fileName: file.name,
      ...parseSbomPayload(file, file.text)
    }));
    self.postMessage({ id, ok: true, results });
  } catch {
    self.postMessage({ id, ok: false, message: "The background SBOM parser failed." });
  }
});
