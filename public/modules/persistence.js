const COLLECTIONS = new Set(["cases", "watchlist", "decisions", "receipts", "settings"]);
const BACKUP_LIMIT = 20 * 1024 * 1024;

export class WorkspaceStore {
  constructor(factory = globalThis.indexedDB) { this.factory = factory; }

  async open() {
    if (!this.factory) throw new Error("Browser storage is unavailable. Export your work before leaving.");
    this.db = await new Promise((resolve, reject) => {
      const request = this.factory.open("vulnscope-workspace", 1);
      request.onupgradeneeded = () => {
        const records = request.result.createObjectStore("records", { keyPath: "key" });
        records.createIndex("collection", "collection");
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
      request.onblocked = () => reject(new Error("Close older VulnScope tabs, then reload to enable storage."));
    });
    this.db.onversionchange = () => this.db.close();
    await this.migrateLegacy();
    return this;
  }

  transaction(mode, action) {
    return new Promise((resolve, reject) => {
      if (!this.db) return reject(new Error("Storage unavailable. Export the draft and retry after reloading."));
      const tx = this.db.transaction("records", mode);
      const records = tx.objectStore("records");
      let result, failure;
      const done = (value) => { result = value; };
      const fail = (error) => { failure = error; tx.abort(); };
      tx.oncomplete = () => resolve(result);
      tx.onabort = tx.onerror = () => reject(failure || tx.error || new Error("Storage write failed. Your unsaved draft is still available."));
      try { action(records, done, fail); } catch (error) { fail(error); }
    });
  }

  async list(collection) {
    return this.transaction("readonly", (records, done) => {
      const request = records.index("collection").getAll(collection);
      request.onsuccess = () => done(request.result.map((row) => row.value));
    });
  }

  async snapshot() {
    return this.transaction("readonly", (records, done) => {
      const request = records.getAll();
      request.onsuccess = () => {
        const collections = Object.fromEntries([...COLLECTIONS].map((key) => [key, []]));
        for (const row of request.result) if (collections[row.collection]) collections[row.collection].push(row.value);
        done(collections);
      };
    });
  }

  async put(collection, record, expectedRevision = record.revision || 0) {
    validateRecord(collection, record);
    return this.transaction("readwrite", (records, done, fail) => {
      const key = `${collection}:${record.id}`;
      const request = records.get(key);
      request.onsuccess = () => {
        try {
          const revision = request.result?.value.revision || 0;
          if (revision !== expectedRevision) return fail(new Error("This record changed in another tab. Export your draft, then reopen the latest record before saving."));
          const value = { ...structuredClone(record), revision: revision + 1 };
          records.put({ key, collection, value });
          done(value);
        } catch (error) { fail(error); }
      };
    });
  }

  async remove(collection, id, expectedRevision) {
    return this.transaction("readwrite", (records, done, fail) => {
      const key = `${collection}:${id}`;
      const request = records.get(key);
      request.onsuccess = () => {
        if (request.result && request.result.value.revision !== expectedRevision) return fail(new Error("Record changed in another tab. Reopen it before deleting."));
        records.delete(key);
        done(true);
      };
    });
  }

  async clear() { return this.transaction("readwrite", (records, done) => {
    records.clear();
    records.put({ key: "settings:legacy-migration", collection: "settings", value: { id: "legacy-migration", revision: 1 } });
    done(true);
  }); }

  async restore(data, replace = false) {
    validateBackup(data);
    return this.transaction("readwrite", (records, done, fail) => {
      if (replace) records.clear();
      for (const [collection, entries] of Object.entries(data.records)) {
        for (const entry of entries) {
          const key = `${collection}:${entry.id}`;
          const request = records.get(key);
          request.onsuccess = () => {
            try {
              if (request.result && !replace) return;
              const value = clearImportedTrust(entry);
              if (collection === "receipts") value.status = "Unknown";
              records.put({ key, collection, value: { ...value, revision: (request.result?.value.revision || 0) + 1 } });
            } catch (error) { fail(error); }
          };
        }
      }
      records.put({ key: "settings:legacy-migration", collection: "settings", value: { id: "legacy-migration", revision: 1 } });
      done(true);
    });
  }

  async migrateLegacy() {
    let old;
    try {
      old = { cases: JSON.parse(localStorage.getItem("cve-research-cases") || "[]"), watchlist: JSON.parse(localStorage.getItem("cve-research-watchlist") || "[]") };
    } catch { return; }
    await this.transaction("readwrite", (records, done, fail) => {
      const marker = records.get("settings:legacy-migration");
      marker.onsuccess = () => {
        if (marker.result) return;
        for (const [collection, rows] of Object.entries(old)) {
          for (const value of Array.isArray(rows) ? rows : []) {
            try { validateRecord(collection, value); } catch { continue; }
            const key = `${collection}:${value.id}`;
            const request = records.get(key);
            request.onsuccess = () => { try { if (!request.result) records.put({ key, collection, value: { ...value, revision: 1 } }); } catch (error) { fail(error); } };
          }
        }
        records.put({ key: "settings:legacy-migration", collection: "settings", value: { id: "legacy-migration", revision: 1 } });
      };
      done(true);
    });
  }
}

function validateRecord(collection, value) {
  if (!COLLECTIONS.has(collection) || !value || typeof value !== "object" || typeof value.id !== "string" || !value.id || value.id.length > 4000) throw new Error("Invalid workspace record.");
  if (["cases", "watchlist"].includes(collection) && (!/^CVE-\d{4}-\d{4,}$/.test(value.id) || value.investigation?.id !== value.id)) throw new Error("Invalid case identity.");
  if (["cases", "watchlist"].includes(collection)) {
    const item = value.investigation;
    for (const key of ["metrics", "risk", "confidence"]) if (!item[key] || typeof item[key] !== "object" || Array.isArray(item[key])) throw new Error(`Invalid investigation ${key}.`);
    for (const key of ["affected", "references", "sourceResults", "analystActions"]) if (!Array.isArray(item[key])) throw new Error(`Invalid investigation ${key}.`);
  }
  if (collection === "decisions" && (typeof value.scope !== "string" || typeof value.decisionStatus !== "string")) throw new Error("Invalid scoped decision.");
  if (collection === "receipts" && (typeof value.repository !== "string" || typeof value.marker !== "string" || !/^CVE-\d{4}-\d{4,}$/.test(value.cve))) throw new Error("Invalid filing receipt.");
  if (collection === "settings" && value.id === "github-review" && (!Array.isArray(value.selected) || !Array.isArray(value.scan?.packages) || !Array.isArray(value.scan?.findings) || !value.scan?.repository?.fullName)) throw new Error("Invalid repository review.");
}

export function validateBackup(value) {
  if (new TextEncoder().encode(JSON.stringify(value)).length > BACKUP_LIMIT) throw new Error("Backup exceeds 20 MiB.");
  if (value?.format !== "vulnscope-workspace" || value.version !== 1 || !value.records || typeof value.records !== "object" || Array.isArray(value.records)) throw new Error("Unsupported workspace backup version or format.");
  let count = 0;
  for (const [collection, entries] of Object.entries(value.records)) {
    if (!COLLECTIONS.has(collection) || !Array.isArray(entries) || entries.length > 10000) throw new Error("Invalid backup collection.");
    const ids = new Set();
    for (const entry of entries) {
      validateRecord(collection, entry);
      if (ids.has(entry.id)) throw new Error("Backup contains duplicate record IDs.");
      ids.add(entry.id);
    }
  }
  const pending = [[value, 0]];
  while (pending.length) {
    const [node, depth] = pending.pop();
    if (++count > 200000 || depth > 40) throw new Error("Backup structure exceeds safety limits.");
    if (node && typeof node === "object") for (const [key, child] of Object.entries(node)) {
      if (["__proto__", "constructor", "prototype", "token", "authorization", "apiKey", "githubIssueToken"].includes(key)) throw new Error("Backup contains forbidden fields.");
      pending.push([child, depth + 1]);
    }
  }
  if (value.inventory !== undefined) {
    for (const key of ["sbomReports", "evidenceReports", "enrichmentReports"]) if (!Array.isArray(value.inventory?.[key]) || value.inventory[key].length > 100) throw new Error("Invalid inventory backup.");
    for (const report of value.inventory.sbomReports) {
      if (!report.id || !["components", "cves", "files", "warnings"].every((key) => Array.isArray(report[key]))) throw new Error("Invalid SBOM backup.");
      if (report.cves.some((c) => !c.id || !["affectedPackages", "files", "components"].every((key) => Array.isArray(c[key])))) throw new Error("Invalid SBOM CVE record.");
    }
    for (const report of value.inventory.evidenceReports) if (!report.id || !["assets", "findings", "vexStatements", "warnings"].every((key) => Array.isArray(report[key]))) throw new Error("Invalid evidence backup.");
    for (const report of value.inventory.enrichmentReports) if (!report.id || !Array.isArray(report.packages) || report.packages.some((p) => !Array.isArray(p.vulnerabilities))) throw new Error("Invalid enrichment backup.");
  }
  for (const collection of ["cases", "watchlist"]) for (const entry of value.records[collection] || []) {
    const item = entry.investigation;
    for (const key of ["weaknesses", "evidence", "timeline", "sourceLinks"]) if (!Array.isArray(item[key])) throw new Error(`Invalid backup investigation ${key}.`);
    if (!Array.isArray(item.risk.reasons) || !item.remediation || !Array.isArray(item.remediation.advisoryRefs)) throw new Error("Invalid backup research structure.");
    if (item.claims !== undefined && (!Array.isArray(item.claims) || item.claims.some((c) => !c || typeof c.id !== "string" || typeof c.body !== "string" || c.packages !== undefined && !Array.isArray(c.packages)))) throw new Error("Invalid backup claims.");
    const plan = item.caseDraft?.plan;
    if (plan && (!Array.isArray(plan.sources) || !Array.isArray(plan.fixedOptions))) throw new Error("Invalid backup plan.");
  }
  return value;
}

export function clearImportedTrust(value) {
  if (Array.isArray(value)) return value.map(clearImportedTrust);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, ["trusted", "vexTrusted", "approved"].includes(key) ? false : key === "decisionStatus" ? "Needs verification" : clearImportedTrust(child)]));
}
