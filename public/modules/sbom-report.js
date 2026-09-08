import { createSbomBudget } from "./sbom-budget.js";

const unique = (values) => [...new Set(values.filter(Boolean))];
const label = (component) => (component.name || component.purl || component.ref || "Unknown component") + (component.version ? "@" + component.version : "");
const severityRank = (value) => ({ Critical: 5, High: 4, Medium: 3, Low: 2, None: 1 }[value] || 0);
const componentKey = (component) => JSON.stringify([component.fileId, component.ref, component.purl, component.name, component.version]);

export function buildSbomReport(parsedFiles, warnings = [], budget = createSbomBudget()) {
  const id = "sbom-" + crypto.randomUUID();
  const uploadedAt = new Date().toISOString();
  const components = [], vulnerabilities = [], index = new Map();
  const files = parsedFiles.map((file, position) => {
    const fileId = id + ":" + position;
    const seen = new Set();
    for (const original of file.components) {
      const component = { ...original, fileId };
      const key = componentKey(component);
      if (seen.has(key)) continue;
      seen.add(key);
      budget.spend();
      components.push(component);
      for (const ref of unique([component.ref, component.purl, label(component)])) {
        const indexKey = JSON.stringify([fileId, ref]);
        if (!index.has(indexKey)) index.set(indexKey, []);
        index.get(indexKey).push(component);
      }
      for (const cve of component.cves || []) {
        budget.spend();
        vulnerabilities.push({ cve, id: cve, source: "SBOM component reference", fileId, fileName: file.fileName, componentRefs: [component.ref || component.purl || label(component)], components: [label(component)], references: [] });
      }
    }
    for (const vulnerability of file.vulnerabilities) {
      budget.spend();
      vulnerabilities.push({ ...vulnerability, fileId });
    }
    for (const cve of file.cves || []) {
      budget.spend();
      vulnerabilities.push({ cve, id: cve, source: "SBOM file reference", fileId, fileName: file.fileName, components: [], componentRefs: [], references: [] });
    }
    return { fileId, fileName: file.fileName, size: file.size, format: file.format, documentName: file.documentName, componentCount: file.components.length, vulnerabilityCount: file.vulnerabilities.length, cveCount: unique([...(file.cves || []), ...file.vulnerabilities.map((v) => v.cve)]).length, warnings: file.warnings || [] };
  });
  const groups = new Map();
  for (const vulnerability of vulnerabilities) {
    budget.spend(0);
    if (!vulnerability.cve) continue;
    if (!groups.has(vulnerability.cve)) groups.set(vulnerability.cve, { id: vulnerability.cve, files: [], components: [], sources: [], references: [], severity: "", packages: new Map(), count: 0 });
    const group = groups.get(vulnerability.cve);
    group.files.push(vulnerability.fileName);
    group.sources.push(vulnerability.source);
    group.references.push(...(vulnerability.references || []));
    group.count++;
    if (severityRank(vulnerability.severity) > severityRank(group.severity)) group.severity = vulnerability.severity;
    const matched = new Map();
    const refs = vulnerability.componentRefs?.length ? vulnerability.componentRefs : vulnerability.components || [];
    for (const ref of unique(refs)) for (const component of index.get(JSON.stringify([vulnerability.fileId, ref])) || []) {
      budget.spend();
      matched.set(componentKey(component), component);
    }
    for (const [key, component] of matched) {
      if (!group.packages.has(key)) group.packages.set(key, { ...component, label: label(component), source: vulnerability.source, severity: vulnerability.severity, score: vulnerability.score, match: "Matched by exact file and component identity", vexClaims: [] });
      const pkg = group.packages.get(key);
      if (vulnerability.vex) {
        budget.spend();
        pkg.vexClaims.push({
          key: JSON.stringify([id, component.fileId, key, group.id, pkg.vexClaims.length]),
          vulnerability: group.id, products: [component.purl || label(component)],
          fileName: component.fileName, status: vulnerability.vex.status,
          justification: vulnerability.vex.justification || "", detail: vulnerability.vex.detail || "",
          trusted: false, trustReason: "Embedded SBOM VEX is unverified."
        });
      }
    }
  }
  const cves = [...groups.values()].map(({ packages, ...group }) => ({
    ...group, files: unique(group.files), sources: unique(group.sources), references: unique(group.references).slice(0, 6),
    affectedPackages: [...packages.values()], components: [...packages.values()].map((pkg) => pkg.label)
  })).sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || a.id.localeCompare(b.id));
  const report = {
    id, uploadedAt, title: files.length === 1 ? files[0].fileName.replace(/\.[^.]+$/, "") : files.length + " SBOM files",
    files, components, vulnerabilities, cves, warnings: [...warnings, ...files.flatMap((file) => file.warnings)],
    summary: files.length + " files, " + components.length + " components, and " + cves.length + " vulnerability identifiers."
  };
  applySbomVexDecisions(report);
  budget.check(report);
  return report;
}

export function applySbomVexDecisions(report) {
  for (const entry of report.cves) {
    for (const pkg of entry.affectedPackages) {
      const claims = pkg.vexClaims || [];
      const statuses = unique(claims.map((claim) => claim.status));
      const status = statuses.length > 1 ? "Needs verification" : statuses[0] || "Unreviewed";
      const trusted = claims.length > 0 && claims.every((claim) => claim.trusted === true);
      pkg.vexStatus = ["Not affected", "Fixed"].includes(status) && !trusted ? "Needs verification" : status;
      pkg.vex = { status: pkg.vexStatus, trusted: trusted && statuses.length === 1, detail: claims.map((claim) => claim.detail || claim.justification).filter(Boolean).join("; "), trustReason: trusted ? "Analyst approved this exact package decision." : "No approved package-specific VEX decision." };
    }
    const statuses = unique(entry.affectedPackages.map((pkg) => pkg.vexStatus));
    entry.vexStatus = statuses.length > 1 ? "Mixed" : statuses[0] || "Unreviewed";
    // Summaries cannot be used as suppression authority.
    entry.vex = null;
  }
  return report;
}
