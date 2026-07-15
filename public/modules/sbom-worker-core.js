const CVE_PATTERN = /CVE-\d{4}-\d{4,}/gi;

export function parseSbomPayload(file, text) {
  const source = String(text || "");
  const trimmed = source.trim();
  const base = {
    fileName: String(file?.name || "sbom"),
    size: Number(file?.size) || source.length,
    format: "Generic text",
    documentName: String(file?.name || "sbom"),
    components: [],
    vulnerabilities: [],
    cves: [],
    warnings: []
  };
  if (!trimmed) return { handled: true, parsed: { ...base, warnings: [`${base.fileName} is empty.`] } };
  if (trimmed.startsWith("<")) return { handled: false, reason: "XML uses the browser DOM parser fallback." };
  if (/^[\[{]/.test(trimmed)) {
    try {
      return { handled: true, parsed: parseJson(base, JSON.parse(trimmed), source) };
    } catch (error) {
      return {
        handled: true,
        parsed: { ...base, cves: extractCves(source), warnings: [`${base.fileName} is not valid JSON: ${safeMessage(error)}.`] }
      };
    }
  }
  if (/^SPDXVersion:/m.test(source) || /^PackageName:/m.test(source)) {
    return { handled: true, parsed: parseSpdxTagValue(base, source) };
  }
  return {
    handled: true,
    parsed: { ...base, cves: extractCves(source), warnings: [`${base.fileName} was parsed with generic text extraction.`] }
  };
}

function parseJson(base, json, text) {
  if (json?.bomFormat === "CycloneDX") return parseCycloneDx(base, json);
  if (json?.spdxVersion || (Array.isArray(json?.packages) && json?.SPDXID)) return parseSpdx(base, json);
  if (Array.isArray(json?.artifacts) && (json?.descriptor?.name === "syft" || json?.source)) return parseSyft(base, json);
  if (Array.isArray(json?.matches)) return parseGrype(base, json);
  return parseGeneric(base, json, text);
}

function parseCycloneDx(base, json) {
  const byRef = new Map();
  const components = arrayValue(json.components).slice(0, 100000).map((entry) => {
    const component = normalizeComponent({
      fileName: base.fileName,
      ref: entry["bom-ref"] || entry.bomRef || entry.purl,
      type: entry.type || "component",
      name: componentName(entry.group, entry.name),
      version: entry.version,
      supplier: actorName(entry.supplier),
      purl: entry.purl,
      cpes: entry.cpe ? [entry.cpe] : entry.cpes,
      licenses: extractLicenses(entry.licenses),
      cves: extractCves(stringify({ properties: entry.properties, evidence: entry.evidence, pedigree: entry.pedigree }))
    });
    if (component.ref) byRef.set(component.ref, component);
    return component;
  });
  const vulnerabilities = arrayValue(json.vulnerabilities).slice(0, 50000).flatMap((vulnerability) => {
    const cves = extractCves([vulnerability.id, stringify(vulnerability.references), stringify(vulnerability.advisories)].join(" "));
    const ids = cves.length ? cves : /^GHSA-/i.test(vulnerability.id || "") ? [String(vulnerability.id).toUpperCase()] : [];
    const rating = highestRating(vulnerability.ratings);
    const refs = arrayValue(vulnerability.affects).map((item) => item.ref).filter(Boolean);
    return ids.map((id) => ({
      cve: id,
      id: vulnerability.id || id,
      source: vulnerability.source?.name || vulnerability.source?.url || "CycloneDX vulnerability",
      severity: normalizeSeverity(rating?.severity),
      score: rating?.score ?? "",
      title: vulnerability.id || id,
      description: vulnerability.description || vulnerability.detail || "",
      fileName: base.fileName,
      componentRefs: refs,
      components: unique(refs.map((ref) => byRef.get(ref)).filter(Boolean).map(componentLabel)),
      references: extractUrls(stringify(vulnerability)),
      vex: vulnerability.analysis ? {
        status: normalizeVexStatus(vulnerability.analysis.state),
        justification: vulnerability.analysis.justification || "",
        response: arrayValue(vulnerability.analysis.response),
        detail: vulnerability.analysis.detail || ""
      } : null
    }));
  });
  return {
    ...base,
    format: `CycloneDX ${json.specVersion || ""}`.trim(),
    documentName: json.metadata?.component?.name || json.serialNumber || base.fileName,
    components,
    vulnerabilities,
    cves: extractCves(stringify({ metadata: json.metadata, properties: json.properties })),
    warnings: components.length >= 100000 ? ["Component processing was capped at 100,000 records."] : []
  };
}

function parseSpdx(base, json) {
  const components = arrayValue(json.packages).slice(0, 100000).map((entry) => {
    const refs = arrayValue(entry.externalRefs);
    return normalizeComponent({
      fileName: base.fileName,
      ref: entry.SPDXID,
      type: "package",
      name: entry.name || entry.packageName,
      version: entry.versionInfo || entry.packageVersion,
      supplier: actorName(entry.supplier || entry.packageSupplier),
      purl: refs.find((ref) => String(ref.referenceLocator || "").startsWith("pkg:"))?.referenceLocator,
      cpes: refs.map((ref) => ref.referenceLocator).filter((value) => /^cpe:/i.test(String(value || ""))),
      licenses: unique([entry.licenseConcluded, entry.licenseDeclared].filter((value) => value && value !== "NOASSERTION")),
      cves: extractCves(stringify(entry))
    });
  });
  return {
    ...base,
    format: `SPDX JSON ${json.spdxVersion || ""}`.trim(),
    documentName: json.name || json.documentName || base.fileName,
    components,
    cves: extractCves(stringify({ annotations: json.annotations, externalDocumentRefs: json.externalDocumentRefs })),
    warnings: components.length >= 100000 ? ["Package processing was capped at 100,000 records."] : []
  };
}

function parseSyft(base, json) {
  const components = arrayValue(json.artifacts).slice(0, 100000).map((entry) => normalizeComponent({
    fileName: base.fileName,
    ref: entry.id || entry.purl,
    type: entry.type || "package",
    name: entry.name,
    version: entry.version,
    supplier: entry.metadata?.supplier,
    purl: entry.purl,
    cpes: entry.cpes,
    licenses: arrayValue(entry.licenses).map((license) => typeof license === "string" ? license : license.value || license.spdxExpression),
    cves: extractCves(stringify(entry))
  }));
  return {
    ...base,
    format: `Syft JSON ${json.descriptor?.version || ""}`.trim(),
    documentName: json.source?.name || base.fileName,
    components,
    cves: extractCves(stringify(json.distro || {})),
    warnings: components.length >= 100000 ? ["Artifact processing was capped at 100,000 records."] : []
  };
}

function parseGrype(base, json) {
  const components = [];
  const vulnerabilities = arrayValue(json.matches).slice(0, 100000).flatMap((match) => {
    const artifact = match.artifact || {};
    const component = normalizeComponent({
      fileName: base.fileName,
      ref: artifact.id || artifact.purl,
      type: artifact.type || "package",
      name: artifact.name,
      version: artifact.version,
      purl: artifact.purl,
      cpes: artifact.cpes,
      licenses: artifact.licenses
    });
    if (component.name) components.push(component);
    const vulnerability = match.vulnerability || {};
    const ids = extractCves([vulnerability.id, stringify(match.relatedVulnerabilities)].join(" "));
    return ids.map((cve) => ({
      cve,
      id: vulnerability.id || cve,
      source: "Grype vulnerability report",
      severity: normalizeSeverity(vulnerability.severity),
      score: vulnerability.cvss?.[0]?.metrics?.baseScore ?? "",
      title: vulnerability.id || cve,
      description: vulnerability.description || "",
      fileName: base.fileName,
      componentRefs: component.ref || component.purl ? [component.ref || component.purl] : [],
      components: component.name ? [componentLabel(component)] : [],
      references: arrayValue(vulnerability.urls)
    }));
  });
  return {
    ...base,
    format: "Grype vulnerability report",
    documentName: json.source?.target?.userInput || base.fileName,
    components,
    vulnerabilities,
    warnings: arrayValue(json.matches).length > 100000 ? ["Finding processing was capped at 100,000 records."] : []
  };
}

function parseGeneric(base, json, text) {
  const source = Array.isArray(json.components) ? json.components : Array.isArray(json.packages) ? json.packages : [];
  const components = source.slice(0, 100000).map((entry) => normalizeComponent({
    fileName: base.fileName,
    ref: entry["bom-ref"] || entry.SPDXID || entry.id || entry.purl,
    type: entry.type || "component",
    name: entry.name || entry.packageName,
    version: entry.version || entry.versionInfo || entry.packageVersion,
    supplier: actorName(entry.supplier || entry.author || entry.publisher),
    purl: entry.purl,
    cpes: entry.cpe ? [entry.cpe] : entry.cpes,
    licenses: extractLicenses(entry.licenses || entry.license),
    cves: extractCves(stringify(entry))
  }));
  return {
    ...base,
    format: "Generic JSON SBOM",
    documentName: json.name || json.documentName || json.serialNumber || base.fileName,
    components,
    cves: extractCves(text),
    warnings: ["JSON parsed, but its SBOM format was not recognized."].concat(source.length > 100000 ? ["Component processing was capped at 100,000 records."] : [])
  };
}

function parseSpdxTagValue(base, text) {
  const blocks = text.split(/\n(?=PackageName:)/g);
  const components = blocks.slice(0, 100000).map((block) => {
    const refs = [...block.matchAll(/^ExternalRef:\s+\S+\s+\S+\s+(.+)$/gm)].map((match) => match[1].trim());
    return normalizeComponent({
      fileName: base.fileName,
      ref: field(block, "SPDXID"),
      type: "package",
      name: field(block, "PackageName"),
      version: field(block, "PackageVersion"),
      supplier: actorName(field(block, "PackageSupplier")),
      purl: refs.find((value) => value.startsWith("pkg:")),
      cpes: refs.filter((value) => /^cpe:/i.test(value)),
      licenses: [field(block, "PackageLicenseConcluded"), field(block, "PackageLicenseDeclared")].filter((value) => value && value !== "NOASSERTION"),
      cves: extractCves(block)
    });
  }).filter((component) => component.name);
  return {
    ...base,
    format: field(text, "SPDXVersion") || "SPDX tag-value",
    documentName: field(text, "DocumentName") || base.fileName,
    components,
    cves: extractCves(text),
    warnings: blocks.length > 100000 ? ["Package processing was capped at 100,000 records."] : []
  };
}

function normalizeComponent(value) {
  return {
    fileName: String(value.fileName || ""),
    ref: String(value.ref || ""),
    type: String(value.type || "component"),
    name: String(value.name || ""),
    version: String(value.version || ""),
    supplier: String(value.supplier || ""),
    purl: String(value.purl || ""),
    cpes: unique(value.cpes),
    licenses: unique(value.licenses),
    cves: unique(value.cves)
  };
}

function normalizeVexStatus(value) {
  const state = String(value || "").toLowerCase().replace(/[ -]+/g, "_");
  if (["affected", "exploitable", "known_affected"].includes(state)) return "Affected";
  if (["not_affected", "not_exploitable", "known_not_affected"].includes(state)) return "Not affected";
  if (["fixed", "resolved"].includes(state)) return "Fixed";
  if (["under_investigation", "in_triage"].includes(state)) return "Under investigation";
  return state ? state.replace(/_/g, " ") : "Unknown";
}

function normalizeSeverity(value) {
  const text = String(value || "").toLowerCase();
  if (text === "critical") return "Critical";
  if (text === "high") return "High";
  if (["medium", "moderate"].includes(text)) return "Medium";
  if (text === "low") return "Low";
  if (["none", "negligible"].includes(text)) return "None";
  return text ? text[0].toUpperCase() + text.slice(1) : "";
}

function highestRating(value) {
  const rank = { critical: 5, high: 4, medium: 3, moderate: 3, low: 2, none: 1 };
  return [...arrayValue(value)].sort((a, b) => (rank[String(b?.severity || "").toLowerCase()] || 0) - (rank[String(a?.severity || "").toLowerCase()] || 0) || Number(b?.score || 0) - Number(a?.score || 0))[0] || null;
}

function extractCves(value) {
  return unique(String(value || "").match(CVE_PATTERN) || []).map((item) => item.toUpperCase());
}

function extractUrls(value) {
  return unique(String(value || "").match(/https?:\/\/[^\s"'<>),]+/g) || []);
}

function extractLicenses(value) {
  return arrayValue(value).map((entry) => {
    if (typeof entry === "string") return entry;
    return entry?.license?.id || entry?.license?.name || entry?.expression || entry?.id || entry?.name || entry?.value || "";
  }).filter(Boolean);
}

function actorName(value) {
  if (!value) return "";
  const text = typeof value === "string" ? value : value.name || value.url || "";
  return String(text).replace(/^(Organization|Person):\s*/i, "").replace(/^NOASSERTION$/i, "").trim();
}

function componentName(group, name) {
  const left = String(group || "").trim();
  const right = String(name || "").trim();
  return left && right && !right.startsWith(`${left}/`) ? `${left}/${right}` : right || left;
}

function componentLabel(component) {
  return `${component.name || component.purl || component.ref || "Unknown component"}${component.version ? `@${component.version}` : ""}`;
}

function field(text, name) {
  return String(text || "").match(new RegExp(`^${escapeRegExp(name)}:\\s*(.+)$`, "m"))?.[1]?.trim() || "";
}

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function arrayValue(value) {
  if (Array.isArray(value)) return value;
  if (value === undefined || value === null || value === "") return [];
  return [value];
}

function unique(value) {
  return [...new Set(arrayValue(value).filter((item) => item !== undefined && item !== null && String(item).trim()).map((item) => String(item).trim()))];
}

function stringify(value) {
  try {
    return JSON.stringify(value || {});
  } catch {
    return "";
  }
}

function safeMessage(error) {
  return String(error?.message || "invalid input").slice(0, 180);
}
