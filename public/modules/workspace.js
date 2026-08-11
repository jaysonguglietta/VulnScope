const CVE_PATTERN = /CVE-\d{4}-\d{4,}/gi;
const MAX_SOURCE_ROWS = 10000;
const MAX_ARRAY_DIMENSION = 500;
const MAX_VEX_STATEMENTS = 10000;
const MAX_CSV_COLUMNS = 250;
const MAX_CELL_LENGTH = 10000;
const MAX_FLATTEN_DEPTH = 40;
const MAX_FLATTEN_KEYS = 2000;
const DEFAULT_MAX_OUTPUT_RECORDS = 50000;
const VEX_STATES = new Map([
  ["affected", "Affected"],
  ["known_affected", "Affected"],
  ["exploitable", "Affected"],
  ["not_affected", "Not affected"],
  ["known_not_affected", "Not affected"],
  ["not_exploitable", "Not affected"],
  ["fixed", "Fixed"],
  ["resolved", "Fixed"],
  ["under_investigation", "Under investigation"],
  ["in_triage", "Under investigation"]
]);

export function parseEvidenceFile(file, text, options = {}) {
  const trimmed = String(text || "").trim();
  const base = {
    id: makeId("evidence"),
    fileName: file?.name || "evidence",
    size: Number(file?.size) || trimmed.length,
    importedAt: new Date().toISOString(),
    format: "Unknown evidence",
    findings: [],
    assets: [],
    vexStatements: [],
    warnings: []
  };
  base.recordLimit = Math.max(1, Math.min(DEFAULT_MAX_OUTPUT_RECORDS, Number(options.maxOutputRecords) || DEFAULT_MAX_OUTPUT_RECORDS));
  if (!trimmed) return { ...base, warnings: ["The evidence file is empty."] };

  if (/^[\[{]/.test(trimmed)) {
    try {
      return parseEvidenceJson(base, JSON.parse(trimmed));
    } catch (error) {
      return { ...base, warnings: [`JSON could not be parsed: ${safeMessage(error)}.`] };
    }
  }

  const csv = parseCsv(trimmed);
  if (csv.rows.length) {
    if (csv.truncated) base.warnings.push(`CSV processing was capped at ${MAX_SOURCE_ROWS.toLocaleString()} rows and ${MAX_CSV_COLUMNS} columns.`);
    return parseEvidenceRows({ ...base, format: "Cloud vulnerability CSV" }, csv.rows);
  }
  return { ...base, warnings: ["The file was not recognized as supported JSON, VEX, or CSV evidence."] };
}

function parseEvidenceJson(base, json) {
  if (isOpenVex(json)) return parseOpenVex({ ...base, format: "OpenVEX" }, json);
  if (isCsafVex(json)) return parseCsafVex({ ...base, format: "CSAF VEX" }, json);
  if (json?.bomFormat === "CycloneDX" && Array.isArray(json.vulnerabilities)) {
    return parseCycloneVex({ ...base, format: `CycloneDX ${json.specVersion || ""} VEX`.trim() }, json);
  }
  const inspectorFindings = arrayValue(json?.findings);
  if (inspectorFindings.some((item) => item?.packageVulnerabilityDetails || item?.resources)) {
    return parseAwsInspector({ ...base, format: "Amazon Inspector findings" }, inspectorFindings);
  }
  const values = arrayValue(json?.value || json);
  if (values.length) return parseEvidenceRows({ ...base, format: "Cloud vulnerability JSON" }, values);
  return { ...base, warnings: ["JSON was valid but did not contain a supported evidence structure."] };
}

function parseAwsInspector(base, rows) {
  const findings = [];
  const assets = [];
  let truncated = rows.length > MAX_SOURCE_ROWS;
  findingRows: for (const row of rows.slice(0, MAX_SOURCE_ROWS)) {
    const details = row.packageVulnerabilityDetails || {};
    const vulnerabilityIds = unique([
      details.vulnerabilityId,
      ...arrayValue(details.relatedVulnerabilities),
      ...extractCves(stringify(row.title))
    ]).filter(Boolean).slice(0, MAX_ARRAY_DIMENSION);
    const resources = arrayValue(row.resources).slice(0, MAX_ARRAY_DIMENSION);
    const packages = arrayValue(details.vulnerablePackages).slice(0, MAX_ARRAY_DIMENSION);
    if (arrayValue(row.resources).length > resources.length || arrayValue(details.vulnerablePackages).length > packages.length) truncated = true;
    const normalizedResources = resources.length ? resources : [{}];
    const normalizedPackages = packages.length ? packages : [{}];
    for (const resource of normalizedResources) {
      const asset = normalizeAsset({
        provider: "AWS",
        id: resource.id || resource.details?.awsEc2Instance?.instanceId || "",
        name: tagValue(resource.tags, "Name") || resource.id || row.resources?.[0]?.id || "AWS resource",
        type: resource.type || "AWS resource",
        account: resource.partition || "",
        region: resource.region || "",
        source: base.fileName
      });
      assets.push(asset);
      for (const vulnerability of vulnerabilityIds) {
        for (const pkg of normalizedPackages) {
          findings.push(normalizeFinding({
            vulnerability,
            severity: row.severity,
            title: row.title,
            description: row.description,
            provider: "AWS",
            assetId: asset.id,
            assetName: asset.name,
            assetType: asset.type,
            packageName: pkg.name,
            installedVersion: pkg.version,
            fixedVersion: pkg.fixedInVersion,
            packageManager: pkg.packageManager,
            purl: pkg.purl,
            status: row.status,
            fixAvailable: details.fixAvailable || row.fixAvailable,
            exploitAvailable: details.exploitAvailable || row.exploitAvailable,
            remediation: row.remediation?.recommendation?.text || row.remediation?.recommendation?.url || "",
            source: "Amazon Inspector"
          }));
          if (findings.length >= base.recordLimit) {
            truncated = true;
            break findingRows;
          }
        }
      }
    }
  }
  if (truncated) base.warnings.push(`Inspector expansion was capped at ${base.recordLimit.toLocaleString()} normalized records and ${MAX_ARRAY_DIMENSION} values per dimension.`);
  return finalizeReport(base, findings, assets, []);
}

function parseEvidenceRows(base, rows) {
  const findings = [];
  const assets = [];
  let truncated = rows.length > MAX_SOURCE_ROWS;
  rowLoop: for (const row of rows.slice(0, MAX_SOURCE_ROWS)) {
    const flat = flattenRecord(row);
    const vulnerabilityValues = [
      pick(flat, ["cve", "cveid", "vulnerabilityid", "vulnerability", "id"]),
      pick(flat, ["additionaldata.cve", "properties.cve", "metadata.cve"]),
      stringify(row)
    ];
    const vulnerabilities = unique(vulnerabilityValues.flatMap(extractCves)).slice(0, MAX_ARRAY_DIMENSION);
    if (!vulnerabilities.length) continue;
    const resourceId = pick(flat, ["resourceid", "resource.id", "resource", "resourceidentifier", "properties.resourceid"]);
    const provider = inferProvider(resourceId, flat);
    const asset = normalizeAsset({
      provider,
      id: resourceId,
      name: pick(flat, ["resourcename", "resource.name", "assetname", "name", "displayname"]) || resourceId || `${provider || "Cloud"} resource`,
      type: pick(flat, ["resourcetype", "resource.type", "assettype", "type"]),
      account: pick(flat, ["accountid", "subscriptionid", "subscription", "account"]),
      region: pick(flat, ["region", "location"]),
      source: base.fileName
    });
    assets.push(asset);
    for (const vulnerability of vulnerabilities) {
      findings.push(normalizeFinding({
        vulnerability,
        severity: pick(flat, ["severity", "risk", "properties.severity"]),
        title: pick(flat, ["title", "displayname", "assessment", "recommendation"]),
        description: pick(flat, ["description", "properties.description"]),
        provider,
        assetId: asset.id,
        assetName: asset.name,
        assetType: asset.type,
        packageName: pick(flat, ["packagename", "package", "software", "component"]),
        installedVersion: pick(flat, ["installedversion", "version", "currentversion"]),
        fixedVersion: pick(flat, ["fixedversion", "fixversion", "patchedversion", "targetversion"]),
        purl: pick(flat, ["purl", "packageurl"]),
        status: pick(flat, ["status", "state", "workflowstatus"]),
        remediation: pick(flat, ["remediation", "recommendation", "solution"]),
        source: provider === "Azure" ? "Microsoft Defender for Cloud" : provider === "AWS" ? "AWS finding import" : "Cloud finding import"
      }));
      if (findings.length >= base.recordLimit) {
        truncated = true;
        break rowLoop;
      }
    }
  }
  if (truncated) base.warnings.push(`Evidence processing was capped at ${base.recordLimit.toLocaleString()} normalized records.`);
  return finalizeReport(base, findings, assets, []);
}

function parseOpenVex(base, json) {
  const sourceStatements = arrayValue(json.statements);
  const statements = sourceStatements.slice(0, Math.min(MAX_VEX_STATEMENTS, base.recordLimit)).map((statement) => normalizeVexStatement({
    vulnerability: statement.vulnerability?.name || statement.vulnerability?.id,
    aliases: statement.vulnerability?.aliases,
    products: arrayValue(statement.products).slice(0, MAX_ARRAY_DIMENSION).map((product) => product["@id"] || product.id || product.name).filter(Boolean),
    status: statement.status,
    justification: statement.justification,
    impact: statement.impact_statement,
    action: statement.action_statement,
    detail: statement.status_notes,
    timestamp: statement.timestamp || json.timestamp,
    source: "OpenVEX"
  })).filter((statement) => statement.vulnerability);
  if (sourceStatements.length > statements.length) base.warnings.push(`VEX processing was capped at ${statements.length.toLocaleString()} statements.`);
  return finalizeReport(base, [], [], statements);
}

function parseCsafVex(base, json) {
  const names = buildCsafProductNames(json.product_tree);
  const statements = [];
  let truncated = false;
  vulnerabilityLoop: for (const vulnerability of arrayValue(json.vulnerabilities).slice(0, MAX_VEX_STATEMENTS)) {
    const status = vulnerability.product_status || {};
    for (const [rawState, productIds] of Object.entries(status).slice(0, 20)) {
      statements.push(normalizeVexStatement({
        vulnerability: vulnerability.cve || vulnerability.title,
        products: arrayValue(productIds).slice(0, MAX_ARRAY_DIMENSION).map((id) => names.get(id) || id),
        status: rawState,
        justification: arrayValue(vulnerability.flags)[0]?.label || "",
        action: arrayValue(vulnerability.remediations).map((item) => item.details).filter(Boolean).join(" "),
        impact: arrayValue(vulnerability.threats).map((item) => item.details).filter(Boolean).join(" "),
        detail: arrayValue(vulnerability.notes).map((item) => item.text).filter(Boolean).join(" "),
        timestamp: json.document?.tracking?.current_release_date,
        source: "CSAF VEX"
      }));
      if (statements.length >= base.recordLimit) {
        truncated = true;
        break vulnerabilityLoop;
      }
    }
  }
  if (truncated || arrayValue(json.vulnerabilities).length > MAX_VEX_STATEMENTS) base.warnings.push(`CSAF VEX processing was capped at ${base.recordLimit.toLocaleString()} statements.`);
  return finalizeReport(base, [], [], statements.filter((statement) => statement.vulnerability));
}

function parseCycloneVex(base, json) {
  const sourceVulnerabilities = arrayValue(json.vulnerabilities);
  const statements = sourceVulnerabilities.slice(0, Math.min(MAX_VEX_STATEMENTS, base.recordLimit)).map((vulnerability) => normalizeVexStatement({
    vulnerability: vulnerability.id,
    aliases: arrayValue(vulnerability.references).map((item) => item.id),
    products: arrayValue(vulnerability.affects).slice(0, MAX_ARRAY_DIMENSION).map((item) => item.ref).filter(Boolean),
    status: vulnerability.analysis?.state,
    justification: vulnerability.analysis?.justification,
    impact: vulnerability.analysis?.detail,
    action: arrayValue(vulnerability.analysis?.response).join(", "),
    detail: vulnerability.detail || vulnerability.description,
    timestamp: vulnerability.updated || vulnerability.published || json.metadata?.timestamp,
    source: "CycloneDX VEX"
  })).filter((statement) => statement.vulnerability && statement.status !== "Unknown");
  if (sourceVulnerabilities.length > statements.length) base.warnings.push(`CycloneDX VEX processing was capped at ${statements.length.toLocaleString()} statements.`);
  return finalizeReport(base, [], [], statements);
}

export function buildExposureRows({ sbomReports = [], evidenceReports = [], enrichmentReports = [], investigations = [] } = {}) {
  const rows = [];
  for (const report of sbomReports) {
    for (const entry of arrayValue(report.cves)) {
      const packages = arrayValue(entry.affectedPackages);
      const records = packages.length ? packages : [{}];
      for (const pkg of records) {
        rows.push(normalizeExposure({
          vulnerability: entry.id,
          severity: entry.severity,
          packageName: pkg.name || pkg.label,
          installedVersion: pkg.version,
          purl: pkg.purl,
          source: "SBOM",
          sourceFile: pkg.fileName || entry.files?.[0] || report.title,
          assetName: report.title,
          assetType: "SBOM",
          vexStatus: entry.vexStatus,
          vexTrusted: Boolean(entry.vex?.trusted),
          vexClaimedStatus: entry.vexStatus,
          vexTrustReason: entry.vex?.trustReason || "Embedded SBOM VEX is unverified.",
          summary: entry.vex?.detail || entry.vex?.justification || ""
        }));
      }
    }
  }
  for (const report of enrichmentReports) {
    for (const pkg of arrayValue(report.packages)) {
      for (const vulnerability of arrayValue(pkg.vulnerabilities)) {
        const ids = vulnerability.cves?.length ? vulnerability.cves : [vulnerability.id];
        for (const id of ids) {
          rows.push(normalizeExposure({
            vulnerability: id,
            aliases: vulnerability.aliases,
            severity: vulnerability.severity,
            packageName: pkg.name || purlName(pkg.purl),
            installedVersion: pkg.version || purlVersion(pkg.purl),
            fixedVersion: vulnerability.fixedVersions?.[0],
            purl: pkg.purl,
            source: "OSV",
            sourceFile: pkg.fileName,
            assetName: pkg.fileName || "Enriched SBOM",
            assetType: "SBOM",
            summary: vulnerability.summary,
            references: vulnerability.references
          }));
        }
      }
    }
  }
  for (const report of evidenceReports) rows.push(...arrayValue(report.findings).map(normalizeExposure));

  const vexStatements = evidenceReports.flatMap((report) => arrayValue(report.vexStatements));
  const investigationMap = new Map(investigations.filter(Boolean).map((item) => [String(item.id || "").toUpperCase(), item]));
  const deduped = dedupeExposures(rows).map((row) => {
    const investigation = investigationMap.get(row.vulnerability);
    const vex = bestVexStatement(row, vexStatements);
    const claimedVexStatus = vex?.status || row.vexClaimedStatus || row.vexStatus || "Unreviewed";
    const vexTrusted = vex ? Boolean(vex.trusted) : Boolean(row.vexTrusted);
    const suppressiveVex = ["Not affected", "Fixed"].includes(claimedVexStatus);
    const enriched = {
      ...row,
      vexStatus: suppressiveVex && !vexTrusted ? "Needs verification" : claimedVexStatus,
      vexClaimedStatus: claimedVexStatus,
      vexTrusted,
      vexTrustReason: vex?.trustReason || row.vexTrustReason || "No trusted VEX decision is available.",
      vexMatchedProducts: vex?.products || [],
      vexJustification: vex?.justification || vex?.impact || "",
      vexAction: vex?.action || "",
      kev: Boolean(investigation?.metrics?.kev?.listed || row.kev),
      epss: investigation?.metrics?.epss?.epss ?? row.epss ?? null,
      cvss: investigation?.metrics?.cvss?.score ?? row.cvss ?? null,
      exploitStatus: investigation?.realWorld?.exploitedStatus || row.exploitStatus || "Unknown",
      researchRisk: investigation?.risk?.score ?? null,
      owner: investigation?.caseDraft?.owner || investigation?.owner || row.owner || "",
      workflowStatus: investigation?.caseDraft?.status || investigation?.status || row.workflowStatus || "Needs triage"
    };
    return { ...enriched, priorityScore: exposurePriority(enriched), priority: exposurePriorityLabel(exposurePriority(enriched)) };
  });
  return deduped.sort((a, b) => b.priorityScore - a.priorityScore || a.vulnerability.localeCompare(b.vulnerability));
}

export function summarizeExposureRows(rows) {
  const active = rows.filter((row) => !["Not affected", "Fixed"].includes(row.vexStatus));
  return {
    total: rows.length,
    vulnerabilities: new Set(rows.map((row) => row.vulnerability)).size,
    assets: new Set(rows.map((row) => row.assetId || row.assetName).filter(Boolean)).size,
    critical: active.filter((row) => row.priority === "Critical").length,
    knownExploited: active.filter((row) => row.kev).length,
    notAffected: rows.filter((row) => row.vexStatus === "Not affected").length,
    fixed: rows.filter((row) => row.vexStatus === "Fixed").length
  };
}

export function normalizeVexStatus(value) {
  const key = String(value || "").trim().toLowerCase().replace(/[ -]+/g, "_");
  return VEX_STATES.get(key) || (key ? titleCase(key) : "Unknown");
}

function normalizeVexStatement(value) {
  return {
    vulnerability: normalizeVulnerability(value.vulnerability),
    aliases: unique(arrayValue(value.aliases).map(normalizeVulnerability).filter(Boolean)),
    products: unique(arrayValue(value.products).slice(0, MAX_ARRAY_DIMENSION).map((item) => boundedText(item, 1000).trim()).filter(Boolean)),
    status: normalizeVexStatus(value.status),
    justification: boundedText(value.justification),
    impact: boundedText(value.impact),
    action: boundedText(value.action),
    detail: boundedText(value.detail),
    timestamp: value.timestamp || null,
    source: value.source || "VEX",
    trusted: Boolean(value.trusted),
    approvedAt: value.approvedAt || null,
    trustReason: String(value.trustReason || "Imported VEX is unverified.")
  };
}

function normalizeFinding(value) {
  return normalizeExposure(value);
}

function normalizeExposure(value) {
  const vulnerability = normalizeVulnerability(value.vulnerability || value.cve || value.id);
  return {
    id: makeId("exposure"),
    vulnerability,
    aliases: unique(arrayValue(value.aliases).map(normalizeVulnerability).filter(Boolean)),
    severity: normalizeSeverity(value.severity),
    cvss: finiteNumber(value.cvss),
    kev: Boolean(value.kev),
    epss: finiteNumber(value.epss),
    exploitStatus: value.exploitStatus || (truthy(value.exploitAvailable) ? "Exploit evidence available" : "Unknown"),
    packageName: String(value.packageName || value.name || ""),
    installedVersion: String(value.installedVersion || value.version || ""),
    fixedVersion: String(value.fixedVersion || ""),
    packageManager: String(value.packageManager || ""),
    purl: String(value.purl || ""),
    provider: String(value.provider || ""),
    assetId: String(value.assetId || ""),
    assetName: String(value.assetName || ""),
    assetType: String(value.assetType || ""),
    source: String(value.source || "Imported evidence"),
    sourceFile: String(value.sourceFile || ""),
    summary: String(value.summary || value.title || value.description || ""),
    remediation: String(value.remediation || ""),
    workflowStatus: String(value.workflowStatus || value.status || "Needs triage"),
    owner: String(value.owner || ""),
    vexStatus: normalizeVexStatus(value.vexStatus || ""),
    vexClaimedStatus: normalizeVexStatus(value.vexClaimedStatus || value.vexStatus || ""),
    vexTrusted: Boolean(value.vexTrusted),
    vexTrustReason: String(value.vexTrustReason || ""),
    references: arrayValue(value.references)
  };
}

function normalizeAsset(value) {
  return {
    id: String(value.id || value.name || makeId("asset")),
    provider: String(value.provider || ""),
    name: String(value.name || value.id || "Unknown asset"),
    type: String(value.type || "Resource"),
    account: String(value.account || ""),
    region: String(value.region || ""),
    source: String(value.source || "")
  };
}

function finalizeReport(base, findings, assets, vexStatements) {
  const limit = base.recordLimit || DEFAULT_MAX_OUTPUT_RECORDS;
  const cleanFindings = findings.filter((item) => item.vulnerability).slice(0, limit);
  const cleanAssets = dedupeBy(assets.filter((item) => item.id || item.name), (item) => `${item.provider}|${item.id}|${item.name}`).slice(0, Math.max(0, limit - cleanFindings.length));
  const cleanVexStatements = vexStatements.slice(0, Math.max(0, limit - cleanFindings.length - cleanAssets.length));
  const { recordLimit, ...reportBase } = base;
  return {
    ...reportBase,
    findings: cleanFindings,
    assets: cleanAssets,
    vexStatements: cleanVexStatements,
    summary: `${cleanFindings.length} finding${cleanFindings.length === 1 ? "" : "s"}, ${cleanAssets.length} asset${cleanAssets.length === 1 ? "" : "s"}, and ${cleanVexStatements.length} VEX statement${cleanVexStatements.length === 1 ? "" : "s"}.`
  };
}

function dedupeExposures(rows) {
  return dedupeBy(rows.filter((row) => row.vulnerability), (row) => [
    row.vulnerability,
    row.packageName,
    row.installedVersion,
    row.purl,
    row.assetId,
    row.assetName,
    row.sourceFile
  ].join("|").toLowerCase()).map((row) => ({ ...row }));
}

function bestVexStatement(row, statements) {
  const identifiers = new Set([row.vulnerability, ...row.aliases].filter(Boolean));
  const candidates = statements.filter((statement) => identifiers.has(statement.vulnerability) || statement.aliases.some((alias) => identifiers.has(alias)));
  const rowProducts = [row.purl, row.packageName, row.assetId, row.assetName]
    .map(normalizeProductIdentity)
    .filter((value) => value.length >= 3);
  const matched = candidates.find((statement) => statement.products.some((item) => {
    const product = normalizeProductIdentity(item);
    if (product.length < 3) return false;
    return rowProducts.some((value) => value === product);
  }));
  return matched;
}

function exposurePriority(row) {
  if (row.vexStatus === "Not affected") return 0;
  if (row.vexStatus === "Fixed") return 5;
  let score = row.researchRisk ?? 0;
  const severity = normalizeSeverity(row.severity);
  if (!row.researchRisk) score += severity === "Critical" ? 50 : severity === "High" ? 35 : severity === "Medium" ? 20 : severity === "Low" ? 8 : 12;
  if (row.kev) score += 35;
  if (/confirmed|known exploited|weaponized/i.test(row.exploitStatus)) score += 22;
  if (Number.isFinite(row.epss)) score += Math.round(Math.min(1, row.epss) * 25);
  if (row.vexStatus === "Affected") score += 15;
  if (row.fixedVersion) score += 3;
  return Math.max(0, Math.min(100, score));
}

function exposurePriorityLabel(score) {
  if (score >= 80) return "Critical";
  if (score >= 60) return "High";
  if (score >= 35) return "Medium";
  return "Low";
}

function parseCsv(text) {
  const rows = [];
  let row = [];
  let value = "";
  let quoted = false;
  let truncated = false;
  const pushValue = () => {
    if (row.length < MAX_CSV_COLUMNS) row.push(value.replace(/\r$/, ""));
    else truncated = true;
    value = "";
  };
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    if (quoted) {
      if (char === '"' && text[index + 1] === '"') {
        value += '"';
        index += 1;
      } else if (char === '"') quoted = false;
      else if (value.length < MAX_CELL_LENGTH) value += char;
      else truncated = true;
    } else if (char === '"') quoted = true;
    else if (char === ",") {
      pushValue();
    } else if (char === "\n") {
      pushValue();
      rows.push(row);
      row = [];
      if (rows.length > MAX_SOURCE_ROWS) {
        truncated = true;
        break;
      }
    } else if (value.length < MAX_CELL_LENGTH) value += char;
    else truncated = true;
  }
  pushValue();
  if (row.some((item) => item.trim())) rows.push(row);
  if (rows.length < 2) return { rows: [], truncated };
  const headers = rows[0].map((item) => normalizeKey(item));
  return {
    rows: rows.slice(1, MAX_SOURCE_ROWS + 1).map((values) => Object.fromEntries(headers.map((header, index) => [header, values[index] || ""]))),
    truncated
  };
}

function flattenRecord(value, prefix = "", output = {}, depth = 0) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return output;
  if (depth >= MAX_FLATTEN_DEPTH || Object.keys(output).length >= MAX_FLATTEN_KEYS) return output;
  for (const [key, child] of Object.entries(value)) {
    if (Object.keys(output).length >= MAX_FLATTEN_KEYS) break;
    const path = normalizeKey(prefix ? `${prefix}.${key}` : key);
    if (child && typeof child === "object" && !Array.isArray(child)) flattenRecord(child, path, output, depth + 1);
    else output[path] = boundedText(Array.isArray(child) ? child.slice(0, MAX_ARRAY_DIMENSION).join(", ") : child);
  }
  return output;
}

function pick(record, keys) {
  for (const key of keys) {
    const value = record[normalizeKey(key)];
    if (value !== undefined && value !== null && String(value).trim()) return String(value).trim();
  }
  return "";
}

function inferProvider(resourceId, flat) {
  const value = `${resourceId} ${pick(flat, ["provider", "cloud", "platform"])}`.toLowerCase();
  if (value.includes("/subscriptions/") || value.includes("azure") || value.includes("microsoft")) return "Azure";
  if (value.includes("arn:aws") || value.includes("aws") || value.includes("amazon")) return "AWS";
  return "Cloud";
}

function isOpenVex(json) {
  return Array.isArray(json?.statements) && (String(json?.["@context"] || "").toLowerCase().includes("openvex") || json.statements.some((item) => item?.vulnerability && item?.status));
}

function isCsafVex(json) {
  return String(json?.document?.category || "").toLowerCase().includes("vex") && Array.isArray(json?.vulnerabilities);
}

function buildCsafProductNames(productTree) {
  const output = new Map();
  const visit = (branch, depth = 0) => {
    if (depth >= MAX_FLATTEN_DEPTH || output.size >= MAX_FLATTEN_KEYS) return;
    const product = branch?.product;
    if (product?.product_id) output.set(product.product_id, product.name || product.product_id);
    for (const child of arrayValue(branch?.branches).slice(0, MAX_ARRAY_DIMENSION)) visit(child, depth + 1);
  };
  for (const branch of arrayValue(productTree?.branches)) visit(branch);
  for (const relationship of arrayValue(productTree?.relationships)) {
    const product = relationship.full_product_name;
    if (product?.product_id) output.set(product.product_id, product.name || product.product_id);
  }
  return output;
}

function tagValue(tags, key) {
  if (!tags || typeof tags !== "object") return "";
  return tags[key] || tags[key.toLowerCase()] || "";
}

function extractCves(value) {
  return unique(String(value || "").match(CVE_PATTERN) || []).map((item) => item.toUpperCase());
}

function normalizeVulnerability(value) {
  const text = String(value || "").trim().toUpperCase();
  const cve = text.match(/^CVE-\d{4}-\d{4,}$/)?.[0];
  if (cve) return cve;
  return /^GHSA-[A-Z0-9-]+$/i.test(text) ? text : text.slice(0, 120);
}

function normalizeSeverity(value) {
  const text = String(value || "").trim().toLowerCase();
  if (text === "critical") return "Critical";
  if (text === "high") return "High";
  if (["medium", "moderate"].includes(text)) return "Medium";
  if (text === "low") return "Low";
  if (["none", "negligible"].includes(text)) return "None";
  return text ? titleCase(text) : "Unknown";
}

function purlName(purl) {
  const path = String(purl || "").replace(/^pkg:[^/]+\//, "").split(/[?@#]/)[0];
  return safeDecodeURIComponent(path.split("/").pop() || "");
}

function purlVersion(purl) {
  return safeDecodeURIComponent(String(purl || "").match(/@([^?#]+)/)?.[1] || "");
}

function normalizeProductIdentity(value) {
  return safeDecodeURIComponent(String(value || "")).trim().toLowerCase();
}

function safeDecodeURIComponent(value) {
  try {
    return decodeURIComponent(String(value || ""));
  } catch {
    return String(value || "");
  }
}

function finiteNumber(value) {
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}

function truthy(value) {
  return value === true || ["yes", "true", "available", "active"].includes(String(value || "").toLowerCase());
}

function normalizeKey(value) {
  return String(value || "").trim().toLowerCase().replace(/[^a-z0-9.]+/g, "");
}

function arrayValue(value) {
  if (Array.isArray(value)) return value;
  if (value === undefined || value === null || value === "") return [];
  return [value];
}

function unique(values) {
  return [...new Set(arrayValue(values).filter((value) => value !== undefined && value !== null && String(value).trim()).map((value) => String(value).trim()))];
}

function dedupeBy(values, key) {
  const seen = new Set();
  return values.filter((value) => {
    const id = key(value);
    if (seen.has(id)) return false;
    seen.add(id);
    return true;
  });
}

function titleCase(value) {
  return String(value || "").replace(/_/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
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

function boundedText(value, maxLength = MAX_CELL_LENGTH) {
  return String(value || "").slice(0, maxLength);
}

function makeId(prefix) {
  if (globalThis.crypto?.randomUUID) return `${prefix}-${globalThis.crypto.randomUUID()}`;
  return `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}
