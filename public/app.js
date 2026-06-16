const APP_SCHEMA_VERSION = 3;
const STORAGE_RETENTION_DAYS = 90;
const STORAGE_RETENTION_MS = STORAGE_RETENTION_DAYS * 24 * 60 * 60 * 1000;
const SAFE_LINK_PROTOCOLS = new Set(["http:", "https:"]);
const SBOM_MAX_FILES = 10;
const SBOM_MAX_FILE_BYTES = 10 * 1024 * 1024;
const SBOM_MAX_TOTAL_BYTES = 40 * 1024 * 1024;
const SBOM_COMPONENT_DISPLAY_LIMIT = 200;
const SBOM_CVE_DISPLAY_LIMIT = 150;

const state = {
  current: null,
  activeTab: "overview",
  evidenceFilter: "all",
  evidenceSort: "priority",
  cases: loadCases(),
  watchlist: loadWatchlist(),
  sbomReports: [],
  activeSbomId: null,
  activeSbomCveId: null,
  assetInput: "",
  caseFilter: "",
  sourceHealth: [],
  loading: false
};

const elements = {
  form: document.querySelector("#searchForm"),
  input: document.querySelector("#cveInput"),
  button: document.querySelector("#researchButton"),
  content: document.querySelector("#content"),
  toast: document.querySelector("#toast"),
  searchError: document.querySelector("#searchError"),
  caseList: document.querySelector("#caseList"),
  caseFilter: document.querySelector("#caseFilter"),
  health: document.querySelector("#sourceHealth"),
  healthRefresh: document.querySelector("#healthRefresh"),
  watchList: document.querySelector("#watchList"),
  watchRefreshAll: document.querySelector("#watchRefreshAll"),
  sbomInput: document.querySelector("#sbomInput"),
  sbomList: document.querySelector("#sbomList"),
  sbomClear: document.querySelector("#sbomClear"),
  clearLocalData: document.querySelector("#clearLocalData"),
  emptyTemplate: document.querySelector("#emptyTemplate")
};

elements.form.addEventListener("submit", (event) => {
  event.preventDefault();
  const cve = normalizeCve(elements.input.value);
  if (!cve) {
    setSearchError("Enter a valid CVE ID, for example CVE-2023-22527.");
    elements.input.focus();
    return;
  }
  setSearchError("");
  research(cve);
});

document.querySelectorAll(".example-cve").forEach((button) => {
  button.addEventListener("click", () => {
    setSearchError("");
    elements.input.value = button.dataset.cve;
    research(button.dataset.cve);
  });
});

elements.input.addEventListener("input", () => {
  if (!elements.searchError?.hidden) setSearchError("");
});

elements.caseFilter.addEventListener("input", () => {
  state.caseFilter = elements.caseFilter.value.trim().toLowerCase();
  renderCases();
  renderWatchlist();
});

elements.healthRefresh.addEventListener("click", refreshHealth);
elements.watchRefreshAll?.addEventListener("click", refreshWatchlist);
elements.clearLocalData?.addEventListener("click", clearLocalData);
elements.sbomInput?.addEventListener("change", async () => {
  await handleSbomFiles([...elements.sbomInput.files]);
  elements.sbomInput.value = "";
});
elements.sbomClear?.addEventListener("click", clearSboms);

document.addEventListener("click", (event) => {
  const action = event.target.closest("[data-action]");
  if (!action) return;

  const value = action.dataset.value;
  switch (action.dataset.action) {
    case "tab":
      state.activeTab = value;
      render();
      break;
    case "refresh":
      if (state.current) research(state.current.id, { refresh: true });
      break;
    case "save":
      saveCurrentCase();
      break;
    case "watch":
      addCurrentToWatchlist();
      break;
    case "open-watch":
      openWatch(value);
      break;
    case "open-sbom":
      openSbom(value);
      break;
    case "open-sbom-cve":
      openSbomCve(value);
      break;
    case "open-sbom-cve-report":
      openSbomCveReport(action.dataset.reportId, action.dataset.cve);
      break;
    case "refresh-watch":
      refreshWatch(value);
      break;
    case "remove-watch":
      removeWatch(value);
      break;
    case "copy":
      copyBrief();
      break;
    case "copy-remediation":
      copyRemediation();
      break;
    case "copy-executive":
      copyTextBlock(state.current?.executiveBrief?.plainText, "Executive summary copied.");
      break;
    case "copy-ticket":
      copyTextBlock(state.current?.ticketExport?.plainText, "Ticket export copied.");
      break;
    case "copy-risk-acceptance":
      copyTextBlock(state.current?.riskAcceptance?.plainText, "Risk acceptance note copied.");
      break;
    case "copy-detection":
      copyTextBlock(state.current?.detectionGuidance?.plainText, "Detection guidance copied.");
      break;
    case "copy-cloud-impact":
      copyTextBlock(state.current?.cloudImpact?.plainText, "Cloud impact summary copied.");
      break;
    case "copy-sbom-cves":
      copySbomCves();
      break;
    case "export-sbom-json":
      exportSbomJson();
      break;
    case "research-sbom-cve":
      research(value);
      break;
    case "run-asset-impact":
      runAssetImpact();
      break;
    case "export-json":
      exportJson();
      break;
    case "export-md":
      exportMarkdown();
      break;
    case "delete-case":
      deleteCurrentCase();
      break;
    case "open-case":
      openCase(value);
      break;
    default:
      break;
  }
});

document.addEventListener("change", (event) => {
  if (event.target.matches("#evidenceFilter")) {
    state.evidenceFilter = event.target.value;
    render();
  }
  if (event.target.matches("#evidenceSort")) {
    state.evidenceSort = event.target.value;
    render();
  }
});

document.addEventListener("input", (event) => {
  if (event.target.matches("#assetInput")) {
    state.assetInput = event.target.value;
    return;
  }
  if (!state.current) return;
  const field = event.target.dataset.caseField;
  if (!field) return;
  const draft = getCaseDraft();
  draft[field] = event.target.value;
  state.current.caseDraft = draft;
});

refreshHealth();
renderCases();
renderWatchlist();
renderSbomList();
renderEmpty();

async function research(cve, options = {}) {
  const normalized = normalizeCve(cve);
  if (!normalized) return;
  state.loading = true;
  state.current = null;
  state.activeSbomId = null;
  state.activeSbomCveId = null;
  state.activeTab = "overview";
  elements.input.value = normalized;
  setSearchError("");
  elements.button.disabled = true;
  elements.button.textContent = "Researching...";
  elements.content.setAttribute("aria-busy", "true");
  renderLoading(normalized);

  try {
    const response = await fetch(`/api/research?cve=${encodeURIComponent(normalized)}${options.refresh ? "&refresh=1" : ""}`);
    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.message || "Research failed.");
    }
    state.current = attachCaseDraft(normalizeInvestigationPayload(payload));
    state.sourceHealth = payload.sourceResults || state.sourceHealth;
    showToast(payload.cached ? "Loaded cached research." : "Research complete.");
    render();
    focusContent();
    renderHealth();
  } catch (error) {
    renderError(error.message);
    focusContent();
  } finally {
    state.loading = false;
    elements.button.disabled = false;
    elements.button.textContent = "Research CVE";
    elements.content.removeAttribute("aria-busy");
  }
}

async function refreshHealth() {
  try {
    const response = await fetch("/api/health");
    const payload = await response.json();
    state.sourceHealth = (payload.sources || []).map((source) => ({
      id: source.id,
      label: source.label,
      status: "ok",
      message: source.optional ? "Optional source" : "Ready"
    }));
    renderHealth();
  } catch {
    state.sourceHealth = [];
    renderHealth();
  }
}

function attachCaseDraft(investigation) {
  const saved = state.cases.find((item) => item.id === investigation.id);
  return {
    ...investigation,
    caseDraft: saved
      ? { status: saved.status, owner: saved.owner, tags: saved.tags, notes: saved.notes }
      : { status: "Needs triage", owner: "", tags: "", notes: "" }
  };
}

function normalizeInvestigationPayload(investigation) {
  return {
    ...investigation,
    clientSchemaVersion: APP_SCHEMA_VERSION
  };
}

function isStaleInvestigation(investigation) {
  if (!investigation) return false;
  return investigation.clientSchemaVersion !== APP_SCHEMA_VERSION || !investigation.cloudImpact || !investigation.evidenceConfidence;
}

function getCaseDraft() {
  if (!state.current.caseDraft) {
    state.current.caseDraft = { status: "Needs triage", owner: "", tags: "", notes: "" };
  }
  return state.current.caseDraft;
}

function saveCurrentCase() {
  if (!state.current) return;
  const draft = getCaseDraft();
  const now = new Date().toISOString();
  const existing = state.cases.find((item) => item.id === state.current.id);
  const record = {
    id: state.current.id,
    title: state.current.title,
    riskLevel: state.current.risk.level,
    riskScore: state.current.risk.score,
    status: draft.status || "Needs triage",
    owner: draft.owner || "",
    tags: draft.tags || "",
    notes: draft.notes || "",
    savedAt: existing?.savedAt || now,
    updatedAt: now,
    investigation: normalizeInvestigationPayload(state.current)
  };
  state.cases = [record, ...state.cases.filter((item) => item.id !== record.id)].slice(0, 40);
  persistCases();
  renderCases();
  showToast(`${state.current.id} saved to case workspace.`);
}

function deleteCurrentCase() {
  if (!state.current) return;
  const exists = state.cases.some((item) => item.id === state.current.id);
  if (!exists) {
    showToast("This CVE is not saved yet.");
    return;
  }
  if (!window.confirm(`Delete saved case ${state.current.id}?`)) return;
  state.cases = state.cases.filter((item) => item.id !== state.current.id);
  persistCases();
  state.current.caseDraft = { status: "Needs triage", owner: "", tags: "", notes: "" };
  renderCases();
  renderWatchlist();
  render();
  showToast("Case deleted.");
}

function openCase(id) {
  const record = state.cases.find((item) => item.id === id);
  if (!record) return;
  state.current = attachCaseDraft(record.investigation);
  state.activeSbomId = null;
  state.activeSbomCveId = null;
  state.activeTab = "overview";
  elements.input.value = record.id;
  render();
  showToast(isStaleInvestigation(record.investigation) ? `${record.id} loaded. Refresh to update latest research fields.` : `${record.id} loaded.`);
}

function addCurrentToWatchlist() {
  if (!state.current) return;
  const current = normalizeInvestigationPayload(state.current);
  const snapshot = makeWatchSnapshot(current);
  const existing = state.watchlist.find((item) => item.id === current.id);
  const checkedAt = snapshot.checkedAt;
  const record = {
    id: current.id,
    title: current.title,
    addedAt: existing?.addedAt || checkedAt,
    updatedAt: checkedAt,
    lastCheckedAt: checkedAt,
    baseline: existing?.baseline || snapshot,
    latest: snapshot,
    changes: existing ? compareWatchSnapshots(existing.latest || existing.baseline, snapshot) : [],
    history: [...(existing?.history || []), snapshot].slice(-12),
    investigation: current
  };
  state.current = current;
  state.watchlist = [record, ...state.watchlist.filter((item) => item.id !== record.id)].slice(0, 50);
  persistWatchlist();
  renderWatchlist();
  if (state.current?.id === record.id && state.activeTab === "watchlist") render();
  showToast(`${record.id} added to watchlist.`);
}

function openWatch(id) {
  const record = state.watchlist.find((item) => item.id === id);
  if (!record) return;
  state.current = attachCaseDraft(record.investigation);
  state.activeSbomId = null;
  state.activeSbomCveId = null;
  state.activeTab = "watchlist";
  elements.input.value = record.id;
  render();
}

async function refreshWatch(id) {
  const record = state.watchlist.find((item) => item.id === id);
  if (!record) return;
  showToast(`Refreshing ${id}...`);
  let payload;
  try {
    const response = await fetch(`/api/research?cve=${encodeURIComponent(id)}&refresh=1`);
    payload = await response.json();
    if (!response.ok) {
      showToast(payload.message || `Unable to refresh ${id}.`);
      return;
    }
  } catch (error) {
    showToast(`Unable to refresh ${id}: ${error.message || "network error"}.`);
    return;
  }
  payload = normalizeInvestigationPayload(payload);
  const snapshot = makeWatchSnapshot(payload);
  const updated = {
    ...record,
    title: payload.title,
    updatedAt: snapshot.checkedAt,
    lastCheckedAt: snapshot.checkedAt,
    latest: snapshot,
    changes: compareWatchSnapshots(record.latest || record.baseline, snapshot),
    history: [...(record.history || []), snapshot].slice(-12),
    investigation: payload
  };
  state.watchlist = state.watchlist.map((item) => item.id === id ? updated : item);
  persistWatchlist();
  renderWatchlist();
  if (state.current?.id === id) {
    state.current = attachCaseDraft(payload);
    render();
  }
  showToast(`${id} refreshed.`);
}

async function refreshWatchlist() {
  if (!state.watchlist.length) {
    showToast("No watched CVEs to refresh.");
    return;
  }
  for (const item of [...state.watchlist]) {
    await refreshWatch(item.id);
  }
}

function removeWatch(id) {
  if (!window.confirm(`Remove ${id} from the watchlist?`)) return;
  state.watchlist = state.watchlist.filter((item) => item.id !== id);
  persistWatchlist();
  renderWatchlist();
  if (state.current?.id === id && state.activeTab === "watchlist") render();
  showToast(`${id} removed from watchlist.`);
}

async function handleSbomFiles(files) {
  if (!files.length) return;
  const currentInvestigation = state.current;
  const warnings = [];
  const accepted = [];
  let totalBytes = 0;

  for (const file of files.slice(0, SBOM_MAX_FILES)) {
    if (file.size > SBOM_MAX_FILE_BYTES) {
      warnings.push(`${file.name} was skipped because it is larger than ${formatBytes(SBOM_MAX_FILE_BYTES)}.`);
      continue;
    }
    if (totalBytes + file.size > SBOM_MAX_TOTAL_BYTES) {
      warnings.push(`${file.name} was skipped because the selected SBOM batch is larger than ${formatBytes(SBOM_MAX_TOTAL_BYTES)}.`);
      continue;
    }
    totalBytes += file.size;
    accepted.push(file);
  }

  if (files.length > SBOM_MAX_FILES) {
    warnings.push(`Only the first ${SBOM_MAX_FILES} files were processed.`);
  }

  const parsed = [];
  for (const file of accepted) {
    try {
      const text = await file.text();
      parsed.push(parseSbomFile(file, text));
    } catch (error) {
      warnings.push(`${file.name} could not be read: ${error.message || "browser file read failed"}.`);
    }
  }

  if (!parsed.length) {
    showToast("No SBOM files were parsed.");
    return;
  }

  const report = buildSbomReport(parsed, warnings);
  const currentCveMatch = currentInvestigation?.id && report.cves.some((entry) => entry.id === currentInvestigation.id);
  state.sbomReports = [report, ...state.sbomReports].slice(0, 6);
  state.activeSbomId = report.id;
  state.activeSbomCveId = currentCveMatch ? currentInvestigation.id : report.cves[0]?.id || null;
  state.current = currentInvestigation || null;
  renderCases();
  renderSbomList();
  render();
  focusContent();
  showToast(currentCveMatch ? `${currentInvestigation.id} found in the uploaded SBOM.` : `Parsed ${report.files.length} SBOM file${report.files.length === 1 ? "" : "s"} with ${report.cves.length} CVE finding${report.cves.length === 1 ? "" : "s"}.`);
}

function openSbom(id) {
  const report = state.sbomReports.find((item) => item.id === id);
  if (!report) return;
  state.activeSbomId = id;
  state.activeSbomCveId = report.cves.some((entry) => entry.id === state.activeSbomCveId) ? state.activeSbomCveId : report.cves[0]?.id || null;
  state.current = null;
  elements.input.value = "";
  renderCases();
  render();
  renderSbomList();
}

function clearSboms() {
  if (!state.sbomReports.length) {
    showToast("No SBOM uploads to clear.");
    return;
  }
  state.sbomReports = [];
  state.activeSbomId = null;
  state.activeSbomCveId = null;
  renderCases();
  renderSbomList();
  render();
  showToast("SBOM uploads cleared from this browser session.");
}

function openSbomCve(cve) {
  const report = getActiveSbomReport();
  if (!report?.cves.some((entry) => entry.id === cve)) return;
  state.activeSbomCveId = cve;
  render();
}

function openSbomCveReport(reportId, cve) {
  const report = state.sbomReports.find((item) => item.id === reportId);
  if (!report?.cves.some((entry) => entry.id === cve)) return;
  state.activeSbomId = report.id;
  state.activeSbomCveId = cve;
  state.current = null;
  elements.input.value = "";
  renderCases();
  renderSbomList();
  render();
}

async function copySbomCves() {
  const report = getActiveSbomReport();
  if (!report?.cves.length) {
    showToast("No CVEs were found in the active SBOM report.");
    return;
  }
  const text = report.cves.map((entry) => `${entry.id}\t${entry.severity || "Unknown"}\t${entry.components.slice(0, 3).join(", ") || "No component listed"}`).join("\n");
  await copyTextBlock(text, "SBOM CVE list copied.");
}

function exportSbomJson() {
  const report = getActiveSbomReport();
  if (!report) return;
  download(`${sanitizeFilename(report.title)}-summary.json`, JSON.stringify(report, null, 2), "application/json");
}

function parseSbomFile(file, text) {
  const trimmed = text.trim();
  const base = {
    fileName: file.name,
    size: file.size,
    format: "Generic text",
    documentName: file.name,
    components: [],
    vulnerabilities: [],
    cves: [],
    warnings: []
  };

  if (!trimmed) {
    return {
      ...base,
      warnings: [`${file.name} is empty.`]
    };
  }

  if (/^[\[{]/.test(trimmed)) {
    try {
      return parseJsonSbom(file, JSON.parse(trimmed), text);
    } catch (error) {
      return {
        ...base,
        cves: extractCves(text),
        warnings: [`${file.name} is not valid JSON: ${error.message}. Falling back to CVE text extraction.`]
      };
    }
  }

  if (trimmed.startsWith("<")) {
    return parseXmlSbom(file, text);
  }

  if (/^SPDXVersion:/m.test(text) || /^PackageName:/m.test(text)) {
    return parseSpdxTagValue(file, text);
  }

  return {
    ...base,
    cves: extractCves(text),
    warnings: [`${file.name} was parsed with generic text extraction because the SBOM format was not recognized.`]
  };
}

function parseJsonSbom(file, json, text) {
  if (json?.bomFormat === "CycloneDX") return parseCycloneDxJson(file, json);
  if (json?.spdxVersion || Array.isArray(json?.packages) && json?.SPDXID) return parseSpdxJson(file, json);
  if (Array.isArray(json?.artifacts) && (json?.descriptor?.name === "syft" || json?.source)) return parseSyftJson(file, json);
  if (Array.isArray(json?.matches)) return parseGrypeJson(file, json);
  return parseGenericJsonSbom(file, json, text);
}

function parseCycloneDxJson(file, json) {
  const componentByRef = new Map();
  const components = normalizeArray(json.components).map((entry) => {
    const component = normalizeSbomComponent({
      fileName: file.name,
      ref: entry["bom-ref"] || entry.bomRef || entry.purl || "",
      type: entry.type || "component",
      name: componentDisplayName(entry.group, entry.name),
      version: entry.version || "",
      supplier: supplierName(entry.supplier),
      purl: entry.purl || "",
      cpes: normalizeArray(entry.cpe ? [entry.cpe] : entry.cpes),
      licenses: extractCycloneLicenses(entry.licenses),
      cves: extractCves(safeStringify({ properties: entry.properties, evidence: entry.evidence, pedigree: entry.pedigree }))
    });
    if (component.ref) componentByRef.set(component.ref, component);
    return component;
  });

  const vulnerabilities = normalizeArray(json.vulnerabilities).flatMap((vulnerability) => {
    const cves = extractCves([vulnerability.id, safeStringify(vulnerability.references), safeStringify(vulnerability.advisories)].join(" "));
    const rating = highestCycloneRating(vulnerability.ratings);
    const componentRefs = normalizeArray(vulnerability.affects).map((affect) => affect.ref).filter(Boolean);
    const componentNames = uniqueValues(componentRefs.map((ref) => componentByRef.get(ref)).filter(Boolean).map(formatSbomComponentLabel));
    return cves.map((cve) => ({
      cve,
      id: vulnerability.id || cve,
      source: vulnerability.source?.name || vulnerability.source?.url || "CycloneDX vulnerability",
      severity: normalizeSeverity(rating?.severity),
      score: rating?.score ?? "",
      title: vulnerability.id || cve,
      description: vulnerability.description || vulnerability.detail || "",
      fileName: file.name,
      componentRefs,
      components: componentNames,
      references: extractUrls(safeStringify(vulnerability))
    }));
  });

  return {
    fileName: file.name,
    size: file.size,
    format: `CycloneDX ${json.specVersion || ""}`.trim(),
    documentName: json.metadata?.component?.name || json.serialNumber || file.name,
    components,
    vulnerabilities,
    cves: extractCves(safeStringify({ metadata: json.metadata, properties: json.properties })),
    warnings: []
  };
}

function parseSpdxJson(file, json) {
  const components = normalizeArray(json.packages).map((entry) => {
    const refs = normalizeArray(entry.externalRefs);
    const purl = refs.find((ref) => String(ref.referenceLocator || "").startsWith("pkg:"))?.referenceLocator || "";
    const cpes = refs
      .map((ref) => ref.referenceLocator)
      .filter((locator) => /^cpe:/i.test(String(locator || "")));
    return normalizeSbomComponent({
      fileName: file.name,
      ref: entry.SPDXID || "",
      type: "package",
      name: entry.name || entry.packageName || "",
      version: entry.versionInfo || entry.packageVersion || "",
      supplier: cleanSpdxActor(entry.supplier || entry.packageSupplier),
      purl,
      cpes,
      licenses: uniqueValues([entry.licenseConcluded, entry.licenseDeclared].filter((license) => license && license !== "NOASSERTION")),
      cves: extractCves(safeStringify(entry))
    });
  });

  return {
    fileName: file.name,
    size: file.size,
    format: `SPDX JSON ${json.spdxVersion || ""}`.trim(),
    documentName: json.name || json.documentName || file.name,
    components,
    vulnerabilities: [],
    cves: extractCves(safeStringify({ annotations: json.annotations, externalDocumentRefs: json.externalDocumentRefs })),
    warnings: []
  };
}

function parseSyftJson(file, json) {
  const components = normalizeArray(json.artifacts).map((entry) => normalizeSbomComponent({
    fileName: file.name,
    ref: entry.id || entry.purl || "",
    type: entry.type || "package",
    name: entry.name || "",
    version: entry.version || "",
    supplier: entry.metadata?.supplier || "",
    purl: entry.purl || "",
    cpes: normalizeArray(entry.cpes),
    licenses: normalizeArray(entry.licenses).map((license) => typeof license === "string" ? license : license.value || license.spdxExpression || "").filter(Boolean),
    cves: extractCves(safeStringify(entry))
  }));

  return {
    fileName: file.name,
    size: file.size,
    format: `Syft JSON ${json.descriptor?.version || ""}`.trim(),
    documentName: json.source?.name || file.name,
    components,
    vulnerabilities: [],
    cves: extractCves(safeStringify(json.distro || {})),
    warnings: []
  };
}

function parseGrypeJson(file, json) {
  const components = [];
  const vulnerabilities = normalizeArray(json.matches).flatMap((match) => {
    const artifact = match.artifact || {};
    const component = normalizeSbomComponent({
      fileName: file.name,
      ref: artifact.id || artifact.purl || "",
      type: artifact.type || "package",
      name: artifact.name || "",
      version: artifact.version || "",
      supplier: "",
      purl: artifact.purl || "",
      cpes: normalizeArray(artifact.cpes),
      licenses: normalizeArray(artifact.licenses),
      cves: []
    });
    if (component.name) components.push(component);
    const vulnerability = match.vulnerability || {};
    const related = normalizeArray(match.relatedVulnerabilities);
    const cves = extractCves([vulnerability.id, safeStringify(related)].join(" "));
    return cves.map((cve) => ({
      cve,
      id: vulnerability.id || cve,
      source: "Grype vulnerability report",
      severity: normalizeSeverity(vulnerability.severity),
      score: vulnerability.cvss?.[0]?.metrics?.baseScore ?? "",
      title: vulnerability.id || cve,
      description: vulnerability.description || "",
      fileName: file.name,
      componentRefs: component.ref || component.purl ? [component.ref || component.purl] : [],
      components: component.name ? [formatSbomComponentLabel(component)] : [],
      references: normalizeArray(vulnerability.urls)
    }));
  });

  return {
    fileName: file.name,
    size: file.size,
    format: "Grype vulnerability report",
    documentName: json.source?.target?.userInput || file.name,
    components,
    vulnerabilities,
    cves: [],
    warnings: []
  };
}

function parseGenericJsonSbom(file, json, text) {
  const possibleComponents = Array.isArray(json.components) ? json.components : Array.isArray(json.packages) ? json.packages : [];
  const components = possibleComponents.map((entry) => normalizeSbomComponent({
    fileName: file.name,
    ref: entry["bom-ref"] || entry.SPDXID || entry.id || entry.purl || "",
    type: entry.type || "component",
    name: entry.name || entry.packageName || "",
    version: entry.version || entry.versionInfo || entry.packageVersion || "",
    supplier: supplierName(entry.supplier || entry.author || entry.publisher),
    purl: entry.purl || "",
    cpes: normalizeArray(entry.cpe ? [entry.cpe] : entry.cpes),
    licenses: extractGenericLicenses(entry.licenses || entry.license),
    cves: extractCves(safeStringify(entry))
  }));

  return {
    fileName: file.name,
    size: file.size,
    format: "Generic JSON SBOM",
    documentName: json.name || json.documentName || json.serialNumber || file.name,
    components,
    vulnerabilities: [],
    cves: extractCves(text),
    warnings: ["JSON parsed, but the SBOM format was not recognized as CycloneDX, SPDX, Syft, or Grype."]
  };
}

function parseXmlSbom(file, text) {
  const parser = new DOMParser();
  const doc = parser.parseFromString(text, "application/xml");
  if (findXmlChildren(doc, "parsererror").length) {
    return {
      fileName: file.name,
      size: file.size,
      format: "Generic XML",
      documentName: file.name,
      components: [],
      vulnerabilities: [],
      cves: extractCves(text),
      warnings: [`${file.name} is not valid XML. Falling back to CVE text extraction.`]
    };
  }
  if (doc.documentElement?.localName?.toLowerCase() === "bom") {
    return parseCycloneDxXml(file, doc, text);
  }
  return {
    fileName: file.name,
    size: file.size,
    format: "Generic XML",
    documentName: file.name,
    components: [],
    vulnerabilities: [],
    cves: extractCves(text),
    warnings: [`${file.name} XML parsed, but the SBOM format was not recognized.`]
  };
}

function parseCycloneDxXml(file, doc, text) {
  const componentByRef = new Map();
  const componentsRoot = firstXmlChild(doc.documentElement, "components");
  const components = findXmlChildren(componentsRoot, "component").map((entry) => {
    const component = normalizeSbomComponent({
      fileName: file.name,
      ref: entry.getAttribute("bom-ref") || "",
      type: entry.getAttribute("type") || "component",
      name: xmlText(entry, "name"),
      version: xmlText(entry, "version"),
      supplier: xmlText(firstXmlChild(entry, "supplier"), "name"),
      purl: xmlText(entry, "purl"),
      cpes: findXmlChildren(entry, "cpe").map((node) => node.textContent.trim()).filter(Boolean),
      licenses: findXmlChildren(entry, "license").map((node) => xmlText(node, "id") || xmlText(node, "name")).filter(Boolean),
      cves: extractCves(entry.textContent || "")
    });
    if (component.ref) componentByRef.set(component.ref, component);
    return component;
  });

  const vulnerabilitiesRoot = firstXmlChild(doc.documentElement, "vulnerabilities");
  const vulnerabilities = findXmlChildren(vulnerabilitiesRoot, "vulnerability").flatMap((entry) => {
    const cves = extractCves([xmlText(entry, "id"), entry.textContent || ""].join(" "));
    const severity = xmlText(firstXmlChild(firstXmlChild(entry, "ratings"), "rating"), "severity");
    const score = xmlText(firstXmlChild(firstXmlChild(entry, "ratings"), "rating"), "score");
    const componentRefs = findXmlChildren(firstXmlChild(entry, "affects"), "target").map((target) => target.getAttribute("ref")).filter(Boolean);
    const componentNames = uniqueValues(componentRefs.map((ref) => componentByRef.get(ref)).filter(Boolean).map(formatSbomComponentLabel));
    return cves.map((cve) => ({
      cve,
      id: xmlText(entry, "id") || cve,
      source: xmlText(firstXmlChild(entry, "source"), "name") || "CycloneDX XML vulnerability",
      severity: normalizeSeverity(severity),
      score,
      title: xmlText(entry, "id") || cve,
      description: xmlText(entry, "description") || xmlText(entry, "detail"),
      fileName: file.name,
      componentRefs,
      components: componentNames,
      references: extractUrls(entry.textContent || "")
    }));
  });

  return {
    fileName: file.name,
    size: file.size,
    format: `CycloneDX XML ${doc.documentElement.getAttribute("version") || ""}`.trim(),
    documentName: doc.documentElement.getAttribute("serialNumber") || file.name,
    components,
    vulnerabilities,
    cves: extractCves(text),
    warnings: []
  };
}

function parseSpdxTagValue(file, text) {
  const components = [];
  let current = null;
  const pushCurrent = () => {
    if (current?.name) components.push(normalizeSbomComponent(current));
  };

  for (const rawLine of text.split(/\r?\n/)) {
    const separator = rawLine.indexOf(":");
    if (separator === -1) {
      if (current) current.cves.push(...extractCves(rawLine));
      continue;
    }
    const key = rawLine.slice(0, separator).trim();
    const value = rawLine.slice(separator + 1).trim();
    if (key === "PackageName") {
      pushCurrent();
      current = {
        fileName: file.name,
        ref: "",
        type: "package",
        name: value,
        version: "",
        supplier: "",
        purl: "",
        cpes: [],
        licenses: [],
        cves: []
      };
      continue;
    }
    if (!current) continue;
    if (key === "SPDXID") current.ref = value;
    if (key === "PackageVersion") current.version = value;
    if (key === "PackageSupplier") current.supplier = cleanSpdxActor(value);
    if (key === "PackageLicenseDeclared" && value !== "NOASSERTION") current.licenses.push(value);
    if (key === "ExternalRef") {
      if (value.includes("pkg:")) current.purl = value.split(/\s+/).find((part) => part.startsWith("pkg:")) || current.purl;
      const cpe = value.split(/\s+/).find((part) => /^cpe:/i.test(part));
      if (cpe) current.cpes.push(cpe);
    }
    current.cves.push(...extractCves(value));
  }
  pushCurrent();

  return {
    fileName: file.name,
    size: file.size,
    format: "SPDX tag-value",
    documentName: firstTagValue(text, "DocumentName") || file.name,
    components,
    vulnerabilities: [],
    cves: extractCves(text),
    warnings: []
  };
}

function buildSbomReport(parsedFiles, warnings = []) {
  const uploadedAt = new Date().toISOString();
  const files = parsedFiles.map((file) => ({
    fileName: file.fileName,
    size: file.size,
    format: file.format,
    documentName: file.documentName,
    componentCount: file.components.length,
    vulnerabilityCount: file.vulnerabilities.length,
    cveCount: uniqueValues([...file.cves, ...file.vulnerabilities.map((vulnerability) => vulnerability.cve)]).length,
    warnings: file.warnings || []
  }));
  const components = dedupeBy(parsedFiles.flatMap((file) => file.components), (component) => [
    component.fileName,
    component.purl,
    component.ref,
    component.name,
    component.version
  ].join("|"));
  const componentVulnerabilities = components.flatMap((component) => normalizeArray(component.cves).map((cve) => ({
    cve,
    id: cve,
    source: "SBOM component reference",
    severity: "",
    score: "",
    title: cve,
    description: "CVE reference was found near this component in the SBOM.",
    fileName: component.fileName,
    componentRefs: sbomComponentRefValues(component),
    components: [formatSbomComponentLabel(component)],
    references: []
  })));
  const fileOnlyVulnerabilities = parsedFiles.flatMap((file) => normalizeArray(file.cves).map((cve) => ({
    cve,
    id: cve,
    source: "SBOM file reference",
    severity: "",
    score: "",
    title: cve,
    description: "CVE reference was found in the SBOM file text.",
    fileName: file.fileName,
    componentRefs: [],
    components: [],
    references: []
  })));
  const vulnerabilities = dedupeBy([
    ...parsedFiles.flatMap((file) => file.vulnerabilities),
    ...componentVulnerabilities,
    ...fileOnlyVulnerabilities
  ], (vulnerability) => [
    vulnerability.cve,
    vulnerability.fileName,
    vulnerability.components.join(",")
  ].join("|")).sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || sortCveId(b.cve) - sortCveId(a.cve));
  const cveMap = new Map();
  for (const vulnerability of vulnerabilities) {
    if (!vulnerability.cve) continue;
    const entry = cveMap.get(vulnerability.cve) || {
      id: vulnerability.cve,
      files: new Set(),
      components: new Set(),
      sources: new Set(),
      severities: new Set(),
      references: new Set(),
      affectedPackages: new Map(),
      count: 0
    };
    entry.files.add(vulnerability.fileName);
    for (const component of vulnerability.components || []) entry.components.add(component);
    entry.sources.add(vulnerability.source || "SBOM");
    if (vulnerability.severity) entry.severities.add(vulnerability.severity);
    for (const ref of vulnerability.references || []) entry.references.add(ref);
    for (const affectedPackage of findSbomAffectedPackages(vulnerability, components)) {
      entry.affectedPackages.set(sbomAffectedPackageKey(affectedPackage), affectedPackage);
    }
    entry.count += 1;
    cveMap.set(vulnerability.cve, entry);
  }
  const cves = [...cveMap.values()].map((entry) => ({
    id: entry.id,
    files: [...entry.files],
    components: [...entry.components],
    sources: [...entry.sources],
    severity: highestSeverity([...entry.severities]),
    references: [...entry.references].slice(0, 6),
    affectedPackages: [...entry.affectedPackages.values()],
    count: entry.count
  })).sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || sortCveId(b.id) - sortCveId(a.id));
  const title = files.length === 1 ? stripExtension(files[0].fileName) : `${files.length} SBOM files`;
  return {
    id: makeSbomId(files, uploadedAt),
    title,
    uploadedAt,
    files,
    components,
    vulnerabilities,
    cves,
    warnings: [...warnings, ...files.flatMap((file) => file.warnings || [])],
    summary: makeSbomSummary(files, components, vulnerabilities, cves)
  };
}

async function copyBrief() {
  if (!state.current) return;
  try {
    await navigator.clipboard.writeText(makeMarkdown(state.current));
    showToast("Brief copied to clipboard.");
  } catch {
    showToast("Clipboard permission was not available.");
  }
}

async function copyRemediation() {
  await copyTextBlock(state.current?.remediation?.plainText, "Remediation instructions copied.");
}

async function copyTextBlock(text, message) {
  if (!text) {
    showToast("Nothing available to copy yet.");
    return;
  }
  try {
    await navigator.clipboard.writeText(text);
    showToast(message);
  } catch {
    showToast("Clipboard permission was not available.");
  }
}

function confirmSensitiveExport(format) {
  return window.confirm(`${format} exports can include analyst notes, case metadata, and research context. Continue?`);
}

function clearLocalData() {
  if (!window.confirm("Delete saved cases, watchlist data, and SBOM uploads from this browser?")) return;
  state.cases = [];
  state.watchlist = [];
  state.sbomReports = [];
  state.activeSbomId = null;
  state.activeSbomCveId = null;
  localStorage.removeItem("cve-research-cases");
  localStorage.removeItem("cve-research-watchlist");
  if (state.current) {
    state.current.caseDraft = { status: "Needs triage", owner: "", tags: "", notes: "" };
  }
  renderCases();
  renderWatchlist();
  renderSbomList();
  if (state.current) render();
  if (!state.current) render();
  showToast("Local cases, watchlist, and SBOM uploads cleared.");
}

function exportJson() {
  if (!state.current) return;
  if (!confirmSensitiveExport("JSON")) return;
  download(`${state.current.id}-research.json`, JSON.stringify(state.current, null, 2), "application/json");
}

function exportMarkdown() {
  if (!state.current) return;
  if (!confirmSensitiveExport("Markdown")) return;
  download(`${state.current.id}-brief.md`, makeMarkdown(state.current), "text/markdown");
}

function render() {
  if (!state.current) {
    const report = getActiveSbomReport();
    if (report) {
      renderSbomWorkspace(report);
      return;
    }
    renderEmpty();
    return;
  }
  const item = state.current;
  elements.content.innerHTML = `
    <article class="investigation">
      <section class="brief-header">
        <div class="brief-title">
          <div class="badge-row">
            <span class="risk-badge risk-${escapeAttr(item.risk.level)}">${item.risk.level} ${item.risk.score}/100</span>
            <span class="badge">${escapeHtml(item.id)}</span>
            <span class="badge">Confidence ${escapeHtml(item.confidence.label)}</span>
            <span class="badge">${escapeHtml(item.status || "Unknown")}</span>
          </div>
          <h2>${escapeHtml(item.title)}</h2>
          <p>${escapeHtml(item.executiveSummary)}</p>
        </div>
        <div class="header-actions">
          <button class="secondary-button" type="button" data-action="refresh">Refresh</button>
          <button class="secondary-button" type="button" data-action="copy">Copy brief</button>
          <button class="secondary-button" type="button" data-action="watch">Watch CVE</button>
          <button class="secondary-button" type="button" data-action="export-md">Export MD</button>
          <button class="secondary-button" type="button" data-action="export-json">Export JSON</button>
          <button class="primary-button" type="button" data-action="save">Save case</button>
        </div>
      </section>

      ${renderStaleBanner(item)}
      ${renderMetrics(item)}
      ${renderSearchedCveSbomMatch(item)}
      ${renderTabs()}
      ${renderActiveTab(item)}
    </article>
  `;
  renderCases();
  renderSbomList();
}

function renderStaleBanner(item) {
  if (!isStaleInvestigation(item)) return "";
  return `
    <section class="stale-banner" role="status">
      <div>
        <strong>Saved case needs a refresh</strong>
        <p>This local case was saved before the latest research model. Refresh it to populate newer sections such as cloud impact, confidence labels, and updated exports.</p>
      </div>
      <button class="secondary-button" type="button" data-action="refresh">Refresh now</button>
    </section>
  `;
}

function renderMetrics(item) {
  const cvss = item.metrics.cvss;
  const epss = item.metrics.epss;
  const kev = item.metrics.kev;
  const github = item.metrics.github;
  const realWorld = item.realWorld || item.metrics.realWorld;
  return `
    <section class="metric-grid" aria-label="Research metrics">
      <div class="metric-card">
        <div class="metric-label">Real World</div>
        <div class="metric-value compact">${escapeHtml(realWorld?.verdict || "Unknown")}</div>
        <div class="metric-detail">${escapeHtml(realWorld?.exploitedStatus || "Assessment unavailable")}</div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Exploit Maturity</div>
        <div class="metric-value compact">${escapeHtml(item.exploitMaturity?.stage || "Unknown")}</div>
        <div class="metric-detail">${item.exploitMaturity?.score ?? "n/a"}/100 maturity</div>
      </div>
      <div class="metric-card">
        <div class="metric-label">CVSS</div>
        <div class="metric-value">${cvss?.score ?? "n/a"}</div>
        <div class="metric-detail">${escapeHtml(cvss?.severity || "No score")} ${escapeHtml(cvss?.version || "")}</div>
      </div>
      <div class="metric-card">
        <div class="metric-label">EPSS</div>
        <div class="metric-value">${epss?.epss !== null && epss?.epss !== undefined ? formatPercent(epss.epss) : "n/a"}</div>
        <div class="metric-detail">Percentile ${epss?.percentile !== null && epss?.percentile !== undefined ? formatPercent(epss.percentile) : "n/a"}</div>
      </div>
      <div class="metric-card">
        <div class="metric-label">CISA KEV</div>
        <div class="metric-value">${kev?.listed ? "Listed" : "No"}</div>
        <div class="metric-detail">${kev?.dueDate ? `Due ${formatDate(kev.dueDate)}` : "Current catalog check"}</div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Chatter</div>
        <div class="metric-value">${realWorld?.counts?.totalChatter ?? "n/a"}</div>
        <div class="metric-detail">${escapeHtml(realWorld?.chatterLevel || "Public discussion leads")}</div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Public Code</div>
        <div class="metric-value">${github?.totalCount ?? "n/a"}</div>
        <div class="metric-detail">GitHub repository leads</div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Cloud</div>
        <div class="metric-value">${item.cloudImpact?.services?.length ?? 0}</div>
        <div class="metric-detail">${escapeHtml(cloudMetricLabel(item.cloudImpact))}</div>
      </div>
    </section>
  `;
}

function renderSearchedCveSbomMatch(item) {
  if (!state.sbomReports.length) return "";
  const matches = findSbomCveMatches(item.id);
  if (!matches.length) {
    return `
      <section class="panel sbom-search-match">
        <div class="panel-title-row">
          <div>
            <h3>Loaded SBOM Check</h3>
            <p>${escapeHtml(item.id)} was not found as an exact CVE ID in the currently loaded SBOM files.</p>
          </div>
          <span class="badge">Checked ${state.sbomReports.length} upload${state.sbomReports.length === 1 ? "" : "s"}</span>
        </div>
      </section>
    `;
  }

  const packageRows = dedupeBy(matches.flatMap((match) => (match.entry.affectedPackages || []).map((pkg) => ({
    ...pkg,
    reportId: match.report.id,
    reportTitle: match.report.title,
    cve: match.entry.id
  }))), sbomAffectedPackageKey);

  return `
    <section class="panel sbom-search-match found">
      <div class="panel-title-row">
        <div>
          <h3>Found in Uploaded SBOMs</h3>
          <p>${escapeHtml(item.id)} appears in ${matches.length} loaded SBOM report${matches.length === 1 ? "" : "s"}${packageRows.length ? ` with ${packageRows.length} affected package record${packageRows.length === 1 ? "" : "s"}.` : ", but package-level mapping was not included."}</p>
        </div>
        <span class="badge">${packageRows.length || matches.length} match${(packageRows.length || matches.length) === 1 ? "" : "es"}</span>
      </div>
      ${
        packageRows.length
          ? `<div class="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Package</th>
                    <th>Version</th>
                    <th>Package URL / CPE</th>
                    <th>SBOM</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  ${packageRows.map((pkg) => `
                    <tr>
                      <td><strong>${escapeHtml(pkg.name || pkg.label || "Unknown package")}</strong>${pkg.supplier ? `<br><span class="muted-cell">${escapeHtml(pkg.supplier)}</span>` : ""}</td>
                      <td>${escapeHtml(pkg.version || "n/a")}</td>
                      <td>${escapeHtml(pkg.purl || pkg.cpes?.[0] || "n/a")}</td>
                      <td>${escapeHtml(pkg.fileName || pkg.reportTitle || "Loaded SBOM")}</td>
                      <td><button class="secondary-button table-button" type="button" data-action="open-sbom-cve-report" data-report-id="${escapeAttr(pkg.reportId)}" data-cve="${escapeAttr(pkg.cve)}">View SBOM</button></td>
                    </tr>
                  `).join("")}
                </tbody>
              </table>
            </div>`
          : `<div class="card-grid">
              ${matches.map((match) => `
                <div class="action-item">
                  <span class="badge">${escapeHtml(match.entry.severity || "Unknown severity")}</span>
                  <strong>${escapeHtml(match.report.title)}</strong>
                  <p>${escapeHtml(match.entry.files.join(", ") || "Loaded SBOM")}</p>
                  <button class="secondary-button table-button" type="button" data-action="open-sbom-cve-report" data-report-id="${escapeAttr(match.report.id)}" data-cve="${escapeAttr(match.entry.id)}">View SBOM</button>
                </div>
              `).join("")}
            </div>`
      }
    </section>
  `;
}

function cloudMetricLabel(cloudImpact) {
  if (!cloudImpact) return "Not assessed";
  const official = (cloudImpact.providers || []).filter((provider) => provider.officialReferenceCount > 0).map((provider) => provider.provider);
  if (official.length) return `${official.join(" / ")} official signal`;
  if (cloudImpact.services?.length) return "Possible exposure";
  return "No cloud signal";
}

function renderTabs() {
  const tabs = [
    ["overview", "Overview"],
    ["real-world", "Real World"],
    ["evidence", "Evidence"],
    ["timeline", "Timeline"],
    ["remediation", "Remediation"],
    ["impact", "Impact"],
    ["cloud", "Cloud"],
    ["reports", "Reports"],
    ["watchlist", "Watchlist"],
    ["workspace", "Workspace"]
  ];
  return `
    <nav class="tabs" aria-label="Investigation views">
      ${tabs
        .map(
          ([id, label]) => `
            <button class="tab-button ${state.activeTab === id ? "active" : ""}" type="button" data-action="tab" data-value="${id}">
              ${label}
            </button>
          `
        )
        .join("")}
    </nav>
  `;
}

function renderActiveTab(item) {
  if (state.activeTab === "real-world") return renderRealWorld(item);
  if (state.activeTab === "evidence") return renderEvidence(item);
  if (state.activeTab === "timeline") return renderTimeline(item);
  if (state.activeTab === "remediation") return renderRemediation(item);
  if (state.activeTab === "impact") return renderImpact(item);
  if (state.activeTab === "cloud") return renderCloudImpact(item);
  if (state.activeTab === "reports") return renderReports(item);
  if (state.activeTab === "watchlist") return renderWatchlistTab(item);
  if (state.activeTab === "workspace") return renderWorkspace(item);
  return renderOverview(item);
}

function renderOverview(item) {
  return `
    <section class="tab-panel">
      ${renderRealWorldPanel(item)}

      <div class="panel">
        <h3>Analyst Summary</h3>
        <p>${escapeHtml(item.description || "No public description was returned by the primary sources.")}</p>
        <div class="badge-row">
          ${item.risk.reasons.map((reason) => `<span class="badge">${escapeHtml(reason)}</span>`).join("") || `<span class="badge">baseline research</span>`}
        </div>
      </div>

      <div class="card-grid">
        ${item.analystActions
          .map(
            (action) => `
              <div class="action-item">
                <span class="badge">${escapeHtml(action.priority)}</span>
                <strong>${escapeHtml(action.label)}</strong>
                <p>${escapeHtml(action.detail)}</p>
              </div>
            `
          )
          .join("")}
      </div>

      ${renderIntelligencePanel(item)}

      <div class="panel">
        <h3>Affected Product Signals</h3>
        ${renderAffectedTable(item.affected)}
      </div>

      <div class="panel">
        <h3>Weakness Mapping</h3>
        ${
          item.weaknesses.length
            ? `<div class="badge-row">${item.weaknesses.map((weakness) => `<span class="badge">${escapeHtml(weakness.id)}</span>`).join("")}</div>`
            : `<p>No CWE mapping was extracted from the public records.</p>`
        }
      </div>
    </section>
  `;
}

function renderRealWorldPanel(item) {
  const realWorld = item.realWorld || item.metrics.realWorld;
  if (!realWorld) {
    return `
      <div class="panel">
        <h3>Real-World Assessment</h3>
        <p>No real-world assessment was returned by the research server.</p>
      </div>
    `;
  }
  return `
    <div class="panel real-world-panel">
      <div class="real-world-header">
        <div>
          <h3>Real-World Assessment</h3>
          <p>${escapeHtml(realWorld.summary)}</p>
        </div>
        <div class="real-world-score">
          <span class="risk-badge risk-${escapeAttr(item.risk.level)}">${escapeHtml(realWorld.verdict)}</span>
          <strong>${realWorld.score}/100</strong>
          <span>${escapeHtml(realWorld.confidence)} confidence</span>
        </div>
      </div>
      <div class="signal-grid">
        <div>
          <span class="metric-label">Exploitation</span>
          <strong>${escapeHtml(realWorld.exploitedStatus)}</strong>
        </div>
        <div>
          <span class="metric-label">Public Exploit</span>
          <strong>${escapeHtml(realWorld.publicExploitLevel)}</strong>
        </div>
        <div>
          <span class="metric-label">Chatter</span>
          <strong>${escapeHtml(realWorld.chatterLevel)} (${realWorld.counts?.totalChatter ?? 0})</strong>
        </div>
      </div>
    </div>
  `;
}

function renderRealWorld(item) {
  const realWorld = item.realWorld || item.metrics.realWorld;
  if (!realWorld) {
    return `<section class="tab-panel"><div class="panel"><p>No real-world assessment was returned.</p></div></section>`;
  }
  return `
    <section class="tab-panel">
      ${renderRealWorldPanel(item)}
      <div class="card-grid">
        ${realWorld.signals.map(renderSignalCard).join("")}
      </div>
      <div class="panel">
        <h3>Chatter Breakdown</h3>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Source</th>
                <th>Lead Count</th>
                <th>How to read it</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>GitHub Issues/PRs</td>
                <td>${realWorld.counts?.githubDiscussions ?? 0}</td>
                <td>Developer and security project discussion. Useful for patches, breakage, PoCs, and detection rules.</td>
              </tr>
              <tr>
                <td>Hacker News</td>
                <td>${realWorld.counts?.hackerNews ?? 0}</td>
                <td>Broad technical discussion. Useful for high-signal public awareness, not proof of exploitation.</td>
              </tr>
              <tr>
                <td>Reddit</td>
                <td>${realWorld.counts?.reddit ?? 0}</td>
                <td>Community discussion. Useful for early chatter and questions, lower confidence than primary intelligence.</td>
              </tr>
              <tr>
                <td>Public Code</td>
                <td>${realWorld.counts?.publicCode ?? 0}</td>
                <td>Repository leads that may include PoCs, scanners, advisories, or unrelated mentions. Validate manually.</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </section>
  `;
}

function renderSignalCard(signal) {
  const safeUrl = safeExternalUrl(signal.url);
  return `
    <div class="action-item">
      <span class="badge">${escapeHtml(signal.status)}</span>
      <strong>${escapeHtml(signal.label)}</strong>
      <p>${escapeHtml(signal.detail)}</p>
      ${safeUrl ? `<p><a href="${escapeAttr(safeUrl)}" target="_blank" rel="noreferrer noopener">${escapeHtml(signal.source)}</a></p>` : `<p>${escapeHtml(signal.source)}</p>`}
    </div>
  `;
}

function renderAffectedTable(affected) {
  if (!affected.length) {
    return `<p>No affected product list was extracted. Check vendor references before closing the case.</p>`;
  }
  return `
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Vendor</th>
            <th>Product</th>
            <th>Version Signal</th>
            <th>Source</th>
          </tr>
        </thead>
        <tbody>
          ${affected
            .slice(0, 18)
            .map(
              (item) => `
                <tr>
                  <td>${escapeHtml(item.vendor)}</td>
                  <td>${escapeHtml(item.product)}</td>
                  <td>${escapeHtml(item.version || item.cpe || "See advisory")}</td>
                  <td>${escapeHtml(item.source)}</td>
                </tr>
              `
            )
            .join("")}
        </tbody>
      </table>
    </div>
  `;
}

function renderEvidence(item) {
  const types = [...new Set(item.evidence.map((entry) => entry.type))].sort();
  let evidence = item.evidence;
  if (state.evidenceFilter !== "all") {
    evidence = evidence.filter((entry) => entry.type === state.evidenceFilter);
  }
  evidence = [...evidence].sort((a, b) => {
    if (state.evidenceSort === "date") {
      return new Date(b.date || 0) - new Date(a.date || 0);
    }
    if (state.evidenceSort === "source") {
      return a.source.localeCompare(b.source);
    }
    return evidencePriority(b) - evidencePriority(a);
  });

  return `
    <section class="tab-panel">
      ${renderEvidenceTrustSummary(item.evidenceConfidence || item.metrics.evidenceConfidence)}
      <div class="toolbar">
        <div class="toolbar-group">
          <label class="field-label" for="evidenceFilter">Type</label>
          <select id="evidenceFilter" class="select">
            <option value="all">All evidence</option>
            ${types.map((type) => `<option value="${escapeAttr(type)}" ${state.evidenceFilter === type ? "selected" : ""}>${escapeHtml(labelize(type))}</option>`).join("")}
          </select>
        </div>
        <div class="toolbar-group">
          <label class="field-label" for="evidenceSort">Sort</label>
          <select id="evidenceSort" class="select">
            <option value="priority" ${state.evidenceSort === "priority" ? "selected" : ""}>Relevance</option>
            <option value="date" ${state.evidenceSort === "date" ? "selected" : ""}>Newest</option>
            <option value="source" ${state.evidenceSort === "source" ? "selected" : ""}>Source</option>
          </select>
        </div>
      </div>
      <div class="evidence-list">
        ${
          evidence.length
            ? evidence.map(renderEvidenceCard).join("")
            : `<div class="panel"><p>No evidence matched the current filter.</p></div>`
        }
      </div>
    </section>
  `;
}

function renderEvidenceTrustSummary(summary = {}) {
  const counts = summary.counts || {};
  return `
    <div class="trust-strip" aria-label="Evidence trust summary">
      <div>
        <span>Confirmed</span>
        <strong>${counts.Confirmed || 0}</strong>
      </div>
      <div>
        <span>Strong</span>
        <strong>${counts["Strong signal"] || 0}</strong>
      </div>
      <div>
        <span>Leads</span>
        <strong>${counts.Lead || 0}</strong>
      </div>
      <div>
        <span>Noise-prone</span>
        <strong>${counts["Noise-prone"] || 0}</strong>
      </div>
      <p>${escapeHtml(summary.guidance || "Prioritize confirmed evidence and validate public leads manually.")}</p>
    </div>
  `;
}

function renderEvidenceCard(entry) {
  const safeUrl = safeExternalUrl(entry.url);
  const link = safeUrl ? `<a href="${escapeAttr(safeUrl)}" target="_blank" rel="noreferrer noopener">Open</a>` : `<span class="badge">No URL</span>`;
  return `
    <article class="evidence-card">
      <div>
        <div class="badge-row">
          <span class="badge">${escapeHtml(entry.source)}</span>
          <span class="badge">${escapeHtml(labelize(entry.type))}</span>
          <span class="badge">${escapeHtml(entry.credibility || entry.confidence)} </span>
          <span class="badge" title="${escapeAttr(entry.reputation?.guidance || "")}">${escapeHtml(entry.reputation?.tier || "Unrated source")}</span>
          <span class="badge">${escapeHtml(entry.confidence)} confidence</span>
        </div>
        <h3>${escapeHtml(entry.title)}</h3>
        <p>${escapeHtml(entry.description || "No description supplied by this source.")}</p>
        <div class="evidence-meta">
          ${entry.date ? `<span class="badge">${formatDate(entry.date)}</span>` : ""}
          ${(entry.tags || []).slice(0, 6).map((tag) => `<span class="badge">${escapeHtml(tag)}</span>`).join("")}
        </div>
      </div>
      <div>${link}</div>
    </article>
  `;
}

function renderTimeline(item) {
  return `
    <section class="tab-panel">
      <div class="timeline-list">
        ${
          item.timeline.length
            ? item.timeline
                .map(
                  (event) => `
                    <div class="timeline-item">
                      <div class="timeline-date">${event.date ? formatDate(event.date) : "Undated"}</div>
                      <div>
                        <strong>${escapeHtml(event.label)}</strong>
                        <p>${escapeHtml(event.source)}${event.detail ? ` - ${escapeHtml(event.detail)}` : ""}</p>
                      </div>
                    </div>
                  `
                )
                .join("")
            : `<div class="panel"><p>No dated events were extracted.</p></div>`
        }
      </div>
    </section>
  `;
}

function renderIntelligencePanel(item) {
  return `
    <div class="panel">
      <h3>Exploit, Patch, and Evidence Intelligence</h3>
      <div class="card-grid">
        <div class="action-item">
          <span class="badge">${item.exploitMaturity?.score ?? "n/a"}/100</span>
          <strong>${escapeHtml(item.exploitMaturity?.stage || "Exploit maturity unknown")}</strong>
          <p>${(item.exploitMaturity?.signals || []).map(escapeHtml).join(" ")}</p>
        </div>
        <div class="action-item">
          <span class="badge">${escapeHtml(item.vendorPatch?.status || "Patch intelligence")}</span>
          <strong>Vendor Patch Intelligence</strong>
          <p>${escapeHtml(item.vendorPatch?.summary || "No vendor patch summary available.")}</p>
        </div>
        <div class="action-item">
          <span class="badge">Evidence quality</span>
          <strong>Confidence Labels</strong>
          <p>${escapeHtml(item.evidenceConfidence?.summary || item.metrics.evidenceConfidence?.summary || "No evidence confidence summary available.")}</p>
        </div>
        <div class="action-item">
          <span class="badge">${item.cloudImpact?.services?.length ?? 0} services</span>
          <strong>Cloud Impact</strong>
          <p>${escapeHtml(item.cloudImpact?.summary || "No AWS or Azure cloud impact summary available.")}</p>
        </div>
      </div>
    </div>
  `;
}

function renderRemediation(item) {
  return `
    <section class="tab-panel">
      <div class="panel copy-panel">
        <div class="panel-title-row">
          <div>
            <h3>Copy-Ready Remediation Instructions</h3>
            <p>Plain text for a ticket, email, change request, or handoff note.</p>
          </div>
          <button class="primary-button" type="button" data-action="copy-remediation">Copy Instructions</button>
        </div>
        <textarea class="textarea remediation-text" readonly>${escapeHtml(item.remediation.plainText || "No remediation instructions were generated.")}</textarea>
      </div>
      <div class="card-grid">
        ${item.remediation.steps
          .map(
            (step) => `
              <div class="action-item">
                <span class="badge">${escapeHtml(step.priority)}</span>
                <strong>${escapeHtml(step.title)}</strong>
                <p>${escapeHtml(step.detail)}</p>
                ${step.dueDate ? `<p><strong>Due:</strong> ${formatDate(step.dueDate)}</p>` : ""}
              </div>
            `
          )
          .join("")}
      </div>
      <div class="panel">
        <h3>Remediation Links</h3>
        ${
          item.remediation.primaryLinks?.length
            ? `<div class="link-grid">${item.remediation.primaryLinks.map(renderSourceLink).join("")}</div>`
            : `<p>No remediation links were generated. Review the full evidence list and vendor site manually.</p>`
        }
      </div>
      <div class="panel">
        <h3>Advisory and Patch References</h3>
        ${
          item.remediation.advisoryRefs.length
            ? `<div class="link-grid">${item.remediation.advisoryRefs.map(renderSourceLink).join("")}</div>`
            : `<p>No patch-specific reference was classified. Review the full evidence list and vendor site manually.</p>`
        }
      </div>
      <div class="panel">
        <h3>External Research Links</h3>
        <div class="link-grid">${item.sourceLinks.map(renderSourceLink).join("")}</div>
      </div>
      <div class="panel">
        <h3>Source Results</h3>
        <div class="source-list light">
          ${item.sourceResults.map(renderSourceResult).join("")}
        </div>
      </div>
    </section>
  `;
}


function renderImpact(item) {
  const matches = analyzeAssetImpact(item, state.assetInput);
  const sbomMatches = analyzeSbomImpact(item);
  return `
    <section class="tab-panel">
      <div class="panel copy-panel">
        <div class="panel-title-row">
          <div>
            <h3>Asset Impact Checker</h3>
            <p>Paste hostnames, product names, versions, scanner output, SBOM snippets, or inventory rows.</p>
          </div>
          <button class="primary-button" type="button" data-action="run-asset-impact">Check Impact</button>
        </div>
        <textarea id="assetInput" class="textarea remediation-text" placeholder="Example: confluence-server 8.5.4 on wiki-prod-01">${escapeHtml(state.assetInput)}</textarea>
      </div>
      <div class="panel">
        <h3>Impact Results</h3>
        ${matches.length ? `<div class="evidence-list">${matches.map((match) => `<div class="action-item"><span class="badge">${escapeHtml(match.confidence)}</span><strong>${escapeHtml(match.product)}</strong><p>${escapeHtml(match.reason)}</p><p>${escapeHtml(match.line)}</p></div>`).join("")}</div>` : `<p>No local inventory match yet. Paste asset/software data and click Check Impact.</p>`}
      </div>
      <div class="panel">
        <h3>Loaded SBOM Matches</h3>
        ${
          sbomMatches.length
            ? `<div class="evidence-list">${sbomMatches.map((match) => `<div class="action-item"><span class="badge">${escapeHtml(match.confidence)}</span><strong>${escapeHtml(match.component)}</strong><p>${escapeHtml(match.reason)}</p><p>${escapeHtml(match.fileName)}</p></div>`).join("")}</div>`
            : `<p>No loaded SBOM component matched the affected product signals for this CVE.</p>`
        }
      </div>
    </section>
  `;
}

function renderCloudImpact(item) {
  const cloud = item.cloudImpact || {};
  return `
    <section class="tab-panel">
      <div class="panel copy-panel">
        <div class="panel-title-row">
          <div>
            <h3>AWS and Azure Impact</h3>
            <p>${escapeHtml(cloud.summary || "No AWS or Azure cloud impact summary was generated.")}</p>
          </div>
          <button class="primary-button" type="button" data-action="copy-cloud-impact">Copy Summary</button>
        </div>
        <textarea class="textarea remediation-text" readonly>${escapeHtml(cloud.plainText || "No cloud impact summary is available yet.")}</textarea>
      </div>
      <div class="card-grid">
        ${(cloud.providers || []).map((provider) => `
          <div class="action-item">
            <span class="badge">${escapeHtml(provider.confidence || "Unknown")} confidence</span>
            <strong>${escapeHtml(provider.provider || "Cloud provider")}</strong>
            <p>${escapeHtml(provider.status || "No status available.")}</p>
            <p>${escapeHtml(provider.guidance || "")}</p>
          </div>
        `).join("")}
      </div>
      <div class="panel">
        <h3>Cloud Services to Validate</h3>
        ${renderCloudServices(cloud.services || [])}
      </div>
      <div class="panel">
        <h3>Cloud Research Links</h3>
        <div class="link-grid">${(cloud.links || []).map(renderSourceLink).join("")}</div>
      </div>
      <div class="panel">
        <h3>Official Cloud References Found</h3>
        ${
          cloud.officialRefs?.length
            ? `<div class="link-grid">${cloud.officialRefs.map(renderSourceLink).join("")}</div>`
            : `<p>No AWS or Microsoft/Azure advisory reference was found in the CVE/NVD/CISA references. Use the research links above to verify manually.</p>`
        }
      </div>
    </section>
  `;
}

function renderCloudServices(services) {
  if (!services.length) {
    return `<p>No service-specific match was inferred. If you run the affected product in AWS or Azure, validate your own VM, container, function, database, and marketplace deployments manually.</p>`;
  }
  return `
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Provider</th>
            <th>Service</th>
            <th>Status</th>
            <th>Confidence</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          ${services.map((service) => `
            <tr>
              <td>${escapeHtml(service.provider)}</td>
              <td>${escapeHtml(service.service)}</td>
              <td>${escapeHtml(service.status)}</td>
              <td>${escapeHtml(service.confidence)}</td>
              <td>${escapeHtml(service.action)}</td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    </div>
  `;
}

function renderReports(item) {
  return `
    <section class="tab-panel">
      ${renderCopyBlock("Executive Summary Mode", "copy-executive", item.executiveBrief?.plainText)}
      ${renderCopyBlock("Ticket Export Mode", "copy-ticket", item.ticketExport?.plainText)}
      ${renderCopyBlock("Detection Guidance", "copy-detection", item.detectionGuidance?.plainText)}
      ${renderCopyBlock("Cloud Impact Summary", "copy-cloud-impact", item.cloudImpact?.plainText)}
      ${renderCopyBlock("Risk Acceptance Note", "copy-risk-acceptance", item.riskAcceptance?.plainText)}
    </section>
  `;
}

function renderCopyBlock(title, action, text) {
  return `
    <div class="panel copy-panel">
      <div class="panel-title-row">
        <div>
          <h3>${escapeHtml(title)}</h3>
          <p>Plain text, ready to paste into your workflow.</p>
        </div>
        <button class="primary-button" type="button" data-action="${escapeAttr(action)}">Copy</button>
      </div>
      <textarea class="textarea remediation-text" readonly>${escapeHtml(text || "Not available yet.")}</textarea>
    </div>
  `;
}

function renderWatchlistTab(item) {
  const record = state.watchlist.find((entry) => entry.id === item.id);
  return `
    <section class="tab-panel">
      <div class="panel">
        <div class="panel-title-row">
          <div>
            <h3>Watchlist and Change Detection</h3>
            <p>Save the CVE, refresh later, and track what changed since the last check.</p>
          </div>
          <button class="primary-button" type="button" data-action="watch">Watch CVE</button>
        </div>
        ${record ? renderWatchRecord(record) : `<p>This CVE is not on the watchlist yet.</p>`}
      </div>
    </section>
  `;
}

function renderWatchRecord(record) {
  const changes = record.changes || [];
  const baselineTime = record.baseline?.checkedAt || record.addedAt;
  const latestTime = record.latest?.checkedAt || record.lastCheckedAt;
  return `
    <div class="card-grid">
      <div class="action-item"><span class="badge">Baseline</span><strong>${formatDateTime(baselineTime)}</strong><p>${escapeHtml(record.baseline?.verdict || "Unknown")} / ${escapeHtml(record.baseline?.maturity || "Unknown")}</p></div>
      <div class="action-item"><span class="badge">Latest check</span><strong>${formatDateTime(latestTime)}</strong><p>${escapeHtml(record.latest?.verdict || "Unknown")} / ${escapeHtml(record.latest?.maturity || "Unknown")}</p></div>
    </div>
    <div class="timeline-list watch-change-list">
      ${changes.length ? changes.map((change) => `<div class="timeline-item"><div class="timeline-date">Changed</div><div><strong>${escapeHtml(change.label)}</strong><p>${escapeHtml(change.before)} -> ${escapeHtml(change.after)}</p></div></div>`).join("") : `<div class="timeline-item"><div class="timeline-date">Stable</div><div><strong>No tracked changes since last refresh</strong><p>KEV, EPSS, exploit maturity, risk, chatter, and evidence counts are unchanged.</p></div></div>`}
    </div>
  `;
}

function renderWorkspace(item) {
  const draft = getCaseDraft();
  return `
    <section class="tab-panel">
      <div class="workspace-grid">
        <div class="panel">
          <h3>Case Controls</h3>
          <div class="form-grid">
            <label>
              <span class="field-label">Status</span>
              <select class="select" data-case-field="status">
                ${["Needs triage", "Investigating", "Patching", "Monitoring", "Accepted risk", "Closed"]
                  .map((status) => `<option value="${status}" ${draft.status === status ? "selected" : ""}>${status}</option>`)
                  .join("")}
              </select>
            </label>
            <label>
              <span class="field-label">Owner</span>
              <input class="input" data-case-field="owner" value="${escapeAttr(draft.owner)}" placeholder="Team or analyst">
            </label>
            <label>
              <span class="field-label">Tags</span>
              <input class="input" data-case-field="tags" value="${escapeAttr(draft.tags)}" placeholder="internet-facing, vpn, java">
            </label>
            <button class="primary-button" type="button" data-action="save">Save case</button>
            <button class="danger-button" type="button" data-action="delete-case">Delete saved case</button>
          </div>
        </div>
        <div class="panel">
          <h3>Analyst Notes</h3>
          <textarea class="textarea" data-case-field="notes" placeholder="Record environment impact, patch plan, exceptions, and links.">${escapeHtml(draft.notes)}</textarea>
        </div>
      </div>
    </section>
  `;
}

function renderSourceLink(link) {
  const safeUrl = safeExternalUrl(link.url);
  const label = link.label || link.title || link.url;
  if (!safeUrl) {
    return `
      <div class="source-link blocked-link" title="Unsafe or malformed URL was blocked">
        <span>${escapeHtml(label)}</span>
        <strong>Blocked</strong>
      </div>
    `;
  }
  return `
    <a class="source-link" href="${escapeAttr(safeUrl)}" target="_blank" rel="noreferrer noopener">
      <span>${escapeHtml(label)}</span>
      <strong>Open</strong>
    </a>
  `;
}

function renderSourceResult(source) {
  return `
    <div class="source-row">
      <span>${escapeHtml(source.label)} - ${escapeHtml(source.message || source.status)}</span>
      <span class="status-dot ${escapeAttr(source.status)}" title="${escapeAttr(source.status)}"></span>
    </div>
  `;
}

function renderWatchlist() {
  if (!elements.watchList) return;
  if (!state.watchlist.length) {
    elements.watchList.innerHTML = `<div class="empty-list">No watched CVEs.</div>`;
    return;
  }
  elements.watchList.innerHTML = state.watchlist.map((item) => `
    <div class="case-card watch-card">
      <button type="button" class="watch-main" data-action="open-watch" data-value="${escapeAttr(item.id)}">
        <strong>${escapeHtml(item.id)}</strong>
        <span>${escapeHtml(item.title)}</span>
        <div class="case-meta">
          <span>${escapeHtml(item.latest?.verdict || "Unknown")}</span>
          <span>${escapeHtml(item.latest?.maturity || "Unknown")}</span>
          <span>${(item.changes || []).length} changes</span>
        </div>
      </button>
      <div class="watch-actions">
        <button type="button" data-action="refresh-watch" data-value="${escapeAttr(item.id)}">Refresh</button>
        <button type="button" data-action="remove-watch" data-value="${escapeAttr(item.id)}">Remove</button>
      </div>
    </div>
  `).join("");
}

function renderSbomList() {
  if (!elements.sbomList) return;
  if (!state.sbomReports.length) {
    elements.sbomList.innerHTML = `<div class="empty-list">No SBOM files loaded.</div>`;
    return;
  }
  elements.sbomList.innerHTML = state.sbomReports.map((report) => `
    <button class="case-card ${state.activeSbomId === report.id ? "active" : ""}" type="button" data-action="open-sbom" data-value="${escapeAttr(report.id)}">
      <strong>${escapeHtml(report.title)}</strong>
      <span>${report.files.length} file${report.files.length === 1 ? "" : "s"} parsed</span>
      <div class="case-meta">
        <span>${report.components.length} components</span>
        <span>${report.cves.length} CVEs</span>
        <span>${formatDate(report.uploadedAt)}</span>
      </div>
    </button>
  `).join("");
}

function renderSbomWorkspace(report) {
  elements.content.innerHTML = `
    <article class="investigation">
      <section class="brief-header">
        <div class="brief-title">
          <div class="badge-row">
            <span class="badge">SBOM analysis</span>
            <span class="badge">${report.files.length} file${report.files.length === 1 ? "" : "s"}</span>
            <span class="badge">${report.cves.length} CVEs</span>
          </div>
          <h2>${escapeHtml(report.title)}</h2>
          <p>${escapeHtml(report.summary)}</p>
        </div>
        <div class="header-actions">
          <label class="secondary-button" for="sbomInput">Upload more</label>
          <button class="secondary-button" type="button" data-action="copy-sbom-cves">Copy CVEs</button>
          <button class="secondary-button" type="button" data-action="export-sbom-json">Export JSON</button>
        </div>
      </section>

      <section class="metric-grid" aria-label="SBOM metrics">
        <div class="metric-card">
          <div class="metric-label">Files</div>
          <div class="metric-value">${report.files.length}</div>
          <div class="metric-detail">Current upload batch</div>
        </div>
        <div class="metric-card">
          <div class="metric-label">Components</div>
          <div class="metric-value">${report.components.length}</div>
          <div class="metric-detail">Packages and services extracted</div>
        </div>
        <div class="metric-card">
          <div class="metric-label">CVE Findings</div>
          <div class="metric-value">${report.cves.length}</div>
          <div class="metric-detail">Unique CVE IDs found</div>
        </div>
        <div class="metric-card">
          <div class="metric-label">Vulnerability Rows</div>
          <div class="metric-value">${report.vulnerabilities.length}</div>
          <div class="metric-detail">SBOM vulnerability references</div>
        </div>
      </section>

      <section class="tab-panel">
        ${renderSbomWarnings(report)}
        <div class="panel">
          <h3>CVE Findings</h3>
          ${renderSbomCveTable(report)}
        </div>
        <div class="panel">
          ${renderSbomAffectedPackages(report)}
        </div>
        <div class="panel">
          <h3>Vulnerability Detail</h3>
          ${renderSbomVulnerabilities(report)}
        </div>
        <div class="panel">
          <h3>Component Inventory</h3>
          ${renderSbomComponents(report)}
        </div>
        <div class="panel">
          <h3>Uploaded Files</h3>
          ${renderSbomFiles(report)}
        </div>
      </section>
    </article>
  `;
}

function renderSbomWarnings(report) {
  if (!report.warnings.length) return "";
  return `
    <div class="stale-banner" role="status">
      <div>
        <strong>SBOM parser notes</strong>
        <p>${report.warnings.slice(0, 4).map(escapeHtml).join(" ")}</p>
      </div>
    </div>
  `;
}

function renderSbomCveTable(report) {
  if (!report.cves.length) {
    return `<p>No CVE IDs were found in the uploaded SBOM files. The component inventory was still extracted where possible.</p>`;
  }
  const activeCve = getSelectedSbomCve(report)?.id;
  return `
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>CVE</th>
            <th>Severity</th>
            <th>Components</th>
            <th>Files</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          ${report.cves.slice(0, SBOM_CVE_DISPLAY_LIMIT).map((entry) => `
            <tr class="${activeCve === entry.id ? "selected-row" : ""}">
              <td><button class="link-button" type="button" data-action="open-sbom-cve" data-value="${escapeAttr(entry.id)}" aria-pressed="${activeCve === entry.id ? "true" : "false"}">${escapeHtml(entry.id)}</button></td>
              <td>${escapeHtml(entry.severity || "Unknown")}</td>
              <td>${escapeHtml(entry.affectedPackages?.slice(0, 3).map((pkg) => pkg.label).join(", ") || entry.components.slice(0, 3).join(", ") || "No component listed")}</td>
              <td>${escapeHtml(entry.files.slice(0, 2).join(", "))}</td>
              <td><button class="secondary-button table-button" type="button" data-action="research-sbom-cve" data-value="${escapeAttr(entry.id)}">Research</button></td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    </div>
    ${report.cves.length > SBOM_CVE_DISPLAY_LIMIT ? `<p class="table-note">Showing first ${SBOM_CVE_DISPLAY_LIMIT} CVEs. Export JSON for the full list.</p>` : ""}
  `;
}

function renderSbomAffectedPackages(report) {
  const selected = getSelectedSbomCve(report);
  if (!selected) {
    return `
      <h3>Affected Packages</h3>
      <p>Select a CVE above to view the package records tied to that finding.</p>
    `;
  }
  const packages = selected.affectedPackages || [];
  return `
    <div class="panel-title-row">
      <div>
        <h3>Affected Packages for ${escapeHtml(selected.id)}</h3>
        <p>${packages.length ? `${packages.length} package record${packages.length === 1 ? "" : "s"} mapped from the uploaded SBOM data.` : "This CVE was found in the SBOM, but no package-level mapping was included."}</p>
      </div>
      <button class="secondary-button" type="button" data-action="research-sbom-cve" data-value="${escapeAttr(selected.id)}">Research CVE</button>
    </div>
    ${
      packages.length
        ? `<div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Package</th>
                  <th>Version</th>
                  <th>Type</th>
                  <th>Package URL / CPE</th>
                  <th>Evidence</th>
                  <th>File</th>
                </tr>
              </thead>
              <tbody>
                ${packages.map((pkg) => `
                  <tr>
                    <td><strong>${escapeHtml(pkg.name || pkg.label || "Unknown package")}</strong>${pkg.supplier ? `<br><span class="muted-cell">${escapeHtml(pkg.supplier)}</span>` : ""}</td>
                    <td>${escapeHtml(pkg.version || "n/a")}</td>
                    <td>${escapeHtml(pkg.type || "component")}</td>
                    <td>${escapeHtml(pkg.purl || pkg.cpes?.[0] || "n/a")}</td>
                    <td>${escapeHtml(pkg.match || pkg.source || "SBOM mapping")}${pkg.severity ? `<br><span class="muted-cell">${escapeHtml(pkg.severity)}${pkg.score ? ` ${escapeHtml(String(pkg.score))}` : ""}</span>` : ""}</td>
                    <td>${escapeHtml(pkg.fileName || "Unknown file")}</td>
                  </tr>
                `).join("")}
              </tbody>
            </table>
          </div>`
        : `<p>Some tools emit file-level CVE references without affected package references. Review the vulnerability detail and component inventory for additional context.</p>`
    }
  `;
}

function renderSbomVulnerabilities(report) {
  if (!report.vulnerabilities.length) {
    return `<p>No structured vulnerability rows were found. Some SBOMs only list components and do not include vulnerability analysis.</p>`;
  }
  return `
    <div class="evidence-list">
      ${report.vulnerabilities.slice(0, 40).map((vulnerability) => `
        <div class="action-item">
          <div class="badge-row">
            <span class="badge">${escapeHtml(vulnerability.cve)}</span>
            <span class="badge">${escapeHtml(vulnerability.severity || "Unknown severity")}</span>
            <span class="badge">${escapeHtml(vulnerability.source || "SBOM")}</span>
          </div>
          <strong>${escapeHtml(vulnerability.title || vulnerability.cve)}</strong>
          <p>${escapeHtml(vulnerability.description || "No description included in the SBOM.")}</p>
          <p>${escapeHtml(vulnerability.components?.join(", ") || "No component listed")} ${vulnerability.fileName ? `- ${escapeHtml(vulnerability.fileName)}` : ""}</p>
        </div>
      `).join("")}
    </div>
    ${report.vulnerabilities.length > 40 ? `<p class="table-note">Showing first 40 vulnerability rows. Export JSON for the full list.</p>` : ""}
  `;
}

function renderSbomComponents(report) {
  if (!report.components.length) {
    return `<p>No component inventory was extracted from these files.</p>`;
  }
  return `
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Component</th>
            <th>Version</th>
            <th>Type</th>
            <th>Package URL / CPE</th>
            <th>File</th>
          </tr>
        </thead>
        <tbody>
          ${report.components.slice(0, SBOM_COMPONENT_DISPLAY_LIMIT).map((component) => `
            <tr>
              <td>${escapeHtml(component.name || "Unknown")}</td>
              <td>${escapeHtml(component.version || "n/a")}</td>
              <td>${escapeHtml(component.type || "component")}</td>
              <td>${escapeHtml(component.purl || component.cpes?.[0] || "n/a")}</td>
              <td>${escapeHtml(component.fileName)}</td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    </div>
    ${report.components.length > SBOM_COMPONENT_DISPLAY_LIMIT ? `<p class="table-note">Showing first ${SBOM_COMPONENT_DISPLAY_LIMIT} components. Export JSON for the full list.</p>` : ""}
  `;
}

function renderSbomFiles(report) {
  return `
    <div class="card-grid">
      ${report.files.map((file) => `
        <div class="action-item">
          <span class="badge">${escapeHtml(file.format)}</span>
          <strong>${escapeHtml(file.fileName)}</strong>
          <p>${escapeHtml(file.documentName || file.fileName)}</p>
          <p>${formatBytes(file.size)} - ${file.componentCount} components - ${file.cveCount} CVEs</p>
        </div>
      `).join("")}
    </div>
  `;
}

function renderCases() {
  const filtered = state.cases.filter((item) => {
    const haystack = `${item.id} ${item.title} ${item.status} ${item.tags} ${item.owner}`.toLowerCase();
    return !state.caseFilter || haystack.includes(state.caseFilter);
  });
  if (!filtered.length) {
    elements.caseList.innerHTML = `<div class="empty-list">No saved cases.</div>`;
    return;
  }
  elements.caseList.innerHTML = filtered
    .map(
      (item) => `
        <button class="case-card ${state.current?.id === item.id ? "active" : ""}" type="button" data-action="open-case" data-value="${escapeAttr(item.id)}">
          <strong>${escapeHtml(item.id)}</strong>
          <span>${escapeHtml(item.title)}</span>
          <div class="case-meta">
            <span>${escapeHtml(item.riskLevel)} ${item.riskScore}</span>
            <span>${escapeHtml(item.status)}</span>
            <span>${formatDate(item.savedAt)}</span>
          </div>
        </button>
      `
    )
    .join("");
}

function renderHealth() {
  if (!state.sourceHealth.length) {
    elements.health.innerHTML = `<div class="empty-list">Source health unavailable.</div>`;
    return;
  }
  elements.health.innerHTML = state.sourceHealth.map(renderSourceResult).join("");
}

function renderEmpty() {
  elements.content.replaceChildren(elements.emptyTemplate.content.cloneNode(true));
}

function renderLoading(cve) {
  elements.content.innerHTML = `
    <section class="loading" aria-busy="true">
      <div class="panel">
        <p class="eyebrow">Researching</p>
        <h2>${escapeHtml(cve)}</h2>
        <p>Collecting CVE metadata, exploit probability, KEV status, references, and public code leads.</p>
      </div>
      <div class="skeleton"></div>
      <div class="skeleton"></div>
      <div class="skeleton"></div>
    </section>
  `;
}

function renderError(message) {
  elements.content.innerHTML = `
    <div class="error-panel">
      <strong>Research failed</strong>
      <p>${escapeHtml(message)}</p>
    </div>
  `;
  showToast(message);
}

function makeMarkdown(item) {
  const lines = [];
  const realWorld = item.realWorld || item.metrics.realWorld;
  lines.push(`# ${item.id} Research Brief`);
  lines.push("");
  lines.push(`**Title:** ${item.title}`);
  lines.push(`**Risk:** ${item.risk.level} (${item.risk.score}/100)`);
  if (realWorld) {
    lines.push(`**Real-world verdict:** ${realWorld.verdict} (${realWorld.score}/100)`);
  }
  lines.push(`**Confidence:** ${item.confidence.label}`);
  lines.push(`**Generated:** ${formatDateTime(item.generatedAt)}`);
  lines.push("");
  lines.push("## Executive Summary");
  lines.push(item.executiveSummary);
  lines.push("");
  if (realWorld) {
    lines.push("## Real-World Assessment");
    lines.push(realWorld.summary);
    lines.push("");
    lines.push(`- Exploitation: ${realWorld.exploitedStatus}`);
    lines.push(`- Public exploit level: ${realWorld.publicExploitLevel}`);
    lines.push(`- Chatter level: ${realWorld.chatterLevel}`);
    lines.push(`- Chatter leads: ${realWorld.counts?.totalChatter ?? 0}`);
    lines.push("");
  }
  if (item.exploitMaturity) {
    lines.push("## Exploit Maturity");
    lines.push(`${item.exploitMaturity.stage} (${item.exploitMaturity.score}/100)`);
    for (const signal of item.exploitMaturity.signals || []) lines.push(`- ${signal}`);
    lines.push("");
  }
  if (item.cloudImpact) {
    lines.push("## Cloud Impact");
    lines.push(item.cloudImpact.summary);
    lines.push("");
    for (const provider of item.cloudImpact.providers || []) {
      lines.push(`- ${provider.provider}: ${provider.status} (${provider.confidence} confidence)`);
    }
    for (const service of (item.cloudImpact.services || []).slice(0, 12)) {
      lines.push(`- ${service.provider} ${service.service}: ${service.status}. ${service.action}`);
    }
    lines.push("");
  }
  lines.push("## Key Metrics");
  lines.push(`- CVSS: ${item.metrics.cvss?.score ?? "n/a"} ${item.metrics.cvss?.severity ?? ""}`);
  lines.push(`- EPSS: ${item.metrics.epss?.epss !== null && item.metrics.epss?.epss !== undefined ? formatPercent(item.metrics.epss.epss) : "n/a"}`);
  lines.push(`- CISA KEV: ${item.metrics.kev?.listed ? "Listed" : "Not listed"}`);
  lines.push(`- GitHub leads: ${item.metrics.github?.totalCount ?? "n/a"}`);
  lines.push(`- GitHub discussion leads: ${item.metrics.githubIssues?.totalCount ?? "n/a"}`);
  lines.push(`- Hacker News leads: ${item.metrics.hackerNews?.totalCount ?? "n/a"}`);
  lines.push(`- Reddit leads: ${item.metrics.reddit?.totalCount ?? "n/a"}`);
  lines.push("");
  if (item.remediation?.plainText) {
    lines.push("## Copy-Ready Remediation Instructions");
    lines.push("```text");
    lines.push(item.remediation.plainText);
    lines.push("```");
    lines.push("");
  }
  if (item.executiveBrief?.plainText) {
    lines.push("## Executive Summary Mode");
    lines.push("```text");
    lines.push(item.executiveBrief.plainText);
    lines.push("```");
    lines.push("");
  }
  if (item.ticketExport?.plainText) {
    lines.push("## Ticket Export Mode");
    lines.push("```text");
    lines.push(item.ticketExport.plainText);
    lines.push("```");
    lines.push("");
  }
  lines.push("## Analyst Actions");
  for (const action of item.analystActions) {
    lines.push(`- [${action.priority}] ${action.label}: ${action.detail}`);
  }
  lines.push("");
  lines.push("## Evidence");
  for (const evidence of item.evidence.slice(0, 20)) {
    lines.push(`- ${evidence.source}: ${evidence.title}${evidence.url ? ` (${evidence.url})` : ""}`);
  }
  lines.push("");
  lines.push("## Source Links");
  for (const link of item.sourceLinks) {
    lines.push(`- ${link.label}: ${link.url}`);
  }
  return lines.join("\n");
}

function download(filename, contents, type) {
  const blob = new Blob([contents], { type });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
  showToast(`${filename} downloaded.`);
}

function showToast(message) {
  elements.toast.textContent = message;
  elements.toast.hidden = false;
  clearTimeout(showToast.timeout);
  showToast.timeout = setTimeout(() => {
    elements.toast.hidden = true;
  }, 3600);
}

function setSearchError(message) {
  if (!elements.searchError) return;
  elements.searchError.textContent = message;
  elements.searchError.hidden = !message;
  elements.input.setAttribute("aria-invalid", message ? "true" : "false");
}

function focusContent() {
  requestAnimationFrame(() => elements.content.focus({ preventScroll: true }));
}

function getActiveSbomReport() {
  return state.sbomReports.find((item) => item.id === state.activeSbomId) || null;
}

function getSelectedSbomCve(report) {
  if (!report?.cves.length) return null;
  return report.cves.find((entry) => entry.id === state.activeSbomCveId) || report.cves[0];
}

function findSbomCveMatches(cve) {
  const normalized = normalizeCve(cve);
  if (!normalized) return [];
  return state.sbomReports.flatMap((report) => {
    const entry = report.cves.find((item) => item.id === normalized);
    return entry ? [{ report, entry }] : [];
  });
}

function normalizeSbomComponent(component) {
  return {
    fileName: component.fileName || "",
    ref: String(component.ref || ""),
    type: String(component.type || "component"),
    name: String(component.name || "").trim(),
    version: String(component.version || "").trim(),
    supplier: String(component.supplier || "").trim(),
    purl: String(component.purl || "").trim(),
    cpes: uniqueValues(normalizeArray(component.cpes).map(String).filter(Boolean)),
    licenses: uniqueValues(normalizeArray(component.licenses).map(String).filter(Boolean)),
    cves: uniqueValues(normalizeArray(component.cves).flatMap((value) => extractCves(value)))
  };
}

function findSbomAffectedPackages(vulnerability, components) {
  const refs = new Set(uniqueValues(vulnerability.componentRefs || []));
  const labels = new Set(uniqueValues(vulnerability.components || []));
  const matchingComponents = components.filter((component) => {
    if (component.fileName !== vulnerability.fileName) return false;
    const refHit = sbomComponentRefValues(component).some((ref) => refs.has(ref));
    const labelHit = labels.has(formatSbomComponentLabel(component));
    return refHit || labelHit;
  });

  if (matchingComponents.length) {
    return matchingComponents.map((component) => ({
      label: formatSbomComponentLabel(component),
      name: component.name || component.purl || component.ref || "Unknown package",
      version: component.version || "",
      type: component.type || "component",
      supplier: component.supplier || "",
      purl: component.purl || "",
      cpes: component.cpes || [],
      fileName: component.fileName,
      source: vulnerability.source || "SBOM",
      severity: vulnerability.severity || "",
      score: vulnerability.score || "",
      match: refs.size ? "Matched by SBOM component reference" : "Matched by SBOM component label"
    }));
  }

  return [...labels].map((label) => ({
    label,
    name: label,
    version: "",
    type: "component",
    supplier: "",
    purl: "",
    cpes: [],
    fileName: vulnerability.fileName,
    source: vulnerability.source || "SBOM",
    severity: vulnerability.severity || "",
    score: vulnerability.score || "",
    match: "SBOM listed this component label, but no full package record was available"
  }));
}

function sbomComponentRefValues(component) {
  return uniqueValues([component.ref, component.purl, sbomComponentKey(component)]);
}

function sbomComponentKey(component) {
  return [component.fileName, component.ref, component.purl, component.name, component.version].map((value) => String(value || "")).join("|");
}

function sbomAffectedPackageKey(pkg) {
  return [pkg.reportId, pkg.fileName, pkg.name, pkg.version, pkg.purl, pkg.label].map((value) => String(value || "")).join("|");
}

function analyzeSbomImpact(item) {
  const components = state.sbomReports.flatMap((report) => report.components || []);
  if (!components.length) return [];
  const products = (item.affected || []).map((entry) => ({
    product: `${entry.vendor} ${entry.product}`.trim(),
    vendor: String(entry.vendor || "").toLowerCase(),
    name: String(entry.product || "").toLowerCase(),
    version: String(entry.version || "")
  }));
  const matches = [];
  for (const component of components) {
    const low = [
      component.name,
      component.supplier,
      component.purl,
      component.cpes?.join(" ")
    ].join(" ").toLowerCase();
    for (const product of products) {
      const productTokens = product.name.split(/\s+/).filter((token) => token.length > 3);
      const vendorHit = product.vendor && low.includes(product.vendor);
      const productHit = productTokens.some((token) => low.includes(token));
      if (vendorHit || productHit) {
        matches.push({
          component: formatSbomComponentLabel(component),
          fileName: component.fileName,
          confidence: vendorHit && productHit ? "High" : "Possible",
          reason: `${vendorHit ? "Vendor" : "Product"} term matched affected product signal ${product.product}${product.version ? ` (${product.version})` : ""}.`
        });
      }
    }
  }
  return dedupeBy(matches, (match) => `${match.component}|${match.fileName}|${match.reason}`).slice(0, 30);
}

function analyzeAssetImpact(item, input) {
  const lines = String(input || "").split(/\n+/).map((line) => line.trim()).filter(Boolean);
  const products = (item.affected || []).map((entry) => ({
    product: `${entry.vendor} ${entry.product}`.trim(),
    vendor: String(entry.vendor || "").toLowerCase(),
    name: String(entry.product || "").toLowerCase(),
    version: String(entry.version || "")
  }));
  const matches = [];
  for (const line of lines) {
    const low = line.toLowerCase();
    for (const product of products) {
      const productTokens = product.name.split(/\s+/).filter((token) => token.length > 3);
      const vendorHit = product.vendor && low.includes(product.vendor);
      const productHit = productTokens.some((token) => low.includes(token));
      if (vendorHit || productHit) {
        matches.push({
          product: product.product,
          line,
          confidence: vendorHit && productHit ? "High" : "Possible",
          reason: `${vendorHit ? "Vendor" : "Product"} term matched affected product signal${product.version ? ` (${product.version})` : ""}.`
        });
      }
    }
  }
  return matches.slice(0, 30);
}

function runAssetImpact() {
  render();
  showToast("Asset impact check updated.");
}

function makeWatchSnapshot(item) {
  return {
    checkedAt: new Date().toISOString(),
    analyzedAt: item.generatedAt || null,
    risk: item.risk?.score ?? null,
    riskLevel: item.risk?.level || "Unknown",
    verdict: item.realWorld?.verdict || "Unknown",
    exploited: item.realWorld?.exploitedStatus || "Unknown",
    maturity: item.exploitMaturity?.stage || "Unknown",
    maturityScore: item.exploitMaturity?.score ?? null,
    kev: Boolean(item.metrics?.kev?.listed),
    epss: item.metrics?.epss?.epss ?? null,
    evidence: item.evidence?.length || 0,
    chatter: item.realWorld?.counts?.totalChatter || 0,
    references: item.references?.length || 0,
    cloudServices: item.cloudImpact?.services?.length || 0
  };
}

function compareWatchSnapshots(before = {}, after = {}) {
  const checks = [
    ["riskLevel", "Risk level"],
    ["risk", "Risk score"],
    ["verdict", "Real-world verdict"],
    ["exploited", "Exploitation status"],
    ["maturity", "Exploit maturity"],
    ["kev", "CISA KEV listed"],
    ["epss", "EPSS"],
    ["evidence", "Evidence count"],
    ["chatter", "Chatter count"],
    ["references", "Reference count"],
    ["cloudServices", "Cloud service candidates"]
  ];
  return checks
    .filter(([key]) => JSON.stringify(before[key]) !== JSON.stringify(after[key]))
    .map(([key, label]) => ({ label, before: formatWatchValue(before[key]), after: formatWatchValue(after[key]) }));
}

function formatWatchValue(value) {
  if (typeof value === "number") return value < 1 ? formatPercent(value) : String(value);
  if (typeof value === "boolean") return value ? "Yes" : "No";
  return value === undefined || value === null ? "n/a" : String(value);
}

function loadWatchlist() {
  const records = readStorageArray("cve-research-watchlist");
  const retained = pruneStoredRecords(records, ["updatedAt", "lastCheckedAt", "addedAt"], "addedAt").slice(0, 50);
  if (storageChanged(records, retained)) writeStorageArray("cve-research-watchlist", retained);
  return retained;
}

function persistWatchlist() {
  writeStorageArray("cve-research-watchlist", state.watchlist);
}

function loadCases() {
  const records = readStorageArray("cve-research-cases");
  const retained = pruneStoredRecords(records, ["updatedAt", "savedAt"], "savedAt").slice(0, 40);
  if (storageChanged(records, retained)) writeStorageArray("cve-research-cases", retained);
  return retained;
}

function persistCases() {
  writeStorageArray("cve-research-cases", state.cases);
}

function readStorageArray(key) {
  try {
    const parsed = JSON.parse(localStorage.getItem(key) || "[]");
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function writeStorageArray(key, records) {
  try {
    localStorage.setItem(key, JSON.stringify(records));
  } catch (error) {
    console.warn(`Unable to persist ${key}:`, error);
  }
}

function pruneStoredRecords(records, timestampKeys, fallbackTimestampKey) {
  const now = Date.now();
  const nowIso = new Date(now).toISOString();
  return records.reduce((retained, record) => {
    if (!record || typeof record !== "object") return retained;
    const timestamp = firstFiniteTimestamp(record, timestampKeys);
    if (timestamp && now - timestamp > STORAGE_RETENTION_MS) return retained;
    if (!timestamp) {
      retained.push({
        ...record,
        [fallbackTimestampKey]: nowIso,
        updatedAt: nowIso
      });
      return retained;
    }
    retained.push(record);
    return retained;
  }, []);
}

function firstFiniteTimestamp(record, keys) {
  for (const key of keys) {
    const timestamp = Date.parse(record[key]);
    if (Number.isFinite(timestamp)) return timestamp;
  }
  return 0;
}

function storageChanged(before, after) {
  return before.length !== after.length || JSON.stringify(before) !== JSON.stringify(after);
}

function extractCves(value) {
  return uniqueValues(String(value || "").toUpperCase().match(/CVE-\d{4}-\d{4,}/g) || []);
}

function extractUrls(value) {
  return uniqueValues(String(value || "").match(/https?:\/\/[^\s"'<>),]+/g) || []);
}

function normalizeArray(value) {
  if (Array.isArray(value)) return value;
  if (value === undefined || value === null || value === "") return [];
  return [value];
}

function uniqueValues(values) {
  return [...new Set(normalizeArray(values).filter((value) => value !== undefined && value !== null && String(value).trim() !== "").map((value) => String(value).trim()))];
}

function dedupeBy(items, getKey) {
  const seen = new Set();
  const output = [];
  for (const item of items) {
    const key = getKey(item);
    if (seen.has(key)) continue;
    seen.add(key);
    output.push(item);
  }
  return output;
}

function safeStringify(value) {
  try {
    return JSON.stringify(value || {});
  } catch {
    return "";
  }
}

function supplierName(value) {
  if (!value) return "";
  if (typeof value === "string") return cleanSpdxActor(value);
  return cleanSpdxActor(value.name || value.url || "");
}

function cleanSpdxActor(value) {
  return String(value || "").replace(/^(Organization|Person):\s*/i, "").replace(/^NOASSERTION$/i, "").trim();
}

function componentDisplayName(group, name) {
  const safeGroup = String(group || "").trim();
  const safeName = String(name || "").trim();
  return safeGroup && safeName && !safeName.startsWith(`${safeGroup}/`) ? `${safeGroup}/${safeName}` : safeName || safeGroup;
}

function formatSbomComponentLabel(component) {
  const version = component.version ? `@${component.version}` : "";
  return `${component.name || component.purl || component.ref || "Unknown component"}${version}`;
}

function extractCycloneLicenses(licenses) {
  return normalizeArray(licenses).map((entry) => {
    if (typeof entry === "string") return entry;
    return entry.license?.id || entry.license?.name || entry.expression || "";
  }).filter(Boolean);
}

function extractGenericLicenses(licenses) {
  return normalizeArray(licenses).map((entry) => {
    if (typeof entry === "string") return entry;
    return entry.id || entry.name || entry.value || entry.spdxExpression || "";
  }).filter(Boolean);
}

function highestCycloneRating(ratings) {
  return normalizeArray(ratings).sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || Number(b.score || 0) - Number(a.score || 0))[0] || null;
}

function normalizeSeverity(value) {
  const text = String(value || "").trim().toLowerCase();
  if (!text) return "";
  if (text === "critical") return "Critical";
  if (text === "high") return "High";
  if (text === "medium" || text === "moderate") return "Medium";
  if (text === "low") return "Low";
  if (text === "none" || text === "negligible") return "None";
  return text.charAt(0).toUpperCase() + text.slice(1);
}

function highestSeverity(values) {
  return uniqueValues(values).sort((a, b) => severityRank(b) - severityRank(a))[0] || "";
}

function severityRank(value) {
  const normalized = normalizeSeverity(value);
  if (normalized === "Critical") return 5;
  if (normalized === "High") return 4;
  if (normalized === "Medium") return 3;
  if (normalized === "Low") return 2;
  if (normalized === "None") return 1;
  return 0;
}

function sortCveId(value) {
  const match = String(value || "").match(/^CVE-(\d{4})-(\d+)$/);
  return match ? Number(match[1]) * 10000000 + Number(match[2]) : 0;
}

function findXmlChildren(root, localName) {
  if (!root) return [];
  return [...root.getElementsByTagName("*")].filter((node) => node.localName === localName);
}

function firstXmlChild(root, localName) {
  if (!root) return null;
  return [...root.children].find((node) => node.localName === localName) || null;
}

function xmlText(root, localName) {
  const node = localName ? firstXmlChild(root, localName) : root;
  return node?.textContent?.trim() || "";
}

function firstTagValue(text, key) {
  const pattern = new RegExp(`^${escapeRegExp(key)}:\\s*(.+)$`, "m");
  return text.match(pattern)?.[1]?.trim() || "";
}

function makeSbomId(files, uploadedAt) {
  const fingerprint = `${uploadedAt}|${files.map((file) => `${file.fileName}:${file.size}:${file.componentCount}:${file.cveCount}`).join("|")}`;
  if (globalThis.crypto?.randomUUID) return `sbom-${globalThis.crypto.randomUUID()}`;
  return `sbom-${Math.abs([...fingerprint].reduce((sum, char) => ((sum << 5) - sum + char.charCodeAt(0)) | 0, 0)).toString(36)}`;
}

function makeSbomSummary(files, components, vulnerabilities, cves) {
  const formats = uniqueValues(files.map((file) => file.format)).join(", ");
  if (cves.length) {
    return `${files.length} SBOM file${files.length === 1 ? "" : "s"} parsed as ${formats}. Found ${components.length} components, ${vulnerabilities.length} vulnerability references, and ${cves.length} unique CVEs ready for research.`;
  }
  return `${files.length} SBOM file${files.length === 1 ? "" : "s"} parsed as ${formats}. Found ${components.length} components, but no CVE IDs were embedded in the SBOM data.`;
}

function stripExtension(filename) {
  return String(filename || "sbom").replace(/\.[^.]+$/, "");
}

function sanitizeFilename(value) {
  return String(value || "sbom").toLowerCase().replace(/[^a-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "") || "sbom";
}

function formatBytes(value) {
  const bytes = Number(value) || 0;
  if (bytes >= 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${bytes} B`;
}

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function normalizeCve(value) {
  const normalized = String(value || "").trim().toUpperCase();
  return /^CVE-\d{4}-\d{4,}$/.test(normalized) ? normalized : "";
}

function safeExternalUrl(value) {
  if (!value) return "";
  try {
    const url = new URL(String(value));
    return SAFE_LINK_PROTOCOLS.has(url.protocol) ? url.href : "";
  } catch {
    return "";
  }
}

function formatPercent(value) {
  if (value === null || value === undefined || Number.isNaN(Number(value))) return "n/a";
  return `${(Number(value) * 100).toFixed(Number(value) < 0.01 ? 3 : 1)}%`;
}

function formatDate(value) {
  if (!value) return "Unknown";
  const date = parseDisplayDate(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(undefined, { year: "numeric", month: "short", day: "numeric" }).format(date);
}

function formatDateTime(value) {
  if (!value) return "Unknown";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit"
  }).format(date);
}

function parseDisplayDate(value) {
  const text = String(value);
  const dateOnly = text.match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (dateOnly) {
    return new Date(Number(dateOnly[1]), Number(dateOnly[2]) - 1, Number(dateOnly[3]));
  }
  return new Date(text);
}

function evidencePriority(item) {
  let score = 0;
  if (item.confidence === "high") score += 40;
  if (item.confidence === "medium") score += 20;
  if (/exploitation|commercial|exploit|public-code/.test(item.type)) score += 25;
  if (/chatter/.test(item.type)) score += 8;
  if (item.date) score += 5;
  return score;
}

function labelize(value) {
  return String(value || "")
    .replace(/[-_]/g, " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function escapeAttr(value) {
  return escapeHtml(value).replace(/`/g, "&#096;");
}
