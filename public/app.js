import { buildExposureRows, summarizeExposureRows } from "./modules/workspace.js";
import { formatSafeDate as formatDate, formatSafeDateTime as formatDateTime } from "./modules/date.js";
import { csvCell } from "./modules/csv.js";
import { applySbomVexDecisions } from "./modules/sbom-report.js";
import { buildGitHubIssueDraft, buildRepositoryCveFindings } from "./modules/github.js";
import { WorkspaceStore, validateBackup, clearImportedTrust } from "./modules/persistence.js";
import { Operations, requestJson, pause } from "./modules/operations.js";
import { normalizeResearch, kevLabel, packageKey, occurrenceKey, applyDecisions, makePlan, planText, caseHandoff, matchSemverRange, parsedPackage } from "./modules/research-model.js";
import { createWorkspaceTools, dialogForm } from "./modules/workspace-tools.js";

const store = new WorkspaceStore();
const operations = new Operations();
let storageFailure = "";
let stored = { cases: [], watchlist: [], decisions: [], receipts: [], settings: [] };
try {
  await store.open();
  for (const collection of Object.keys(stored)) stored[collection] = await store.list(collection);
} catch (error) { storageFailure = error.message; }
const changes = typeof BroadcastChannel === "function" ? new BroadcastChannel("vulnscope-workspace") : null;

const APP_SCHEMA_VERSION = 4;
const SAFE_LINK_PROTOCOLS = new Set(["http:", "https:"]);
const SBOM_MAX_FILES = 10;
const SBOM_MAX_FILE_BYTES = 10 * 1024 * 1024;
const SBOM_MAX_TOTAL_BYTES = 40 * 1024 * 1024;
const SBOM_COMPONENT_DISPLAY_LIMIT = 200;
const SBOM_CVE_DISPLAY_LIMIT = 150;

const state = {
  current: null,
  view: "empty",
  activeTab: "overview",
  evidenceFilter: "all",
  evidenceSort: "priority",
  cases: storageFailure ? loadCases() : stored.cases,
  watchlist: storageFailure ? loadWatchlist() : stored.watchlist,
  decisions: stored.decisions,
  receipts: stored.receipts,
  settings: stored.settings,
  researchRecords: {},
  dirty: false,
  savedDraft: null,
  caseRevision: 0,
  exposurePage: 0,
  exposureSource: "all",
  exposureSeverity: "all",
  exposureWorkflow: "all",
  returnView: null,
  tablePages: {},
  tableFilters: {},
  sbomReports: [],
  evidenceReports: [],
  enrichmentReports: [],
  activeSbomId: null,
  activeSbomCveId: null,
  activeEvidenceId: null,
  assetInput: "",
  caseFilter: "",
  exposureFilter: "",
  exposurePriority: "all",
  exposureStatus: "all",
  exposureProvider: "all",
  bulkInput: "",
  bulkQueue: [],
  bulkRunning: false,
  githubRepositoryUrl: "",
  githubScan: stored.settings.find((s) => s.id === "github-review")?.scan || null,
  githubSelectedCves: stored.settings.find((s) => s.id === "github-review")?.selected || [],
  githubIssueReview: false,
  githubIssueResults: [],
  githubScanError: "",
  githubScanning: false,
  githubPublishing: false,
  enriching: false,
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
  evidenceInput: document.querySelector("#evidenceInput"),
  evidenceList: document.querySelector("#evidenceList"),
  clearLocalData: document.querySelector("#clearLocalData"),
  emptyTemplate: document.querySelector("#emptyTemplate")
};

const { renderTools, exportWorkspace, restoreWorkspace, renderResearchExtras, savePlanFromForm, reviewClaim, decideExposure, revokeDecision, removeImport, renderComparison, exportMonitorConfig } = createWorkspaceTools({ state, store, showToast, download, render, saveCurrentCase, getExposureRows, changes, focusContent, renderCases, renderWatchlist, renderSbomList, renderEvidenceList, mayLeave, attachCaseDraft, cancelImports: cancelOperations });

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
  if (state.loading) elements.button.disabled = false;
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
elements.evidenceInput?.addEventListener("change", async () => {
  await handleEvidenceFiles([...elements.evidenceInput.files]);
  elements.evidenceInput.value = "";
});

document.addEventListener("click", async (event) => {
  const action = event.target.closest("[data-action]");
  if (!action) return;

  const value = action.dataset.value;
  try {
  if (["open-watch", "open-sbom", "open-case", "open-sbom-cve-report", "open-exposures", "open-bulk", "open-github-scan", "open-evidence", "open-bulk-result", "open-tools", "return-view", "remove-import"].includes(action.dataset.action)) {
    if (!await mayLeave()) return;
    rememberCurrent();
    operations.cancel("research");
    finishResearch();
  }
  switch (action.dataset.action) {
    case "open-tools": state.current = null; state.view = "tools"; render(); break;
    case "return-view": state.current = null; state.view = state.returnView || "exposures"; render(); break;
    case "backup": await exportWorkspace(); break;
    case "download-issue": { const draft = selectedGitHubIssueDrafts().find((d) => d.cve === value); if (draft) download(`${draft.cve}-issue.md`, draft.body, "text/markdown"); break; }
    case "save-plan": await savePlanFromForm(); break;
    case "review-claim": await reviewClaim(value); break;
    case "decide-exposure": await decideExposure(value); break;
    case "revoke-decision": await revokeDecision(value); break;
    case "compare-inventories": renderComparison(); break;
    case "monitor-config": await exportMonitorConfig(); break;
    case "remove-import": removeImport(value, action.dataset.kind); break;
    case "page": state.tablePages[value] = Math.max(0, (state.tablePages[value] || 0) + Number(action.dataset.delta)); render(); break;
    case "add-repo-workspace": addRepositoryToWorkspace(); break;
    case "continue-repo": await continueRepositoryScan(); break;
    case "resume-repo": await scanGitHubRepository({ resume: true }); break;
    case "fallback-repo": await scanGitHubRepository({ fallback: true }); break;
    case "cancel-work": cancelOperations(); render(); showToast("Operations cancelled. Completed results retained. GitHub writes already sent cannot be cancelled."); break;
    case "retry-bulk": await runBulkResearch(true); break;
    case "tab":
      state.activeTab = value;
      render();
      break;
    case "refresh":
      if (state.current) research(state.current.id, { refresh: true });
      break;
    case "save":
      await saveCurrentCase();
      break;
    case "watch":
      await addCurrentToWatchlist();
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
    case "open-exposures":
      openExposureWorkspace();
      break;
    case "open-bulk":
      openBulkWorkspace();
      break;
    case "open-github-scan":
      openGitHubRepositoryWorkspace();
      break;
    case "reset-github-scan":
      resetGitHubRepositoryScan();
      break;
    case "review-github-issues":
      await reviewGitHubIssues();
      break;
    case "back-github-results":
      state.githubIssueReview = false;
      state.githubIssueResults = [];
      renderGitHubRepositoryWorkspace();
      break;
    case "publish-github-issues":
      await publishGitHubIssues();
      break;
    case "select-all-github-findings":
      selectAllGitHubFindings();
      break;
    case "open-evidence":
      openEvidenceReport(value);
      break;
    case "clear-evidence":
      clearEvidenceReports();
      break;
    case "enrich-sbom":
      await enrichActiveSbom();
      break;
    case "export-exposures":
      exportExposureCsv();
      break;
    case "research-exposure":
      research(value);
      break;
    case "run-bulk":
      await runBulkResearch();
      break;
    case "open-bulk-result":
      openBulkResult(value);
      break;
    case "clear-bulk":
      clearBulkResearch();
      break;
    case "copy-monitor-config":
      copyMonitorConfiguration();
      break;
    case "refresh-watch":
      await refreshWatch(value);
      break;
    case "remove-watch":
      await removeWatch(value);
      break;
    case "copy":
      copyBrief();
      break;
    case "copy-remediation":
      copyRemediation();
      break;
    case "copy-executive":
      copyTextBlock(caseHandoff(state.current, "Executive summary"), "Executive summary copied.");
      break;
    case "copy-ticket":
      copyTextBlock(caseHandoff(state.current, "Remediation ticket"), "Ticket export copied.");
      break;
    case "copy-risk-acceptance":
      copyTextBlock(caseHandoff(state.current, "Risk decision - local analyst record"), "Risk decision copied.");
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
      await deleteCurrentCase();
      break;
    case "open-case":
      openCase(value);
      break;
    default:
      break;
  }
  } catch (error) { showToast(error.message || "Operation failed. Existing data was retained."); }
});

document.addEventListener("change", (event) => {
  if (event.target.dataset.exposureFilter) {
    state[event.target.dataset.exposureFilter] = event.target.value;
    state.tablePages.exposures = 0;
    renderExposureWorkspace();
    return;
  }
  if (event.target.matches("#evidenceFilter")) {
    state.evidenceFilter = event.target.value;
    render();
  }
  if (event.target.matches("#evidenceSort")) {
    state.evidenceSort = event.target.value;
    render();
  }
  if (event.target.matches("#exposurePriority")) {
    state.exposurePriority = event.target.value;
    renderExposureWorkspace();
  }
  if (event.target.matches("#exposureStatus")) {
    state.exposureStatus = event.target.value;
    renderExposureWorkspace();
  }
  if (event.target.matches("#exposureProvider")) {
    state.exposureProvider = event.target.value;
    renderExposureWorkspace();
  }
  if (event.target.matches("[data-github-cve]")) {
    const cve = event.target.dataset.githubCve;
    if (event.target.checked && !state.githubSelectedCves.includes(cve) && state.githubSelectedCves.length >= 10) {
      event.target.checked = false;
      showToast("Review and publish up to 10 CVEs at a time.");
      return;
    }
    state.githubSelectedCves = event.target.checked
      ? [...new Set([...state.githubSelectedCves, cve])]
      : state.githubSelectedCves.filter((value) => value !== cve);
    updateGitHubSelectionControls();
  }
});

document.addEventListener("submit", (event) => {
  if (!event.target.matches("#githubRepositoryScanForm")) return;
  event.preventDefault();
  scanGitHubRepository();
});

document.addEventListener("input", (event) => {
  if (event.target.dataset.tableFilter) {
    const key = event.target.dataset.tableFilter;
    state.tableFilters[key] = event.target.value;
    state.tablePages[key] = 0; render();
    const next = document.querySelector(`[data-table-filter="${key}"]`);
    next?.focus(); next?.setSelectionRange(next.value.length, next.value.length);
    return;
  }
  if (event.target.closest("#remediationPlan") && state.current) {
    const values = Object.fromEntries(new FormData(event.target.closest("form")));
    state.current.caseDraft.plan = { ...(state.current.caseDraft.plan || makePlan(state.current)), ...values, sources: values.sources.split("\n").map(safeExternalUrl).filter(Boolean) };
    state.dirty = true;
    return;
  }
  if (event.target.matches("#assetInput")) {
    state.assetInput = event.target.value;
    return;
  }
  if (event.target.matches("#exposureFilter")) {
    state.tablePages.exposures = 0;
    state.exposureFilter = event.target.value.trim().toLowerCase();
    renderExposureWorkspace();
    requestAnimationFrame(() => {
      const input = document.querySelector("#exposureFilter");
      if (!input) return;
      input.focus();
      input.setSelectionRange(input.value.length, input.value.length);
    });
    return;
  }
  if (event.target.matches("#bulkCves")) {
    state.bulkInput = event.target.value;
    return;
  }
  if (event.target.matches("#githubRepositoryUrl")) {
    state.githubRepositoryUrl = event.target.value;
    return;
  }
  if (!state.current) return;
  const field = event.target.dataset.caseField;
  if (!field) return;
  const draft = getCaseDraft();
  draft[field] = event.target.value;
  state.current.caseDraft = draft;
  state.dirty = true;
  document.querySelector("#draftStatus")?.replaceChildren(document.createTextNode("Unsaved changes"));
});

window.addEventListener("beforeunload", (event) => { if (state.dirty || state.githubPublishing) { event.preventDefault(); event.returnValue = ""; } });
let restoringRoute = false;
history.replaceState(routeSnapshot(), "");
window.addEventListener("popstate", async (event) => {
  const route = event.state;
  if (!route?.view) return;
  if (!await mayLeave()) { history.pushState(routeSnapshot(), ""); return; }
  rememberCurrent(); operations.cancel("research"); finishResearch();
  restoringRoute = true;
  state.view = route.view; state.activeTab = route.tab || "overview";
  state.activeSbomId = route.sbomId; state.activeEvidenceId = route.evidenceId;
  const item = state.researchRecords[route.cve] || state.cases.find((c) => c.id === route.cve)?.investigation;
  state.current = item ? attachCaseDraft(item) : null;
  elements.input.value = state.current?.id || "";
  render(); focusContent(); restoringRoute = false;
});
if (changes) changes.onmessage = async () => {
  try {
    for (const collection of ["cases", "watchlist", "decisions", "receipts", "settings"]) state[collection] = await store.list(collection);
    renderCases(); renderWatchlist();
    showToast("Workspace changed in another tab. Reopen edited records before saving.");
  } catch (error) { showToast(error.message); }
};
document.querySelector("#restoreInput")?.addEventListener("change", async (event) => {
  try { await restoreWorkspace(event.target.files[0]); } catch (error) { showToast(error.message); }
  event.target.value = "";
});

refreshHealth();
renderCases();
renderWatchlist();
renderSbomList();
renderEvidenceList();
renderEmpty();
if (storageFailure) showToast(storageFailure);
const initialCve = normalizeCve(new URLSearchParams(globalThis.location?.search || "").get("cve"));
if (initialCve) {
  elements.input.value = initialCve;
  research(initialCve);
}

async function research(cve, options = {}) {
  const normalized = normalizeCve(cve);
  if (!normalized) return;
  if (!await mayLeave()) return;
  rememberCurrent();
  const previous = state.researchRecords[normalized] || state.cases.find((c) => c.id === normalized)?.investigation;
  state.returnView = state.view === "investigation" ? state.returnView : state.view;
  const operation = operations.start("research");
  state.loading = true;
  state.view = "investigation";
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
    const payload = await requestJson(`/api/research?cve=${encodeURIComponent(normalized)}${options.refresh ? "&refresh=1" : ""}`, { signal: operation.signal, onWait: showToast });
    if (!operation.current()) return;
    state.current = attachCaseDraft(normalizeInvestigationPayload(normalizeResearch(payload, previous)));
    rememberCurrent();
    mergeSourceHealth(payload.sourceResults);
    showToast(payload.cached ? "Loaded cached research." : "Research complete.");
    render();
    focusContent();
    renderHealth();
  } catch (error) {
    if (!operation.current()) return;
    renderError(error.message);
    focusContent();
  } finally {
    if (operation.current()) finishResearch();
  }
}

async function refreshHealth() {
  try {
    const response = await fetch("/api/health");
    const payload = await response.json();
    state.sourceHealth = (payload.sources || []).map((source) => ({
      id: source.id,
      label: source.label,
      status: source.status || (source.optional ? "optional" : "unknown"),
      message: source.message || (source.optional ? "Optional source" : "No live check yet"),
      latencyMs: source.latencyMs ?? null,
      lastCheckedAt: source.lastCheckedAt || null
    }));
    renderHealth();
  } catch {
    state.sourceHealth = [];
    renderHealth();
  }
}

function attachCaseDraft(investigation) {
  const saved = state.cases.find((item) => item.id === investigation.id);
  state.dirty = false;
  state.caseRevision = saved?.revision || 0;
  const draft = saved ? { ...saved.investigation?.caseDraft, status: saved.status, owner: saved.owner, tags: saved.tags, notes: saved.notes } : { status: "Needs triage", owner: "", tags: "", notes: "" };
  state.savedDraft = structuredClone(draft);
  return {
    ...investigation,
    caseDraft: structuredClone(draft)
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
  return investigation.clientSchemaVersion !== APP_SCHEMA_VERSION || !investigation.cloudImpact || !investigation.evidenceConfidence || !Number.isFinite(Date.parse(investigation.generatedAt)) || Date.now() - Date.parse(investigation.generatedAt) > 24 * 60 * 60 * 1000;
}

function getCaseDraft() {
  if (!state.current.caseDraft) {
    state.current.caseDraft = { status: "Needs triage", owner: "", tags: "", notes: "" };
  }
  return state.current.caseDraft;
}

async function saveCurrentCase() {
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
  let saved;
  try { saved = await store.put("cases", record, state.caseRevision); }
  catch (error) { showToast(`Not saved: ${error.message}`); return false; }
  state.caseRevision = saved.revision;
  state.cases = [saved, ...state.cases.filter((item) => item.id !== record.id)];
  state.dirty = false;
  state.savedDraft = structuredClone(draft);
  rememberCurrent();
  changes?.postMessage("cases");
  document.querySelector("#draftStatus")?.replaceChildren(document.createTextNode("Saved in this browser"));
  renderCases();
  showToast(`${state.current.id} saved to case workspace.`);
  return true;
}

async function deleteCurrentCase() {
  if (!state.current) return;
  const exists = state.cases.some((item) => item.id === state.current.id);
  if (!exists) {
    showToast("This CVE is not saved yet.");
    return;
  }
  if (!window.confirm(`Delete saved case ${state.current.id}?`)) return;
  await store.remove("cases", state.current.id, state.caseRevision);
  state.cases = state.cases.filter((item) => item.id !== state.current.id);
  state.caseRevision = 0;
  state.dirty = false;
  changes?.postMessage("cases");
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
  state.view = "investigation";
  state.activeSbomId = null;
  state.activeSbomCveId = null;
  state.activeTab = "overview";
  elements.input.value = record.id;
  render();
  showToast(isStaleInvestigation(record.investigation) ? `${record.id} loaded. Refresh to update latest research fields.` : `${record.id} loaded.`);
}

async function addCurrentToWatchlist() {
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
  const saved = await store.put("watchlist", record, existing?.revision || 0);
  state.watchlist = [saved, ...state.watchlist.filter((item) => item.id !== record.id)];
  changes?.postMessage("watchlist");
  renderWatchlist();
  if (state.current?.id === record.id && state.activeTab === "watchlist") render();
  showToast(`${record.id} added to watchlist.`);
}

function openWatch(id) {
  const record = state.watchlist.find((item) => item.id === id);
  if (!record) return;
  state.current = attachCaseDraft(record.investigation);
  state.view = "investigation";
  state.activeSbomId = null;
  state.activeSbomCveId = null;
  state.activeTab = "watchlist";
  elements.input.value = record.id;
  render();
}

async function refreshWatch(id, operation = operations.start("watch")) {
  const record = state.watchlist.find((item) => item.id === id);
  if (!record) return;
  showToast(`Refreshing ${id}...`);
  let payload;
  try {
    payload = await requestJson(`/api/research?cve=${encodeURIComponent(id)}&refresh=1`, { signal: operation.signal, onWait: showToast });
    if (!operation.current()) return;
  } catch (error) {
    showToast(`Unable to refresh ${id}: ${error.message || "network error"}.`);
    return;
  }
  payload = normalizeInvestigationPayload(normalizeResearch(payload, record.investigation));
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
  const saved = await store.put("watchlist", updated, record.revision);
  if (!operation.current()) return;
  state.watchlist = state.watchlist.map((item) => item.id === id ? saved : item);
  state.researchRecords[id] = payload;
  changes?.postMessage("watchlist");
  renderWatchlist();
  if (state.current?.id === id && !state.dirty) {
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
  const operation = operations.start("watch");
  try {
    for (const [index, item] of [...state.watchlist].entries()) {
      if (!operation.current()) break;
      if (index) await pause(10500, operation.signal);
      await refreshWatch(item.id, operation);
    }
  } catch (error) { if (error.name !== "AbortError") showToast(error.message); }
}

async function removeWatch(id) {
  if (!window.confirm(`Remove ${id} from the watchlist?`)) return;
  await store.remove("watchlist", id, state.watchlist.find((item) => item.id === id)?.revision);
  state.watchlist = state.watchlist.filter((item) => item.id !== id);
  changes?.postMessage("watchlist");
  renderWatchlist();
  if (state.current?.id === id && state.activeTab === "watchlist") render();
  showToast(`${id} removed from watchlist.`);
}

async function handleSbomFiles(files) {
  if (!files.length) return;
  if (state.sbomReports.length >= 30) { showToast("30 inventory batches are loaded. Remove a selected batch before importing more."); return; }
  const epoch = operations.epoch;
  showToast("Parsing SBOM files in a bounded background worker...");
  const currentInvestigation = state.current;
  const originalView = state.view;
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

  const readable = [];
  for (const file of accepted) {
    try {
      readable.push({ file, text: await file.text() });
    } catch (error) {
      warnings.push(`${file.name} could not be read: ${error.message || "browser file read failed"}.`);
    }
  }

  let report;
  try {
    report = await parseSbomsInBackground(readable);
    if (epoch !== operations.epoch) return;
    if (!report) throw new Error("No SBOM files were processed.");
    report.warnings = [...warnings, ...(report.warnings || [])];
    reviewSuppressiveVexClaims(report.cves.flatMap((entry) => entry.affectedPackages.flatMap((pkg) => pkg.vexClaims || [])), "the uploaded SBOM");
    applySbomVexDecisions(report);
  } catch (error) {
    showToast(error.message || "SBOM import failed. Existing data was preserved.");
    return;
  }
  const currentCveMatch = currentInvestigation?.id && report.cves.some((entry) => entry.id === currentInvestigation.id);
  state.sbomReports = [report, ...state.sbomReports];
  state.activeSbomId = report.id;
  state.activeSbomCveId = currentCveMatch ? currentInvestigation.id : report.cves[0]?.id || null;
  if (state.current === currentInvestigation && state.view === originalView) {
    state.view = currentInvestigation ? "investigation" : "sbom";
  }
  renderCases();
  renderSbomList();
  render();
  focusContent();
  showToast(currentCveMatch ? `${currentInvestigation.id} found in the uploaded SBOM.` : `Parsed ${report.files.length} SBOM file${report.files.length === 1 ? "" : "s"} with ${report.cves.length} CVE finding${report.cves.length === 1 ? "" : "s"}.`);
}

async function parseSbomsInBackground(files) {
  if (!files.length) return null;
  if (typeof Worker === "undefined") throw new Error("SBOM import requires browser worker support.");
  const id = crypto.randomUUID();
  let worker;
  let timeout;
  try {
    worker = new Worker("/generated/sbom-worker.js", { type: "module" });
    return await new Promise((resolve, reject) => {
      timeout = setTimeout(() => reject(new Error("SBOM processing timed out. Split the inventory and retry.")), 20000);
      worker.addEventListener("message", (event) => {
        if (event.data?.id !== id) return;
        clearTimeout(timeout);
        if (event.data.ok && event.data.report) resolve(event.data.report);
        else reject(new Error(event.data.message || "SBOM processing failed."));
      });
      worker.addEventListener("error", () => {
        clearTimeout(timeout);
        reject(new Error("SBOM worker failed. Rebuild client assets and retry."));
      }, { once: true });
      worker.postMessage({ id, files: files.map(({ file, text }) => ({ name: file.name, size: file.size, text })) });
    });
  } finally { clearTimeout(timeout); worker?.terminate(); }
}

function openSbom(id) {
  const report = state.sbomReports.find((item) => item.id === id);
  if (!report) return;
  state.activeSbomId = id;
  state.view = "sbom";
  state.activeSbomCveId = report.cves.some((entry) => entry.id === state.activeSbomCveId) ? state.activeSbomCveId : report.cves[0]?.id || null;
  state.current = null;
  elements.input.value = "";
  renderCases();
  render();
  renderSbomList();
}

function clearSboms() {
  if (!window.confirm("Remove all loaded SBOMs and their enrichment results? Export a workspace backup first if needed.")) return;
  cancelOperations();
  if (!state.sbomReports.length) {
    showToast("No SBOM uploads to clear.");
    return;
  }
  state.sbomReports = [];
  state.enrichmentReports = [];
  state.activeSbomId = null;
  state.activeSbomCveId = null;
  renderCases();
  renderSbomList();
  render();
  showToast("SBOM uploads cleared from this browser session.");
}

async function handleEvidenceFiles(files) {
  if (!files.length) return;
  if (!await mayLeave()) return;
  rememberCurrent();
  const epoch = operations.epoch;
  const originalCurrent = state.current;
  const originalView = state.view;
  const warnings = [];
  const readable = [];
  let totalBytes = 0;
  for (const file of files.slice(0, SBOM_MAX_FILES)) {
    if (file.size > SBOM_MAX_FILE_BYTES) {
      warnings.push(`${file.name} was skipped because it is larger than ${formatBytes(SBOM_MAX_FILE_BYTES)}.`);
      continue;
    }
    if (totalBytes + file.size > SBOM_MAX_TOTAL_BYTES) {
      warnings.push(`${file.name} was skipped because the selected evidence batch is larger than ${formatBytes(SBOM_MAX_TOTAL_BYTES)}.`);
      continue;
    }
    totalBytes += file.size;
    try {
      readable.push({ file, text: await file.text() });
    } catch (error) {
      warnings.push(`${file.name} could not be imported: ${error.message || "browser file read failed"}.`);
    }
  }
  if (files.length > SBOM_MAX_FILES) warnings.push(`Only the first ${SBOM_MAX_FILES} evidence files were processed.`);
  const background = await parseEvidenceInBackground(readable);
  if (epoch !== operations.epoch) return;
  const reports = background?.results || [];
  if (background?.truncated) warnings.push("The evidence batch reached the 50,000-record safety limit; remaining files were not processed.");
  if (!background && readable.length) warnings.push("Evidence parsing timed out or the browser worker was unavailable. No files were reparsed on the main thread.");
  if (!reports.length) {
    showToast(warnings[0] || "No evidence files were imported.");
    return;
  }
  if (warnings.length) reports[0].warnings = [...warnings, ...(reports[0].warnings || [])];
  reviewSuppressiveVexClaims(reports.flatMap((report) => report.vexStatements || []), "the imported VEX evidence");
  if (state.evidenceReports.length + reports.length > 30) { showToast("Evidence capacity reached. Remove selected imports before adding more."); return; }
  state.evidenceReports = [...reports, ...state.evidenceReports];
  state.activeEvidenceId = reports[0].id;
  if (state.current === originalCurrent && state.view === originalView) {
    state.view = "evidence";
    state.current = null;
    state.activeSbomId = null;
    elements.input.value = "";
  }
  renderEvidenceList();
  render();
  focusContent();
  const findingCount = reports.reduce((count, report) => count + report.findings.length, 0);
  const vexCount = reports.reduce((count, report) => count + report.vexStatements.length, 0);
  showToast(`Imported ${reports.length} evidence file${reports.length === 1 ? "" : "s"}: ${findingCount} findings and ${vexCount} VEX statements.`);
}

async function parseEvidenceInBackground(files) {
  if (!files.length || typeof Worker === "undefined") return null;
  const id = globalThis.crypto?.randomUUID?.() || `evidence-${Date.now()}`;
  const worker = new Worker("/evidence-worker.js", { type: "module" });
  try {
    return await new Promise((resolve) => {
      const timeout = setTimeout(() => resolve(null), 30000);
      worker.addEventListener("message", (event) => {
        if (event.data?.id !== id) return;
        clearTimeout(timeout);
        resolve(event.data.ok ? { results: event.data.results, truncated: event.data.truncated } : null);
      }, { once: true });
      worker.addEventListener("error", () => {
        clearTimeout(timeout);
        resolve(null);
      }, { once: true });
      worker.postMessage({
        id,
        files: files.map(({ file, text }) => ({ name: file.name, size: file.size, text }))
      });
    });
  } finally {
    worker.terminate();
  }
}

function reviewSuppressiveVexClaims(statements, sourceLabel) {
  const suppressive = statements.filter((statement) => ["Not affected", "Fixed"].includes(statement.status));
  for (const statement of suppressive) {
    statement.trusted = false;
    statement.approvedAt = null;
    statement.trustReason = `Unverified claim from ${sourceLabel}; record a target-scoped decision in Exposures.`;
  }
}

function openEvidenceReport(id) {
  if (!state.evidenceReports.some((report) => report.id === id)) return;
  state.activeEvidenceId = id;
  state.view = "evidence";
  state.current = null;
  state.activeSbomId = null;
  elements.input.value = "";
  render();
  renderEvidenceList();
}

function clearEvidenceReports() {
  if (!window.confirm("Remove all imported cloud and VEX evidence?")) return;
  if (!state.evidenceReports.length) {
    showToast("No imported evidence to clear.");
    return;
  }
  cancelOperations();
  state.evidenceReports = [];
  state.activeEvidenceId = null;
  renderEvidenceList();
  if (state.view === "evidence" || state.view === "exposures") openExposureWorkspace();
  showToast("Imported evidence cleared.");
}

function renderEvidenceList() {
  if (!elements.evidenceList) return;
  if (!state.evidenceReports.length) {
    elements.evidenceList.innerHTML = `<div class="empty-list">No cloud or VEX evidence loaded.</div>`;
    return;
  }
  elements.evidenceList.innerHTML = `${state.evidenceReports.map((report) => `
    <button class="case-card ${state.activeEvidenceId === report.id ? "active" : ""}" type="button" data-action="open-evidence" data-value="${escapeAttr(report.id)}">
      <strong>${escapeHtml(report.fileName)}</strong>
      <span>${escapeHtml(report.format)}</span>
      <div class="case-meta">
        <span>${report.findings.length} findings</span>
        <span>${report.assets.length} assets</span>
        <span>${report.vexStatements.length} VEX</span>
      </div>
    </button>
    <button class="sidebar-text-button" type="button" data-action="remove-import" data-kind="evidence" data-value="${escapeAttr(report.id)}">Remove ${escapeHtml(report.fileName)}</button>
  `).join("")}
    <button class="sidebar-text-button" type="button" data-action="clear-evidence">Clear imported evidence</button>`;
}

async function enrichActiveSbom() {
  const report = getActiveSbomReport();
  if (!report) return;
  const inventory = dedupeBy(report.components.map((component) => ({
    purl: component.purl,
    ecosystem: inferOsvEcosystem(component),
    name: component.name,
    version: component.version || parsedPackage(component.purl)?.version || "",
    fileName: component.fileName
  })), packageKey);
  const previous = state.enrichmentReports.find((r) => r.sbomId === report.id);
  const pending = previous?.pending || inventory;
  const packages = pending.filter((pkg) => pkg.version && (pkg.purl || (pkg.ecosystem && pkg.name))).slice(0, 50).map((pkg) => {
    const old = previous?.packages?.find((p) => packageKey(p) === packageKey(pkg));
    return { ...pkg, pageToken: old?.nextDetailOffset != null ? old.pageToken : old?.nextPageToken, detailOffset: old?.nextDetailOffset || 0 };
  });
  if (!packages.length) {
    showToast("No package URLs or ecosystem package versions were available for online enrichment.");
    return;
  }
  if (!window.confirm(`Online enrichment will send ${packages.length} package identifier${packages.length === 1 ? "" : "s"} to OSV. The SBOM file and unrelated metadata remain in this browser. Continue?`)) return;
  const operation = operations.start("enrich");
  state.enriching = true;
  render();
  try {
    const payload = await requestJson("/api/enrich", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ packages }), signal: operation.signal, onWait: showToast
    });
    if (!operation.current()) return;
    const enrichment = {
      id: `enrichment-${report.id}`,
      sbomId: report.id,
      title: report.title,
      ...mergeEnrichment(previous, payload, inventory)
    };
    state.enrichmentReports = [enrichment, ...state.enrichmentReports.filter((item) => item.sbomId !== report.id)];
    mergeSourceHealth(payload.sourceResults);
    showToast(`Enrichment ${payload.status || "partial"}: ${payload.vulnerabilityCount ?? "unknown"} vulnerability records.`);
  } catch (error) {
    showToast(error.message || "Package enrichment failed.");
  } finally {
    if (operation.current()) { state.enriching = false; render(); }
  }
}

function inferOsvEcosystem(component) {
  const type = String(component?.purl || "").match(/^pkg:([^/]+)\//i)?.[1]?.toLowerCase() || String(component?.type || "").toLowerCase();
  return {
    pypi: "PyPI",
    npm: "npm",
    maven: "Maven",
    nuget: "NuGet",
    cargo: "crates.io",
    gem: "RubyGems",
    golang: "Go",
    composer: "Packagist",
    pub: "Pub",
    hex: "Hex"
  }[type] || "";
}

function openExposureWorkspace() {
  rememberCurrent();
  state.view = "exposures";
  state.current = null;
  state.activeSbomId = null;
  state.activeEvidenceId = null;
  elements.input.value = "";
  render();
  renderSbomList();
  renderEvidenceList();
}

function getExposureRows() {
  const investigations = [
    ...state.cases.map((item) => item.investigation),
    ...state.watchlist.map((item) => item.investigation),
    ...state.bulkQueue.map((item) => item.investigation),
    ...Object.values(state.researchRecords),
    state.current
  ].filter(Boolean);
  return applyDecisions(buildExposureRows({
    sbomReports: state.sbomReports,
    evidenceReports: state.evidenceReports,
    enrichmentReports: state.enrichmentReports,
    investigations: investigations.sort((a, b) => Date.parse(a.generatedAt || 0) - Date.parse(b.generatedAt || 0))
  }), state.decisions);
}

function filteredExposureRows() {
  return getExposureRows().filter((row) => {
    const text = [row.vulnerability, row.packageName, row.installedVersion, row.assetName, row.assetId, row.provider, row.source, row.vexStatus, row.owner].join(" ").toLowerCase();
    if (state.exposureFilter && !text.includes(state.exposureFilter)) return false;
    if (state.exposurePriority !== "all" && row.priority !== state.exposurePriority) return false;
    if (state.exposureStatus !== "all" && row.vexStatus !== state.exposureStatus) return false;
    if (state.exposureProvider !== "all" && row.provider !== state.exposureProvider) return false;
    if (state.exposureSource !== "all" && row.source !== state.exposureSource) return false;
    if (state.exposureSeverity !== "all" && row.severity !== state.exposureSeverity) return false;
    if (state.exposureWorkflow !== "all" && row.workflowStatus !== state.exposureWorkflow) return false;
    return true;
  });
}

function renderExposureWorkspace() {
  const allRows = getExposureRows();
  const rows = filteredExposureRows();
  const summary = summarizeExposureRows(allRows);
  const providers = uniqueValues(allRows.map((row) => row.provider).filter(Boolean));
  elements.content.innerHTML = `
    <article class="investigation exposure-workspace">
      <section class="brief-header">
        <div class="brief-title">
          <div class="badge-row">
            <span class="badge">Exposure workspace</span>
            <span class="badge">${summary.vulnerabilities} vulnerabilities</span>
            <span class="badge">${summary.assets} assets</span>
          </div>
          <h2>Prioritized software exposure</h2>
          <p>Consolidated SBOM, OSV, cloud finding, VEX, and saved investigation evidence. VEX statements affect prioritization but remain visible for auditability.</p>
        </div>
        <div class="header-actions">
          <label class="secondary-button" for="sbomInput">Upload SBOM</label>
          <label class="secondary-button" for="evidenceInput">Import evidence</label>
          <button class="secondary-button" type="button" data-action="export-exposures" ${allRows.length ? "" : "disabled"}>Export CSV</button>
        </div>
      </section>

      <section class="metric-grid" aria-label="Exposure metrics">
        <div class="metric-card"><div class="metric-label">Exposure rows</div><div class="metric-value">${summary.total}</div><div class="metric-detail">Packages and assets</div></div>
        <div class="metric-card"><div class="metric-label">Critical priority</div><div class="metric-value">${summary.critical}</div><div class="metric-detail">Active exposure records</div></div>
        <div class="metric-card"><div class="metric-label">Known exploited</div><div class="metric-value">${summary.knownExploited}</div><div class="metric-detail">CISA KEV matches</div></div>
        <div class="metric-card"><div class="metric-label">VEX resolved</div><div class="metric-value">${summary.notAffected + summary.fixed}</div><div class="metric-detail">Not affected or fixed</div></div>
      </section>

      <section class="panel">
        <div class="exposure-filters">
          <div>
            <label class="field-label" for="exposureFilter">Search exposures</label>
            <input id="exposureFilter" class="input" type="search" value="${escapeAttr(state.exposureFilter)}" placeholder="CVE, package, asset, owner">
          </div>
          <div>
            <label class="field-label" for="exposurePriority">Priority</label>
            <select id="exposurePriority" class="select">
              ${selectOptions(["all", "Critical", "High", "Medium", "Low", "Unknown"], state.exposurePriority, "All priorities")}
            </select>
          </div>
          <div>
            <label class="field-label" for="exposureStatus">VEX status</label>
            <select id="exposureStatus" class="select">
              ${selectOptions(["all", "Affected", "Under investigation", "Not affected", "Fixed", "Unreviewed", "Unknown", "Needs verification"], state.exposureStatus, "All VEX states")}
            </select>
          </div>
          <div>
            <label class="field-label" for="exposureProvider">Provider</label>
            <select id="exposureProvider" class="select">
              ${selectOptions(["all", ...providers], state.exposureProvider, "All providers")}
            </select>
          </div>
        </div>
      </section>

      <section class="panel">
        <div class="panel-title-row">
          <div>
            <h3>Exposure register</h3>
            <p>${rows.length} matching records of ${allRows.length}. Package-version matches require deployment validation.</p>
          </div>
        </div>
        ${[ ["Source", "exposureSource", "source"], ["Severity", "exposureSeverity", "severity"], ["Workflow", "exposureWorkflow", "workflowStatus"] ].map(([label, key, field]) => `<label class="inline-filter">${label}<select data-exposure-filter="${key}" class="select">${selectOptions(["all", ...uniqueValues(allRows.map((r) => r[field]).filter(Boolean))], state[key], "All")}</select></label>`).join("")}
        ${renderExposureTable(rows)}
      </section>
      ${renderUnlinkedResearch(allRows)}
    </article>
  `;
}

function renderExposureTable(rows) {
  if (!rows.length) {
    return `<div class="workspace-empty"><strong>No matching exposure records</strong><p>Upload an SBOM, import cloud findings, enrich packages, or adjust the filters.</p></div>`;
  }
  return `
    ${pager("exposures", rows.length, 100)}
    <div class="table-wrap">
      <table class="exposure-table">
        <thead><tr><th>Priority</th><th>Vulnerability</th><th>Package / Asset</th><th>Version / Fix</th><th>Evidence</th><th>VEX</th><th>Action</th></tr></thead>
        <tbody>
          ${pageRows("exposures", rows, 100).map((row) => `
            <tr>
              <td><span class="risk-badge risk-${escapeAttr(row.priority)}">${escapeHtml(row.priority)} ${row.priorityScore ?? ""}</span></td>
              <td><strong>${escapeHtml(row.vulnerability)}</strong><br><span class="muted-cell">${escapeHtml(row.severity || "Unknown")} ${row.kev ? "- KEV" : ""}${row.epss !== null ? ` - EPSS ${formatPercent(row.epss)}` : ""}</span></td>
              <td><strong>${escapeHtml(row.packageName || row.assetName || "Unmapped")}</strong><br><span class="muted-cell">${escapeHtml(row.assetName || row.assetId || row.sourceFile || row.source)} ${escapeHtml([row.account, row.region].filter(Boolean).join(" / "))}</span></td>
              <td>${escapeHtml(row.installedVersion || "n/a")}${row.fixedVersions?.length ? `<br><span class="fixed-version" title="${escapeAttr(row.fixProvenance?.map((item) => `${item.package}: ${item.version}`).join("; ") || "OSV package-specific fix candidates")}">Fix: ${escapeHtml(row.fixedVersions.join(" or "))}</span>` : ""}</td>
              <td>${escapeHtml(row.provider || row.source)}<br><span class="muted-cell">${escapeHtml(row.exploitStatus || "Unknown")}</span></td>
              <td><span class="vex-badge vex-${escapeAttr(classToken(row.vexStatus))}">${escapeHtml(row.vexStatus)}</span><br><span class="muted-cell" title="${escapeAttr(row.vexTrustReason)}">${row.vexTrusted ? "Analyst approved" : `Unverified claim: ${escapeHtml(row.vexClaimedStatus)}`}</span>${row.vexJustification ? `<br><span class="muted-cell" title="${escapeAttr(row.vexJustification)}">${escapeHtml(row.vexJustification.slice(0, 90))}</span>` : ""}</td>
              <td>${/^CVE-\d{4}-\d{4,}$/.test(row.vulnerability) ? `<button class="secondary-button table-button" type="button" data-action="research-exposure" data-value="${escapeAttr(row.vulnerability)}">Research</button>` : `<span class="muted-cell">Advisory only</span>`}<button class="secondary-button table-button" data-action="decide-exposure" data-value="${escapeAttr(occurrenceKey(row))}">Decision / plan</button></td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    </div>
    ${pager("exposures", rows.length, 100)}
  `;
}

function selectOptions(values, selected, allLabel) {
  return values.map((value) => `<option value="${escapeAttr(value)}" ${value === selected ? "selected" : ""}>${escapeHtml(value === "all" ? allLabel : value)}</option>`).join("");
}

function exportExposureCsv() {
  const rows = filteredExposureRows();
  if (!rows.length) {
    showToast("No exposure rows to export.");
    return;
  }
  const headers = ["Priority", "Score", "Vulnerability", "Severity", "KEV", "EPSS", "Package", "Installed Version", "Fixed Version", "Provider", "Asset ID", "Asset Name", "Source", "VEX Status", "VEX Claimed Status", "VEX Trust", "VEX Justification", "Owner", "Workflow Status", "Package URL", "Account", "Region"];
  const values = rows.map((row) => [row.priority, row.priorityScore, row.vulnerability, row.severity, row.kev ?? "Unknown", row.epss ?? "", row.packageName, row.installedVersion, row.fixedVersions?.join(" or ") || row.fixedVersion, row.provider, row.assetId, row.assetName, row.source, row.vexStatus, row.vexClaimedStatus, row.vexTrusted ? row.vexTrustReason : `Unverified: ${row.vexTrustReason}`, row.vexJustification, row.owner, row.workflowStatus, row.purl, row.account, row.region]);
  download("vulnscope-exposure-register.csv", [headers, ...values].map((record) => record.map(csvCell).join(",")).join("\n"), "text/csv");
}

function openBulkWorkspace() {
  state.view = "bulk";
  state.current = null;
  state.activeSbomId = null;
  state.activeEvidenceId = null;
  elements.input.value = "";
  render();
}

function renderBulkWorkspace() {
  const complete = state.bulkQueue.filter((item) => item.status === "Complete").length;
  const failed = state.bulkQueue.filter((item) => item.status === "Failed").length;
  elements.content.innerHTML = `
    <article class="investigation bulk-workspace">
      <section class="brief-header">
        <div class="brief-title">
          <div class="badge-row">
            <span class="badge">Bulk research</span>
            <span class="badge">Maximum 25 CVEs</span>
          </div>
          <h2>Research a CVE campaign</h2>
          <p>Paste CVE identifiers from scanner output, a ticket, or an advisory. VulnScope validates, deduplicates, and researches them sequentially to protect upstream sources.</p>
        </div>
        <div class="header-actions">
          <button class="secondary-button" type="button" data-action="copy-monitor-config">Monitor configuration</button>
          <button class="secondary-button" type="button" data-action="clear-bulk" ${state.bulkQueue.length && !state.bulkRunning ? "" : "disabled"}>Clear results</button>
          <button class="secondary-button" type="button" data-action="retry-bulk" ${state.bulkQueue.some((r) => r.status !== "Complete") && !state.bulkRunning ? "" : "disabled"}>Retry remaining</button>
        </div>
      </section>

      <section class="panel bulk-input-panel">
        <label class="field-label" for="bulkCves">CVE list</label>
        <textarea id="bulkCves" class="textarea" placeholder="CVE-2021-44228\nCVE-2024-3094\nCVE-2023-22527" ${state.bulkRunning ? "disabled" : ""}>${escapeHtml(state.bulkInput)}</textarea>
        <div class="panel-title-row bulk-run-row">
          <p>Only valid CVE identifiers are queued. Duplicate identifiers are removed.</p>
          <button class="primary-button" type="button" data-action="run-bulk" ${state.bulkRunning ? "disabled" : ""}>${state.bulkRunning ? "Researching..." : "Run research queue"}</button>
        </div>
      </section>

      <section class="metric-grid" aria-label="Bulk research progress">
        <div class="metric-card"><div class="metric-label">Queued</div><div class="metric-value">${state.bulkQueue.length}</div><div class="metric-detail">Unique CVEs</div></div>
        <div class="metric-card"><div class="metric-label">Complete</div><div class="metric-value">${complete}</div><div class="metric-detail">Research records</div></div>
        <div class="metric-card"><div class="metric-label">Failed</div><div class="metric-value">${failed}</div><div class="metric-detail">Retry individually</div></div>
        <div class="metric-card"><div class="metric-label">Progress</div><div class="metric-value">${state.bulkQueue.length ? Math.round(((complete + failed) / state.bulkQueue.length) * 100) : 0}%</div><div class="metric-detail">Current queue</div></div>
      </section>

      <section class="panel">
        <div class="panel-title-row"><div><h3>Campaign results</h3><p>Completed records feed the exposure workspace and can be opened as full investigations.</p></div></div>
        ${renderBulkResults()}
      </section>
    </article>
  `;
}

function renderBulkResults() {
  if (!state.bulkQueue.length) return `<div class="workspace-empty"><strong>No campaign is queued</strong><p>Paste one or more CVE identifiers above to begin.</p></div>`;
  return `
    <div class="table-wrap">
      <table>
        <thead><tr><th>CVE</th><th>Status</th><th>Risk</th><th>KEV / EPSS</th><th>Real-world verdict</th><th>Action</th></tr></thead>
        <tbody>${state.bulkQueue.map((item) => `
          <tr>
            <td><strong>${escapeHtml(item.id)}</strong></td>
            <td><span class="badge">${escapeHtml(item.status)}</span>${item.error ? `<br><span class="muted-cell">${escapeHtml(item.error)}</span>` : ""}</td>
            <td>${item.investigation ? `${escapeHtml(item.investigation.risk?.level || "Unknown")} ${item.investigation.risk?.score ?? ""}` : "n/a"}</td>
            <td>${escapeHtml(kevLabel(item.investigation))}${item.investigation?.metrics?.epss?.epss !== null && item.investigation?.metrics?.epss?.epss !== undefined ? `<br><span class="muted-cell">EPSS ${formatPercent(item.investigation.metrics.epss.epss)}</span>` : ""}</td>
            <td>${escapeHtml(item.investigation?.realWorld?.verdict || "Pending")}</td>
            <td><button class="secondary-button table-button" type="button" data-action="open-bulk-result" data-value="${escapeAttr(item.id)}" ${item.investigation ? "" : "disabled"}>Open</button></td>
          </tr>
        `).join("")}</tbody>
      </table>
    </div>
  `;
}

async function runBulkResearch(retryOnly = false) {
  if (state.bulkRunning) return;
  const allCves = uniqueValues(extractCves(state.bulkInput));
  const cves = allCves.slice(0, 25);
  if (!retryOnly && allCves.length > 25) { showToast(`Queue limit is 25. Remove these additional IDs before running: ${allCves.slice(25).join(", ")}`); return; }
  if (!cves.length) {
    showToast("Paste at least one valid CVE identifier.");
    return;
  }
  if (!retryOnly) state.bulkQueue = cves.map((id) => ({ id, status: "Queued", investigation: null, error: "" }));
  const operation = operations.start("bulk");
  state.bulkRunning = true;
  if (state.view === "bulk") renderBulkWorkspace();
  for (const item of state.bulkQueue) {
    if (!operation.current()) break;
    if (retryOnly && item.status === "Complete") continue;
    item.status = "Researching";
    if (state.view === "bulk") renderBulkWorkspace();
    try {
      const payload = await requestJson(`/api/research?cve=${encodeURIComponent(item.id)}`, { signal: operation.signal, onWait: showToast });
      if (!operation.current()) break;
      item.investigation = normalizeInvestigationPayload(normalizeResearch(payload, state.researchRecords[item.id]));
      state.researchRecords[item.id] = item.investigation;
      item.status = "Complete";
    } catch (error) {
      if (!operation.current()) { item.status = "Cancelled"; break; }
      item.status = "Failed";
      item.error = error.message || "Research failed.";
    }
    if (state.view === "bulk") renderBulkWorkspace();
  }
  if (!operation.current()) return;
  state.bulkRunning = false;
  if (state.view === "bulk") renderBulkWorkspace();
  showToast(`Bulk research completed: ${state.bulkQueue.filter((item) => item.status === "Complete").length} of ${state.bulkQueue.length} records loaded.`);
}

function openBulkResult(id) {
  const item = state.bulkQueue.find((entry) => entry.id === id);
  if (!item?.investigation) return;
  state.current = attachCaseDraft(item.investigation);
  state.view = "investigation";
  state.activeSbomId = null;
  state.activeEvidenceId = null;
  state.activeTab = "overview";
  elements.input.value = id;
  render();
}

function clearBulkResearch() {
  if (state.bulkRunning) return;
  state.bulkQueue = [];
  state.bulkInput = "";
  renderBulkWorkspace();
  showToast("Bulk research results cleared.");
}

function openGitHubRepositoryWorkspace() {
  state.view = "github";
  state.current = null;
  state.activeSbomId = null;
  state.activeEvidenceId = null;
  elements.input.value = "";
  render();
}

function resetGitHubRepositoryScan() {
  state.githubScan = null;
  state.githubSelectedCves = [];
  state.githubIssueReview = false;
  state.githubIssueResults = [];
  state.githubScanError = "";
  renderGitHubRepositoryWorkspace();
}

async function scanGitHubRepository(options = {}) {
  if (state.githubScanning) return;
  const url = String(document.querySelector("#githubRepositoryUrl")?.value || state.githubRepositoryUrl).trim();
  state.githubRepositoryUrl = url;
  state.githubScanError = "";
  if (!/^https:\/\/github\.com\/[a-z0-9-]+\/[a-z0-9._-]+(?:\.git)?\/?$/i.test(url)) {
    state.githubScanError = "Enter a public repository URL such as https://github.com/owner/repository.";
    renderGitHubRepositoryWorkspace();
    document.querySelector("#githubRepositoryUrl")?.focus();
    return;
  }
  state.githubScanning = true;
  const previousScan = options.resume ? state.githubScan : null;
  state.githubScan = null;
  const operation = operations.start("github-scan");
  state.githubSelectedCves = [];
  state.githubIssueReview = false;
  state.githubIssueResults = [];
  renderGitHubRepositoryWorkspace();
  try {
    let jobId = previousScan?.jobId;
    let payload;
    for (let poll = 0; poll < 6; poll++) {
      payload = await requestJson("/api/github/scan", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ url, jobId, inventoryMethod: options.fallback ? "lockfiles" : undefined }), signal: operation.signal, onWait: showToast });
      if (!operation.current()) return;
      if (payload.status !== "pending") break;
      jobId = payload.jobId;
      state.githubScan = { ...payload, findings: [] };
      if (state.view === "github") renderGitHubRepositoryWorkspace();
      await pause(2000, operation.signal);
    }
    state.githubScan = {
      ...payload,
      findings: buildRepositoryCveFindings(payload)
    };
    mergeSourceHealth(payload.sourceResults);
    showToast(payload.status === "failed" ? "Repository scan failed. CVE results are unknown; review coverage and retry." : `Repository scan ${payload.status || "partial"}: ${state.githubScan.findings.length} returned CVE matches. Check coverage before drawing conclusions.`);
  } catch (error) {
    if (!operation.current()) return;
    state.githubScanError = error.message || "Repository scan failed.";
  } finally {
    if (operation.current()) { state.githubScanning = false; if (state.view === "github") { renderGitHubRepositoryWorkspace(); focusContent(); } }
  }
}

async function reviewGitHubIssues() {
  const findings = state.githubScan?.findings || [];
  state.githubSelectedCves = state.githubSelectedCves.filter((cve) => findings.some((finding) => finding.cve === cve)).slice(0, 10);
  if (!state.githubSelectedCves.length) {
    showToast("Select at least one CVE to review.");
    return;
  }
  state.githubIssueReview = true;
  const prior = state.settings.find((s) => s.id === "github-review");
  const saved = await store.put("settings", { id: "github-review", scan: state.githubScan, selected: state.githubSelectedCves, confirmedAt: new Date().toISOString() }, prior?.revision || 0);
  state.settings = [saved, ...state.settings.filter((s) => s.id !== saved.id)];
  changes?.postMessage("settings");
  state.githubIssueResults = [];
  renderGitHubRepositoryWorkspace();
  focusContent();
}

function selectAllGitHubFindings() {
  const all = (state.githubScan?.findings || []).filter((finding) => !finding.withdrawn).slice(0, 10).map((finding) => finding.cve);
  state.githubSelectedCves = all.every((cve) => state.githubSelectedCves.includes(cve)) ? [] : all;
  renderGitHubRepositoryWorkspace();
}

function updateGitHubSelectionControls() {
  const count = state.githubSelectedCves.length;
  const reviewButton = document.querySelector("[data-action='review-github-issues']");
  if (reviewButton) {
    reviewButton.disabled = count === 0;
    reviewButton.textContent = count ? `Review ${count} issue${count === 1 ? "" : "s"}` : "Review selected";
  }
  document.querySelectorAll("[data-github-cve]").forEach((checkbox) => {
    checkbox.disabled = checkbox.dataset.githubWithdrawn === "true" || (count >= 10 && !checkbox.checked);
  });
}

async function publishGitHubIssues() {
  if (state.githubPublishing || !state.githubScan?.repository) return;
  const tokenInput = document.querySelector("#githubIssueToken");
  const consent = document.querySelector("#githubIssueConsent");
  const token = String(tokenInput?.value || "").trim();
  if (!state.githubScan.repository.issuesEnabled) {
    showToast("GitHub Issues are disabled for this repository.");
    return;
  }
  if (!consent?.checked) {
    showToast("Confirm the reviewed CVE matches before publishing issues.");
    consent?.focus();
    return;
  }
  if (token.length < 20 || token.length > 500 || /\s/.test(token)) {
    showToast("Enter a valid fine-grained GitHub token with Issues write permission.");
    tokenInput?.focus();
    return;
  }
  const drafts = selectedGitHubIssueDrafts();
  if (!drafts.length) return;
  if (!window.confirm(`Publish ${drafts.length} reviewed issue${drafts.length === 1 ? "" : "s"} in ${state.githubScan.repository.fullName}? Any existing CVE issue will require your choice before reuse.`)) return;

  state.githubPublishing = true;
  state.githubIssueResults = [];
  renderGitHubRepositoryWorkspace();
  const repository = state.githubScan.repository;
  for (const draft of drafts) {
    let receipt;
    let attemptedWrite = false;
    try {
      const bytes = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(JSON.stringify([repository.fullName, draft.cve, draft.body])));
      const digest = [...new Uint8Array(bytes)].map((n) => n.toString(16).padStart(2, "0")).join("");
      const id = `${repository.fullName}:${draft.cve}:${digest}`;
      state.receipts = await store.list("receipts");
      const prior = state.receipts.find((r) => r.id === id);
      if (prior && ["Created", "Reused"].includes(prior.status)) {
        state.githubIssueResults.push({ ...prior, message: "This exact draft already has a recorded issue. No new issue was posted." });
        continue;
      }
      const pending = state.receipts.find((r) => r.repository === repository.fullName && r.cve === draft.cve && ["Submitting", "Unknown"].includes(r.status));
      if (pending) {
        const result = await githubApiRequest(`https://api.github.com/search/issues?q=${encodeURIComponent(`repo:${repository.fullName} is:issue in:body \"${pending.marker}\"`)}&per_page=100`, token);
        const found = (result.items || []).find((r) => String(r.body || "").includes(`<!-- ${pending.marker} -->`));
        if (!found) throw new Error("Previous filing outcome is unknown. Check GitHub manually; no automatic duplicate will be created. Search indexing may be delayed.");
        if (!window.confirm(`A prior filing is issue #${found.number}: ${found.html_url}. Reuse it?`)) continue;
        const resolved = await store.put("receipts", { ...pending, status: "Reused", url: found.html_url, number: found.number, updatedAt: new Date().toISOString() }, pending.revision);
        state.receipts = [resolved, ...state.receipts.filter((r) => r.id !== resolved.id)];
        state.githubIssueResults.push(resolved); changes?.postMessage("receipts"); continue;
      }
      receipt = await store.put("receipts", { id, repository: repository.fullName, cve: draft.cve, marker: `vulnscope-draft:${digest}`, status: "Reviewed", scanAt: state.githubScan.generatedAt, updatedAt: new Date().toISOString() }, prior?.revision || 0);
      state.receipts = [receipt, ...state.receipts.filter((r) => r.id !== id)];
      const existing = await findExistingGitHubIssue(repository, draft.cve, token);
      if (existing && window.confirm(`Issue #${existing.number} (${existing.state}) mentions ${draft.cve}:\n${existing.title}\n${existing.html_url}\n\nReuse this issue? Verify its package/version scope and resolution first. Cancel declines reuse.`)) {
        state.githubIssueResults.push({ cve: draft.cve, status: "Reused", url: existing.html_url, number: existing.number, message: "Analyst chose to reuse this candidate issue." });
      } else if (existing && !window.confirm(`Create a NEW issue for ${draft.cve} instead of reusing #${existing.number}? Cancel skips this CVE without posting.`)) {
        state.githubIssueResults.push({ cve: draft.cve, status: "Skipped", url: "", number: null, message: "Analyst cancelled publication for this CVE." });
      } else {
        if (draft.body.length > 60000) throw new Error("Issue body exceeds 60,000 characters. Export the case and shorten the scoped plan before retrying.");
        receipt = await store.put("receipts", { ...receipt, status: "Submitting", updatedAt: new Date().toISOString() }, receipt.revision);
        state.receipts = [receipt, ...state.receipts.filter((r) => r.id !== receipt.id)];
        attemptedWrite = true;
        const created = await githubApiRequest(`https://api.github.com/repos/${encodeURIComponent(repository.owner)}/${encodeURIComponent(repository.name)}/issues`, token, {
          method: "POST",
          body: JSON.stringify({ title: draft.title, body: `${draft.body}\n\n<!-- ${receipt.marker} -->` })
        });
        if (!Number.isInteger(created.number) || !safeExternalUrl(created.html_url)) throw new Error("GitHub returned an incomplete receipt. Reconcile before retrying.");
        state.githubIssueResults.push({ cve: draft.cve, status: "Created", url: created.html_url, number: created.number, message: "Issue created." });
      }
      const outcome = state.githubIssueResults.at(-1);
      receipt = await store.put("receipts", { ...receipt, ...outcome, updatedAt: new Date().toISOString() }, receipt.revision);
      state.receipts = [receipt, ...state.receipts.filter((r) => r.id !== receipt.id)];
    } catch (error) {
      const outcome = { cve: draft.cve, status: attemptedWrite ? "Unknown" : "Failed", url: "", number: null, message: error.message || "GitHub issue creation failed." };
      state.githubIssueResults.push(outcome);
      if (receipt) {
        try { const saved = await store.put("receipts", { ...receipt, ...outcome, updatedAt: new Date().toISOString() }, receipt.revision); state.receipts = [saved, ...state.receipts.filter((r) => r.id !== saved.id)]; } catch { showToast("Receipt could not be updated. Reconcile the recorded pending attempt before retrying."); }
      }
    }
    changes?.postMessage("receipts");
    if (state.view === "github") renderGitHubRepositoryWorkspace();
    await delay(750);
  }
  state.githubPublishing = false;
  if (state.view === "github") renderGitHubRepositoryWorkspace();
  const createdCount = state.githubIssueResults.filter((result) => result.status === "Created").length;
  showToast(`GitHub issue publishing complete: ${createdCount} created, ${state.githubIssueResults.length - createdCount} skipped or failed.`);
}

async function findExistingGitHubIssue(repository, cve, token) {
  const query = `repo:${repository.fullName} is:issue in:title \"${cve}\"`;
  const result = await githubApiRequest(`https://api.github.com/search/issues?q=${encodeURIComponent(query)}&per_page=5`, token);
  const exactCve = new RegExp("(?:^|[^A-Z0-9-])" + escapeRegExp(cve) + "(?![A-Z0-9-])", "i");
  return (result.items || []).find((item) => exactCve.test(String(item.title || ""))) || null;
}

async function githubApiRequest(url, token, options = {}) {
  const response = await fetch(url, {
    ...options,
    signal: AbortSignal.timeout(20000),
    redirect: "error",
    headers: {
      accept: "application/vnd.github+json",
      authorization: `Bearer ${token}`,
      "x-github-api-version": "2026-03-10",
      ...(options.body ? { "content-type": "application/json" } : {})
    },
    credentials: "omit",
    referrerPolicy: "no-referrer"
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const message = response.status === 401
      ? "GitHub rejected the token."
      : response.status === 403
        ? "The token lacks Issues write permission or GitHub rate-limited the request."
        : response.status === 410
          ? "GitHub Issues are disabled for this repository."
          : response.status === 422
            ? "GitHub rejected the issue content or repository selection."
            : `GitHub returned HTTP ${response.status}.`;
    throw new Error(message);
  }
  return payload;
}

function selectedGitHubIssueDrafts() {
  const selected = new Set(state.githubSelectedCves);
  return (state.githubScan?.findings || [])
    .filter((finding) => selected.has(finding.cve))
    .slice(0, 10)
    .map((finding) => {
      const draft = buildGitHubIssueDraft(finding, state.githubScan.repository, state.githubScan.generatedAt);
      const record = state.cases.find((c) => c.id === finding.cve)?.investigation;
      if (record?.caseDraft?.plan) draft.body += `\n\n### Analyst remediation plan\n${planText(record.caseDraft.plan)}`;
      draft.draftUrl = `https://github.com/${state.githubScan.repository.fullName}/issues/new?title=${encodeURIComponent(draft.title)}&body=${encodeURIComponent(draft.body)}`;
      return draft;
    });
}

function renderGitHubRepositoryWorkspace() {
  if (state.githubIssueReview && state.githubScan) {
    renderGitHubIssueReview();
    return;
  }
  const scan = state.githubScan;
  const repository = scan?.repository;
  const findings = scan?.findings || [];
  const inventorySource = scan?.sourceResults?.find((result) => result.id === "githubSbom");
  const vulnerablePackages = new Set(findings.flatMap((finding) => finding.packages.map((pkg) => pkg.key))).size;
  elements.content.innerHTML = `
    <article class="investigation github-workspace">
      <section class="brief-header">
        <div class="brief-title">
          <div class="badge-row">
            <span class="badge">Public repository</span>
            <span class="badge">Dependency CVEs</span>
            ${repository?.archived ? `<span class="badge">Archived</span>` : ""}
          </div>
          <h2>${escapeHtml(repository?.fullName || "Scan a GitHub repository")}</h2>
          <p>${escapeHtml(repository?.description || "Analyze exact repository dependency versions against OSV and promote reviewed CVE matches into GitHub issues.")}</p>
        </div>
        <div class="header-actions">
          ${repository ? `<a class="secondary-button" href="${escapeAttr(safeExternalUrl(repository.url))}" target="_blank" rel="noreferrer noopener">Open repository</a>` : ""}
          ${scan ? `<button class="secondary-button" type="button" data-action="reset-github-scan">New scan</button>` : ""}
        </div>
      </section>

      <section class="panel github-scan-panel">
        <form id="githubRepositoryScanForm" class="github-scan-form" novalidate>
          <div class="search-field">
            <label class="field-label" for="githubRepositoryUrl">Public GitHub repository URL</label>
            <input id="githubRepositoryUrl" class="input" type="url" inputmode="url" autocomplete="url" spellcheck="false" placeholder="https://github.com/owner/repository" value="${escapeAttr(state.githubRepositoryUrl)}" aria-invalid="${state.githubScanError ? "true" : "false"}" aria-describedby="githubRepositoryError" ${state.githubScanning ? "disabled" : ""}>
            <div id="githubRepositoryError" class="field-error" role="alert" ${state.githubScanError ? "" : "hidden"}>${escapeHtml(state.githubScanError)}</div>
          </div>
          <button class="primary-button" type="submit" ${state.githubScanning ? "disabled" : ""}>${state.githubScanning ? "Scanning..." : "Scan repository"}</button>
        </form>
      </section>

      ${state.githubScanning ? renderGitHubScanLoading() : scan ? `
        <section class="metric-grid" aria-label="Repository scan metrics">
          <div class="metric-card"><div class="metric-label">Dependencies</div><div class="metric-value">${scan.inventory?.discoveredPackageCount || 0}</div><div class="metric-detail">${escapeHtml(inventorySource?.label || "GitHub repository inventory")}</div></div>
          <div class="metric-card"><div class="metric-label">Checked packages</div><div class="metric-value">${scan.coverage?.checkedPackageCount ?? 0}</div><div class="metric-detail">Received OSV batch results</div></div>
          <div class="metric-card"><div class="metric-label">Vulnerable packages</div><div class="metric-value">${scan.status === "failed" ? "Unknown" : vulnerablePackages}</div><div class="metric-detail">Returned package-version matches</div></div>
          <div class="metric-card"><div class="metric-label">Returned CVEs</div><div class="metric-value">${scan.status === "failed" ? "Unknown" : findings.length}</div><div class="metric-detail">${scan.status === "complete" ? "Ready for analyst review" : "Coverage is incomplete"}</div></div>
        </section>
        ${renderScanCoverage(scan)}
        <div class="toolbar"><button class="secondary-button" data-action="add-repo-workspace" ${scan.packages?.length ? "" : "disabled"}>Add to exposure workspace</button><button class="secondary-button" data-action="continue-repo" ${scan.pending?.length ? "" : "disabled"}>Continue package batch</button>${scan.status === "pending" ? `<button class="secondary-button" data-action="resume-repo">Resume generated report</button>` : ""}<button class="secondary-button" data-action="fallback-repo">Use lockfile inventory</button></div>
        <section class="panel">
          <div class="panel-title-row">
            <div><h3>Dependency CVE matches</h3><p>Confirm only findings that apply to the repository and its deployed artifacts.</p></div>
            <div class="toolbar-group">
              <button class="secondary-button" type="button" data-action="select-all-github-findings" ${findings.length ? "" : "disabled"}>Select first 10</button>
              <button class="primary-button" type="button" data-action="review-github-issues" ${state.githubSelectedCves.length ? "" : "disabled"}>${state.githubSelectedCves.length ? `Review ${state.githubSelectedCves.length} issue${state.githubSelectedCves.length === 1 ? "" : "s"}` : "Review selected"}</button>
            </div>
          </div>
          ${renderGitHubFindingTable(findings, scan)}
        </section>
      ` : ""}
    </article>
  `;
}

function renderGitHubScanLoading() {
  return `<section class="loading" aria-label="Scanning repository"><div class="skeleton"></div><div class="skeleton"></div><div class="skeleton"></div></section>`;
}

function renderGitHubFindingTable(findings, scan = {}) {
  if (!findings.length) return `<div class="workspace-empty"><strong>${scan.status === "complete" ? "No CVE matches in checked packages" : "No CVE conclusion available"}</strong><p>${scan.status === "complete" ? "Inventory matching is not proof of deployed safety or reachability." : "The scan was incomplete or failed. Resolve the coverage warnings and retry."}</p></div>`;
  const allCount = findings.length;
  findings = filterTableRows("github-findings", findings);
  return `
    ${tableSearch("github-findings", "Search repository findings", allCount)}
    ${pager("github-findings", findings.length, 100)}
    <div class="table-wrap">
      <table class="github-findings-table">
        <thead><tr><th scope="col">Confirm</th><th scope="col">CVE</th><th scope="col">Severity</th><th scope="col">Affected dependencies</th><th scope="col">Known fixes</th><th scope="col">OSV records</th></tr></thead>
        <tbody>${pageRows("github-findings", findings, 100).map((finding) => `
          <tr class="${state.githubSelectedCves.includes(finding.cve) ? "selected-row" : ""}">
            <td><input type="checkbox" data-github-cve="${escapeAttr(finding.cve)}" data-github-withdrawn="${finding.withdrawn ? "true" : "false"}" aria-label="Confirm ${escapeAttr(finding.cve)}" ${state.githubSelectedCves.includes(finding.cve) ? "checked" : ""} ${finding.withdrawn || (state.githubSelectedCves.length >= 10 && !state.githubSelectedCves.includes(finding.cve)) ? "disabled" : ""}></td>
            <td><button class="link-button" type="button" data-action="research-exposure" data-value="${escapeAttr(finding.cve)}">${escapeHtml(finding.cve)}</button>${finding.withdrawn ? `<br><span class="muted-cell">Withdrawn</span>` : ""}</td>
            <td><span class="risk-badge risk-${escapeAttr(severityRiskClass(finding.severity))}">${escapeHtml(finding.severity)}</span></td>
            <td>${finding.packages.slice(0, 3).map((pkg) => `<strong>${escapeHtml(pkg.name)}@${escapeHtml(pkg.version)}</strong>`).join("<br>")}${finding.packages.length > 3 ? `<br><span class="muted-cell">+${finding.packages.length - 3} more</span>` : ""}</td>
            <td>${escapeHtml(uniqueValues(finding.packages.flatMap((pkg) => pkg.fixedVersions || [])).join(" or ") || "Not reported")}</td>
            <td>${escapeHtml(finding.advisoryIds.join(", ") || "Unknown")}</td>
          </tr>
        `).join("")}</tbody>
      </table>
    </div>
  `;
}

function renderGitHubIssueReview() {
  const repository = state.githubScan.repository;
  const drafts = selectedGitHubIssueDrafts();
  elements.content.innerHTML = `
    <article class="investigation github-workspace">
      <section class="brief-header">
        <div class="brief-title">
          <div class="badge-row"><span class="badge">Issue review</span><span class="badge">${drafts.length} confirmed CVE${drafts.length === 1 ? "" : "s"}</span></div>
          <h2>${escapeHtml(repository.fullName)}</h2>
          <p>Review the generated issue titles and dependency evidence before publishing.</p>
        </div>
        <div class="header-actions"><button class="secondary-button" type="button" data-action="back-github-results" ${state.githubPublishing ? "disabled" : ""}>Back to findings</button></div>
      </section>

      <section class="panel">
        <div class="panel-title-row"><div><h3>Issue drafts</h3><p>One issue is generated per confirmed CVE and groups every matched dependency.</p></div></div>
        <div class="table-wrap">
          <table><thead><tr><th>CVE</th><th>Issue title</th><th>Packages</th><th>Manual fallback</th></tr></thead><tbody>
            ${drafts.map((draft) => {
              const finding = state.githubScan.findings.find((item) => item.cve === draft.cve);
              return `<tr><td class="issue-cve"><strong>${escapeHtml(draft.cve)}</strong></td><td>${escapeHtml(draft.title)}</td><td>${finding?.packages.length || 0}</td><td><a class="secondary-button table-button" href="${escapeAttr(draft.draftUrl.length <= 8000 ? draft.draftUrl : `https://github.com/${repository.fullName}/issues/new`)}" target="_blank" rel="noreferrer noopener">${draft.draftUrl.length <= 8000 ? "Open draft" : "Open blank issue (draft too long)"}</a><button class="secondary-button" data-action="download-issue" data-value="${escapeAttr(draft.cve)}">Download full draft</button></td></tr>`;
            }).join("")}
          </tbody></table>
        </div>
        ${drafts.map((draft) => `<details class="issue-draft-body"><summary>${escapeHtml(draft.cve)} issue body</summary><pre class="issue-body-preview">${escapeHtml(draft.body)}</pre></details>`).join("")}
      </section>

      <section class="panel github-publish-panel">
        <div class="panel-title-row"><div><h3>Publish to GitHub</h3><p>The token is sent directly to api.github.com and is not stored or sent to VulnScope.</p></div><span class="badge">Issues: write</span></div>
        ${repository.issuesEnabled ? `
          <div class="form-grid">
            <div class="search-field">
              <label class="field-label" for="githubIssueToken">Fine-grained GitHub token</label>
              <input id="githubIssueToken" class="input" type="password" autocomplete="off" spellcheck="false" placeholder="github_pat_..." ${state.githubPublishing ? "disabled" : ""}>
            </div>
            <label class="confirmation-check"><input id="githubIssueConsent" type="checkbox" ${state.githubPublishing ? "disabled" : ""}> <span>I reviewed these dependency matches and confirm they should be filed as repository issues.</span></label>
            <div class="toolbar"><span class="field-hint">Use a repository-scoped token with only Issues write permission.</span><button class="primary-button" type="button" data-action="publish-github-issues" ${state.githubPublishing ? "disabled" : ""}>${state.githubPublishing ? "Publishing..." : `Publish ${drafts.length} issue${drafts.length === 1 ? "" : "s"}`}</button></div>
          </div>
        ` : `<div class="error-panel">GitHub Issues are disabled for this repository. Use the issue drafts in another tracking system.</div>`}
      </section>
      ${renderGitHubIssueResults()}
    </article>
  `;
}

function renderGitHubIssueResults() {
  if (!state.githubIssueResults.length) return "";
  return `<section class="panel"><div class="panel-title-row"><div><h3>Publishing results</h3><p>Candidate issues are reused only after explicit review.</p></div></div><div class="evidence-list">${state.githubIssueResults.map((result) => `
    <div class="evidence-card"><div><h3>${escapeHtml(result.cve)} - ${escapeHtml(result.status)}</h3><p>${escapeHtml(result.message)}</p></div>${result.url ? `<a class="secondary-button" href="${escapeAttr(safeExternalUrl(result.url))}" target="_blank" rel="noreferrer noopener">Issue #${escapeHtml(String(result.number))}</a>` : ""}</div>
  `).join("")}</div></section>`;
}

function severityRiskClass(severity) {
  return { CRITICAL: "Critical", HIGH: "High", MODERATE: "Elevated", MEDIUM: "Elevated", LOW: "Watch", UNKNOWN: "Watch" }[String(severity || "UNKNOWN").toUpperCase()] || "Watch";
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function copyMonitorConfiguration() {
  if (!await mayLeave()) return;
  rememberCurrent(); state.current = null; state.view = "tools"; renderTools();
}

function openSbomCve(cve) {
  const report = getActiveSbomReport();
  if (!report?.cves.some((entry) => entry.id === cve)) return;
  state.activeSbomCveId = cve;
  render();
}

function openSbomCveReport(reportId, cve) {
  const raw = state.sbomReports.find((item) => item.id === reportId);
  const report = raw ? enrichedSbomReport(raw) : null;
  if (!report?.cves.some((entry) => entry.id === cve)) return;
  state.activeSbomId = report.id;
  state.view = "sbom";
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

async function copyBrief() {
  if (!state.current) return;
  await copyTextBlock(makeMarkdown(state.current), "Brief copied to clipboard.");
}

async function copyRemediation() {
  await copyTextBlock(state.current?.caseDraft?.plan ? planText(state.current.caseDraft.plan) : state.current?.remediation?.plainText, "Remediation instructions copied.");
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
    download("vulnscope-handoff.txt", text, "text/plain");
    showToast("Clipboard unavailable. Downloaded the text instead.");
  }
}

function confirmSensitiveExport(format) {
  return window.confirm(`${format} exports can include analyst notes, case metadata, and research context. Continue?`);
}

async function clearLocalData() {
  if (state.githubPublishing) { showToast("Wait for GitHub publishing to finish before deleting filing receipts."); return; }
  if (!window.confirm("Delete saved cases, watchlist data, SBOM uploads, enrichment results, imported evidence, and bulk results from this browser?")) return;
  cancelOperations();
  try { await store.clear(); }
  catch (error) { showToast(`Unable to clear workspace: ${error.message}`); return; }
  state.dirty = false;
  state.current = null;
  state.view = "empty";
  state.researchRecords = {};
  state.decisions = []; state.receipts = []; state.settings = [];
  changes?.postMessage("clear");
  state.cases = [];
  state.watchlist = [];
  state.sbomReports = [];
  state.enrichmentReports = [];
  state.evidenceReports = [];
  state.bulkQueue = [];
  state.bulkInput = "";
  state.githubScan = null;
  state.githubSelectedCves = [];
  state.githubIssueReview = false;
  state.githubIssueResults = [];
  state.githubScanError = "";
  state.activeSbomId = null;
  state.activeSbomCveId = null;
  state.activeEvidenceId = null;
  try { localStorage.removeItem("cve-research-cases"); localStorage.removeItem("cve-research-watchlist"); } catch { /* The migration marker prevents reimport of inaccessible legacy keys. */ }
  if (state.current) {
    state.current.caseDraft = { status: "Needs triage", owner: "", tags: "", notes: "" };
  }
  renderCases();
  renderWatchlist();
  renderSbomList();
  renderEvidenceList();
  if (state.current) render();
  if (!state.current) render();
  showToast("Local VulnScope workspace data cleared.");
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
  syncRoute();
  if (state.view === "tools") { renderTools(); return; }
  if (state.view === "exposures") {
    renderExposureWorkspace();
    return;
  }
  if (state.view === "bulk") {
    renderBulkWorkspace();
    return;
  }
  if (state.view === "github") {
    renderGitHubRepositoryWorkspace();
    return;
  }
  if (state.view === "evidence") {
    renderEvidenceWorkspace();
    return;
  }
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
            <span class="risk-badge risk-${escapeAttr(item.risk.level)}">${escapeHtml(item.risk.level)} ${item.risk.score ?? "Unknown"}/100</span>
            <span class="badge">${escapeHtml(item.id)}</span>
            <span class="badge">Confidence ${escapeHtml(item.confidence.label)}</span>
            <span class="badge">${escapeHtml(item.status || "Unknown")}</span>
          </div>
          <h2>${escapeHtml(item.title)}</h2>
          <p>${escapeHtml(item.executiveSummary)}</p>
        </div>
        <div class="header-actions">
          ${state.returnView ? `<button class="secondary-button" data-action="return-view">Back to workspace</button>` : ""}
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
      ${renderResearchExtras(item)}
    </article>
  `;
  renderCases();
  renderSbomList();
  renderEvidenceList();
}

function renderEvidenceWorkspace() {
  const report = state.evidenceReports.find((item) => item.id === state.activeEvidenceId) || state.evidenceReports[0];
  if (!report) {
    openExposureWorkspace();
    return;
  }
  elements.content.innerHTML = `
    <article class="investigation">
      <section class="brief-header">
        <div class="brief-title">
          <div class="badge-row">
            <span class="badge">Imported evidence</span>
            <span class="badge">${escapeHtml(report.format)}</span>
          </div>
          <h2>${escapeHtml(report.fileName)}</h2>
          <p>${escapeHtml(report.summary || "Imported cloud and vulnerability evidence.")}</p>
        </div>
        <div class="header-actions">
          <label class="secondary-button" for="evidenceInput">Import more</label>
          <button class="primary-button" type="button" data-action="open-exposures">Open exposure workspace</button>
        </div>
      </section>
      <section class="metric-grid" aria-label="Evidence import metrics">
        <div class="metric-card"><div class="metric-label">Findings</div><div class="metric-value">${report.findings.length}</div><div class="metric-detail">Vulnerability evidence rows</div></div>
        <div class="metric-card"><div class="metric-label">Assets</div><div class="metric-value">${report.assets.length}</div><div class="metric-detail">Unique cloud resources</div></div>
        <div class="metric-card"><div class="metric-label">VEX statements</div><div class="metric-value">${report.vexStatements.length}</div><div class="metric-detail">Disposition records</div></div>
        <div class="metric-card"><div class="metric-label">Warnings</div><div class="metric-value">${report.warnings.length}</div><div class="metric-detail">Parser notes</div></div>
      </section>
      ${report.warnings.length ? `<section class="notice warning"><strong>Import notes</strong><ul>${report.warnings.map((warning) => `<li>${escapeHtml(warning)}</li>`).join("")}</ul></section>` : ""}
      <section class="panel">
        <div class="panel-title-row"><div><h3>VEX assertions</h3><p>Imported affected-state decisions and supporting rationale.</p></div></div>
        ${renderVexStatements(report.vexStatements)}
      </section>
      <section class="panel">
        <div class="panel-title-row"><div><h3>Cloud and package findings</h3><p>Imported records are normalized into the exposure workspace.</p></div></div>
        ${renderImportedFindings(report.findings)}
      </section>
      <section class="panel">
        <div class="panel-title-row"><div><h3>Assets</h3><p>Resources referenced by imported findings.</p></div></div>
        ${renderImportedAssets(report.assets)}
      </section>
    </article>
  `;
}

function renderVexStatements(statements) {
  if (!statements.length) return `<p>No VEX statements were found in this file.</p>`;
  return `<div class="card-grid">${statements.slice(0, 100).map((statement) => `
    <div class="action-item">
      <div class="badge-row"><span class="badge">${escapeHtml(statement.vulnerability)}</span><span class="vex-badge">${escapeHtml(statement.status)}</span><span class="badge">${statement.trusted ? "Analyst approved" : "Unverified"}</span></div>
      <strong>${escapeHtml(statement.products.join(", ") || "All referenced products")}</strong>
      <p>${escapeHtml(statement.justification || statement.impact || statement.detail || "No justification supplied.")}</p>
      <p class="muted-cell">${escapeHtml(statement.trustReason)}</p>
      ${statement.action ? `<p><strong>Action:</strong> ${escapeHtml(statement.action)}</p>` : ""}
    </div>
  `).join("")}</div>${statements.length > 100 ? `<p class="table-note">Showing the first 100 VEX statements.</p>` : ""}`;
}

function renderImportedFindings(findings) {
  if (!findings.length) return `<p>No cloud vulnerability finding rows were found in this file.</p>`;
  return `<div class="table-wrap"><table><thead><tr><th>Vulnerability</th><th>Severity</th><th>Package</th><th>Asset</th><th>Fix</th><th>Source</th></tr></thead><tbody>${findings.slice(0, 300).map((finding) => `
    <tr><td><strong>${escapeHtml(finding.vulnerability)}</strong></td><td>${escapeHtml(finding.severity)}</td><td>${escapeHtml(finding.packageName || "n/a")} ${escapeHtml(finding.installedVersion || "")}</td><td>${escapeHtml(finding.assetName || finding.assetId || "Unmapped")}</td><td>${escapeHtml(finding.fixedVersion || finding.remediation || "Validate vendor guidance")}</td><td>${escapeHtml(finding.source)}</td></tr>
  `).join("")}</tbody></table></div>${findings.length > 300 ? `<p class="table-note">Showing the first 300 findings.</p>` : ""}`;
}

function renderImportedAssets(assets) {
  if (!assets.length) return `<p>No explicit cloud assets were found in this file.</p>`;
  return `<div class="table-wrap"><table><thead><tr><th>Provider</th><th>Asset</th><th>Type</th><th>Account</th><th>Region</th></tr></thead><tbody>${assets.slice(0, 300).map((asset) => `
    <tr><td>${escapeHtml(asset.provider || "Cloud")}</td><td><strong>${escapeHtml(asset.name)}</strong><br><span class="muted-cell">${escapeHtml(asset.id)}</span></td><td>${escapeHtml(asset.type)}</td><td>${escapeHtml(asset.account || "n/a")}</td><td>${escapeHtml(asset.region || "n/a")}</td></tr>
  `).join("")}</tbody></table></div>`;
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
        <div class="metric-detail">${escapeHtml(cvss?.severity || "No score")} ${escapeHtml(cvss?.version || "")} ${observationText(item, "cvss")}</div>
      </div>
      <div class="metric-card">
        <div class="metric-label">EPSS</div>
        <div class="metric-value">${epss?.epss !== null && epss?.epss !== undefined ? formatPercent(epss.epss) : "n/a"}</div>
        <div class="metric-detail">Percentile ${epss?.percentile !== null && epss?.percentile !== undefined ? formatPercent(epss.percentile) : "n/a"}. ${observationText(item, "epss")}</div>
      </div>
      <div class="metric-card">
        <div class="metric-label">CISA KEV</div>
        <div class="metric-value">${kev ? (kev.listed ? "Listed" : "Not listed") : "Unknown"}</div>
        <div class="metric-detail">${observationText(item, "kev")}${kev?.dueDate ? `; Due ${escapeHtml(formatDate(kev.dueDate))}` : ""}</div>
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
            <button class="tab-button ${state.activeTab === id ? "active" : ""}" aria-current="${state.activeTab === id ? "page" : "false"}" type="button" data-action="tab" data-value="${id}">
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
          ${Object.entries(item.caseDraft?.claimReviews || {}).length ? `<p class="analyst-review-context">Local evidence review: ${Object.values(item.caseDraft.claimReviews).map((r) => `${escapeHtml(r.status)}: ${escapeHtml(r.reason)}`).join("; ")}. These case decisions do not alter source observations.</p>` : ""}
        </div>
        <div class="real-world-score">
          <span class="risk-badge risk-${escapeAttr(item.risk.level)}">${escapeHtml(realWorld.verdict)}</span>
          <strong>${realWorld.score ?? "Unknown"}/100</strong>
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
          ${entry.date ? `<span class="badge">${escapeHtml(formatDate(entry.date))}</span>` : ""}
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
                      <div class="timeline-date">${event.date ? escapeHtml(formatDate(event.date)) : "Undated"}</div>
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
        <textarea class="textarea remediation-text" aria-label="Current remediation text" readonly>${escapeHtml(item.caseDraft?.plan ? planText(item.caseDraft.plan) : item.remediation?.plainText || "No remediation instructions were generated.")}</textarea>
      </div>
      <div class="card-grid">
        ${(item.remediation?.steps || [])
          .map(
            (step) => `
              <div class="action-item">
                <span class="badge">${escapeHtml(step.priority)}</span>
                <strong>${escapeHtml(step.title)}</strong>
                <p>${escapeHtml(step.detail)}</p>
                ${step.dueDate ? `<p><strong>Due:</strong> ${escapeHtml(formatDate(step.dueDate))}</p>` : ""}
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
        <label class="field-label" for="assetInput">Inventory to check</label><textarea id="assetInput" class="textarea remediation-text" placeholder="Example: confluence-server 8.5.4 on wiki-prod-01">${escapeHtml(state.assetInput)}</textarea>
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
        <textarea class="textarea remediation-text" aria-label="Cloud impact text" readonly>${escapeHtml(cloud.plainText || "No cloud impact summary is available yet.")}</textarea>
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
      ${renderCopyBlock("Executive Summary Mode", "copy-executive", caseHandoff(item, "Executive summary"))}
      ${renderCopyBlock("Ticket Export Mode", "copy-ticket", caseHandoff(item, "Remediation ticket"))}
      ${renderCopyBlock("Detection Guidance", "copy-detection", item.detectionGuidance?.plainText)}
      ${renderCopyBlock("Cloud Impact Summary", "copy-cloud-impact", item.cloudImpact?.plainText)}
      ${renderCopyBlock("Risk Acceptance Note", "copy-risk-acceptance", caseHandoff(item, "Risk decision - local analyst record"))}
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
      <textarea class="textarea remediation-text" aria-label="${escapeAttr(title)}" readonly>${escapeHtml(text || "Not available yet.")}</textarea>
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
      <div class="action-item"><span class="badge">Baseline</span><strong>${escapeHtml(formatDateTime(baselineTime))}</strong><p>${escapeHtml(record.baseline?.verdict || "Unknown")} / ${escapeHtml(record.baseline?.maturity || "Unknown")}</p></div>
      <div class="action-item"><span class="badge">Latest check</span><strong>${escapeHtml(formatDateTime(latestTime))}</strong><p>${escapeHtml(record.latest?.verdict || "Unknown")} / ${escapeHtml(record.latest?.maturity || "Unknown")}</p></div>
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
          <label class="field-label" for="analystNotes">Analyst notes</label>
          <textarea id="analystNotes" class="textarea" data-case-field="notes" placeholder="Record environment impact, patch plan, exceptions, and links.">${escapeHtml(draft.notes)}</textarea>
          <p id="draftStatus" role="status">${state.dirty ? "Unsaved changes" : "No unsaved changes"}</p>
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

function mergeSourceHealth(results) {
  if (!Array.isArray(results)) return;
  const merged = new Map(state.sourceHealth.map((source) => [source.id, source]));
  for (const source of results) merged.set(source.id, { ...merged.get(source.id), ...source });
  state.sourceHealth = [...merged.values()];
  renderHealth();
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
        <span>${escapeHtml(formatDate(report.uploadedAt))}</span>
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
          <button class="secondary-button" type="button" data-action="enrich-sbom" ${state.enriching ? "disabled" : ""}>${state.enriching ? "Enriching..." : "Enrich / continue next batch"}</button>
          <button class="danger-button" data-action="remove-import" data-kind="sbom" data-value="${escapeAttr(report.id)}">Remove this import</button>
          <button class="secondary-button" type="button" data-action="open-exposures">View exposures</button>
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

      ${renderSbomEnrichment(report)}

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

function renderSbomEnrichment(report) {
  const enrichment = state.enrichmentReports.find((item) => item.sbomId === report.id);
  if (!enrichment) return '<section class="panel enrichment-panel"><h3>OSV enrichment</h3><p>Not run</p></section>';
  return '<section class="panel enrichment-panel"><h3>OSV enrichment</h3>' + renderScanCoverage(enrichment) +
    '<p>' + (enrichment.vulnerabilityCount ?? "Unknown") + ' vulnerability records returned.</p></section>';
}

function renderScanCoverage(scan) {
  const status = ["complete", "partial", "failed", "pending"].includes(scan.status) ? scan.status : "partial";
  const reasons = scan.coverage?.reasons || (status === "complete" ? [] : ["Coverage was not fully verified."]);
  const unresolved = scan.coverage?.unresolvedAdvisoryIds || [];
  const advisoryOnly = (scan.packages || []).flatMap((pkg) => (pkg.vulnerabilities || []).filter((item) => !(item.cves?.length || item.aliases?.some((id) => /^CVE-/i.test(id)))).map((item) => item.id));
  return '<div class="' + (status === "complete" ? "scan-coverage" : "stale-banner") + '" role="status"><div><strong>Scan ' + status +
    '</strong><p>' + (scan.coverage?.checkedPackageCount ?? 0) + ' packages checked. ' + reasons.map(escapeHtml).join(" ") +
    '</p>' + (unresolved.length ? '<p>Unresolved advisories: ' + unresolved.map(escapeHtml).join(", ") + '</p>' : "") +
    (advisoryOnly.length ? '<p>Advisory IDs without a resolved CVE: ' + uniqueValues(advisoryOnly).map(escapeHtml).join(", ") + '</p>' : "") + '</div></div>';
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
  const rows = filterTableRows("sbom-cves", report.cves);
  return `
    ${tableSearch("sbom-cves", "Search SBOM CVEs", report.cves.length)}
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>CVE</th>
            <th>Severity</th>
            <th>VEX</th>
            <th>Components</th>
            <th>Files</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          ${pageRows("sbom-cves", rows, SBOM_CVE_DISPLAY_LIMIT).map((entry) => `
            <tr class="${activeCve === entry.id ? "selected-row" : ""}">
              <td><button class="link-button" type="button" data-action="open-sbom-cve" data-value="${escapeAttr(entry.id)}" aria-pressed="${activeCve === entry.id ? "true" : "false"}">${escapeHtml(entry.id)}</button></td>
              <td>${escapeHtml(entry.severity || "Unknown")}</td>
              <td><span class="vex-badge">${escapeHtml(entry.vexStatus || "Unreviewed")}</span></td>
              <td>${escapeHtml(entry.affectedPackages?.slice(0, 3).map((pkg) => pkg.label).join(", ") || entry.components.slice(0, 3).join(", ") || "No component listed")}</td>
              <td>${escapeHtml(entry.files.slice(0, 2).join(", "))}</td>
              <td><button class="secondary-button table-button" type="button" data-action="research-sbom-cve" data-value="${escapeAttr(entry.id)}">Research</button></td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    </div>
    ${pager("sbom-cves", rows.length, SBOM_CVE_DISPLAY_LIMIT)}
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
                  <th>VEX</th>
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
                    <td>${escapeHtml(pkg.vexStatus || "Unreviewed")}</td>
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
  const rows = filterTableRows("sbom-components", report.components);
  return `
    ${tableSearch("sbom-components", "Search component inventory", report.components.length)}
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
          ${pageRows("sbom-components", rows, SBOM_COMPONENT_DISPLAY_LIMIT).map((component) => `
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
    ${pager("sbom-components", rows.length, SBOM_COMPONENT_DISPLAY_LIMIT)}
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
            <span>${escapeHtml(formatDate(item.savedAt))}</span>
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
  lines.push(caseHandoff(item));
  lines.push(`**Risk:** ${item.risk.level} (${item.risk.score ?? "Unknown"}/100)`);
  if (realWorld) {
  lines.push(`**Real-world verdict:** ${realWorld.verdict} (${realWorld.score ?? "Unknown"}/100)`);
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
  lines.push(`- CISA KEV: ${kevLabel(item)}`);
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
  const report = state.sbomReports.find((item) => item.id === state.activeSbomId);
  return report ? enrichedSbomReport(report) : null;
}

function getSelectedSbomCve(report) {
  if (!report?.cves.length) return null;
  return report.cves.find((entry) => entry.id === state.activeSbomCveId) || report.cves[0];
}

function findSbomCveMatches(cve) {
  const normalized = normalizeCve(cve);
  if (!normalized) return [];
  return state.sbomReports.map(enrichedSbomReport).flatMap((report) => {
    const entry = report.cves.find((item) => item.id === normalized);
    return entry ? [{ report, entry }] : [];
  });
}


function sbomAffectedPackageKey(pkg) {
  return JSON.stringify([pkg.reportId, pkg.fileId, pkg.ref, pkg.fileName, pkg.name, pkg.version, pkg.purl, pkg.label]);
}

function analyzeSbomImpact(item) {
  const components = state.sbomReports.flatMap((report) => report.components || []);
  if (!components.length) return [];
  const products = (item.affected || []).map((entry) => ({
    product: `${entry.vendor} ${entry.product}`.trim(),
    vendor: String(entry.vendor || "").toLowerCase(),
    name: String(entry.product || "").toLowerCase(),
    version: String(entry.version || ""), ranges: entry.versionRanges || []
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
          confidence: "Candidate identity - verify",
          reason: `Text match for ${product.product}. ${product.ranges.length ? product.ranges.map((range) => matchSemverRange(component.version, range)).join("; ") : "Unknown version applicability"}. Product identity and all advisory ranges must be verified.`
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
          confidence: "Text candidate only",
          reason: `${vendorHit ? "Vendor" : "Product"} term matched. Unknown version applicability; free text is not a verified package identity${product.version ? ` (${product.version})` : ""}.`
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
    kev: item.metrics?.kev?.listed ?? null,
    kevState: item.observations?.kev?.state || "unavailable",
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

function finishResearch() {
  state.loading = false;
  elements.button.disabled = false;
  elements.button.textContent = "Research CVE";
  elements.content.removeAttribute("aria-busy");
}

function observationText(item, field) {
  const observation = item.observations?.[field];
  if (!observation || observation.state === "unavailable") return "Source observation unavailable";
  return `${observation.state === "stale" ? "Last known; current source unavailable" : "Observed"}: ${escapeHtml(formatDateTime(observation.dataAsOf))}`;
}

function cancelOperations() {
  operations.clear();
  state.loading = state.bulkRunning = state.enriching = state.githubScanning = false;
  for (const item of state.bulkQueue) if (["Queued", "Researching"].includes(item.status)) item.status = "Cancelled";
  finishResearch();
}

function routeSnapshot() {
  return { view: state.view, tab: state.activeTab, cve: state.current?.id || null, sbomId: state.activeSbomId, evidenceId: state.activeEvidenceId };
}

function syncRoute() {
  const route = routeSnapshot();
  if (!restoringRoute && JSON.stringify(history.state) !== JSON.stringify(route)) history.pushState(route, "");
  const actions = { exposures: "open-exposures", github: "open-github-scan", bulk: "open-bulk", tools: "open-tools" };
  document.querySelectorAll(".sidebar [data-action], .mobile-workspaces [data-action]").forEach((el) => {
    if (Object.values(actions).includes(el.dataset.action)) el.setAttribute("aria-current", el.dataset.action === actions[state.view] ? "page" : "false");
  });
}

function rememberCurrent() {
  if (state.current) state.researchRecords[state.current.id] = structuredClone(state.current);
}

async function mayLeave() {
  if (!state.dirty) return true;
  const choice = await dialogForm("Unsaved case changes", "<p>Save your work before leaving this case?</p>", [["save", "Save and continue"], ["discard", "Discard draft"], ["cancel", "Stay here"]]);
  if (choice.action === "cancel") return false;
  if (choice.action === "save") return Boolean(await saveCurrentCase());
  if (state.current) state.current.caseDraft = structuredClone(state.savedDraft || {});
  state.dirty = false;
  return true;
}

function pageRows(key, rows, size) {
  const page = Math.max(0, Math.min(state.tablePages[key] || 0, Math.ceil(rows.length / size) - 1));
  state.tablePages[key] = page;
  return rows.slice(page * size, (page + 1) * size);
}

function filterTableRows(key, rows) {
  const filter = (state.tableFilters[key] || "").toLowerCase();
  return filter ? rows.filter((row) => JSON.stringify(row).toLowerCase().includes(filter)) : rows;
}

function tableSearch(key, label, count) {
  return `<label class="field-label">${label} (${count} total)<input type="search" class="input" data-table-filter="${key}" maxlength="200" value="${escapeAttr(state.tableFilters[key] || "")}"></label>`;
}

function pager(key, count, size) {
  const page = Math.max(0, Math.min(state.tablePages[key] || 0, Math.ceil(count / size) - 1));
  return `<nav class="pagination" aria-label="${escapeAttr(key)} pages"><button class="secondary-button" data-action="page" data-value="${escapeAttr(key)}" data-delta="-1" title="Previous page" aria-label="Previous page" ${page === 0 ? "disabled" : ""}>&#8592;</button><span>${count ? page * size + 1 : 0}-${Math.min(count, (page + 1) * size)} of ${count}</span><button class="secondary-button" data-action="page" data-value="${escapeAttr(key)}" data-delta="1" title="Next page" aria-label="Next page" ${(page + 1) * size >= count ? "disabled" : ""}>&#8594;</button></nav>`;
}

function renderUnlinkedResearch(rows) {
  const linked = new Set(rows.map((r) => r.vulnerability));
  const records = new Map([...state.cases.map((r) => r.investigation), ...state.watchlist.map((r) => r.investigation), ...Object.values(state.researchRecords)].filter(Boolean).map((r) => [r.id, r]));
  const unlinked = [...records.values()].filter((r) => !linked.has(r.id));
  return `<section class="panel"><h3>Research without linked inventory</h3><p>${unlinked.length} researched CVEs without package or asset evidence. These are not confirmed exposures.</p>${pager("triage", unlinked.length, 50)}<div class="table-wrap"><table><thead><tr><th>CVE</th><th>Research</th><th>Action</th></tr></thead><tbody>${pageRows("triage", unlinked, 50).map((r) => `<tr><td>${escapeHtml(r.id)}</td><td>${escapeHtml(r.title)}</td><td><button class="secondary-button" data-action="research-exposure" data-value="${escapeAttr(r.id)}">Research</button></td></tr>`).join("")}</tbody></table></div></section>`;
}

function enrichedSbomReport(report) {
  const enrichment = state.enrichmentReports.find((r) => r.sbomId === report.id);
  if (!enrichment) return report;
  const cves = new Map(report.cves.map((entry) => [entry.id, { ...entry, affectedPackages: [...entry.affectedPackages], files: [...entry.files], components: [...entry.components] }]));
  for (const pkg of enrichment.packages || []) for (const advisory of pkg.vulnerabilities || []) for (const id of advisory.cves || []) {
    if (!cves.has(id)) cves.set(id, { id, severity: advisory.severity, affectedPackages: [], files: [], components: [], sources: ["OSV enrichment"], references: (advisory.references || []).map((r) => r.url), count: 1 });
    const entry = cves.get(id);
    const originals = report.components.filter((p) => p.version === pkg.version && (p.purl && p.purl === pkg.purl || p.name === pkg.name));
    for (const original of originals.length ? originals : [pkg]) {
      const affected = { ...original, label: `${original.name}@${original.version}`, source: "OSV enrichment", match: "OSV package-version match", fixedVersions: advisory.fixedVersions, vexStatus: "Needs verification" };
      if (!entry.affectedPackages.some((p) => sbomAffectedPackageKey(p) === sbomAffectedPackageKey(affected))) entry.affectedPackages.push(affected);
      entry.files = uniqueValues([...entry.files, original.fileName || report.title]);
      entry.components = uniqueValues([...entry.components, affected.label]);
    }
  }
  return { ...report, cves: [...cves.values()] };
}

function addRepositoryToWorkspace() {
  if (!state.githubScan) return;
  const scan = state.githubScan;
  const id = `repository:${scan.repository.fullName}:${scan.generatedAt}`;
  const report = { ...scan, id, title: scan.repository.fullName, packages: scan.packages.map((p) => ({ ...p, fileName: `${scan.repository.fullName}:${p.fileName || scan.repository.defaultBranch}` })) };
  state.enrichmentReports = [report, ...state.enrichmentReports.filter((r) => r.id !== id)];
  showToast("Repository package findings added to the exposure workspace.");
}

function mergeEnrichment(previous, next, inventory) {
  const known = new Map((previous?.packages || []).map((p) => [packageKey(p), p]));
  for (const pkg of next.packages || []) {
    const old = known.get(packageKey(pkg));
    const vulnerabilities = new Map((old?.vulnerabilities || []).map((v) => [v.id, v]));
    for (const v of pkg.vulnerabilities || []) if (v.detailStatus === "complete" || !vulnerabilities.has(v.id)) vulnerabilities.set(v.id, v);
    known.set(packageKey(pkg), { ...pkg, vulnerabilities: [...vulnerabilities.values()] });
  }
  const packages = [...known.values()];
  const completed = packages.filter((p) => p.checkStatus === "complete" || (!p.checkStatus && next.status === "complete" && (next.packages || []).some((n) => packageKey(n) === packageKey(p))));
  const pending = inventory.filter((p) => !completed.some((c) => packageKey(c) === packageKey(p)));
  const unsupportedCount = inventory.filter((p) => !p.version || !(p.purl || p.ecosystem && p.name)).length;
  const inventoryIncomplete = Boolean(previous?.inventoryIncomplete || previous?.inventory?.truncated || previous?.inventory?.partial);
  const warnings = uniqueValues([...(previous?.warnings || []), ...(next.warnings || [])]);
  const reasons = [...(pending.length ? [`${pending.length} package queries or details remain pending. Continue or retry the next batch.`] : []), ...(unsupportedCount ? [`${unsupportedCount} packages lack a supported exact identity/version.`] : []), ...(inventoryIncomplete ? ["Source inventory was incomplete; continuation cannot recover omitted source packages."] : [])];
  const status = pending.length || unsupportedCount || inventoryIncomplete || next.status === "failed" ? "partial" : "complete";
  return { ...previous, ...next, packages, pending, inventory, inventoryIncomplete, warnings, status, truncated: status !== "complete", vulnerabilityCount: new Set(packages.flatMap((p) => (p.vulnerabilities || []).map((v) => v.id))).size, coverage: { checkedPackageCount: completed.length, reasons, unresolvedAdvisoryIds: packages.flatMap((p) => (p.vulnerabilities || []).filter((v) => v.detailStatus === "unresolved").map((v) => v.id)) } };
}

async function continueRepositoryScan() {
  const scan = state.githubScan;
  if (!scan) return;
  const packages = (scan.pending || scan.inventoryPackages || []).filter((p) => p.version && (p.purl || p.ecosystem && p.name)).slice(0, 50).map((pkg) => {
    const old = scan.packages?.find((p) => packageKey(p) === packageKey(pkg));
    return { ...pkg, pageToken: old?.nextDetailOffset != null ? old.pageToken : old?.nextPageToken, detailOffset: old?.nextDetailOffset || 0 };
  });
  if (!packages.length) { showToast("No remaining queryable packages. Review unsupported inventory warnings."); return; }
  const operation = operations.start("enrich");
  state.githubScanning = true;
  try {
    const payload = await requestJson("/api/enrich", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ packages }), signal: operation.signal, onWait: showToast });
    if (!operation.current()) return;
    const combined = mergeEnrichment(scan, payload, scan.inventoryPackages || (Array.isArray(scan.inventory) ? scan.inventory : scan.packages));
    state.githubScan = { ...scan, ...combined, repository: scan.repository, inventory: scan.inventory, findings: buildRepositoryCveFindings(combined) };
  } finally { if (operation.current()) { state.githubScanning = false; if (state.view === "github") renderGitHubRepositoryWorkspace(); } }
}

function loadWatchlist() {
  return readStorageArray("cve-research-watchlist");
}

function loadCases() {
  return readStorageArray("cve-research-cases");
}

function readStorageArray(key) {
  try {
    const parsed = JSON.parse(localStorage.getItem(key) || "[]");
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
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

function normalizeVexState(value) {
  const state = String(value || "").trim().toLowerCase().replace(/[ -]+/g, "_");
  if (["affected", "known_affected", "exploitable"].includes(state)) return "Affected";
  if (["not_affected", "known_not_affected", "not_exploitable"].includes(state)) return "Not affected";
  if (["fixed", "resolved"].includes(state)) return "Fixed";
  if (["under_investigation", "in_triage"].includes(state)) return "Under investigation";
  return state ? labelize(state) : "Unknown";
}

function selectVexStatus(values) {
  const statuses = uniqueValues(values);
  for (const status of ["Affected", "Under investigation", "Fixed", "Not affected"]) {
    if (statuses.includes(status)) return status;
  }
  return statuses[0] || "Unreviewed";
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

function classToken(value) {
  return String(value || "unknown").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "") || "unknown";
}
