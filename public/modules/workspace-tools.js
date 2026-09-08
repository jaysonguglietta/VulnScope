import { validateBackup, clearImportedTrust } from "./persistence.js";
import { makePlan, planText, caseHandoff, occurrenceKey, compareInventories } from "./research-model.js";

export const escapeText = (value) => String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const safeUrl = (value) => { try { const u = new URL(value); return ["https:", "http:"].includes(u.protocol) ? u.href : ""; } catch { return ""; } };
let fieldSequence = 0;
const field = (label, control) => { const id = `workspace-field-${++fieldSequence}`; return `<div class="form-field"><label class="field-label" for="${id}">${label}</label>${control(id)}</div>`; };
const input = (label, name, value = "", type = "text") => field(label, (id) => `<input id="${id}" class="input" name="${name}" type="${type}" value="${escapeText(value)}">`);
const area = (label, name, value = "") => field(label, (id) => `<textarea id="${id}" class="textarea" name="${name}">${escapeText(value)}</textarea>`);
const select = (label, name, options, value) => field(label, (id) => `<select id="${id}" class="select" name="${name}">${options.map((x) => `<option ${x === value ? "selected" : ""}>${escapeText(x)}</option>`).join("")}</select>`);

export function dialogForm(title, body, buttons = [["save", "Save"], ["cancel", "Cancel"]]) {
  return new Promise((resolve) => {
    const previous = document.activeElement;
    const dialog = document.createElement("dialog");
    dialog.className = "workspace-dialog";
    dialog.setAttribute("aria-label", title);
    dialog.innerHTML = `<form method="dialog"><h2>${escapeText(title)}</h2><div class="dialog-fields">${body}</div><div class="toolbar">${buttons.map(([value, label]) => `<button class="secondary-button" value="${value}" ${value === "cancel" ? "formnovalidate" : ""}>${escapeText(label)}</button>`).join("")}</div></form>`;
    document.body.append(dialog);
    dialog.addEventListener("close", () => {
      const data = Object.fromEntries(new FormData(dialog.querySelector("form")));
      const action = dialog.returnValue || "cancel";
      dialog.remove();
      previous?.focus();
      resolve({ action, data });
    }, { once: true });
    dialog.showModal();
  });
}

export function createWorkspaceTools(context) {
  const { state, store, showToast, download, render, saveCurrentCase, getExposureRows, changes, focusContent, renderCases, renderWatchlist, renderSbomList, renderEvidenceList, mayLeave } = context;
  const content = () => document.querySelector("#content");
  const notify = () => changes?.postMessage("records");

  async function exportWorkspace() {
    const choice = await dialogForm("Backup workspace", `<p>Exports include local notes, decisions and issue URLs. Tokens are excluded.</p><label><input type="checkbox" name="inventory"> Include normalized inventory (may contain confidential package and cloud details)</label>`, [["export", "Export backup"], ["cancel", "Cancel"]]);
    if (choice.action !== "export") return;
    const records = await store.snapshot();
    const backup = { format: "vulnscope-workspace", version: 1, exportedAt: new Date().toISOString(), records };
    if (choice.data.inventory) backup.inventory = { sbomReports: state.sbomReports, evidenceReports: state.evidenceReports, enrichmentReports: state.enrichmentReports };
    validateBackup(backup);
    download(`vulnscope-workspace-${new Date().toISOString().slice(0, 10)}.json`, JSON.stringify(backup, null, 2), "application/json");
  }

  async function restoreWorkspace(file) {
    if (!file) return;
    if (state.githubPublishing) throw new Error("Wait for publishing to finish before replacing filing receipts.");
    if (!await mayLeave()) return;
    if (file.size > 20 * 1024 * 1024) throw new Error("Backup exceeds 20 MiB.");
    const backup = validateBackup(JSON.parse(await file.text()));
    const counts = Object.entries(backup.records).map(([key, values]) => `${key}: ${values.length}`).join("; ");
    const choice = await dialogForm("Restore preview", `<p>${escapeText(counts)}</p><p>Merge keeps existing IDs; replace replaces local records. Imported approvals require a new review. Inventory replaces the current session inventory only when included.</p>`, [["merge", "Merge new IDs"], ["replace", "Replace workspace"], ["cancel", "Cancel"]]);
    if (choice.action === "cancel") return;
    if (choice.action === "replace" && !window.confirm("Replace all saved workspace records? Export a backup first if needed.")) return;
    context.cancelImports();
    await store.restore(backup, choice.action === "replace");
    for (const collection of ["cases", "watchlist", "decisions", "receipts", "settings"]) state[collection] = await store.list(collection);
    if (backup.inventory) Object.assign(state, clearImportedTrust(backup.inventory));
    state.current = null;
    state.dirty = false;
    state.view = "tools";
    notify(); renderCases(); renderWatchlist(); renderSbomList(); renderEvidenceList(); renderTools();
    showToast("Backup restored. Imported approvals are unverified.");
  }

  function renderTools() {
    const inventories = [...state.sbomReports, ...state.enrichmentReports];
    if (state.githubScan) inventories.push({ ...state.githubScan, id: "current-repository", title: state.githubScan.repository?.fullName });
    const options = inventories.map((x) => `<option value="${escapeText(x.id)}">${escapeText(x.title || x.id)} - ${escapeText(x.generatedAt || x.uploadedAt || "session")}</option>`).join("");
    content().innerHTML = `<article class="investigation"><h2>Workspace data and operations</h2>
      <section class="panel"><h3>Local data</h3><p>${state.cases.length} cases; ${state.watchlist.length} watches; ${state.decisions.length} decisions. Records are retained until explicitly deleted. Imports are session-only unless included in a backup.</p><div class="toolbar"><button class="primary-button" data-action="backup">Export backup</button><label class="secondary-button" for="restoreInput">Restore backup</label></div></section>
      <section class="panel"><h3>Scoped decisions</h3>${state.decisions.length ? `<div class="table-wrap"><table><thead><tr><th>Target</th><th>Status</th><th>Review date</th><th>Rationale</th><th>Action</th></tr></thead><tbody>${state.decisions.map((d) => `<tr><td>${escapeText(d.target)}</td><td>${escapeText(d.approved && (!d.reviewAt || Date.parse(d.reviewAt) > Date.now()) ? d.decisionStatus : "Needs verification")}</td><td>${escapeText(d.reviewAt || "Not set")}</td><td>${escapeText(d.reason)}</td><td><button class="secondary-button" data-action="revoke-decision" data-value="${escapeText(d.id)}">Revoke</button></td></tr>`).join("")}</tbody></table></div>` : `<p>No local decisions.</p>`}</section>
      <section class="panel"><h3>GitHub filing receipts</h3>${state.receipts.length ? `<div class="table-wrap"><table><thead><tr><th>Repository / CVE</th><th>Outcome</th><th>Recorded</th><th>Issue</th></tr></thead><tbody>${state.receipts.map((r) => `<tr><td>${escapeText(r.repository)} / ${escapeText(r.cve)}</td><td>${escapeText(r.status)}</td><td>${escapeText(r.updatedAt)}</td><td>${safeUrl(r.url) ? `<a target="_blank" rel="noreferrer noopener" href="${escapeText(safeUrl(r.url))}">Issue ${escapeText(r.number)}</a>` : escapeText(r.message || "Reconcile before retry")}</td></tr>`).join("")}</tbody></table></div>` : `<p>No recorded filing attempts.</p>`}</section>
      <section class="panel"><h3>Compare inventories <span class="badge">Experimental</span></h3><div class="form-grid"><label class="field-label">Earlier snapshot<select class="select" id="compareBefore">${options}</select></label><label class="field-label">Later snapshot<select class="select" id="compareAfter">${options}</select></label><button class="secondary-button" data-action="compare-inventories" ${inventories.length < 2 ? "disabled" : ""}>Compare</button></div><div id="comparisonResult"></div></section>
      <section class="panel"><h3>Email monitor configuration</h3><p>Deployment and delivery: not verified. Local watches do not enable AWS monitoring.</p>${input("Notification email", "monitorEmail", "", "email")}<label class="field-label">Monitored CVEs (maximum 25)<textarea id="monitorCves" class="textarea">${escapeText(state.watchlist.map((x) => x.id).join("\n"))}</textarea></label><button class="secondary-button" data-action="monitor-config">Export operator configuration</button><p><a href="https://github.com/jaysonguglietta/VulnScope/blob/feature/github-repository-scan/docs/deployment.md" target="_blank" rel="noreferrer noopener">Deployment and subscription verification procedure</a></p></section>
      </article>`;
    focusContent();
  }

  function renderResearchExtras(item) {
    let result = "";
    if (["evidence", "real-world", "realworld", "overview"].includes(state.activeTab)) {
      const claims = item.claims || [];
      result += `<section class="panel"><h3>Claim review</h3><p>${claims.length} source claims; analyst decisions apply only to this case.</p>${claims.map((claim) => {
        const review = item.caseDraft?.claimReviews?.[claim.id];
        return `<details class="claim-record"><summary>${escapeText(claim.title)} <span class="badge">${escapeText(review?.status || claim.review || "Unreviewed")}</span></summary><p>${escapeText(claim.authority)}. Published ${escapeText(claim.publishedAt || "unknown")}; checked ${escapeText(claim.checkedAt || item.generatedAt)}${claim.withdrawn ? "; WITHDRAWN" : ""}.</p><pre class="claim-body">${escapeText(claim.body)}</pre>${claim.packages?.length ? `<ul>${claim.packages.map((p) => `<li>${escapeText(p.ecosystem)} ${escapeText(p.package)}: ${escapeText(p.vulnerableRange)}; first patched: ${escapeText(p.firstPatchedVersion || "unknown")}</li>`).join("")}</ul>` : ""}<p>${escapeText(review?.reason || "No local review recorded.")}</p><div class="toolbar"><a class="secondary-button" target="_blank" rel="noreferrer noopener" href="${escapeText(safeUrl(claim.url))}">Source</a><button class="secondary-button" data-action="review-claim" data-value="${escapeText(claim.id)}">Review claim</button></div></details>`;
      }).join("")}</section>`;
    }
    if (["remediation", "workspace"].includes(state.activeTab)) {
      const plan = item.caseDraft?.plan || makePlan(item);
      result += `<section class="panel"><h3>Scoped remediation plan</h3><form id="remediationPlan"><div class="form-grid">${input("Target package or asset", "target", plan.target)}${input("Installed version", "installedVersion", plan.installedVersion)}${select("Action", "action", ["Patch", "Mitigate", "Investigate"], plan.action)}${input("Owner", "owner", plan.owner)}${input("Target date (local policy)", "targetDate", plan.targetDate, "date")}${plan.fixedOptions?.length ? select("Applicable fix (verify supported branch)", "selectedFix", ["", ...plan.fixedOptions], plan.selectedFix) : input("Vendor-verified fixed version", "selectedFix", plan.selectedFix)}</div>${area("Prerequisites", "prerequisites", plan.prerequisites)}${area("Remediation steps", "steps", plan.steps)}${area("Post-change verification", "verification", plan.verification)}${area("Recovery / rollback considerations", "rollback", plan.rollback)}${area("Plan notes and unresolved questions", "notes", plan.notes)}${area("Source links (one per line)", "sources", plan.sources?.join("\n"))}<button type="button" class="primary-button" data-action="save-plan">Save plan to case</button></form></section>`;
    }
    return result;
  }

  async function savePlanFromForm() {
    const form = document.querySelector("#remediationPlan");
    if (!form || !state.current) return;
    const values = Object.fromEntries(new FormData(form));
    const previous = state.current.caseDraft.plan || makePlan(state.current);
    state.current.caseDraft.plan = { ...previous, ...values, sources: values.sources.split("\n").map(safeUrl).filter(Boolean).slice(0, 30) };
    state.dirty = true;
    if (await saveCurrentCase()) { render(); showToast("Scoped plan saved. Copy remediation includes these edits."); }
  }

  async function reviewClaim(id) {
    const claim = state.current?.claims?.find((x) => x.id === id);
    if (!claim) return;
    const old = state.current.caseDraft.claimReviews?.[id] || {};
    const choice = await dialogForm("Review evidence claim", `<p>${escapeText(claim.title)}</p>${select("Decision", "status", ["Accepted for this case", "Rejected lead", "Conflicting evidence", "Needs verification"], old.status)}${area("Reason and supporting source", "reason", old.reason)}`);
    if (choice.action !== "save") return;
    if (!choice.data.reason.trim()) throw new Error("A review rationale and supporting source are required.");
    state.current.caseDraft.claimReviews ||= {};
    state.current.caseDraft.claimReviews[id] = { ...choice.data, at: new Date().toISOString() };
    state.dirty = true;
    render();
    showToast("Claim decision added to draft. Save the case to retain it.");
  }

  async function decideExposure(scope) {
    const row = getExposureRows().find((x) => occurrenceKey(x) === scope);
    if (!row) return;
    const old = state.decisions.find((d) => d.scope === scope);
    const choice = await dialogForm("Target decision", `<p>${escapeText(row.vulnerability)} / ${escapeText(row.packageName || row.assetId)} / ${escapeText(row.installedVersion)} / ${escapeText(row.account)} ${escapeText(row.region)}</p>${select("Disposition", "decisionStatus", ["Needs verification", "Affected", "Under investigation", "Not affected", "Mitigated", "Accepted risk", "Fixed"], old?.decisionStatus)}${input("Owner label (not authenticated)", "owner", old?.owner)}${input("Review by", "reviewAt", old?.reviewAt?.slice(0, 10), "date")}${area("Rationale", "reason", old?.reason)}${area("Verification evidence / source links", "verification", old?.verification)}`, [["save", "Save scoped decision"], ["plan", "Create remediation plan"], ["cancel", "Cancel"]]);
    if (choice.action === "cancel") return;
    if (choice.action === "plan") {
      const item = state.researchRecords[row.vulnerability] || state.cases.find((c) => c.id === row.vulnerability)?.investigation;
      if (!item) throw new Error("Research this CVE first, then create its scoped plan.");
      state.current = context.attachCaseDraft(item);
      state.current.caseDraft.plan = makePlan(state.current, row);
      state.view = "investigation"; state.activeTab = "remediation"; state.dirty = true;
      render(); focusContent(); return;
    }
    const data = choice.data;
    if (!data.reason.trim()) throw new Error("A rationale is required.");
    if (["Fixed", "Not affected"].includes(data.decisionStatus) && !data.verification.trim()) throw new Error("Fixed and Not affected require target-specific verification evidence.");
    if (!data.reviewAt) throw new Error("A scoped decision requires a review date.");
    if (data.reviewAt && Date.parse(data.reviewAt + "T23:59:59Z") <= Date.now()) throw new Error("Choose a future review date.");
    const record = { id: old?.id || crypto.randomUUID(), scope, target: `${row.vulnerability} ${row.packageName || row.assetName}@${row.installedVersion}`, ...data, reviewAt: data.reviewAt ? data.reviewAt + "T23:59:59Z" : null, approved: true, updatedAt: new Date().toISOString(), previous: old ? [...(old.previous || []), { status: old.decisionStatus, reason: old.reason, at: old.updatedAt }].slice(-30) : [] };
    const saved = await store.put("decisions", record, old?.revision || 0);
    state.decisions = [saved, ...state.decisions.filter((d) => d.id !== saved.id)]; notify(); render();
  }

  async function revokeDecision(id) {
    const old = state.decisions.find((d) => d.id === id);
    if (!old || !window.confirm(`Revoke the decision for ${old.target}?`)) return;
    const saved = await store.put("decisions", { ...old, approved: false, updatedAt: new Date().toISOString() }, old.revision);
    state.decisions = state.decisions.map((d) => d.id === id ? saved : d); notify(); renderTools();
  }

  function removeImport(id, kind) {
    if (!window.confirm("Remove this import and its derived enrichment? Unrelated imports are retained.")) return;
    context.cancelImports();
    if (kind === "evidence") state.evidenceReports = state.evidenceReports.filter((r) => r.id !== id);
    else { state.sbomReports = state.sbomReports.filter((r) => r.id !== id); state.enrichmentReports = state.enrichmentReports.filter((r) => r.sbomId !== id); }
    state.activeSbomId = state.activeEvidenceId = null;
    state.view = "exposures"; state.current = null;
    renderSbomList(); renderEvidenceList(); render();
  }

  function renderComparison() {
    const entries = [...state.sbomReports, ...state.enrichmentReports, ...(state.githubScan ? [{ ...state.githubScan, id: "current-repository" }] : [])];
    const before = entries.find((r) => r.id === document.querySelector("#compareBefore").value);
    const after = entries.find((r) => r.id === document.querySelector("#compareAfter").value);
    if (!before || !after || before.id === after.id) throw new Error("Select two different inventory snapshots.");
    const comparison = compareInventories(before, after);
    const filter = document.createElement("input"); filter.className = "input"; filter.type = "search"; filter.setAttribute("aria-label", "Filter comparison");
    const result = document.querySelector("#comparisonResult");
    result.innerHTML = `<p>Earlier coverage: ${escapeText(comparison.beforeStatus)}. Later coverage: ${escapeText(comparison.afterStatus)}. Missing packages are not automatically fixed.</p>`;
    result.append(filter);
    const table = document.createElement("div"); table.className = "table-wrap"; result.append(table);
    const paint = () => {
      const rows = comparison.rows.filter((r) => JSON.stringify([r.name, r.purl, r.version, r.comparison]).toLowerCase().includes(filter.value.toLowerCase()));
      table.innerHTML = `<p>${rows.length} matching package versions; first 200 displayed.</p><table><thead><tr><th>Package</th><th>Version</th><th>Change</th></tr></thead><tbody>${rows.slice(0, 200).map((r) => `<tr><td>${escapeText(r.name || r.purl)}</td><td>${escapeText(r.version)}</td><td>${escapeText(r.comparison)}</td></tr>`).join("")}</tbody></table>`;
    };
    filter.addEventListener("input", paint); paint();
    const exportButton = document.createElement("button"); exportButton.className = "secondary-button"; exportButton.textContent = "Export full comparison";
    exportButton.onclick = () => download("inventory-comparison.json", JSON.stringify(comparison, null, 2), "application/json"); result.append(exportButton);
  }

  async function exportMonitorConfig() {
    const email = document.querySelector("[name=monitorEmail]");
    const text = document.querySelector("#monitorCves").value;
    const ids = [...new Set(text.toUpperCase().split(/[\s,]+/).filter(Boolean))];
    if (!email.value || !email.checkValidity()) throw new Error("Enter a valid notification email.");
    if (!ids.length || ids.length > 25 || ids.some((id) => !/^CVE-\d{4}-\d{4,}$/.test(id))) throw new Error("Choose 1-25 valid CVE IDs. No entries are silently omitted.");
    const data = { notificationEmail: email.value.trim(), monitoredCves: ids, region: "us-east-1", deploymentState: "not verified", subscriptionState: "not verified", deliveryState: "not verified", prerequisites: ["Approved whole-deployment bundle", "DEPLOYMENT_BUNDLE_PATH", "DEPLOYMENT_BUNDLE_SHA256", "RELEASE_SOURCE_SHA", "RELEASE_SOURCE_REF", "Confirm SNS subscription email", "Run the documented operator status check"], environment: { NOTIFICATION_EMAIL: email.value.trim(), MONITORED_CVES: ids.join(",") } };
    download("vulnscope-monitor-config.json", JSON.stringify(data, null, 2), "application/json");
    showToast("Operator configuration exported. No AWS changes or email sent.");
  }

  return { renderTools, exportWorkspace, restoreWorkspace, renderResearchExtras, savePlanFromForm, reviewClaim, decideExposure, revokeDecision, removeImport, renderComparison, exportMonitorConfig };
}
