import { PackageURL } from "packageurl-js";
import semver from "semver";

export function parsedPackage(value) {
  try { return PackageURL.fromString(String(value)); } catch { return null; }
}

export function matchSemverRange(version, range) {
  if (range?.versionType !== "semver" || !semver.valid(version) || !semver.valid(range.version) || range.changes?.length) return "Unknown version applicability";
  const expression = range.lessThan ? `>=${range.version} <${range.lessThan}` : range.lessThanOrEqual ? `>=${range.version} <=${range.lessThanOrEqual}` : range.version;
  if (!semver.validRange(expression)) return "Unknown version applicability";
  const matches = semver.satisfies(version, expression, { includePrerelease: true });
  return matches ? range.status === "affected" ? "Matches reported affected range" : `Reported ${range.status || "unknown"}` : "Outside this reported range (check other advisories)";
}

export function packageKey(pkg) {
  return JSON.stringify([pkg.purl || "", pkg.ecosystem || pkg.packageManager || "", pkg.name || pkg.packageName || "", pkg.version || pkg.installedVersion || ""]);
}

export function occurrenceKey(row) {
  return JSON.stringify([row.vulnerability, row.purl, row.packageName, row.installedVersion, row.assetId || row.assetName, row.account, row.region, row.sourceRecordId || row.sourceFile]);
}

export function kevLabel(item) {
  const value = item?.metrics?.kev;
  if (value?.listed) return item?.observations?.kev?.state === "stale" ? "Listed (last known; source unavailable)" : "Listed";
  return value && value.listed === false ? item?.observations?.kev?.state === "stale" ? "Not listed in last known catalog; current status unknown" : "Not listed in checked catalog" : "Unknown - catalog unavailable";
}

export function normalizeResearch(item, previous) {
  if (!item) return item;
  const data = structuredClone(item);
  const sources = data.sourceResults || [];
  const ok = (id) => sources.some((source) => source.id === id && source.status === "ok");
  const checkedAt = data.generatedAt || new Date().toISOString();
  data.observations = { ...data.observations };
  data.metrics ||= {};
  for (const [field, source] of [["kev", "kev"], ["epss", "epss"], ["cvss", "nvd"]]) {
    const available = field === "cvss" ? (ok("nvd") || ok("cve")) && data.metrics[field] != null : ok(source) && data.metrics[field] != null;
    if (available) data.observations[field] = { state: "observed", dataAsOf: checkedAt, checkedAt, source };
    else if (previous?.metrics?.[field] != null) {
      data.metrics[field] = structuredClone(previous.metrics[field]);
      data.observations[field] = { state: "stale", dataAsOf: previous.observations?.[field]?.dataAsOf || previous.generatedAt, checkedAt, source };
    } else if (!(data.observations[field]?.state === "stale" && data.metrics[field] != null)) {
      data.metrics[field] = null;
      data.observations[field] = { state: "unavailable", dataAsOf: null, checkedAt, source };
    }
  }
  const primary = ok("nvd") || ok("cve");
  const exploitSources = ["kev", "github", "vulncheck"].filter(ok);
  data.assessment = { state: primary ? (sources.some((s) => s.status !== "ok") ? "partial" : "complete") : "unavailable", checkedAt, policyVersion: 1, missingSources: sources.filter((s) => s.status !== "ok").map((s) => s.id) };
  if (!primary && !data.metrics.kev?.listed) {
    data.risk = { score: null, level: "Unknown", reasons: ["Primary CVE records unavailable; priority cannot be assessed."] };
    data.realWorld = { ...data.realWorld, score: null, verdict: "Insufficient current evidence", exploitedStatus: "Unknown - primary sources unavailable", publicExploitLevel: "Unknown - incomplete research", chatterLevel: "Unknown - incomplete research", summary: "Research is incomplete. Inspect source health and retry; unavailable evidence is not a negative finding." };
    data.exploitMaturity = { ...data.exploitMaturity, stage: "Unknown - research incomplete", score: null };
    data.executiveSummary = data.realWorld.summary;
    data.realWorld.counts = { ...data.realWorld.counts, totalChatter: null };
    for (const key of ["executiveBrief", "ticketExport", "riskAcceptance"]) data[key] = { ...data[key], plainText: `${data.id}: ${data.realWorld.summary}` };
  } else if (!data.metrics.kev?.listed && !exploitSources.length) {
    data.realWorld = { ...data.realWorld, verdict: "Insufficient exploitation evidence", exploitedStatus: "Unknown - exploitation sources unavailable", summary: "Exploitation sources are unavailable. Severity remains relevant, but real-world exploitation cannot currently be assessed." };
    data.exploitMaturity = { ...data.exploitMaturity, stage: "Unknown - exploitation sources unavailable", score: null };
    data.executiveSummary = data.realWorld.summary;
  }
  if (data.observations.kev.state === "stale" && data.metrics.kev?.listed) {
    data.realWorld = { ...data.realWorld, exploitedStatus: "Known exploited (last known catalog; current check unavailable)" };
    if (previous?.risk && (previous.risk.score || 0) > (data.risk?.score || 0)) data.risk = { ...previous.risk, stale: true };
  }
  if (primary && !data.metrics.kev?.listed && data.observations.kev.state !== "observed") {
    data.realWorld = { ...data.realWorld, verdict: "Assessment incomplete", exploitedStatus: "Exploitation not fully assessed; current KEV catalog unavailable", summary: "Review available source evidence and severity. Current known-exploitation catalog status is unavailable, not a negative finding." };
    data.executiveSummary = data.realWorld.summary;
  }
  data.metrics.realWorld = data.realWorld;
  data.metrics.exploitMaturity = data.exploitMaturity;
  return data;
}

export function affectedRangeText(range = {}) {
  const lower = range.version || "unspecified";
  const upper = range.lessThan ? `< ${range.lessThan}` : range.lessThanOrEqual ? `<= ${range.lessThanOrEqual}` : "";
  const changes = (range.changes || []).map((x) => `${x.at}: ${x.status}`).join("; ");
  return `${upper ? `>= ${lower}, ${upper}` : lower} (${range.status || "unknown"}; ${range.versionType || "unspecified version scheme"})${changes ? `; changes: ${changes}` : ""}`;
}

export async function buildResearchClaims(cve, { cveOrg, githubAdvisories, kev, references = [] }, checkedAt) {
  const claims = [];
  const add = (value) => claims.push({ id: `${cve}:claim:${claims.length}`, cve, checkedAt, review: "Unreviewed", ...value });
  if (kev?.listed) add({ type: "exploitation", title: "CISA reports known exploitation", source: "CISA KEV", url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", publishedAt: kev.dateAdded, body: kev.requiredAction || "CVE is present in the checked catalog.", authority: "Catalog observation", review: "Source confirmed" });
  for (const advisory of (githubAdvisories?.items || []).slice(0, 10)) {
    add({ type: "advisory", title: advisory.summary || advisory.id, source: "GitHub Advisory Database", url: advisory.url, publishedAt: advisory.publishedAt, modifiedAt: advisory.updatedAt, withdrawn: Boolean(advisory.withdrawnAt), body: String(advisory.description || "No advisory narrative returned.").slice(0, 16000), packages: advisory.vulnerabilities || [], authority: "Advisory narrative; verify applicability" });
  }
  for (const field of ["solutions", "workarounds", "impacts"]) for (const entry of (cveOrg?.containers?.cna?.[field] || []).slice(0, 10)) {
    if (entry.value) add({ type: field, title: `CNA ${field}`, source: "CVE CNA", url: `https://www.cve.org/CVERecord?id=${cve}`, body: String(entry.value).slice(0, 12000), authority: "Publisher statement; verify applicability" });
  }
  for (const ref of references.slice(0, 40)) add({ type: "reference", title: ref.title || ref.url, source: ref.source || "CVE reference", url: ref.url, body: "Linked source has not been independently read by VulnScope. Review it before accepting a claim.", authority: "Manual review required" });
  return Promise.all(claims.map(async (claim) => {
    const bytes = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(JSON.stringify([cve, claim.type, claim.source, claim.url, claim.body, claim.packages])));
    return { ...claim, id: `${cve}:claim:${[...new Uint8Array(bytes)].map((n) => n.toString(16).padStart(2, "0")).join("")}` };
  }));
}

export function makePlan(item, target = {}) {
  return { target: target.purl || [target.packageName || target.assetName, target.installedVersion].filter(Boolean).join("@") || "Target not yet confirmed", installedVersion: target.installedVersion || "Unknown", fixedOptions: target.fixedVersions || [], selectedFix: "", owner: item.caseDraft?.owner || "", targetDate: "", action: "Patch", prerequisites: "Confirm the affected version, deployed artifact and vendor-supported upgrade branch. Record backups and change approval.", steps: item.remediation?.plainText || "Review vendor guidance and record target-specific steps.", verification: "Rebuild/redeploy as applicable, confirm the running version, rescan the same target and perform functional health checks.", rollback: "Record the tested restore/redeploy procedure and conditions for rollback. Do not assume restoring a vulnerable version is an acceptable permanent state.", notes: "", sources: (item.remediation?.primaryLinks || item.references || []).slice(0, 12).map((x) => x.url).filter(Boolean) };
}

export function planText(plan) {
  if (!plan) return "No scoped remediation plan saved.";
  return [`Target: ${plan.target}`, `Installed: ${plan.installedVersion}`, `Action: ${plan.action}`, `Chosen fixed version: ${plan.selectedFix || "Not selected; verify supported branch"}`, `Known fix candidates: ${plan.fixedOptions?.join(", ") || "Not reported"}`, `Owner: ${plan.owner || "Unassigned"}`, `Target date (local policy): ${plan.targetDate || "Not set"}`, "", "Prerequisites", plan.prerequisites, "", "Steps", plan.steps, "", "Verification", plan.verification, "", "Recovery considerations", plan.rollback, "", plan.notes, "", "Sources", ...(plan.sources || [])].join("\n");
}

export function caseHandoff(item, audience = "Engineering handoff") {
  const draft = item.caseDraft || {};
  return [`# ${item.id} - ${audience}`, item.title, `Researched: ${item.generatedAt || "Unknown"}`, `Assessment: ${item.assessment?.state || "Unverified legacy record"}`, `Heuristic priority: ${item.risk?.level || "Unknown"} (${item.risk?.score ?? "Unknown"}/100)`, `KEV: ${kevLabel(item)}`, `Exploitation: ${item.realWorld?.exploitedStatus || "Unknown"}`, `Status: ${draft.status || "Needs triage"}`, `Owner: ${draft.owner || "Unassigned"}`, `Tags: ${draft.tags || "None"}`, "", "Analyst notes", draft.notes || "None recorded", "", planText(draft.plan), "", "Evidence decisions", ...Object.entries(draft.claimReviews || {}).map(([id, value]) => `${id}: ${value.status}; ${value.reason}; reviewed ${value.at}`), "", "Source checks", ...(item.sourceResults || []).map((s) => `${s.label}: ${s.status} - ${s.message || ""}`)].join("\n");
}

export function applyDecisions(rows, decisions, now = Date.now()) {
  const byScope = new Map(decisions.map((d) => [d.scope, d]));
  return rows.map((row) => {
    const decision = byScope.get(occurrenceKey(row));
    if (!decision) return row;
    const active = decision.approved && decision.reviewAt && Date.parse(decision.reviewAt) > now;
    return { ...row, decision, owner: decision.owner || row.owner, workflowStatus: active ? decision.decisionStatus : "Needs verification", vexStatus: active && ["Fixed", "Not affected"].includes(decision.decisionStatus) ? decision.decisionStatus : row.vexStatus, priorityScore: active && ["Fixed", "Not affected"].includes(decision.decisionStatus) ? 0 : row.priorityScore, priority: active && ["Fixed", "Not affected"].includes(decision.decisionStatus) ? "Low" : row.priority };
  });
}

export function compareInventories(before, after) {
  const old = new Map((before?.components || before?.packages || []).map((p) => [packageKey(p), p]));
  const next = new Map((after?.components || after?.packages || []).map((p) => [packageKey(p), p]));
  const rows = [];
  for (const [key, pkg] of old) rows.push({ ...pkg, comparison: next.has(key) ? "Unchanged" : "Absent from later inventory (not verified fixed)", key });
  for (const [key, pkg] of next) if (!old.has(key)) rows.push({ ...pkg, comparison: "Added or changed version", key });
  return { rows, beforeStatus: before?.status || "Imported inventory; vulnerability coverage unknown", afterStatus: after?.status || "Imported inventory; vulnerability coverage unknown", closureVerified: false };
}
