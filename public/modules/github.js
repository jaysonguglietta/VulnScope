const CVE_PATTERN = /^CVE-\d{4}-\d{4,}$/i;
const SEVERITY_ORDER = new Map([
  ["CRITICAL", 5],
  ["HIGH", 4],
  ["MODERATE", 3],
  ["MEDIUM", 3],
  ["LOW", 2],
  ["UNKNOWN", 1]
]);

export function buildRepositoryCveFindings(scan) {
  const findings = new Map();
  for (const pkg of arrayValue(scan?.packages).slice(0, 500)) {
    for (const vulnerability of arrayValue(pkg?.vulnerabilities).slice(0, 100)) {
      const cves = unique(arrayValue(vulnerability?.cves)
        .concat(arrayValue(vulnerability?.aliases))
        .map((value) => String(value || "").toUpperCase())
        .filter((value) => CVE_PATTERN.test(value)));
      for (const cve of cves) {
        if (!findings.has(cve)) {
          findings.set(cve, {
            cve,
            severity: "UNKNOWN",
            summaries: [],
            packages: [],
            advisoryIds: [],
            references: [],
            withdrawn: true
          });
        }
        const finding = findings.get(cve);
        const severity = normalizeSeverity(vulnerability?.severity);
        if (severityRank(severity) > severityRank(finding.severity)) finding.severity = severity;
        if (vulnerability?.summary) finding.summaries.push(String(vulnerability.summary));
        if (vulnerability?.id) finding.advisoryIds.push(String(vulnerability.id));
        finding.references.push(...arrayValue(vulnerability?.references).map((reference) => reference?.url).filter(isSafeHttpUrl));
        finding.withdrawn = finding.withdrawn && Boolean(vulnerability?.withdrawn);
        finding.packages.push({
          key: String(pkg?.purl || `${pkg?.ecosystem || "package"}:${pkg?.name || "unknown"}@${pkg?.version || "unknown"}`),
          name: String(pkg?.name || packageNameFromPurl(pkg?.purl) || "Unknown package"),
          version: String(pkg?.version || packageVersionFromPurl(pkg?.purl) || "Unknown"),
          purl: String(pkg?.purl || ""),
          ecosystem: String(pkg?.ecosystem || ""),
          fixedVersions: unique(arrayValue(vulnerability?.fixedVersions).map(String).filter(Boolean)),
          advisoryId: String(vulnerability?.id || "")
        });
      }
    }
  }

  return [...findings.values()].map((finding) => ({
    ...finding,
    summaries: unique(finding.summaries).slice(0, 5),
    packages: uniqueBy(finding.packages, (pkg) => pkg.key.toLowerCase()).slice(0, 100),
    advisoryIds: unique(finding.advisoryIds).slice(0, 50),
    references: unique(finding.references).slice(0, 20)
  })).sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || a.cve.localeCompare(b.cve));
}

export function buildGitHubIssueDraft(finding, repository, generatedAt = new Date().toISOString()) {
  const packages = arrayValue(finding?.packages).slice(0, 30);
  const repositoryCandidate = bounded(repository?.fullName, 220);
  const repositoryName = /^[a-z0-9](?:[a-z0-9-]{0,38})\/[a-z0-9._-]{1,100}$/i.test(repositoryCandidate)
    ? repositoryCandidate
    : "unknown/repository";
  const cve = CVE_PATTERN.test(String(finding?.cve || "")) ? String(finding.cve).toUpperCase() : "CVE-UNKNOWN";
  const packageTitle = packages.length === 1
    ? `${bounded(packages[0].name, 80)}@${bounded(packages[0].version, 40)}`
    : `${packages.length} dependencies`;
  const title = bounded(`[Security] ${cve} affects ${packageTitle}`, 240);
  const packageRows = packages.map((pkg) => {
    const identity = pkg.purl || `${pkg.name}@${pkg.version}`;
    return `| ${markdownCell(identity)} | ${markdownCell(pkg.version || "Unknown")} | ${markdownCell(pkg.fixedVersions?.join(", ") || "Not reported")} |`;
  });
  const body = [
    `<!-- vulnscope:${cve}:${repositoryName.toLowerCase()} -->`,
    `## Confirmed dependency vulnerability`,
    "",
    `VulnScope matched **${markdownInline(cve)}** to versioned dependencies reported by the repository inventory for **${markdownInline(repositoryName)}**.`,
    "",
    `- Severity signal: **${markdownInline(normalizeSeverity(finding?.severity))}**`,
    `- OSV records: ${arrayValue(finding?.advisoryIds).map((value) => `\`${markdownCode(value)}\``).join(", ") || "Not reported"}`,
    `- Repository scan: https://github.com/${repositoryName}`,
    `- Scanned at: ${markdownInline(generatedAt)}`,
    finding?.withdrawn ? "- OSV status: **Withdrawn; validate before remediation**" : null,
    "",
    "### Affected dependencies",
    "",
    "| Package | Detected version | Known fixed versions |",
    "| --- | --- | --- |",
    ...packageRows,
    ...(finding?.packages?.length > packages.length ? [`| ... | ${finding.packages.length - packages.length} additional package matches | See VulnScope scan |`] : []),
    "",
    "### Validation and remediation",
    "",
    "- [ ] Confirm the dependency and version are present in the deployed artifact.",
    "- [ ] Review the linked vendor and OSV advisories for applicability.",
    "- [ ] Upgrade to an applicable fixed version or document a compensating control.",
    "- [ ] Rebuild and rescan the repository inventory.",
    "",
    "### References",
    "",
    `- https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve)}`,
    `- https://osv.dev/list?q=${encodeURIComponent(cve)}`,
    ...arrayValue(finding?.references).filter(isSafeHttpUrl).slice(0, 10).map((url) => `- ${url}`),
    "",
    "> Analyst confirmation in VulnScope means the dependency match was reviewed before issue creation. It is not proof that the vulnerable code path is reachable or exploitable."
  ].filter((line) => line !== null).join("\n").slice(0, 60000);
  return {
    cve,
    title,
    body,
    draftUrl: `https://github.com/${repositoryName}/issues/new?title=${encodeURIComponent(title)}&body=${encodeURIComponent(body)}`
  };
}

function normalizeSeverity(value) {
  const severity = String(value || "UNKNOWN").trim().toUpperCase();
  return SEVERITY_ORDER.has(severity) ? severity : "UNKNOWN";
}

function severityRank(value) {
  return SEVERITY_ORDER.get(normalizeSeverity(value)) || 0;
}

function packageNameFromPurl(value) {
  const path = String(value || "").split(/[?#]/)[0].replace(/^pkg:[^/]+\//i, "").split("@")[0];
  return safeDecode(path.split("/").pop() || "");
}

function packageVersionFromPurl(value) {
  return safeDecode(String(value || "").match(/@([^?#]+)(?:[?#]|$)/)?.[1] || "");
}

function safeDecode(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return String(value || "");
  }
}

function markdownCell(value) {
  return bounded(value, 1000).replace(/\|/g, "\\|").replace(/[\r\n]+/g, " ").replace(/`/g, "'");
}

function markdownInline(value) {
  return bounded(value, 1000).replace(/[\r\n]+/g, " ").replace(/[*_`<>]/g, "");
}

function markdownCode(value) {
  return bounded(value, 200).replace(/[`\r\n]/g, "");
}

function bounded(value, maxLength) {
  return String(value || "").replace(/[\u0000-\u001f\u007f]/g, " ").trim().slice(0, maxLength);
}

function isSafeHttpUrl(value) {
  try {
    return ["http:", "https:"].includes(new URL(String(value || "")).protocol);
  } catch {
    return false;
  }
}

function arrayValue(value) {
  return Array.isArray(value) ? value : [];
}

function unique(values) {
  return [...new Set(values)];
}

function uniqueBy(values, keyFn) {
  const seen = new Set();
  return values.filter((value) => {
    const key = keyFn(value);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
