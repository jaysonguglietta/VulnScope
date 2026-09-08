# Changelog

## Unreleased

### 0.4.0 Product Readiness

- Implement the 16-item September readiness backlog within the browser-local/public-data boundary; track external validation separately in `docs/product-readiness.md`.
- Add transactional IndexedDB cases/watches/decisions/receipts, legacy migration, cross-tab revision checks, truthful save errors and unsaved navigation guards; remove silent retention/capacity eviction.
- Add bounded, versioned workspace backup/restore with opt-in inventory and trust reset, plus complete analyst-note/plan handoffs.
- Preserve unknown and dated stale KEV/EPSS/CVSS observations; add source-content-bound claim review, full advisory narratives, CNA guidance and explicit manual-review leads.
- Preserve package versions, range bounds and cloud account/region provenance; use PackageURL and semver libraries for supported identity/comparison operations.
- Join research, bulk triage, enriched SBOM drilldown and repository exposures; add pagination, scoped dispositions, editable remediation plans and per-import removal.
- Add resumable OSV package/detail/page batches, asynchronous GitHub SBOM report polling/fallback, cancel/retry controls and a shared 17-second API deadline.
- Persist token-free GitHub confirmation snapshots and issue receipts; block automatic duplicate writes after unknown outcomes or identical completed drafts.
- Add explicit monitor configuration export and read-only operator status command; reject excessive monitored-CVE lists.
- Add mobile navigation, labeled forms, browser history and an experimental inventory comparison with no automatic closure.
- Gate CI/release builds with offline browser workflows; add model/deadline/adapter tests and a separate public provider contract check.
- Authentication and request/activity logging remain deferred. No AWS deployment, resource recreation, or real issue/email write is included.

### September 2026 Security Remediation

- Address all 11 confirmed findings from the September 6 adversarial audit.
- Remove credentials from public GitHub reads and reject private/unverified results before caching.
- Scope embedded VEX approval by CVE, package/version and file; preserve mixed/conflicting decisions.
- Distinguish failed, partial, and complete OSV coverage; retain primary CVE IDs and unresolved advisories.
- Reject forwarded address chains and bound limiter state.
- Move XML, SBOM parsing and report aggregation into a fail-closed, resource-bounded worker.
- Disclose raw-row caps, unsupported versions and incomplete repository inventories.
- Verify one source-bound release bundle containing Lambda, frontend and infrastructure.
- Persist monitor notifications before SNS delivery and advance baselines only after acceptance.
- Require explicit issue reuse and display full issue bodies; allow cancelling without publication.
- Classify cloud sources by parsed authority and avoid treating source identity as proven service impact.
- Add adversarial regressions and archive tampering tests; update all operational documentation.
- Authentication and request/activity logging remain intentionally out of scope. No deployment or publishing is performed by this change.

- Add bounded public GitHub dependency-graph scanning with OSV CVE matching.
- Fall back to bounded public lockfile inspection when GitHub's generated SBOM is unavailable.
- Add analyst confirmation, duplicate checks, prefilled issue drafts, and direct
  GitHub issue publishing with an ephemeral fine-grained token.
- Document the complete analyst workflow, supported lockfile fallback, scan
  limits, token separation, API contract, recovery paths, and security boundary.
- Correct the deployment cost notes to reflect the CloudFront WAF resources in
  the current production template.

## 0.3.0 - 2026-08-11

Security hardening release for VulnScope's public research API, browser evidence
workflows, vulnerability matching, exports, AWS infrastructure, and release
pipeline.

### Security

- Bound OSV enrichment fan-out, upstream concurrency, response bytes, deadlines,
  cache growth, API capacity, and public-origin access.
- Require analyst-approved, exact-product VEX matches before suppressive claims
  can lower exposure priority.
- Neutralize spreadsheet formulas in CSV exports while preserving typed numbers
  and booleans.
- Move cloud and VEX evidence parsing into a fail-closed worker with explicit
  file, row, nesting, dimension, cell, and expansion budgets.
- Bind OSV fixed versions and affected ranges to the queried package instead of
  returning fixes from unrelated package entries.
- Reject invalid upstream dates and encode every rendered date value.
- Add immutable action and container references, dependency signature checks,
  release checksums, SPDX SBOM generation, and GitHub build provenance.
- Manage deployment artifacts and Lambda log retention in CloudFormation,
  tighten log-write IAM resources, and scan infrastructure in CI.
- Add AWS managed known-bad-input WAF protection alongside API rate limiting.

### Deployment

- Production AWS deployment now requires a checksum-verified, GitHub-attested
  Lambda artifact by default.
- Set `ALLOW_LOCAL_UNSIGNED_BUILD=1` only for a documented emergency deployment.
- Deployment artifacts expire after 30 days by default; Lambda logs are retained
  for 30 days.

### Fixed Issues

- [#1](https://github.com/jaysonguglietta/VulnScope/issues/1)
- [#2](https://github.com/jaysonguglietta/VulnScope/issues/2)
- [#3](https://github.com/jaysonguglietta/VulnScope/issues/3)
- [#4](https://github.com/jaysonguglietta/VulnScope/issues/4)
- [#5](https://github.com/jaysonguglietta/VulnScope/issues/5)
- [#6](https://github.com/jaysonguglietta/VulnScope/issues/6)
- [#7](https://github.com/jaysonguglietta/VulnScope/issues/7)
- [#8](https://github.com/jaysonguglietta/VulnScope/issues/8)
