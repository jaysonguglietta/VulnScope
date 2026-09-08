# Product Readiness: 0.4.0

Implementation date: September 8, 2026. This release addresses the 16-item
September 6 review on top of the existing 11-finding security remediation.
Authentication, authorization, tenant hosting, request/activity logging, and
AWS deployment remain outside the agreed implementation boundary.

## Product Brief

- **Users:** vulnerability analysts and engineers conducting browser-local public-CVE triage.
- **Problem:** retain trustworthy research, identify exact package/asset scope, and carry reviewed decisions through remediation handoff and issue filing.
- **Workflows:** research -> assess claims -> join inventory -> scope a decision/plan -> save/export -> confirm and file -> reconcile outcome.
- **Views:** research tabs, Exposures, SBOM/evidence detail, public GitHub scan, bulk queue, and Data and operations.
- **Models:** research observations/claims, versioned package occurrences, case drafts, revisioned local records, scoped decisions, continuation cursors, filing receipts and workspace backups.
- **Edge cases:** quotas, cross-tab conflicts, unsaved navigation, source outages, partial inventory, stale decisions, malformed restores, cancelled reads and uncertain external writes.
- **Assumptions:** single browser profile is the ownership boundary; imports are ephemeral unless exported; local owner labels are not authenticated identities; source availability and production applicability require independent validation.
- **Done for this version:** implemented local workflows, deterministic security/model/browser regression coverage, current documentation, and source pushed to GitHub. Live AWS/SNS qualification and user-value validation are separate checks, not implied by a passing local build.

## Implementation Matrix

| ID | Delivered behavior | Principal code / verification |
| --- | --- | --- |
| FR-01 | Per-record IndexedDB transactions, revisions, cross-tab notification, atomic migration, truthful save failure, draft guards, explicit deletion; no 40-record cap or 90-day auto-prune. | `persistence.js`, case/watch handlers; model concurrency tests and browser quota/reload/conflict tests. |
| FR-02 | Versioned bounded backup, opt-in normalized inventory, preview/merge/replace, incompatible-format rejection, imported trust reset; notes/owner/status/plan/source checks in handoff. | `persistence.js`, `workspace-tools.js`, `caseHandoff`; model malformed/duplicate/atomicity tests, browser export/restore. |
| FR-03 | Observed/unavailable/stale KEV/EPSS/CVSS with data and check dates; source outage preserves dated positives and cannot create a clean research verdict; explicit Unknown output. | Shared `research-model.js`, API synthesis, watch and export consumers; source-failure/EPSS-zero/stale fixture matrix. |
| FR-04 | Full bounded GitHub advisory narratives, CNA solutions/workarounds/impacts, dated KEV claim and explicit unreviewed links; content-bound claim IDs and local accept/reject/conflict rationale. Public code remains a lead, not automatically a verified exploit. | `buildResearchClaims`, Evidence/Real World claim review; narrative/link and browser review fixtures. Vendor-specific breadth and analyst benchmark remain validation work. |
| FR-05 | PackageURL parsing, versioned keys without indiscriminate lowercasing, retained CNA/NVD bounds, explicit-semver comparison, unknown unsupported schemes, Inspector account/region/source provenance. | Server, `github.js`, `workspace.js`, shared model; boundary, identity, cloud/parser and scope tests. |
| FR-06 | Session research cache, separate unlinked CVE triage, repository-to-Exposure action, enriched SBOM exact-CVE matches and package drilldown, retained originating workspace. | App state and derived views; browser latest-result/unlinked/enrichment/drilldown tests. |
| FR-07 | Per-import removal, dense-result pagination/search, 50-package enrichment batches, 40-detail continuations, per-package OSV pages and unresolved retries; preserve old results and inventory omissions. | App continuation merge, `/api/enrich`; 51-package/137-advisory fixtures and browser worker/search paths. Source inventory remains bounded. |
| FR-08 | Async GitHub generate/fetch adapter, repository-bound UUID, pending/resume, validated limited redirects, expiration/error handling and explicit lockfile fallback. | `lib/github-sbom.mjs`; pending/ready/unsafe-redirect fixtures. Live anonymous generation returned 404; fallback is retained. |
| FR-09 | Operation identity/epoch, latest-search-wins, cancel active reads, bounded Retry-After, retry remaining bulk work, resumable jobs, no automatic write retries. | `operations.js`, UI queue handlers; cancellation/retry and browser race fixtures. |
| FR-10 | Target-specific editable remediation plan, installed/fixed version candidates, chosen branch, prerequisites, steps, owner/date, verification, recovery and links; identical saved plan in copy/export/issue handoff. | `makePlan`, `planText`, remediation form; model handoff and browser persistence tests. Dates are local policy, not vendor SLAs. |
| FR-11 | Imported suppressions untrusted; exact-target decisions with rationale/evidence/review dates, local status/owner, revocation and expiry. No batch approval prompt. | `occurrenceKey`, `applyDecisions`, decision UI; account/version isolation and revoke/expiry tests. |
| FR-12 | Persisted token-free review snapshots/selection, SHA-256 draft receipt before POST, full body/manual download, per-item outcomes, exact-marker reconciliation and no repeat POST for an identical completed draft. | GitHub publishing handler and receipt store; offline explicit reuse/create/skip and browser interrupted-write tests. |
| FR-13 | Chosen email and explicit 1-25 CVEs exported with release prerequisites; separate local/deployment/subscription/delivery states; read-only operator status script. | `workspace-tools.js`, `monitor-status.mjs`, monitor config validator; no AWS calls from browser or normal tests. Live delivery remains unverified. |
| FR-14 | Top-of-page mobile workspace switcher, associated form labels, current-view indication, native focus-managed dialogs, browser back/forward, focus and overflow checks. | Shell/CSS/forms/history; Chromium 390/768/1440 workflows. Full WCAG/assistive-technology certification is not claimed. |
| FR-15 | Local model/security/browser gates, CI-owned Playwright, release browser gates, one API deadline including queues, adapter fixtures, public contract command and release qualification checklist. | `scripts/*`, workflows, request context; actual hosting qualification remains separately authorized. |
| FR-16 | Small **experimental** inventory comparison: unchanged, added/changed and absent records, coverage labels, searchable results and full export; never auto-closes a finding. | Shared model and Data and operations. User interviews and time-saved benchmark have not been performed. |

Paths in this table refer to `public/modules/` unless a server, app or script path
is specified. Source references in backups are data, not executable instructions.

## Data Contracts

`WorkspaceBackup` has `format: "vulnscope-workspace"`, `version: 1`, export time,
record collections and optional normalized inventory. Restore is bounded to
20 MiB, 40 nesting levels, 200,000 structural nodes, 10,000 records per collection,
and validated identities/shapes. Merge keeps existing IDs; replace is explicit.
Neither option imports trusted suppression authority. Imported receipts become
unknown until reconciled. No token field is allowed in the backup schema.

Case/watch/decision/receipt records have monotonically incremented local
revisions. Same-record stale writes fail and preserve the draft; they are not
automatically merged. Independent records coexist. Migration retains original
legacy localStorage keys; explicit clear records an atomic migration marker so
legacy records do not reappear.

Research observations contain `state`, `dataAsOf`, `checkedAt`, and source.
Missing evidence is unavailable, not zero. Saved investigations older than
24 hours, or with an older schema, show a stale banner. Refresh preserves the
saved draft and retains last-known valid numeric/catalog observations during an
outage. Claim IDs hash source URL, type, narrative and package evidence so changed
text does not inherit an unrelated review. The heuristic score is not a
probability, vendor attestation or proof of exploitability.

Decisions are scoped to CVE, package URL/name/version, asset identity, account,
region and source record/file. Every decision requires a review date. Fixed/Not
affected additionally require verification evidence. Expiry or revocation
restores evidence-derived priority. Case-level Closed is organizational status,
not automatic verification that every target is fixed.

OSV cursors are per package. Repeat detail failures keep the current page and
offset; completed results are merged by advisory ID. Exhausting selected
inventory is distinct from verifying the repository's complete runtime
inventory. Source inventory caps, unsupported identifiers, source outages and
changing upstream pages can still require a fresh scan.

## Operating the New Workflows

1. Research a CVE and inspect source health, observation dates and claim reviews.
2. Upload inventory locally; choose online OSV enrichment only when package metadata may be disclosed. Continue remaining batches explicitly.
3. Open Exposures, research a row, and return to its workspace. Use the target decision action to create a plan or record a dated disposition.
4. Save cases and keep workspace backups. Include normalized inventory only when permitted. Use the full Markdown/text handoff for engineering work.
5. For public GitHub findings, review the complete issue body and destination. Download long drafts. A token is optional for manual filing and never saved.
6. After an interrupted POST, do not retry manually until the target repository is checked. The application blocks an automatic repeat while the receipt is unresolved.
7. Monitoring configuration is an operator artifact, not a deployment. Read `deployment.md` and verify the intended account before any separately approved AWS action.

## Verification and Release Checklist

```bash
npm ci --ignore-scripts
npm run verify
npx playwright install chromium
npm run test:browser
npm audit signatures
npm run build:release
npm run test:bundle
# Dirty local inspection only: ALLOW_DIRTY_BUNDLE=1 npm run test:bundle
# Optional public network contract check, independent of deterministic gates:
npm run test:providers
```

The browser runner starts and closes an ephemeral local server and blocks all
external browser traffic except mocked responses. Tests never create real
issues, send email or mutate AWS. Screenshots are ignored local artifacts under
`.deploy/browser-checks/`. Model tests include concurrency, restore rejection,
unknown/stale data, identity/range boundaries, scoped expiry, async adapter
redirect rejection, 137 detail records, 51-package continuation and overall
deadline behavior. Browser tests exercise storage failure, same-record conflict,
backup/restore, rapid searches, SBOM enrichment joins, plans, decisions,
mobile/history and an interrupted issue POST.

Before production, require green Node 22 CI for the exact pushed commit, then
build and verify an attested release bundle from its reviewed tag/main ref.
Qualify that exact bundle on a separately authorized target: TLS/security
headers, blocked direct API origin, expected routes, degraded upstream states,
bounded slow requests, public repository fallback and fresh browser migration.
The local dirty-worktree archive is for inspection, not a production attestation.

Local validation on September 8 used Node 26.8.1: syntax/build, the existing
security/parser suites, all 11 audit regression groups, the new product model
groups, and both Chromium suites passed. Desktop/tablet/mobile viewport
screenshots were inspected; the heading/action layout and form labels were
corrected during validation. npm audit reported zero known vulnerabilities;
45 packages had verified registry signatures and 17 had verified attestations.
The release runtime check verifies the archive manifest and imports/invokes the
Lambda extracted from `lambda.zip` with a synthetic API Gateway v2 event. It
does not call AWS or prove Lambda IAM/production network behavior.

External validation is explicitly separate:

- September 8 anonymous provider probe: OSV query schema passed; GitHub asynchronous generation returned HTTP 404 and is marked unverified/degraded. Deterministic pending/redirect contracts pass independently of provider rollout/quota.
- AWS resources, IAM, billing alarms and SNS inbox delivery were not queried or deployed in this change.
- No real GitHub issue was posted to validate reconciliation; browser fixtures cover response-loss behavior. Use an explicitly approved disposable repository for external write qualification.
- Docker runtime and full screen-reader/200%-zoom certification remain release-environment checks unless separately recorded.

## Comparison Validation Protocol

FR-16 was a product hypothesis, not evidence that comparison saves time. The
experimental local view is available for evaluation only. Use two sanitized
before/after tasks: one successful package upgrade and one incomplete later
inventory. Record manual comparison time, experimental-view time, false identity
matches and whether the output changes the remediation decision. The provisional
target is at least 30% less analyst time with zero false automatic closures.
No user interview, benchmark result or production closure guarantee is claimed.
Do not expand this into automated release gates until those tasks demonstrate
value and the identity/coverage limitations are understood.

## Remaining Constraints

No authenticated shared storage, cross-device sync, private GitHub scanning,
arbitrary crawling, PoC execution, SAST/reachability, or automatic patch deployment.
Advisory extraction currently covers GitHub/CNA material; other references need
manual review. Import/repository processing is deliberately bounded. Backups
are unencrypted and can contain sensitive data. Local storage can be evicted.
GitHub search indexing and profile loss prevent any global exactly-once filing
guarantee. Browser cancellation cannot recall a request already sent upstream.
