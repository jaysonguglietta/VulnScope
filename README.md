# VulnScope

VulnScope is a CVE research and exposure-triage console. Paste one CVE, research a batch, or load SBOM and cloud evidence to answer the questions that matter during remediation:

- Is exploitation confirmed, plausible, or only being discussed?
- Is exploit code public, and how credible is the evidence?
- Which packages and imported cloud assets are exposed?
- Do AWS or Azure advisories or customer-managed services intersect with the issue?
- What should an engineer validate, patch, mitigate, and monitor?

Configured deployment domain: `vulnscope.jsontechnology.com`. AWS availability and previously recorded resources have not been revalidated in this local security-remediation pass.

Version 0.4.0 implements the September product-readiness recommendations. See
[the 16-item implementation matrix](docs/product-readiness.md) for scope,
verification, remaining external checks, and the experimental comparison feature.

## Product Workflows

### Deep CVE research

- Validates CVE IDs and collects NVD, CVE Services, CISA KEV, FIRST EPSS, GitHub Advisory Database, GitHub code and discussion leads, Hacker News, Reddit, and optional VulnCheck intelligence.
- Separates authoritative records, confirmed exploitation, public exploit leads, predictive risk, and public chatter.
- Produces a real-world verdict, risk score, evidence timeline, affected-product signals, cloud exposure analysis, and source health.
- Generates plain-text remediation, detection, cloud validation, ticket, executive, and risk-acceptance text with source links.
- Saves cases and watchlist entries locally in the browser and exports Markdown or JSON briefs.
- Retains dated last-known KEV/EPSS/CVSS values during outages; unknown research is not a clean result.
- Includes full bounded GitHub advisory narratives and CNA guidance, with source-content-bound claim IDs and local accept/reject/conflict review. Other web references remain explicitly unreviewed links.

### SBOM and package intelligence

- Loads up to 10 SBOMs per batch and parses them in a background browser worker.
- Supports CycloneDX JSON/XML, SPDX JSON/tag-value, Syft JSON, Grype JSON, and generic JSON/text containing CVEs.
- Shows the exact package rows associated with an SBOM CVE and automatically checks loaded SBOMs for the CVE currently being researched.
- Optionally enriches package URLs and ecosystems against OSV after explicit confirmation, including aliases, matching affected ranges, and package-specific fixed-version candidates with provenance.
- Preserves CycloneDX VEX per CVE, package/version, and imported file. Imported suppressions stay unverified. Analysts record separate, reversible target-scoped decisions with evidence and review dates in Exposures.
- Rejects malformed, oversized, or timed-out imports without reparsing on the main thread. XML is parsed inside the same bounded worker.
- Continues OSV enrichment in 50-package/40-advisory batches, including per-package pages and unresolved-detail retries. Enriched CVEs participate in the loaded-SBOM exact-CVE check and package drilldown.

### Public GitHub repository scanning

- Accepts only canonical public `https://github.com/owner/repository` URLs and retrieves GitHub's generated SPDX dependency graph when available.
- Falls back to bounded, read-only lockfile inspection when Dependency Graph is disabled. Exact pins are supported from npm, pip/Pipenv, Composer, Go, Cargo, and Bundler lock formats.
- Queries versioned package identifiers against OSV and groups package-specific matches by CVE for analyst confirmation.
- Generates one remediation issue per confirmed CVE, including detected versions, known fixes, OSV records, references, and validation steps.
- Shows the full issue body and checks exact CVE-title candidates before publishing. Existing issues are reused only after explicit review; declining reuse allows a separate create-or-skip choice. A fine-grained token with repository-scoped **Issues: Read and write** permission is held only in browser memory and sent directly to `api.github.com`.
- Provides prefilled GitHub issue drafts when automatic publishing is not desired.
- Uses asynchronous SBOM generation with resumable report handles and bounded lockfile fallback. Records confirmed scan snapshots and token-free filing receipts locally. An uncertain POST is reconciled before another issue can be created.

Typical workflow: open **Scan GitHub repository**, paste the public repository
URL, run the scan, review package-specific CVE matches, select up to 10 findings,
and review the generated issues. Automatic publishing requires a fine-grained
token restricted to the destination repository with **Issues: Read and write**;
manual prefilled issue drafts do not require a token in VulnScope.

See [Public GitHub Repository Scanning](docs/github-repository-scanning.md) for
the complete workflow, supported lockfiles, limits, token boundary, API contract,
failure recovery, and interpretation guidance.

### Exposure workspace

- Combines SBOM packages, OSV results, imported cloud findings, VEX statements, cases, watchlist entries, and bulk-research results.
- Filters by CVE, package or asset, source, severity, workflow status, and VEX status.
- Prioritizes confirmed exploitation, KEV membership, EPSS, CVSS, fix availability, and asset evidence while suppressing valid `not_affected` VEX statements.
- Exports the normalized exposure queue as CSV and opens any row directly in the full CVE investigation.
- Preserves account, region, package version, and occurrence scope; paginates dense results and retains researched CVEs without linked inventory in a separate triage list.
- Adds repository results to Exposures on request. Editable remediation plans retain prerequisites, chosen fix, owner, target date, verification, recovery notes, and sources.

### Local workspace management

- IndexedDB transactions and record revisions prevent silent cross-tab overwrites; failed saves retain drafts.
- Unsaved-change guards offer save/discard/cancel. Records are not automatically evicted or expired.
- **Data and operations** exports versioned backups and previews merge/replace restores. Normalized inventory is an explicit opt-in; restored suppressions require fresh review.
- An experimental before/after comparison highlights added, changed, absent, and unchanged package versions. Absence never automatically closes a finding.
- Mobile workspace navigation, browser back/forward, and labeled forms preserve core navigation.

### Cloud and VEX evidence

- Imports Amazon Inspector findings and generic AWS/Azure vulnerability JSON.
- Imports Microsoft Defender-style CSV or JSON exports.
- Imports OpenVEX, CSAF VEX, and CycloneDX VEX statements.
- Lists affected assets, package or resource evidence, remediation details, and VEX justification without uploading the original files.

### Bulk research and scheduled monitoring

- Queues up to 25 CVEs for bounded, sequential bulk research and feeds completed results into the exposure workspace.
- Supports an optional AWS scheduled monitor configured at deployment time.
- The monitor stores encrypted DynamoDB baselines and a durable pending notification before publishing material changes to SNS. Failed delivery is retried without advancing the baseline. Delivered snapshots expire after 180 days; pending notifications do not expire.

## Privacy Boundary

Raw SBOM, cloud finding, and VEX files are parsed locally and retained only in memory for the browser session. They are not uploaded to VulnScope, S3, Lambda, or a third party.

OSV enrichment is a separate, explicit action. After confirmation, VulnScope sends only normalized package identifiers, ecosystems, and versions to the server, which queries OSV. Do not enrich package metadata that your policy treats as confidential.

Public repository scans send the canonical repository name to the VulnScope server, which requests GitHub's public dependency-graph SBOM or supported public lockfiles and sends only exact versioned package identifiers to OSV. The optional issue-publishing token is never sent to VulnScope or persisted; the browser sends it directly to GitHub and discards it after the publishing action.

Imported suppressive VEX claims remain `Needs verification`. Use an exact-target decision in Exposures to record rationale, verification evidence and a review date. Decisions can be revoked and do not transfer to another version, file or cloud account. Restored approvals are unverified, including imported filing outcomes.

Cases, watchlist entries, local decisions, confirmed repository scan snapshots and filing receipts are stored in IndexedDB until explicitly deleted. Legacy cases/watchlists are migrated without deleting their original localStorage keys. Browser eviction, private browsing, profile loss and origin changes can still remove or hide local work; keep backups. Authentication and request logging are intentionally excluded; do not treat this as shared confidential case management. Backups are unencrypted and may contain sensitive inventory and analyst notes.

## Run Locally

Requires Node.js 20 or newer (Node 22 is the CI/deployment target). Python 3 is required for release-verification tests. Client assets are built automatically by `npm start`.

```bash
npm ci --ignore-scripts
npm start
```

Open `http://127.0.0.1:5173`. The server binds to localhost by default.

Optional source tokens improve coverage or rate limits:

```bash
NVD_API_KEY=... VULNCHECK_API_TOKEN=... npm start
```

Public GitHub research and inventory requests are anonymous. A server-side
`GITHUB_TOKEN` is deliberately ignored so private account data cannot enter public
responses or shared caches. Anonymous API quota exhaustion may reduce coverage.
The ephemeral browser issue token is separate. Use `.env.example` as a reference
and do not commit real secrets.

## Verify

```bash
npm run verify
npx playwright install chromium
npm run test:browser
```

Verification includes syntax and client builds, API/parser/model regressions, 11 adversarial regression groups, release tampering tests, and dependency auditing. CI and release workflows also run offline Playwright journeys against built CSP-constrained assets. `npm run test:providers` is a separate, opt-in anonymous public GitHub/OSV contract check; provider outages fail that check without changing deterministic tests. No normal test creates GitHub issues, AWS resources, or email. See [Security Remediation](docs/security-remediation.md) and [Product Readiness](docs/product-readiness.md).

## Security Defaults

- Security headers include CSP, HSTS in production, frame blocking, referrer policy, permissions policy, and content-sniffing protection.
- Research, enrichment, and public repository scan requests have per-client and CloudFront WAF rate limits, bounded queues, request-body limits, aggregate enrichment budgets, upstream response limits, and allowlisted API methods.
- AWS API Gateway throttles the stage to 2 requests per second with a burst of 5; API Lambda reserved concurrency is 2.
- CloudFront supplies a deployment-only origin secret, so direct calls to the public API Gateway endpoint are rejected.
- Client identity uses the trusted API Gateway source address. Loopback reverse proxies must overwrite forwarded addresses with a single validated client IP; appended chains are rejected. Limiter state has a hard capacity bound.
- Static and deployment-artifact buckets block public access and use server-side encryption; the static bucket also has versioning and lifecycle cleanup.
- External links are limited to HTTP(S), rendered text is escaped, and uploaded evidence is parsed as data rather than injected into markup.
- Source health reports observed success, failure, optional-token, or not-yet-checked state instead of implying every source is available.

The built-in controls reduce abuse; they do not replace authentication or authorization. Keep the public site free of sensitive case notes and inventory data until identity and tenant controls are added.

## AWS Deployment

The template uses Route 53, CloudFront, a private S3 static origin, API Gateway HTTP API, and on-demand Lambda. Historical account-level `$10`/`$20` email alarms are documented but have not been queried or recreated by this change.

Production deployment requires an approved, attested whole-deployment bundle,
checksum, source commit, and release ref. Follow [the release procedure](docs/deployment.md#deploy)
to set `DEPLOYMENT_BUNDLE_PATH`, `DEPLOYMENT_BUNDLE_SHA256`, `RELEASE_SOURCE_SHA`,
and `RELEASE_SOURCE_REF` before running `npm run deploy:aws`. Local `public/` or
`infra/` files are never mixed into that verified deployment.

After setting those release variables, enable scheduled CVE monitoring during deployment:

```bash
NOTIFICATION_EMAIL=Jayson.Guglietta@gmail.com \
MONITORED_CVES=CVE-2021-44228,CVE-2023-22527 \
npm run deploy:aws
```

AWS sends an SNS subscription-confirmation email the first time monitoring is enabled. Monitoring remains disabled when either the email or CVE list is empty.

Use **Data and operations** to export the intended email and exact 1-25 CVEs
with release prerequisites. More than 25 IDs are rejected, never silently
trimmed. `npm run monitor:status` is an explicitly invoked read-only operator
check; it is not a deployment command or proof of email delivery.

See [docs/deployment.md](docs/deployment.md) for the resource inventory, route and quota details, validation commands, Docker and reverse-proxy guidance, and monitor operations. See [SECURITY.md](SECURITY.md) for the deployment boundary and reporting process.

## Limitations

VulnScope is a research and prioritization console, not an authenticated scanner or proof of exploitability. Repository scanning supports public repositories only and evaluates dependencies represented in GitHub's generated SBOM or a bounded set of exact-version lockfiles; it does not perform SAST, secret scanning, reachability analysis, or dynamic testing. Unsupported lockfiles, unpinned manifests, scan limits, and upstream outages can produce incomplete coverage. Scans distinguish `complete`, `partial`, and `failed`; incomplete coverage is never a clean result. Primary CVE IDs, unresolved advisories, and unconsumed OSV pages are preserved or disclosed. Search matches, public chatter, inferred cloud services, imported findings, and package-version ranges can be incomplete or wrong. An official cloud reference establishes its source, not applicability to every service. Confirm decisions against vendor advisories, authoritative inventory, scanner evidence, compensating controls, and production telemetry.
