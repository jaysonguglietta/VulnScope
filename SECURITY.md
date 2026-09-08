# Security Policy

## Supported Version

The `main` branch is the active development version.

## Deployment Boundary

VulnScope has no authentication, authorization, tenant isolation, or request logging by design. The documented AWS template is intended for public CVE research with non-sensitive browser-local data. It is not suitable for confidential shared case management, regulated evidence, or untrusted multi-user administration.

Do not place private research-source tokens in the browser bundle, commit them to Git, or enter confidential notes into a shared browser profile. The optional GitHub issue token is an analyst-supplied, repository-scoped credential held only in browser memory and sent directly to GitHub. Add identity and per-user authorization before introducing server-side case, watchlist, SBOM, or inventory storage.

Repository scanning processes public repository metadata, GitHub's generated
SBOM, or recognized public lockfiles on the server and sends exact package
identities and versions to OSV. Do not use the feature when that disclosure is
prohibited by policy. Public GitHub requests are anonymous and ignore any
server-side `GITHUB_TOKEN`; private or unverifiable search results are excluded
before public response construction and caching.

## Implemented Controls

- Research-source credentials remain server-side in environment variables; GitHub issue tokens never pass through the VulnScope server.
- API methods and paths are allowlisted; JSON bodies and package counts are bounded.
- Research and enrichment have per-client rate limits, queue bounds, outbound concurrency limits, response-size limits, and Lambda/API Gateway capacity limits.
- Public repository scanning accepts only canonical GitHub HTTPS URLs, constructs fixed `api.github.com` destinations, rejects private repositories, and caps tree entries, lockfiles, decoded bytes, upstream calls, dependency queries, vulnerability processing, and issue batches.
- Repository metadata, package identities, advisory text, links, and generated issue Markdown are treated as untrusted input; rendered content is escaped, links are restricted to HTTP(S), and issue fields are bounded and sanitized.
- Automatic issue filing requires analyst selection, issue-draft review, an explicit confirmation checkbox, and a final browser confirmation. Exact CVE-title matches are candidates only. The analyst must explicitly reuse them or separately confirm a new issue; cancelling both does not publish.
- API Gateway supplies the trusted client address in Lambda. The optional loopback proxy accepts only one validated IP, never a caller-controlled forwarded chain. The limiter has a hard 2,000-client bound and prunes expired entries.
- Static responses and API responses use CSP, frame blocking, content-type protection, referrer and permissions policies, and production HSTS.
- Rendered source text is escaped and external links are restricted to HTTP(S).
- CSV exports neutralize formula-leading imported text before spreadsheet use.
- Raw SBOM, cloud, and VEX files stay in browser memory. OSV enrichment sends only package identifiers after confirmation.
- Static and artifact buckets block public access and use server-side encryption. The static bucket uses versioning with noncurrent-version cleanup.
- Lambda logs have explicit 30-day retention and function-scoped write permissions; deployment artifacts are managed by a retained CloudFormation stack with versioning and expiration.
- Scheduled-monitor state is encrypted in DynamoDB. Pending notifications survive publish failures and have no TTL; acknowledged baselines expire after 180 days. Conditional revisions prevent lost state updates. Delivery is at least once, not exactly once.
- All dependencies, including the XML parser and client bundler, are checked with `npm audit` in `npm run verify`. CI installation disables lifecycle scripts.
- Release actions and the production container base are immutable. A single signed bundle contains Lambda, frontend/worker, infrastructure, and a per-file hash manifest. Deployment binds provenance and manifest to an approved commit/ref and rejects unsafe extraction paths, links, altered/extra/missing files, and dirty releases.
- OSV failures, partial hydration, pagination and inventory limits are explicit coverage states. Primary CVE IDs are retained alongside aliases.
- SBOM parsing and aggregation run entirely inside a bounded worker; failure does not trigger main-thread parsing. Embedded VEX trust is scoped to a single CVE/package/version/file record. Conflicts cannot suppress a finding.
- Official cloud source classification uses exact parsed HTTPS authorities and paths. Official references do not prove service applicability.
- IndexedDB writes use per-record revisions and surface transaction failures. Same-record conflicts require an explicit reopen; independent records do not overwrite a whole collection.
- Unknown and dated last-known observations survive source outages. Source-content-bound claim IDs prevent a review from silently attaching to different advisory text.
- Workspace restore has byte/structure/schema checks and resets imported suppression authority. Backups are unencrypted; do not share them publicly or treat imported issue outcomes as authoritative.
- Local target decisions require review dates and supporting rationale; suppressive decisions require verification evidence, expire, and can be revoked. They are not authenticated approvals.
- GitHub issue POSTs require a persisted pre-write receipt. Unknown outcomes block automatic retries until an exact hidden draft marker is explicitly reconciled. This does not guarantee global uniqueness across browser profiles or manual writes.
- GitHub's asynchronous report handle is repository-bound; signed downloads follow only bounded redirects to explicitly allowed HTTPS GitHub hosts, without a server token.
- API queues and upstream stages share a maximum 17-second overall request budget. Browser reads support cancellation and bounded Retry-After handling; writes are not automatically retried.

## Intentional Omissions

- Authentication and authorization
- Request and analyst activity logging
- Server-side case, SBOM, cloud inventory, or watchlist storage
- Multi-tenant isolation
- Private-repository scanning and GitHub App installation authentication

These omissions are deployment constraints, not controls. Put VulnScope behind an identity-aware proxy or private network boundary if it must handle sensitive work before native identity is implemented.

See [Security Remediation](docs/security-remediation.md) for the 11-finding
regression matrix and remaining deployment assumptions. No AWS resources were
queried or deployed in this remediation pass.

See [Public GitHub Repository Scanning](docs/github-repository-scanning.md) for
the detailed token, data-flow, limit, and recovery model.

See [Product Readiness](docs/product-readiness.md) for the 0.4.0 implementation
matrix and external validation still required. User-study validation, production
AWS/SNS delivery, and global exactly-once GitHub issue creation are not claimed.

## Reporting Issues

Report security issues privately to the repository owner. Include the affected commit, reproduction steps, impact, and suggested remediation when available. Do not include live credentials, private inventory, or other sensitive evidence in a public GitHub issue.
