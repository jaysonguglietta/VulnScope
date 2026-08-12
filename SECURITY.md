# Security Policy

## Supported Version

The `main` branch is the active development version.

## Deployment Boundary

VulnScope has no authentication, authorization, tenant isolation, or request logging by design. The public AWS deployment is suitable for public CVE research with non-sensitive browser-local data. It is not suitable for confidential shared case management, regulated evidence, or untrusted multi-user administration.

Do not place private research-source tokens in the browser bundle, commit them to Git, or enter confidential notes into a shared browser profile. The optional GitHub issue token is an analyst-supplied, repository-scoped credential held only in browser memory and sent directly to GitHub. Add identity and per-user authorization before introducing server-side case, watchlist, SBOM, or inventory storage.

Repository scanning processes public repository metadata, GitHub's generated
SBOM, or recognized public lockfiles on the server and sends exact package
identities and versions to OSV. Do not use the feature when that disclosure is
prohibited by policy. The server-side `GITHUB_TOKEN` used for public API rate
limits is distinct from the browser-only issue token.

## Implemented Controls

- Research-source credentials remain server-side in environment variables; GitHub issue tokens never pass through the VulnScope server.
- API methods and paths are allowlisted; JSON bodies and package counts are bounded.
- Research and enrichment have per-client rate limits, queue bounds, outbound concurrency limits, response-size limits, and Lambda/API Gateway capacity limits.
- Public repository scanning accepts only canonical GitHub HTTPS URLs, constructs fixed `api.github.com` destinations, rejects private repositories, and caps tree entries, lockfiles, decoded bytes, upstream calls, dependency queries, vulnerability processing, and issue batches.
- Repository metadata, package identities, advisory text, links, and generated issue Markdown are treated as untrusted input; rendered content is escaped, links are restricted to HTTP(S), and issue fields are bounded and sanitized.
- Automatic issue filing requires analyst selection, issue-draft review, an explicit confirmation checkbox, and a final browser confirmation. Existing open or closed CVE-title matches are skipped.
- API Gateway supplies the trusted client address in Lambda. Public `X-Forwarded-For` values do not select the rate-limit key.
- Static responses and API responses use CSP, frame blocking, content-type protection, referrer and permissions policies, and production HSTS.
- Rendered source text is escaped and external links are restricted to HTTP(S).
- CSV exports neutralize formula-leading imported text before spreadsheet use.
- Raw SBOM, cloud, and VEX files stay in browser memory. OSV enrichment sends only package identifiers after confirmation.
- Static and artifact buckets block public access and use server-side encryption. The static bucket uses versioning with noncurrent-version cleanup.
- Lambda logs have explicit 30-day retention and function-scoped write permissions; deployment artifacts are managed by a retained CloudFormation stack with versioning and expiration.
- Scheduled-monitor state is encrypted in DynamoDB and expires after 180 days.
- Production dependencies are checked with `npm audit --omit=dev` in `npm run verify`.
- Release actions and the production container base are immutable; release bundles include a checksum, SPDX SBOM, and GitHub-signed provenance that the deployment script verifies.

## Intentional Omissions

- Authentication and authorization
- Request and analyst activity logging
- Server-side case, SBOM, cloud inventory, or watchlist storage
- Multi-tenant isolation
- Private-repository scanning and GitHub App installation authentication

These omissions are deployment constraints, not controls. Put VulnScope behind an identity-aware proxy or private network boundary if it must handle sensitive work before native identity is implemented.

See [Public GitHub Repository Scanning](docs/github-repository-scanning.md) for
the detailed token, data-flow, limit, and recovery model.

## Reporting Issues

Report security issues privately to the repository owner. Include the affected commit, reproduction steps, impact, and suggested remediation when available. Do not include live credentials, private inventory, or other sensitive evidence in a public GitHub issue.
