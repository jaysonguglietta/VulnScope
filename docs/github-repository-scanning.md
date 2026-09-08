# Public GitHub Repository Scanning

VulnScope can inspect a public GitHub repository for known dependency CVEs and
turn analyst-confirmed matches into GitHub issues. The workflow is dependency
vulnerability analysis. It does not perform source-code SAST, secret scanning,
reachability analysis, malware detection, or dynamic exploitation.

## Analyst Workflow

1. Open **Scan GitHub repository** from the VulnScope workspace navigation.
2. Enter a public repository URL in the form
   `https://github.com/owner/repository`. An optional `.git` suffix and trailing
   slash are normalized.
3. Select **Scan repository**. VulnScope builds a bounded versioned dependency
   inventory and queries OSV.
4. Review each CVE, affected package version, known fixed version, and OSV
   advisory identifier. Selecting a finding confirms only that it should be
   reviewed and filed; it does not prove exploitability or reachability.
5. Select up to 10 CVEs and choose **Review selected**.
6. Review the generated issue titles, full expandable body, and package evidence. Use **Open draft** to
   file an issue manually, or provide a fine-grained token for automatic filing.
7. Confirm the publishing statement and select **Publish issues**. VulnScope
   searches for exact CVE identifiers in issue titles. Open and closed matches
   are candidates, never automatic suppression. Review the linked issue's
   package/version scope and resolution before choosing reuse. Declining reuse
   prompts separately to create a new issue; cancelling that prompt skips it.

Each generated issue contains the CVE, severity signal, affected package and
detected version, known fixed versions, OSV records, source links, and a
copyable validation and remediation checklist. One issue is generated per CVE,
with all matching packages grouped into that issue.

## Dependency Discovery

VulnScope requests `/dependency-graph/sbom/generate-report`, validates the
returned repository-bound UUID, then reads `/fetch-report/{id}`. HTTP 202 is
pending; downloads follow at most three HTTPS redirects to GitHub-owned
allowlisted hosts. A pending result retains its handle for **Resume**; the UI
polls at most six times per action. A missing API (404/410) falls back to public
lockfiles; analysts can also explicitly choose lockfile inventory. Unexpected
hosts, errors, expiration and throttling never become a clean result.

This replaces the synchronous endpoint ahead of its announced retirement.
See [GitHub's SBOM REST contract](https://docs.github.com/en/rest/dependency-graph/sboms?apiVersion=2026-03-10).
The September 8 live anonymous contract probe returned 404 for this repository;
asynchronous completion is verified with deterministic fixtures, not claimed
as a successful live download. OSV's live query schema passed that probe.

| Ecosystem | Fallback files | Version rule |
| --- | --- | --- |
| npm | `package-lock.json`, `npm-shrinkwrap.json` | Locked package versions |
| Python | `Pipfile.lock`, `requirements.txt` | Lock entries or exact `==` pins |
| PHP | `composer.lock` | Locked package versions |
| Go | `go.sum` | Module checksum versions; `/go.mod` rows are ignored |
| Rust | `Cargo.lock` | Locked crate versions |
| Ruby | `Gemfile.lock` | Locked gem versions |

Unversioned packages and range-only declarations are not sent to OSV. The
fallback does not currently parse `yarn.lock`, `pnpm-lock.yaml`, Poetry locks,
Maven/Gradle locks, NuGet locks, or arbitrary manifests. For those repositories,
enable GitHub Dependency Graph or upload a generated SBOM in VulnScope.

The default server limits are:

- 20,000 generated-SBOM package rows, or raw rows per supported lockfile, inspected
- 50,000 repository tree entries inspected
- 10 supported lockfiles fetched
- 4 MiB decoded content per lockfile
- 16 MiB aggregate GitHub inventory response budget
- 15-second inventory deadline
- 500 exact package identities retained from the bounded repository inventory
- 50 unique exact package versions queried per request, with explicit continuation
- 40 hydrated OSV vulnerability records per request, with detail offsets and per-package page tokens
- 17-second overall API budget, including queues, inventory and enrichment
- 10 confirmed GitHub issues per publishing batch

When a parser or limit prevents complete coverage, the interface marks the scan
as `partial` or `failed`, with coverage reasons. Empty incomplete results mean
unknown, not clean. Wildcards, ranges, unsupported identities, missing versions,
malformed inventory, and skipped rows cannot produce a fully checked result.

## GitHub Tokens

### Public research boundary

Server GitHub requests are anonymous. `GITHUB_TOKEN` is ignored even when present
in the server environment. Searches request public results, verify repository
visibility, and exclude private or unverifiable results before caching. This
trades authenticated quota for a strict public-data boundary. Wait for anonymous
quota recovery instead of adding a private-capable server token.

### Analyst issue token

Automatic issue filing accepts a fine-grained personal access token in the
browser. Create it with:

- Access limited to the selected destination repository
- Repository permission **Issues: Read and write**
- The shortest practical expiration
- No unrelated account or repository permissions

The token is held only in JavaScript memory, sent directly from the browser to
`https://api.github.com`, and discarded when the publishing view is left or the
page is refreshed. It is never sent to the VulnScope server, stored in local
storage, included in exports, or written to application logs. Manual prefilled
issue drafts require no token in VulnScope.

## API Contract

The browser starts a scan with:

```http
POST /api/github/scan
Content-Type: application/json

{"url":"https://github.com/owner/repository"}
```

The response contains normalized repository metadata, inventory counts,
package-specific OSV matches, coverage state, and source-health results:

- `status`: `pending`, `complete`, `partial`, or `failed`.
- `coverage.checkedPackageCount`: packages whose batch results were received.
- `coverage.reasons`: omissions, query/detail caps, hydration failures, or unconsumed OSV pagination.
- `coverage.unresolvedAdvisoryIds`: returned advisory IDs without usable detail.
- `truncated`: true for incomplete or failed coverage.
- `vulnerabilityCount`: null when matching failed, never a synthetic clean zero.
- `jobId`: repository-bound asynchronous report UUID when pending; resend with the same URL to resume.
- `inventoryPackages` and `pending`: retained exact identities and remaining work.
- Per-package `nextDetailOffset` and `nextPageToken`: continuation state consumed by the browser. `/api/enrich` accepts `detailOffset` and `pageToken` for each package. Failed details are retried without deleting completed results.

Primary OSV IDs that are CVEs are grouped even without aliases. Advisory IDs
without a resolved CVE remain visible. `complete` means all selected supported
packages were checked, not that the repository has no other dependencies or that
runtime exploitability has been established. The
server constructs all GitHub API destinations from the validated owner and
repository name; callers cannot supply an arbitrary outbound URL.

## Privacy and Security Boundary

- Only public repositories are supported. Private repositories are rejected.
- Repository names, public metadata, generated SBOM content, and supported
  public lockfiles are processed by the VulnScope server.
- Only normalized exact package identities and versions are sent to OSV.
- Repository content and advisory text are treated as untrusted data. Rendered
  values are escaped, Markdown fields are bounded and sanitized, and external
  links are restricted to HTTP(S).
- Scan requests use the same client rate limits, bounded research queue, and
  CloudFront/API capacity limits as other public research actions.
- Ordinary scans remain in session memory. Review confirmation persists a token-free scan snapshot and selected CVEs in IndexedDB. Explicitly add scan findings to Exposures or include normalized imports in a workspace backup.
- Issue creation is a separate browser-to-GitHub action requiring explicit
  analyst confirmation and a final browser confirmation dialog.

Do not scan a repository if disclosing its dependency names and versions to OSV
would violate policy. Do not paste an organization-wide or classic broadly
scoped GitHub token into the issue-publishing form.

## Failure and Recovery

- **Repository not found:** confirm that the URL identifies a public GitHub
  repository and contains only the owner and repository path.
- **GitHub refused the request:** wait for the anonymous rate limit to reset.
  Server research tokens are not supported.
- **No versioned packages:** enable GitHub Dependency Graph, commit a supported
  lockfile, or upload a CycloneDX/SPDX/Syft SBOM.
- **Scan incomplete:** reduce repository inventory size, split monorepo SBOMs,
  or upload a generated SBOM with the desired package scope.
- **Issues disabled:** use the generated issue text in another approved tracking
  system or enable GitHub Issues for the repository.
- **Token rejected:** verify repository selection, expiration, and
  **Issues: Read and write** permission. Do not add broader permissions unless
  the repository's policy requires them.
- **Existing candidate found:** inspect its package/version scope and resolution.
  Explicitly reuse it, confirm a new issue, or cancel without publishing.
- **Pending report:** resume the same report or explicitly choose the lockfile fallback. A deleted/expired report requires a new scan.
- **Remaining package/advisory work:** select **Continue** to process the next bounded batch. Original inventory omissions remain partial; continuation does not recover files outside the source inventory limit.
- **Outcome unknown:** a durable `Submitting` receipt was saved before POST. Reconcile its SHA-256 draft marker against GitHub before any new issue is allowed. Search indexing can lag; absence from search is not proof of a failed write. Reuse an exact marker match only after explicit review. Inspect the target repository manually when uncertain.

## Filing Journal

Receipts retain repository, CVE, draft-content digest, hidden issue-body marker,
scan time, status and issue URL without retaining the token. The exact same
completed draft is not posted again. A scan or plan change changes the digest
and requires a new review. Restoring receipts marks them unknown until
reconciled; imports do not establish successful external writes. This local
journal prevents automatic retries, not every possible duplicate across
different browsers, deleted profiles, or manual issue creation.

Drafts over 60,000 characters are refused by automatic publishing. Very long
prefilled URLs may exceed browser/GitHub limits; use the full visible issue body
and the case Markdown/text export instead. A manual draft is not a filing receipt.
