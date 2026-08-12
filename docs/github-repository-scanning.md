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
6. Review the generated issue titles and package evidence. Use **Open draft** to
   file an issue manually, or provide a fine-grained token for automatic filing.
7. Confirm the publishing statement and select **Publish issues**. VulnScope
   searches for an existing issue whose title contains the CVE before creating
   a new one. Open and closed issues are considered duplicates.

Each generated issue contains the CVE, severity signal, affected package and
detected version, known fixed versions, OSV records, source links, and a
copyable validation and remediation checklist. One issue is generated per CVE,
with all matching packages grouped into that issue.

## Dependency Discovery

VulnScope first requests GitHub's generated SPDX SBOM. If that endpoint is not
available, it reads the repository's public default-branch tree and inspects a
bounded set of recognized lockfiles.

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

- 20,000 generated-SBOM package rows inspected
- 50,000 repository tree entries inspected
- 10 supported lockfiles fetched
- 4 MiB decoded content per lockfile
- 16 MiB aggregate GitHub inventory response budget
- 15-second inventory deadline
- 50 unique exact package versions queried
- 40 hydrated OSV vulnerability records
- 10 confirmed GitHub issues per publishing batch

When a parser or limit prevents complete coverage, the interface marks the scan
as incomplete. Treat a clean but incomplete result as unknown, not as proof that
the repository has no vulnerable dependencies.

## GitHub Tokens

Two different optional tokens may be involved. They have different trust
boundaries and must not be reused casually.

### Server research token

`GITHUB_TOKEN` is an optional server environment variable used for public GitHub
research and repository inventory rate limits. It must never be exposed in the
browser bundle. Public repository scans work without it until GitHub's anonymous
API limit is exhausted.

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
package-specific OSV matches, truncation state, and source-health results. The
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
- Scan results remain in browser memory and are not saved as VulnScope cases.
- Issue creation is a separate browser-to-GitHub action requiring explicit
  analyst confirmation and a final browser confirmation dialog.

Do not scan a repository if disclosing its dependency names and versions to OSV
would violate policy. Do not paste an organization-wide or classic broadly
scoped GitHub token into the issue-publishing form.

## Failure and Recovery

- **Repository not found:** confirm that the URL identifies a public GitHub
  repository and contains only the owner and repository path.
- **GitHub refused the request:** wait for the anonymous rate limit to reset or
  configure a read-only server `GITHUB_TOKEN`.
- **No versioned packages:** enable GitHub Dependency Graph, commit a supported
  lockfile, or upload a CycloneDX/SPDX/Syft SBOM.
- **Scan incomplete:** reduce repository inventory size, split monorepo SBOMs,
  or upload a generated SBOM with the desired package scope.
- **Issues disabled:** use the generated issue text in another approved tracking
  system or enable GitHub Issues for the repository.
- **Token rejected:** verify repository selection, expiration, and
  **Issues: Read and write** permission. Do not add broader permissions unless
  the repository's policy requires them.
- **Duplicate found:** review the linked existing issue and update or reopen it
  instead of creating a second CVE ticket.

